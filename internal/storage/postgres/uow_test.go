package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/phall1/blackbird/internal/application"
)

func TestStoreStaticallyComposesAsUnitOfWork(t *testing.T) {
	t.Parallel()
	var _ application.UnitOfWork = (*Store)(nil)

	for file, required := range map[string][]string{
		"command.go": {
			"pgx.Serializable", "pg_advisory_xact_lock", "FOR SHARE", "FOR UPDATE",
			"application.ValidateCommandDecision", "PostgreSQL command callback panic",
			"application.IndeterminateCommandTransactionExecution", "ReceiptIntegrityConflict",
		},
		"security.go": {
			"pgx.Serializable", "pg_advisory_xact_lock", "FOR UPDATE",
			"application.ValidateSecurityDecision", "NewProductionCanonicalCodec",
			"PostgreSQL security callback panic",
		},
	} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s is missing production composition %q", file, fragment)
			}
		}
	}
}

func TestPostgreSQLCommandPathIsNativeAndComplete(t *testing.T) {
	t.Parallel()
	files := []string{"command.go", "command_state.go", "command_apply.go", "command_persist.go"}
	var combined strings.Builder
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		combined.Write(body)
	}
	text := combined.String()
	for _, forbidden := range []string{"QueryRowContext", "ExecContext", "unixepoch(", "zeroblob("} {
		if strings.Contains(text, forbidden) {
			t.Errorf("PostgreSQL command path contains SQLite construct %q", forbidden)
		}
	}
	for _, required := range []string{
		"ReceiptIdentityOrdinary", "ReceiptIdentityProvisioning", "ReceiptIdentityInstallationAdmin",
		"domain.InstallationInvitationState", "domain.PrincipalState", "domain.DeviceState", "domain.GrantState",
		"domain.WorkspaceState", "domain.MembershipState", "domain.ActorState", "domain.ActorDelegationState",
		"domain.ActorSessionState", "VerifyReceiptResult", "VerifyRecoveryCapsule", "EncodeAuditEntry",
		"blackbird.outbox-job/v1", "verifyDurableCommandEvidence", "advanceCommandStream",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("PostgreSQL command path is missing %q", required)
		}
	}
}

func TestDeterministicOutboxUUID(t *testing.T) {
	t.Parallel()
	seed := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	first, second := digestUUID(seed), digestUUID(seed)
	if first != second || len(first) != 36 || first[14] != '4' {
		t.Fatalf("digestUUID(%x) = %q, %q", seed, first, second)
	}
	if first[19] != '8' && first[19] != '9' && first[19] != 'a' && first[19] != 'b' {
		t.Fatalf("digestUUID has invalid RFC 4122 variant: %q", first)
	}
}

func TestPostgreSQLAdvisoryLocksAreTransactionScoped(t *testing.T) {
	appDSN := os.Getenv("BLACKBIRD_TEST_POSTGRES_DSN")
	migrationDSN := os.Getenv("BLACKBIRD_TEST_POSTGRES_MIGRATION_DSN")
	if appDSN == "" || migrationDSN == "" {
		t.Skip("explicit BLACKBIRD_TEST_POSTGRES_DSN and BLACKBIRD_TEST_POSTGRES_MIGRATION_DSN are unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, Config{DSN: appDSN, MigrationDSN: migrationDSN, ApplicationName: "blackbird-uow-lock-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	first, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Rollback(context.Background()) })
	if _, err := first.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", securityLockID); err != nil {
		t.Fatal(err)
	}

	blockedCtx, blockedCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer blockedCancel()
	second, err := store.pool.BeginTx(blockedCtx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	_, lockErr := second.Exec(blockedCtx, "SELECT pg_advisory_xact_lock($1)", securityLockID)
	_ = second.Rollback(context.Background())
	if lockErr == nil || !errors.Is(blockedCtx.Err(), context.DeadlineExceeded) {
		t.Fatalf("competing security lane lock error=%v context=%v", lockErr, blockedCtx.Err())
	}
	if err := first.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	third, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = third.Rollback(context.Background()) }()
	if _, err := third.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", securityLockID); err != nil {
		t.Fatalf("transaction-scoped advisory lock was not released: %v", err)
	}
}
