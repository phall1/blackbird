package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

// These lists are deliberately exhaustive. A storage engine must account for
// every closed application operation before it can claim W0 conformance.
var conformanceCommandOperations = [...]application.CommandOperation{
	application.CommandBootstrapInstallation,
	application.CommandRegisterPrincipal,
	application.CommandCreateWorkspace,
	application.CommandInviteWorkspaceMember,
	application.CommandAcceptWorkspaceMembership,
	application.CommandCreateActor,
	application.CommandProposeActorDelegation,
	application.CommandActivateActorDelegation,
	application.CommandBeginDevicePairing,
	application.CommandPairDevice,
	application.CommandStartActorSession,
}

var conformanceSecurityOperations = [...]application.SecurityOperation{
	application.SecurityInitializeInstallation,
	application.SecurityRotateBootstrapGeneration,
	application.SecurityResumeBootstrapGeneration,
	application.SecurityRecordBootstrapDenial,
	application.SecurityRecordCommandDenial,
}

func TestUnitOfWorkConformanceCorpusCoversClosedOperationSurface(t *testing.T) {
	t.Parallel()
	if len(conformanceCommandOperations) != 11 {
		t.Fatalf("command operations=%d, want 11", len(conformanceCommandOperations))
	}
	if len(conformanceSecurityOperations) != 5 {
		t.Fatalf("security operations=%d, want 5", len(conformanceSecurityOperations))
	}

	commands := make(map[application.CommandOperation]struct{}, len(conformanceCommandOperations))
	for _, operation := range conformanceCommandOperations {
		if operation == "" {
			t.Fatal("conformance corpus contains a zero command operation")
		}
		if _, duplicate := commands[operation]; duplicate {
			t.Fatalf("duplicate command operation %q", operation)
		}
		commands[operation] = struct{}{}
	}
	security := make(map[application.SecurityOperation]struct{}, len(conformanceSecurityOperations))
	for _, operation := range conformanceSecurityOperations {
		if !operation.Valid() {
			t.Fatalf("invalid security operation %q", operation)
		}
		if _, duplicate := security[operation]; duplicate {
			t.Fatalf("duplicate security operation %q", operation)
		}
		security[operation] = struct{}{}
	}
}

func TestUnitOfWorkProductionConstructorHasNoCodecSubstitutionSeam(t *testing.T) {
	t.Parallel()
	// Open is the production Store constructor. Keeping this exact assignment
	// makes an injectable codec or alternate test constructor a compile failure.
	constructor := Open
	constructorType := reflect.TypeOf(constructor)
	if constructorType.NumIn() != 2 || constructorType.NumOut() != 2 {
		t.Fatalf("Open signature changed to %s", constructorType)
	}

	store, err := constructor(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
}

func TestUnitOfWorkAtomicPersistenceRolesArePresent(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})

	for _, table := range []string{
		"command_receipts", "domain_events", "audit_entries", "outbox_jobs",
	} {
		var count int
		if err := store.db.QueryRowContext(context.Background(),
			"SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?", table,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("atomic persistence role %q is absent", table)
		}
	}
}

func TestUnitOfWorkSecurityInitializationRoundTripsStateAndAudit(t *testing.T) {
	t.Parallel()
	store := openConformanceStore(t)
	spec, invitation := conformanceInitializationSpec(t)
	execution, err := store.ExecuteSecurity(context.Background(), spec, func(locked application.SecurityContext) (application.SecurityDecision, error) {
		if locked.Spec().Operation() != application.SecurityInitializeInstallation || locked.Invitation() != (domain.InstallationInvitationState{}) {
			t.Fatal("initialization callback received an invalid locked context")
		}
		return conformanceInitializeDecision(t, locked)
	})
	if err != nil || execution.Kind() != application.SecurityApplied {
		t.Fatalf("initialization execution=%s error=%v", execution.Kind(), err)
	}

	var installationID, publicKey, status string
	var verifier []byte
	var version uint64
	if err := store.db.QueryRowContext(context.Background(), `SELECT installation_id,
		installation_public_key_reference, invitation_verifier, status, version
		FROM installation_invitations WHERE invitation_id = ?`, invitation.ID().String()).Scan(
		&installationID, &publicKey, &verifier, &status, &version,
	); err != nil {
		t.Fatal(err)
	}
	wantVerifier := invitation.InvitationVerifier()
	if installationID != invitation.InstallationID().String() ||
		publicKey != invitation.InstallationPublicKey().String() ||
		string(verifier) != string(wantVerifier[:]) ||
		status != string(invitation.Status()) || version != invitation.Version().Uint64() {
		t.Fatal("installation invitation did not round-trip through normalized state")
	}
	var clockStatus string
	if err := store.db.QueryRowContext(context.Background(),
		"SELECT clock_status FROM authority_streams WHERE scope_kind = 'installation' AND scope_id = ?",
		invitation.InstallationID().String(),
	).Scan(&clockStatus); err != nil {
		t.Fatal(err)
	}
	if clockStatus != "normal" || store.Diagnostics().BackwardClockTolerance != time.Second {
		t.Fatalf("authority clock status=%q tolerance=%s", clockStatus, store.Diagnostics().BackwardClockTolerance)
	}
	assertConformanceCounts(t, store, map[string]int{
		"scope_guards": 1, "authority_streams": 1, "installation_invitations": 1, "audit_entries": 1,
	})
}

func TestUnitOfWorkSecurityCallbackFailuresAreAtomic(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		decide func(application.SecurityContext) (application.SecurityDecision, error)
	}{
		{"error", func(application.SecurityContext) (application.SecurityDecision, error) {
			return application.SecurityDecision{}, errors.New("callback sentinel")
		}},
		{"zero decision", func(application.SecurityContext) (application.SecurityDecision, error) {
			return application.SecurityDecision{}, nil
		}},
		{"panic", func(application.SecurityContext) (application.SecurityDecision, error) {
			panic("callback sentinel")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := openConformanceStore(t)
			spec, _ := conformanceInitializationSpec(t)
			if _, err := store.ExecuteSecurity(context.Background(), spec, test.decide); err == nil {
				t.Fatal("callback failure was accepted")
			}
			assertConformanceCounts(t, store, map[string]int{
				"scope_guards": 0, "authority_streams": 0, "installation_invitations": 0,
				"security_denials": 0, "audit_entries": 0,
			})
		})
	}
}

func TestExecuteCommandReplayLeavesAuthorityClockReadOnly(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	security := newSecurityFixture(t)
	initializeSecurityFixture(t, store, security)
	spec, decide, _ := newBootstrapCommand(t, security)
	if execution, err := store.ExecuteCommand(context.Background(), spec, decide); err != nil ||
		execution.Kind() != application.CommandTransactionCommitted {
		t.Fatalf("bootstrap execution=%q error=%v", execution.Kind(), err)
	}
	var before int64
	if err := store.db.QueryRowContext(context.Background(), `SELECT authority_time_floor_us FROM authority_streams
		WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?`, string(spec.Scope().Kind()),
		spec.Scope().ID(), spec.RequestedEpoch().String()).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if replay, err := store.ExecuteCommand(context.Background(), spec, func(locked application.CommandContext) (application.CommandDecision, error) {
		return application.ReplayCommand(locked, application.ReplayDiscloseResult)
	}); err != nil || replay.Kind() != application.CommandTransactionReplayed {
		t.Fatalf("replay execution=%q error=%v", replay.Kind(), err)
	}
	var after int64
	if err := store.db.QueryRowContext(context.Background(), `SELECT authority_time_floor_us FROM authority_streams
		WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?`, string(spec.Scope().Kind()),
		spec.Scope().ID(), spec.RequestedEpoch().String()).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("replay advanced authority floor from %d to %d", before, after)
	}
}

func openConformanceStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return store
}

func conformanceInitializationSpec(t *testing.T) (application.SecuritySpec, domain.InstallationInvitationState) {
	t.Helper()
	uuid := func(index int) string { return fmt.Sprintf("01b8e094-9888-7000-8000-%012x", index) }
	installation, _ := domain.ParseInstallationID(uuid(900))
	authority, _ := domain.ParseAuthorityID(uuid(901))
	epoch, _ := domain.ParseAuthorityEpoch(uuid(902))
	invitationID, _ := domain.ParseInvitationID(uuid(903))
	generationID, _ := domain.ParseBootstrapGenerationID(uuid(904))
	key, _ := domain.NewPublicKeyReference("keyref:sqlite-conformance")
	invitation, err := domain.NewInstallationInvitation(
		invitationID, installation, key, domain.FingerprintCommand([]byte("sqlite conformance verifier")),
		time.Now().UTC(), generationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := domain.InstallationScope(installation)
	generation, _ := application.NewGuardGeneration(1)
	spec, err := application.InitializeInstallationSecurity(
		scope, authority, epoch, generation, invitation,
		application.DigestBytes([]byte("sqlite conformance initialization guard")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return spec, invitation
}

func conformanceInitializeDecision(t *testing.T, locked application.SecurityContext) (application.SecurityDecision, error) {
	t.Helper()
	operation, fingerprint, ok := application.ExpectedSecurityAudit(locked.Spec())
	if !ok {
		t.Fatal("initialization has no expected security audit")
	}
	name, _ := domain.NewOperationName(operation)
	detail, _ := application.SecurityMutationAuditDetail("installation_initialized")
	audit, err := application.NewAuditIntent(name, application.AuditSecurityMutation, fingerprint, detail)
	if err != nil {
		t.Fatal(err)
	}
	return application.InitializeSecurity(locked, audit)
}

func assertConformanceCounts(t *testing.T, store *Store, expected map[string]int) {
	t.Helper()
	for table, want := range expected {
		var got int
		if err := store.db.QueryRowContext(context.Background(), "SELECT count(*) FROM "+table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s rows=%d, want %d", table, got, want)
		}
	}
}
