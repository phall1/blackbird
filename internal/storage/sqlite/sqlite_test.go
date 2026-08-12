package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

func TestOpenMigratesOnlyEmptyDatabaseAndReportsPinnedRuntime(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := store.Diagnostics()
	if diagnostics.DriverVersion != DriverVersion || diagnostics.SQLiteVersion != SQLiteVersion ||
		diagnostics.SQLiteSourceID != SQLiteSourceID || diagnostics.ApplicationID != ApplicationID ||
		diagnostics.SchemaVersion != SchemaVersion || diagnostics.JournalMode != "wal" ||
		!diagnostics.ForeignKeys || diagnostics.Synchronous != "2" || diagnostics.TrustedSchema ||
		diagnostics.ExtensionLoading || diagnostics.BusyTimeout != defaultBusyTimeout ||
		!diagnostics.FullFSync || !diagnostics.CheckpointFSync ||
		diagnostics.SchemaChecksum == ([sha256.Size]byte{}) {
		t.Fatalf("diagnostics=%+v", diagnostics)
	}
	diagnostics.CompileOptions[0] = "mutated"
	if store.Diagnostics().CompileOptions[0] == "mutated" {
		t.Fatal("diagnostics compile options alias internal state")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	var tables int
	if err := reopened.db.QueryRowContext(context.Background(),
		"SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
	).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 46 {
		t.Fatalf("tables=%d, want 46", tables)
	}
	if err := reopened.IntegrityCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenIncrementallyMigratesInstalledSchemaThree(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blackbird-v3.db")
	db, err := sql.Open("sqlite", databaseURL(Config{Path: path, BusyTimeout: defaultBusyTimeout}))
	if err != nil {
		t.Fatal(err)
	}
	for _, migrationID := range migrationIDs[:3] {
		body, checksum, migrationErr := migration(migrationID)
		if migrationErr != nil {
			t.Fatal(migrationErr)
		}
		if _, migrationErr = db.Exec(string(body)); migrationErr != nil {
			t.Fatal(migrationErr)
		}
		if _, migrationErr = db.Exec(`INSERT INTO schema_migrations(migration_id, checksum, applied_at_us, state)
			VALUES (?, ?, CAST(unixepoch('subsec') * 1000000 AS INTEGER), 'applied')`, migrationID, checksum[:]); migrationErr != nil {
			t.Fatal(migrationErr)
		}
	}
	v3 := expectedSchemaChecksumHex(schemaV3ChecksumHex)
	if _, err = db.Exec(`INSERT INTO schema_manifest(schema_version, checksum) VALUES (3, ?)`, v3[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`PRAGMA application_id = 1111641420`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if store.Diagnostics().SchemaVersion != SchemaVersion {
		t.Fatalf("schema version=%d", store.Diagnostics().SchemaVersion)
	}
	var migrations, keys int
	if err := store.db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT count(*) FROM coordination_event_cursor_keys`).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if migrations != 4 || keys != 1 {
		t.Fatalf("migration rows=%d cursor keys=%d", migrations, keys)
	}
}

func TestOpenRunsIntegrityGateAfterUncleanExit(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if store.Diagnostics().UncleanCheckRan {
		t.Fatal("fresh database reported an unclean recovery check")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	execRaw(t, path, "UPDATE database_runtime SET clean_shutdown = 0 WHERE singleton = 1")
	reopened, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	if !reopened.Diagnostics().UncleanCheckRan {
		t.Fatal("unclean database did not report its startup integrity gate")
	}
}

func TestOpenRejectsSecondOwnerAndLiveSchemaDrift(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("second owner error=%v", err)
	}
	if _, err := store.db.Exec("DROP INDEX outbox_jobs_ready_idx"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("schema drift error=%v", err)
	}
}

func TestOpenRejectsIdentityChecksumAndConfigurationDrift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"application id", func(t *testing.T, path string) { execRaw(t, path, "PRAGMA application_id = 1") }},
		{"schema version", func(t *testing.T, path string) { execRaw(t, path, "PRAGMA user_version = 5") }},
		{"migration checksum", func(t *testing.T, path string) {
			execRaw(t, path, "DROP TRIGGER schema_migrations_no_update")
			execRaw(t, path, "UPDATE schema_migrations SET checksum = zeroblob(32)")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "blackbird.db")
			store, err := Open(context.Background(), Config{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, path)
			if _, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrSchemaMismatch) {
				t.Fatalf("error=%v, want schema mismatch", err)
			}
		})
	}
	for _, config := range []Config{
		{}, {Path: "relative.db"}, {Path: filepath.Join(t.TempDir(), "database")},
		{Path: filepath.Join(t.TempDir(), "database.db"), BusyTimeout: maximumBusyTimeout + time.Millisecond},
		{Path: filepath.Join(t.TempDir(), "database.db"), BusyTimeout: time.Microsecond},
	} {
		if _, err := Open(context.Background(), config); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("config=%+v error=%v", config, err)
		}
	}
}

func TestDurabilityHistoryIsAppendOnly(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		"UPDATE schema_migrations SET state = 'resumable'",
		"DELETE FROM schema_migrations",
	} {
		if _, err := store.db.ExecContext(context.Background(), statement); err == nil {
			t.Fatalf("immutable history accepted %q", statement)
		}
	}
}

func TestSchemaEnforcesReceiptEventAndAuthorityScopeIdentities(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	installationA := "01b8e094-9888-7000-8000-000000000001"
	installationB := "01b8e094-9888-7000-8000-000000000002"
	principalA := "01b8e094-9888-7000-8000-000000000003"
	principalB := "01b8e094-9888-7000-8000-000000000004"
	for _, values := range [][2]string{{installationA, principalA}, {installationB, principalB}} {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO principals(
            principal_id, installation_id, kind, display_name, status, version, created_at_us, updated_at_us
        ) VALUES (?, ?, 'human', 'Owner', 'active', 1, 1, 1)`, values[1], values[0]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO device_registrations(
        device_id, installation_id, principal_id, display_name, credential_algorithm, public_key_reference,
        spki_fingerprint, transcript_fingerprint, trust_revision, status, version, created_at_us, updated_at_us
    ) VALUES (?, ?, ?, 'Wrong scope', 'ed25519-spki-sha256-v1', 'keyref:test', zeroblob(32), zeroblob(32), 1, 'trusted', 1, 1, 1)`,
		"01b8e094-9888-7000-8000-000000000005", installationA, principalB); err == nil {
		t.Fatal("cross-installation device principal accepted")
	}

	workspace := "01b8e094-9888-7000-8000-000000000006"
	epoch := "01b8e094-9888-7000-8000-000000000007"
	insertReceipt := func(receiptID, commandID, principal string) error {
		_, err := store.db.ExecContext(ctx, `INSERT INTO command_receipts(
			receipt_id, command_id, scope_kind, scope_id, authority_id, authority_epoch, identity_kind, workspace_id,
			principal_id, client_instance_id, operation, operation_major, idempotency_key, request_fingerprint, result_digest,
			result_canonical, first_event_sequence, last_event_sequence, final_stream_digest, guard_digest,
			capsule_required, committed_at_us
		) VALUES (?, ?, 'workspace', ?, ?, ?, 'ordinary_workspace', ?, ?, ?, 'actor.create.v1', 1,
			'same-key', zeroblob(32), zeroblob(32), X'00', 1, 1, zeroblob(32), zeroblob(32), 0, 1)`,
			receiptID, commandID, workspace, installationA, epoch, workspace, principal,
			"01b8e094-9888-7000-8000-000000000012")
		return err
	}
	if err := insertReceipt("01b8e094-9888-7000-8000-000000000008", "01b8e094-9888-7000-8000-000000000009", principalA); err != nil {
		t.Fatal(err)
	}
	if err := insertReceipt("01b8e094-9888-7000-8000-00000000000a", "01b8e094-9888-7000-8000-00000000000b", principalB); err != nil {
		t.Fatalf("different principal collided on idempotency key: %v", err)
	}
	if err := insertReceipt("01b8e094-9888-7000-8000-00000000000c", "01b8e094-9888-7000-8000-00000000000d", principalA); err == nil {
		t.Fatal("duplicate canonical receipt identity accepted")
	}

	insertEvent := func(eventID string, sequence, index int) error {
		_, err := store.db.ExecContext(ctx, `INSERT INTO domain_events(
            event_id, command_id, receipt_id, authority_id, authority_epoch, scope_kind, scope_id,
            stream_sequence, previous_stream_digest, event_digest, stream_digest, aggregate_kind,
            aggregate_id, aggregate_version, event_index, event_type, event_schema, payload, principal_id,
            authorization_digest, correlation_id, recorded_at_us
        ) VALUES (?, ?, ?, ?, ?, 'workspace', ?, ?, zeroblob(32), zeroblob(32), zeroblob(32), 'actor',
            ?, 2, ?, 'ActorChanged', 1, X'7b7d', ?, zeroblob(32), ?, 1)`,
			eventID, "01b8e094-9888-7000-8000-000000000009", "01b8e094-9888-7000-8000-000000000008",
			installationA, epoch, workspace, sequence, "01b8e094-9888-7000-8000-00000000000e", index,
			principalA, "01b8e094-9888-7000-8000-00000000000f")
		return err
	}
	if err := insertEvent("01b8e094-9888-7000-8000-000000000010", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := insertEvent("01b8e094-9888-7000-8000-000000000011", 2, 1); err != nil {
		t.Fatalf("second event for one aggregate version rejected: %v", err)
	}
}

func TestWriteLaneSerializesImmediateTransactionsAndRollsBack(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- store.withImmediate(context.Background(), func(tx *sql.Tx) error {
			close(entered)
			<-release
			_, err := tx.Exec("INSERT INTO backup_sessions(backup_id, state, started_at_us) VALUES (?, 'capturing', 1)",
				"01b8e094-9888-7000-8000-000000000001")
			return err
		})
	}()
	<-entered
	var secondEntered atomic.Bool
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- store.withImmediate(context.Background(), func(*sql.Tx) error {
			secondEntered.Store(true)
			return errors.New("rollback sentinel")
		})
	}()
	time.Sleep(20 * time.Millisecond)
	if secondEntered.Load() {
		t.Fatal("second writer entered while first writer held lane")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err == nil || err.Error() != "rollback sentinel" {
		t.Fatalf("second error=%v", err)
	}
	if !secondEntered.Load() {
		t.Fatal("second writer never entered")
	}

	var rows int
	if err := store.db.QueryRow("SELECT count(*) FROM backup_sessions").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d, want committed first write only", rows)
	}
}

func TestExecuteSecurityCoversAllOperationsReplaySuppressionAndAuditChain(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	fixture := newSecurityFixture(t)

	initialization, err := application.InitializeInstallationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, fixture.admission,
		fixture.invitation, application.DigestBytes([]byte("initialization guard")),
	)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := store.ExecuteSecurity(context.Background(), initialization, securityMutationDecision(t, "installation_initialized"))
	if err != nil || execution.Kind() != application.SecurityApplied {
		t.Fatalf("initialize execution=%q error=%v", execution.Kind(), err)
	}

	rotated, err := application.RotateBootstrapGenerationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, fixture.admission, fixture.generationA, fixture.generationB,
	)
	if err != nil {
		t.Fatal(err)
	}
	execution, err = store.ExecuteSecurity(context.Background(), rotated, securityMutationDecision(t, "bootstrap_generation_rotated"))
	if err != nil || execution.Kind() != application.SecurityApplied {
		t.Fatalf("rotate execution=%q error=%v", execution.Kind(), err)
	}

	expectation, err := domain.ExpectAggregateVersion(fixture.invitation.ID(), fixture.invitation.Version())
	if err != nil {
		t.Fatal(err)
	}
	resume, err := application.ResumeBootstrapGenerationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, fixture.admission, expectation,
		fixture.generationA, fixture.generationB, domain.FingerprintCommand([]byte("verified approval")),
	)
	if err != nil {
		t.Fatal(err)
	}
	execution, err = store.ExecuteSecurity(context.Background(), resume, securityMutationDecision(t, "bootstrap_generation_resumed"))
	if err != nil || execution.Kind() != application.SecurityApplied {
		t.Fatalf("resume execution=%q error=%v", execution.Kind(), err)
	}

	attempt := newBootstrapAttempt(t, fixture.invitation.ID(), "first")
	bootstrapDenial, err := application.RecordBootstrapDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch, fixture.admission, expectation, attempt,
	)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapDenial = bindSecurityAudit(t, bootstrapDenial)
	var lockedTime time.Time
	execution, err = store.ExecuteSecurity(context.Background(), bootstrapDenial,
		func(locked application.SecurityContext) (application.SecurityDecision, error) {
			lockedTime = locked.AuthorityTime()
			next := deniedInvitation(t, locked.Invitation())
			return application.DenyBootstrapSecurity(locked, next, securityAudit(t, bootstrapDenial, "bootstrap_proof_rejected"))
		})
	if err != nil || execution.Kind() != application.SecurityDenialCommitted {
		t.Fatalf("fresh denial execution=%q error=%v", execution.Kind(), err)
	}
	committed, _ := execution.Denial()
	if !committed.DeniedAt().Equal(lockedTime) || committed.InvitationVersion().Uint64() != 2 {
		t.Fatalf("committed denial=%+v locked_time=%s", committed, lockedTime)
	}

	callbackInvoked := false
	execution, err = store.ExecuteSecurity(context.Background(), bootstrapDenial,
		func(locked application.SecurityContext) (application.SecurityDecision, error) {
			callbackInvoked = true
			return application.ReplayBootstrapDenialSecurity(locked)
		})
	if err != nil || execution.Kind() != application.SecurityDenialReplayed || !callbackInvoked {
		t.Fatalf("replay execution=%q invoked=%v error=%v", execution.Kind(), callbackInvoked, err)
	}
	replayed, _ := execution.Denial()
	if replayed != committed {
		t.Fatalf("replayed denial=%+v, want %+v", replayed, committed)
	}

	commandDenial := newCommandDenialSpec(t, fixture, "duplicate")
	execution, err = store.ExecuteSecurity(context.Background(), commandDenial, auditOrSuppressDenial(t, commandDenial))
	if err != nil || execution.Kind() != application.SecurityCommandDenialAudited {
		t.Fatalf("command denial execution=%q error=%v", execution.Kind(), err)
	}
	execution, err = store.ExecuteSecurity(context.Background(), commandDenial, auditOrSuppressDenial(t, commandDenial))
	if err != nil || execution.Kind() != application.SecurityCommandDenialSuppressed {
		t.Fatalf("duplicate command denial execution=%q error=%v", execution.Kind(), err)
	}

	var auditCount int
	if err := store.db.QueryRow("SELECT count(*) FROM audit_entries").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 5 {
		t.Fatalf("audit entries=%d, want initialize+rotate+resume+bootstrap+command", auditCount)
	}
	verifyStoredAuditChain(t, store)
}

func TestExecuteSecurityRollbackInvalidDecisionAndCASAreAtomic(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	fixture := newSecurityFixture(t)
	initializeSecurityFixture(t, store, fixture)

	rotate, err := application.RotateBootstrapGenerationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, fixture.admission, fixture.generationA, fixture.generationB,
	)
	if err != nil {
		t.Fatal(err)
	}
	rejection, err := domain.NewCommandError(domain.ErrorCodeStateConflict, "security rollback", nil)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := store.ExecuteSecurity(context.Background(), rotate,
		func(locked application.SecurityContext) (application.SecurityDecision, error) {
			return application.RollbackSecurity(locked, rejection)
		})
	if err != nil || execution.Kind() != application.SecurityRejected {
		t.Fatalf("rollback execution=%q error=%v", execution.Kind(), err)
	}

	_, err = store.ExecuteSecurity(context.Background(), rotate,
		func(application.SecurityContext) (application.SecurityDecision, error) {
			return application.SecurityDecision{}, nil
		})
	if !errors.Is(err, application.ErrInvalidSecurityDecision) {
		t.Fatalf("zero decision error=%v", err)
	}

	sentinel := errors.New("callback failure")
	_, err = store.ExecuteSecurity(context.Background(), rotate,
		func(application.SecurityContext) (application.SecurityDecision, error) {
			return application.SecurityDecision{}, sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("callback error=%v", err)
	}

	_, err = store.ExecuteSecurity(context.Background(), rotate,
		func(application.SecurityContext) (application.SecurityDecision, error) { panic("rollback panic") })
	if err == nil {
		t.Fatal("callback panic was not converted to rollback error")
	}

	var generation string
	var auditCount int
	if err := store.db.QueryRow(`SELECT bootstrap_generation_id FROM scope_guards
		WHERE scope_kind = 'installation' AND scope_id = ?`, fixture.scope.ID()).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM audit_entries").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if generation != fixture.generationA.String() || auditCount != 1 {
		t.Fatalf("rollback leaked generation=%q audits=%d", generation, auditCount)
	}

	staleAdmission, _ := application.NewGuardGeneration(fixture.admission.Uint64() + 1)
	stale, err := application.RotateBootstrapGenerationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, staleAdmission, fixture.generationA, fixture.generationB,
	)
	if err != nil {
		t.Fatal(err)
	}
	invoked := false
	_, err = store.ExecuteSecurity(context.Background(), stale, func(application.SecurityContext) (application.SecurityDecision, error) {
		invoked = true
		return application.SecurityDecision{}, nil
	})
	if !errors.Is(err, application.ErrInvalidSecurityContext) || invoked {
		t.Fatalf("stale CAS admission error=%v callback_invoked=%v", err, invoked)
	}
}

func TestExecuteSecurityDenialSaturationAndReservedAdmission(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	fixture := newSecurityFixture(t)
	initializeSecurityFixture(t, store, fixture)
	// Keep every denial in one authority-time bucket even when the repeated
	// race suite starts near a wall-clock minute boundary.
	bucketFloor := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Minute).Add(10 * time.Second)
	if _, err := store.db.Exec(`UPDATE authority_streams SET authority_time_floor_us = ?
		WHERE scope_kind = ? AND scope_id = ? AND authority_epoch = ?`,
		timeMicros(bucketFloor), string(fixture.scope.Kind()), fixture.scope.ID(), fixture.epoch.String()); err != nil {
		t.Fatal(err)
	}

	for index := range application.MaxDistinctDenialsPerMinute {
		spec := newCommandDenialSpec(t, fixture, fmt.Sprintf("distinct-%d", index))
		execution, err := store.ExecuteSecurity(context.Background(), spec, auditOrSuppressDenial(t, spec))
		if err != nil || execution.Kind() != application.SecurityCommandDenialAudited {
			t.Fatalf("detail %d execution=%q error=%v", index, execution.Kind(), err)
		}
	}
	saturation := newCommandDenialSpec(t, fixture, "saturation")
	var saturationKind application.DenialAdmissionKind
	execution, err := store.ExecuteSecurity(context.Background(), saturation,
		func(locked application.SecurityContext) (application.SecurityDecision, error) {
			admission, _ := locked.DenialAdmission()
			saturationKind = admission.Kind()
			return auditOrSuppressDenial(t, saturation)(locked)
		})
	if err != nil || execution.Kind() != application.SecurityCommandDenialAudited ||
		saturationKind != application.DenialAdmitSaturation {
		t.Fatalf("saturation kind=%q execution=%q error=%v", saturationKind, execution.Kind(), err)
	}
	later := newCommandDenialSpec(t, fixture, "later")
	execution, err = store.ExecuteSecurity(context.Background(), later, auditOrSuppressDenial(t, later))
	if err != nil || execution.Kind() != application.SecurityCommandDenialSuppressed {
		t.Fatalf("post-saturation execution=%q error=%v", execution.Kind(), err)
	}

	// Holding the ordinary writer lane does not consume the independently
	// reserved security admission token, and cancellation remains bounded.
	if err := store.acquireWrite(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = store.ExecuteSecurity(ctx, later, auditOrSuppressDenial(t, later))
	store.releaseWrite()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reserved admission cancellation error=%v", err)
	}
	select {
	case <-store.securityLane:
		store.securityLane <- struct{}{}
	default:
		t.Fatal("cancelled security admission leaked its reserved token")
	}
}

func TestExecuteSecurityScopeDenialSaturationSummaryIsUnique(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	fixture := newSecurityFixture(t)
	initializeSecurityFixture(t, store, fixture)

	var bucket int64
	if err := store.db.QueryRow("SELECT CAST(unixepoch('subsec') AS INTEGER) / 60").Scan(&bucket); err != nil {
		t.Fatal(err)
	}
	err := store.withImmediate(context.Background(), func(tx *sql.Tx) error {
		for index := range application.MaxDenialEntriesPerScopeMinute {
			fingerprint := sha256.Sum256([]byte(fmt.Sprintf("scope-entry-%d", index)))
			if _, err := tx.Exec(`INSERT INTO security_denials(
				record_kind, denial_fingerprint, scope_kind, scope_id, subject_kind, subject_id,
				operation, operation_major, denial_class, reason, bucket, occurrence_count,
				first_recorded_at_us, last_recorded_at_us
			) VALUES ('command', ?, 'installation', ?, 'unattributed_source', ?, 'actor.create.v1', 1,
				'authentication', 'proof_rejected', ?, 1, 1, 1)`,
				fingerprint[:], fixture.scope.ID(), fmt.Sprintf("source-%d", index), bucket,
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	spec := newCommandDenialSpec(t, fixture, "scope-saturation")
	var admissionKind application.DenialAdmissionKind
	execution, err := store.ExecuteSecurity(context.Background(), spec,
		func(locked application.SecurityContext) (application.SecurityDecision, error) {
			admission, _ := locked.DenialAdmission()
			admissionKind = admission.Kind()
			return auditOrSuppressDenial(t, spec)(locked)
		})
	if err != nil || execution.Kind() != application.SecurityCommandDenialAudited ||
		admissionKind != application.DenialAdmitScopeSaturation {
		t.Fatalf("scope saturation admission=%q execution=%q error=%v", admissionKind, execution.Kind(), err)
	}

	later := newCommandDenialSpec(t, fixture, "scope-suppressed")
	execution, err = store.ExecuteSecurity(context.Background(), later, auditOrSuppressDenial(t, later))
	if err != nil || execution.Kind() != application.SecurityCommandDenialSuppressed {
		t.Fatalf("scope suppression execution=%q error=%v", execution.Kind(), err)
	}
	var summaries int
	if err := store.db.QueryRow(`SELECT count(*) FROM security_denials
		WHERE scope_id = ? AND bucket = ? AND reason = 'denial_scope_saturated'`, fixture.scope.ID(), bucket).Scan(&summaries); err != nil {
		t.Fatal(err)
	}
	if summaries != 1 {
		t.Fatalf("scope saturation summaries=%d, want 1", summaries)
	}
}

func TestSecurityDenialIdentityIsScopedAndOperationSpecific(t *testing.T) {
	t.Parallel()
	store := openSecurityStore(t)
	fingerprint := sha256.Sum256([]byte("same safe denial draft"))
	insert := func(scopeID, operation string) error {
		_, err := store.db.Exec(`INSERT INTO security_denials(
			record_kind, denial_fingerprint, scope_kind, scope_id, subject_kind, subject_id,
			operation, operation_major, denial_class, reason, bucket, occurrence_count,
			first_recorded_at_us, last_recorded_at_us
		) VALUES ('command', ?, 'installation', ?, 'unattributed_source', 'same-source',
			?, 1, 'authentication', 'proof_rejected', 1, 1, 1, 1)`,
			fingerprint[:], scopeID, operation,
		)
		return err
	}
	scopeA := "01b8e094-9888-7000-8000-000000000301"
	scopeB := "01b8e094-9888-7000-8000-000000000302"
	if err := insert(scopeA, "actor.create.v1"); err != nil {
		t.Fatal(err)
	}
	if err := insert(scopeB, "actor.create.v1"); err != nil {
		t.Fatalf("same fingerprint in another scope was suppressed: %v", err)
	}
	if err := insert(scopeA, "session.start.v1"); err != nil {
		t.Fatalf("same fingerprint for another operation was suppressed: %v", err)
	}
	if err := insert(scopeA, "actor.create.v1"); err == nil {
		t.Fatal("exact scoped denial identity was accepted twice")
	}
}

type securityFixture struct {
	scope                    domain.AuthorityScope
	authority                domain.AuthorityID
	epoch                    domain.AuthorityEpoch
	admission                application.GuardGeneration
	invitation               domain.InstallationInvitationState
	generationA, generationB domain.BootstrapGenerationID
}

func openSecurityStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "security.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func newSecurityFixture(t *testing.T) securityFixture {
	t.Helper()
	installation, _ := domain.ParseInstallationID("01b8e094-9888-7000-8000-000000000101")
	authority, _ := domain.ParseAuthorityID("01b8e094-9888-7000-8000-000000000102")
	epoch, _ := domain.ParseAuthorityEpoch("01b8e094-9888-7000-8000-000000000103")
	invitationID, _ := domain.ParseInvitationID("01b8e094-9888-7000-8000-000000000104")
	generationA, _ := domain.ParseBootstrapGenerationID("01b8e094-9888-7000-8000-000000000105")
	generationB, _ := domain.ParseBootstrapGenerationID("01b8e094-9888-7000-8000-000000000106")
	publicKey, _ := domain.NewPublicKeyReference("keyref:installation")
	issuedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	invitation, err := domain.NewInstallationInvitation(
		invitationID, installation, publicKey, domain.FingerprintCommand([]byte("invitation verifier")), issuedAt, generationA,
	)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := domain.InstallationScope(installation)
	admission, _ := application.NewGuardGeneration(7)
	return securityFixture{
		scope: scope, authority: authority, epoch: epoch, admission: admission,
		invitation: invitation, generationA: generationA, generationB: generationB,
	}
}

func initializeSecurityFixture(t *testing.T, store *Store, fixture securityFixture) {
	t.Helper()
	spec, err := application.InitializeInstallationSecurity(
		fixture.scope, fixture.authority, fixture.epoch, fixture.admission,
		fixture.invitation, application.DigestBytes([]byte("initialization guard")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExecuteSecurity(context.Background(), spec, securityMutationDecision(t, "installation_initialized")); err != nil {
		t.Fatal(err)
	}
}

func securityMutationDecision(t *testing.T, reason string) func(application.SecurityContext) (application.SecurityDecision, error) {
	t.Helper()
	return func(locked application.SecurityContext) (application.SecurityDecision, error) {
		audit := securityAudit(t, locked.Spec(), reason)
		if locked.Spec().Operation() == application.SecurityInitializeInstallation {
			return application.InitializeSecurity(locked, audit)
		}
		return application.ChangeBootstrapGenerationSecurity(locked, audit)
	}
}

func securityAudit(t *testing.T, spec application.SecuritySpec, reason string) application.AuditIntent {
	t.Helper()
	operation, fingerprint, present := application.ExpectedSecurityAudit(spec)
	if !present {
		t.Fatal("security audit identity absent")
	}
	name, err := domain.NewOperationName(operation)
	if err != nil {
		t.Fatal(err)
	}
	var detail application.AuditDetail
	if reason == "bootstrap_proof_rejected" || reason == "proof_rejected" {
		detail, err = application.SecurityDeniedAuditDetail(reason)
	} else {
		detail, err = application.SecurityMutationAuditDetail(reason)
	}
	if err != nil {
		t.Fatal(err)
	}
	outcome := application.AuditSecurityMutation
	if detail.Kind() == application.AuditDetailSecurityDenied {
		outcome = application.AuditSecurityDenied
	}
	audit, err := application.NewAuditIntent(name, outcome, fingerprint, detail)
	if err != nil {
		t.Fatal(err)
	}
	return audit
}

func bindSecurityAudit(t *testing.T, spec application.SecuritySpec) application.SecuritySpec {
	t.Helper()
	request, err := application.NewAuditRequestContext(
		"01b8e094-9888-7000-8000-000000000201", "01b8e094-9888-7000-8000-000000000202",
		time.Now().UTC().Truncate(time.Microsecond), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := application.NewAuditProvenanceEvidence(spec.AuthorityID(), nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := application.BindSecurityAuditContext(spec, request, provenance)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func newBootstrapAttempt(t *testing.T, invitation domain.InvitationID, seed string) application.BootstrapAttempt {
	t.Helper()
	digest := func(label string) domain.CommandFingerprint { return domain.FingerprintCommand([]byte(seed + label)) }
	attempt, err := application.NewBootstrapAttempt(
		invitation, digest("transcript"), digest("client"), digest("server"), digest("channel"), digest("proof"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func deniedInvitation(t *testing.T, invitation domain.InstallationInvitationState) domain.InstallationInvitationState {
	t.Helper()
	version, err := invitation.Version().Next()
	if err != nil {
		t.Fatal(err)
	}
	status := domain.InstallationInvitationPending
	failures := invitation.FailedAttempts() + 1
	if failures == domain.MaxBootstrapFailedAttempts {
		status = domain.InstallationInvitationExhausted
	}
	next, err := domain.RehydrateInstallationInvitation(domain.InstallationInvitationRehydrationParams{
		ID: invitation.ID(), InstallationID: invitation.InstallationID(),
		InstallationPublicKey: invitation.InstallationPublicKey(), InvitationVerifier: invitation.InvitationVerifier(),
		BootstrapGenerationID: invitation.BootstrapGenerationID(), ExpiresAt: invitation.ExpiresAt(),
		FailedAttempts: failures, Status: status, Version: version,
	})
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func newCommandDenialSpec(t *testing.T, fixture securityFixture, seed string) application.SecuritySpec {
	t.Helper()
	operation, _ := domain.NewOperationName("actor.create.v1")
	major, _ := application.NewOperationMajor(1)
	subject, _ := application.UnattributedDenialSource(application.DigestBytes([]byte("source")))
	correlation, _ := domain.ParseCorrelationID("01b8e094-9888-7000-8000-000000000203")
	draft, err := application.NewCommandDenialDraft(
		operation, major, application.DenialAuthentication, "proof_rejected",
		domain.FingerprintCommand([]byte(seed)), subject, nil, correlation,
	)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := application.RecordCommandDenialSecurity(
		fixture.scope, fixture.authority, fixture.epoch, fixture.admission, draft,
	)
	if err != nil {
		t.Fatal(err)
	}
	return bindSecurityAudit(t, spec)
}

func auditOrSuppressDenial(
	t *testing.T,
	spec application.SecuritySpec,
) func(application.SecurityContext) (application.SecurityDecision, error) {
	t.Helper()
	return func(locked application.SecurityContext) (application.SecurityDecision, error) {
		admission, _ := locked.DenialAdmission()
		switch admission.Kind() {
		case application.DenialAdmitDistinct, application.DenialAdmitSaturation, application.DenialAdmitScopeSaturation:
			return application.AuditCommandDenialSecurity(locked, securityAudit(t, spec, "proof_rejected"))
		default:
			return application.SuppressCommandDenialSecurity(locked)
		}
	}
}

func verifyStoredAuditChain(t *testing.T, store *Store) {
	t.Helper()
	rows, err := store.db.Query(`SELECT previous_entry_hash, entry_hash, canonical_entry
		FROM audit_entries ORDER BY audit_sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var previous application.Digest
	codec := application.NewProductionCanonicalCodec()
	for rows.Next() {
		var storedPrevious, storedDigest, canonical []byte
		if err := rows.Scan(&storedPrevious, &storedDigest, &canonical); err != nil {
			t.Fatal(err)
		}
		if len(storedPrevious) != sha256.Size || len(storedDigest) != sha256.Size {
			t.Fatal("invalid stored audit digest length")
		}
		if string(storedPrevious) != string(previous[:]) {
			t.Fatal("audit predecessor does not match prior entry")
		}
		var digest application.Digest
		copy(digest[:], storedDigest)
		if err := codec.VerifyAuditEntry(previous, canonical, digest); err != nil {
			t.Fatal(err)
		}
		previous = digest
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteLanePrioritizesReservedSecurityAdmission(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "blackbird.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := store.acquireWrite(context.Background(), false); err != nil {
		t.Fatal(err)
	}

	order := make(chan string, 2)
	ordinaryStarted := make(chan struct{})
	go func() {
		close(ordinaryStarted)
		if err := store.acquireWrite(context.Background(), false); err != nil {
			order <- "ordinary-error"
			return
		}
		order <- "ordinary"
		store.releaseWrite()
	}()
	<-ordinaryStarted

	go func() {
		if err := store.acquireWrite(context.Background(), true); err != nil {
			order <- "security-error"
			return
		}
		order <- "security"
		store.releaseWrite()
	}()
	deadline := time.Now().Add(time.Second)
	for {
		store.writes.Lock()
		waiting := store.writes.securityWaiting
		store.writes.Unlock()
		if waiting == 1 {
			break
		}
		if time.Now().After(deadline) {
			store.releaseWrite()
			t.Fatal("security writer never entered the reserved admission queue")
		}
		time.Sleep(time.Millisecond)
	}
	store.releaseWrite()
	if first := <-order; first != "security" {
		t.Fatalf("first admitted writer=%q, want security", first)
	}
	if second := <-order; second != "ordinary" {
		t.Fatalf("second admitted writer=%q, want ordinary", second)
	}
}

func execRaw(t *testing.T, path, statement string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}
