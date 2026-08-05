package postgres

import (
	"context"
	"crypto/sha256"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestSchemaStaticallyMatchesSQLiteLogicalTablesAndNativeTypes(t *testing.T) {
	t.Parallel()
	postgresBody, _, err := initialMigration()
	if err != nil {
		t.Fatal(err)
	}
	sqliteBody, err := os.ReadFile("../sqlite/migrations/0001_w0.sql")
	if err != nil {
		t.Fatal(err)
	}
	tablePattern := regexp.MustCompile(`(?im)^CREATE TABLE ([a-z_]+)\s*\(`)
	tables := func(body []byte) []string {
		matches := tablePattern.FindAllSubmatch(body, -1)
		result := make([]string, 0, len(matches))
		for _, match := range matches {
			result = append(result, string(match[1]))
		}
		sort.Strings(result)
		return result
	}
	postgresTables, sqliteTables := tables(postgresBody), tables(sqliteBody)
	if strings.Join(postgresTables, ",") != strings.Join(sqliteTables, ",") {
		t.Fatalf("PostgreSQL tables=%v, SQLite tables=%v", postgresTables, sqliteTables)
	}
	if len(postgresTables) != 27 {
		t.Fatalf("PostgreSQL table count=%d, want 27", len(postgresTables))
	}

	schema := string(postgresBody)
	for _, required := range []string{
		"scope_id uuid", "event_id uuid PRIMARY KEY", "payload bytea NOT NULL",
		"recorded_at_us bigint", "capabilities_json jsonb NOT NULL",
		"BETWEEN 1 AND 9007199254740991", "BETWEEN 0 AND 9007199254740991",
	} {
		if !strings.Contains(schema, required) {
			t.Errorf("schema is missing %q", required)
		}
	}
	for _, forbidden := range []string{"scope_id text", "event_id text", "recorded_at_us integer"} {
		if strings.Contains(strings.ToLower(schema), forbidden) {
			t.Errorf("schema contains non-native declaration %q", forbidden)
		}
	}
}

func TestEmbeddedMigrationChecksumIsStableAndComplete(t *testing.T) {
	t.Parallel()
	body, checksum, err := initialMigration()
	if err != nil {
		t.Fatal(err)
	}
	if checksum != sha256.Sum256(body) || checksum == ([sha256.Size]byte{}) {
		t.Fatal("embedded migration checksum is not its immutable SHA-256")
	}
	for _, object := range []string{"schema_migrations", "schema_manifest", "domain_events", "audit_entries", "outbox_jobs"} {
		if !strings.Contains(string(body), "CREATE TABLE "+object) {
			t.Errorf("migration does not create %s", object)
		}
	}
}

func TestConfigRejectsUnverifiedTLSAndUnboundedSettings(t *testing.T) {
	t.Parallel()
	base := Config{DSN: "postgres://app@example.test/blackbird?sslmode=verify-full"}
	configured := withDefaults(base)
	if err := validateConfig(configured); err != nil {
		t.Fatal(err)
	}
	parsed, err := poolConfig(configured.DSN, configured, configured.ApplicationName)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.MaxConns != 8 || parsed.MinConns != 1 || parsed.ConnConfig.ConnectTimeout != defaultConnectTimeout ||
		parsed.ConnConfig.RuntimeParams["application_name"] != defaultApplicationName ||
		parsed.ConnConfig.RuntimeParams["statement_timeout"] != "10000ms" ||
		parsed.ConnConfig.RuntimeParams["lock_timeout"] != "5000ms" ||
		parsed.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] != "10000ms" {
		t.Fatalf("pool config=%+v runtime=%v", parsed, parsed.ConnConfig.RuntimeParams)
	}
	for _, config := range []Config{
		{DSN: "postgres://app@example.test/blackbird?sslmode=disable"},
		{DSN: "postgres://app@example.test/blackbird?sslmode=require"},
		{DSN: base.DSN, MinConns: 2, MaxConns: 1},
		{DSN: base.DSN, MaxConns: 65},
		{DSN: base.DSN, LockTimeout: 2 * time.Second, StatementTimeout: time.Second},
		{DSN: base.DSN, AcquireTimeout: time.Microsecond},
	} {
		config = withDefaults(config)
		if err := validateConfig(config); err == nil {
			if _, parseErr := poolConfig(config.DSN, config, config.ApplicationName); parseErr == nil {
				t.Fatalf("configuration accepted: %+v", config)
			}
		}
	}
}

func TestOpenPostgreSQL18MigrationDiagnosticsAndPrivileges(t *testing.T) {
	appDSN := os.Getenv("BLACKBIRD_TEST_POSTGRES_DSN")
	migrationDSN := os.Getenv("BLACKBIRD_TEST_POSTGRES_MIGRATION_DSN")
	if appDSN == "" || migrationDSN == "" {
		t.Skip("explicit BLACKBIRD_TEST_POSTGRES_DSN and BLACKBIRD_TEST_POSTGRES_MIGRATION_DSN are unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, Config{DSN: appDSN, MigrationDSN: migrationDSN, ApplicationName: "blackbird-integration-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	diagnostics := store.Diagnostics()
	if diagnostics.ServerVersionNumber < 180000 || diagnostics.ServerVersionNumber >= 190000 ||
		diagnostics.TLSVersion == "" || diagnostics.DriverVersion != DriverVersion ||
		diagnostics.SchemaVersion != SchemaVersion || diagnostics.MigrationChecksum == ([sha256.Size]byte{}) ||
		diagnostics.ApplicationRole == diagnostics.SchemaOwner {
		t.Fatalf("diagnostics=%+v", diagnostics)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE blackbird.domain_events SET event_type = event_type`); err == nil {
		t.Fatal("application role can update the immutable event journal")
	}
	if _, err := store.pool.Exec(ctx, `UPDATE blackbird.schema_migrations SET state = 'resumable'`); err == nil {
		t.Fatal("application role can update migration history")
	}
	_, err = store.pool.Exec(ctx, `INSERT INTO blackbird.principals(
		principal_id, installation_id, kind, display_name, status, version, created_at_us, updated_at_us
	) VALUES ('0198e094-9888-7000-8000-000000000001', '0198e094-9888-7000-8000-000000000002',
		'human', 'range probe', 'active', 9007199254740992, 1, 1)`)
	if err == nil {
		t.Fatal("schema accepted an integer above max_canonical_integer")
	}
}
