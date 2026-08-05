package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	SchemaVersion       = 1
	DriverVersion       = "v5.10.0"
	PostgreSQLMajor     = 18
	initialMigrationID  = "0001_w0.sql"
	applicationSchema   = "blackbird"
	migrationLockID     = int64(0x42424d4c)
	MaxCanonicalInteger = int64(9_007_199_254_740_991)

	defaultApplicationName  = "blackbird"
	defaultAcquireTimeout   = 5 * time.Second
	defaultConnectTimeout   = 5 * time.Second
	defaultStatementTimeout = 10 * time.Second
	defaultLockTimeout      = 5 * time.Second
	defaultIdleTxTimeout    = 10 * time.Second
	defaultHealthCheck      = 30 * time.Second
	defaultMaxConnLifetime  = 30 * time.Minute
	defaultMaxConnIdleTime  = 5 * time.Minute
)

var (
	ErrInvalidConfiguration = errors.New("invalid PostgreSQL configuration")
	ErrEngineMismatch       = errors.New("PostgreSQL engine mismatch")
	ErrSchemaMismatch       = errors.New("PostgreSQL schema mismatch")
	ErrPrivilegeMismatch    = errors.New("PostgreSQL role or privilege mismatch")

	//go:embed migrations/*.sql
	migrations embed.FS
)

type Config struct {
	DSN               string
	MigrationDSN      string
	ApplicationName   string
	MinConns          int32
	MaxConns          int32
	AcquireTimeout    time.Duration
	ConnectTimeout    time.Duration
	StatementTimeout  time.Duration
	LockTimeout       time.Duration
	HealthCheckPeriod time.Duration
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
}

type Diagnostics struct {
	DriverVersion       string
	DriverVerified      bool
	ServerVersion       string
	ServerVersionNumber int
	TLSVersion          string
	TLSCipher           string
	ApplicationName     string
	DatabaseName        string
	ApplicationRole     string
	SchemaOwner         string
	SchemaVersion       int
	MigrationID         string
	MigrationChecksum   [sha256.Size]byte
	SchemaChecksum      [sha256.Size]byte
	MinConns            int32
	MaxConns            int32
	AcquireTimeout      time.Duration
	ConnectTimeout      time.Duration
	StatementTimeout    time.Duration
	LockTimeout         time.Duration
}

type Store struct {
	pool        *pgxpool.Pool
	diagnostics Diagnostics
	closeOnce   sync.Once
}

func Open(ctx context.Context, config Config) (*Store, error) {
	config = withDefaults(config)
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	appConfig, err := poolConfig(config.DSN, config, config.ApplicationName)
	if err != nil {
		return nil, err
	}
	applicationRole := appConfig.ConnConfig.User
	if applicationRole == "" {
		return nil, fmt.Errorf("%w: application DSN must identify a role", ErrInvalidConfiguration)
	}
	if config.MigrationDSN != "" {
		if err := migrate(ctx, config, applicationRole); err != nil {
			return nil, err
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, appConfig)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL application pool: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			pool.Close()
		}
	}()
	acquireCtx, cancel := context.WithTimeout(ctx, config.AcquireTimeout)
	defer cancel()
	if err := pool.Ping(acquireCtx); err != nil {
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	diagnostics, err := inspect(acquireCtx, pool, config)
	if err != nil {
		return nil, err
	}
	store := &Store{pool: pool, diagnostics: diagnostics}
	opened = true
	return store, nil
}

func withDefaults(config Config) Config {
	if config.ApplicationName == "" {
		config.ApplicationName = defaultApplicationName
	}
	if config.MinConns == 0 {
		config.MinConns = 1
	}
	if config.MaxConns == 0 {
		config.MaxConns = 8
	}
	if config.AcquireTimeout == 0 {
		config.AcquireTimeout = defaultAcquireTimeout
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = defaultConnectTimeout
	}
	if config.StatementTimeout == 0 {
		config.StatementTimeout = defaultStatementTimeout
	}
	if config.LockTimeout == 0 {
		config.LockTimeout = defaultLockTimeout
	}
	if config.HealthCheckPeriod == 0 {
		config.HealthCheckPeriod = defaultHealthCheck
	}
	if config.MaxConnLifetime == 0 {
		config.MaxConnLifetime = defaultMaxConnLifetime
	}
	if config.MaxConnIdleTime == 0 {
		config.MaxConnIdleTime = defaultMaxConnIdleTime
	}
	return config
}

func validateConfig(config Config) error {
	durations := []time.Duration{config.AcquireTimeout, config.ConnectTimeout, config.StatementTimeout, config.LockTimeout,
		config.HealthCheckPeriod, config.MaxConnLifetime, config.MaxConnIdleTime}
	if strings.TrimSpace(config.DSN) == "" || strings.TrimSpace(config.ApplicationName) == "" ||
		config.MinConns < 1 || config.MaxConns < config.MinConns || config.MaxConns > 64 {
		return ErrInvalidConfiguration
	}
	for _, duration := range durations {
		if duration <= 0 || duration%time.Millisecond != 0 {
			return ErrInvalidConfiguration
		}
	}
	if config.LockTimeout > config.StatementTimeout || config.AcquireTimeout > time.Minute ||
		config.ConnectTimeout > time.Minute || config.StatementTimeout > time.Minute {
		return ErrInvalidConfiguration
	}
	return nil
}

func poolConfig(dsn string, config Config, applicationName string) (*pgxpool.Config, error) {
	parsed, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: parse DSN: %v", ErrInvalidConfiguration, err)
	}
	if parsed.ConnConfig.TLSConfig == nil || parsed.ConnConfig.TLSConfig.InsecureSkipVerify ||
		parsed.ConnConfig.TLSConfig.ServerName == "" {
		return nil, fmt.Errorf("%w: TLS with server identity verification is required", ErrInvalidConfiguration)
	}
	parsed.MinConns = config.MinConns
	parsed.MaxConns = config.MaxConns
	parsed.HealthCheckPeriod = config.HealthCheckPeriod
	parsed.MaxConnLifetime = config.MaxConnLifetime
	parsed.MaxConnIdleTime = config.MaxConnIdleTime
	parsed.ConnConfig.ConnectTimeout = config.ConnectTimeout
	parsed.ConnConfig.RuntimeParams["application_name"] = applicationName
	parsed.ConnConfig.RuntimeParams["timezone"] = "UTC"
	parsed.ConnConfig.RuntimeParams["search_path"] = applicationSchema + ",pg_catalog"
	parsed.ConnConfig.RuntimeParams["statement_timeout"] = durationSetting(config.StatementTimeout)
	parsed.ConnConfig.RuntimeParams["lock_timeout"] = durationSetting(config.LockTimeout)
	parsed.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = durationSetting(defaultIdleTxTimeout)
	parsed.AfterConnect = verifyConnection
	return parsed, nil
}

func durationSetting(value time.Duration) string {
	return fmt.Sprintf("%dms", value.Milliseconds())
}

func verifyConnection(ctx context.Context, conn *pgx.Conn) error {
	var version int
	var tls, timezone, searchPath string
	if err := conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer,
		COALESCE((SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid() AND ssl), ''),
		current_setting('TimeZone'), current_setting('search_path')`).Scan(&version, &tls, &timezone, &searchPath); err != nil {
		return fmt.Errorf("inspect PostgreSQL physical connection: %w", err)
	}
	if version < PostgreSQLMajor*10000 || version >= (PostgreSQLMajor+1)*10000 {
		return fmt.Errorf("%w: server_version_num=%d", ErrEngineMismatch, version)
	}
	if tls == "" || timezone != "UTC" || searchPath != applicationSchema+",pg_catalog" {
		return fmt.Errorf("%w: physical connection invariants", ErrEngineMismatch)
	}
	return nil
}

func migrate(ctx context.Context, config Config, applicationRole string) error {
	migrationConfig, err := poolConfig(config.MigrationDSN, config, config.ApplicationName+"-migration")
	if err != nil {
		return fmt.Errorf("migration connection: %w", err)
	}
	if migrationConfig.ConnConfig.User == applicationRole {
		return fmt.Errorf("%w: migration and application roles must differ", ErrInvalidConfiguration)
	}
	pool, err := pgxpool.NewWithConfig(ctx, migrationConfig)
	if err != nil {
		return fmt.Errorf("open PostgreSQL migration pool: %w", err)
	}
	defer pool.Close()
	acquireCtx, cancel := context.WithTimeout(ctx, config.AcquireTimeout)
	defer cancel()
	return pgx.BeginTxFunc(acquireCtx, pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(acquireCtx, "SELECT pg_advisory_xact_lock($1)", migrationLockID); err != nil {
			return fmt.Errorf("acquire PostgreSQL migration lock: %w", err)
		}
		body, checksum, err := initialMigration()
		if err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(acquireCtx, "SELECT to_regclass('blackbird.schema_migrations') IS NOT NULL").Scan(&exists); err != nil {
			return fmt.Errorf("inspect PostgreSQL schema: %w", err)
		}
		if !exists {
			if _, err := tx.Exec(acquireCtx, string(body)); err != nil {
				return fmt.Errorf("apply PostgreSQL migration %s: %w", initialMigrationID, err)
			}
			wall := "floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint"
			liveChecksum, err := schemaChecksum(acquireCtx, tx)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(acquireCtx, `INSERT INTO blackbird.schema_manifest(schema_version, checksum) VALUES ($1, $2)`, SchemaVersion, liveChecksum[:]); err != nil {
				return fmt.Errorf("record PostgreSQL schema manifest: %w", err)
			}
			if _, err := tx.Exec(acquireCtx, `INSERT INTO blackbird.schema_migrations(migration_id, checksum, applied_at_us, state) VALUES ($1, $2, `+wall+`, 'applied')`, initialMigrationID, checksum[:]); err != nil {
				return fmt.Errorf("record PostgreSQL migration: %w", err)
			}
		} else if err := verifyLedger(acquireCtx, tx, checksum); err != nil {
			return err
		}
		return grantApplicationRole(acquireCtx, tx, applicationRole)
	})
}

func initialMigration() ([]byte, [sha256.Size]byte, error) {
	body, err := migrations.ReadFile("migrations/" + initialMigrationID)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("read embedded PostgreSQL migration: %w", err)
	}
	return body, sha256.Sum256(body), nil
}

type pgQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func verifyLedger(ctx context.Context, query pgQuery, expected [sha256.Size]byte) error {
	var migrationChecksum, recordedSchemaChecksum []byte
	var state string
	var count int
	if err := query.QueryRow(ctx, `SELECT checksum, state FROM blackbird.schema_migrations WHERE migration_id = $1`, initialMigrationID).Scan(&migrationChecksum, &state); err != nil {
		return fmt.Errorf("%w: migration ledger: %v", ErrSchemaMismatch, err)
	}
	if err := query.QueryRow(ctx, `SELECT checksum FROM blackbird.schema_manifest WHERE schema_version = $1`, SchemaVersion).Scan(&recordedSchemaChecksum); err != nil {
		return fmt.Errorf("%w: schema manifest: %v", ErrSchemaMismatch, err)
	}
	if err := query.QueryRow(ctx, `SELECT count(*) FROM blackbird.schema_migrations`).Scan(&count); err != nil {
		return fmt.Errorf("%w: count migration ledger: %v", ErrSchemaMismatch, err)
	}
	liveChecksum, err := schemaChecksum(ctx, query)
	if err != nil {
		return err
	}
	if state != "applied" || count != 1 || !bytes.Equal(migrationChecksum, expected[:]) || !bytes.Equal(recordedSchemaChecksum, liveChecksum[:]) {
		return fmt.Errorf("%w: migration checksum, state, or count", ErrSchemaMismatch)
	}
	return nil
}

func schemaChecksum(ctx context.Context, query pgQuery) ([sha256.Size]byte, error) {
	rows, err := query.Query(ctx, `
		SELECT 'column', table_name, lpad(ordinal_position::text, 6, '0'), column_name,
			data_type, udt_name, is_nullable, COALESCE(column_default, '')
		FROM information_schema.columns WHERE table_schema = 'blackbird'
		UNION ALL
		SELECT 'constraint', c.relname, con.conname, con.contype::text,
			pg_get_constraintdef(con.oid, true), '', '', ''
		FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'blackbird'
		UNION ALL
		SELECT 'index', tablename, indexname, indexdef, '', '', '', ''
		FROM pg_indexes WHERE schemaname = 'blackbird'
		ORDER BY 1, 2, 3, 4`)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("read PostgreSQL schema manifest: %w", err)
	}
	defer rows.Close()
	hash := sha256.New()
	_, _ = hash.Write([]byte("blackbird.postgresql-schema/v1\x00"))
	for rows.Next() {
		values := make([]string, 8)
		destinations := make([]any, len(values))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("scan PostgreSQL schema manifest: %w", err)
		}
		for _, value := range values {
			var size [8]byte
			binary.BigEndian.PutUint64(size[:], uint64(len(value)))
			_, _ = hash.Write(size[:])
			_, _ = hash.Write([]byte(value))
		}
	}
	if err := rows.Err(); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("read PostgreSQL schema manifest: %w", err)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func grantApplicationRole(ctx context.Context, tx pgx.Tx, role string) error {
	identifier := pgx.Identifier{role}.Sanitize()
	statements := []string{
		"REVOKE ALL ON SCHEMA blackbird FROM PUBLIC",
		"REVOKE ALL ON ALL TABLES IN SCHEMA blackbird FROM PUBLIC",
		"REVOKE ALL ON SCHEMA blackbird FROM " + identifier,
		"REVOKE ALL ON ALL TABLES IN SCHEMA blackbird FROM " + identifier,
		"GRANT USAGE ON SCHEMA blackbird TO " + identifier,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA blackbird TO " + identifier,
		"REVOKE INSERT, UPDATE, DELETE ON blackbird.schema_migrations, blackbird.schema_manifest FROM " + identifier,
		"REVOKE UPDATE, DELETE ON blackbird.command_receipts, blackbird.command_receipt_resources, blackbird.command_receipt_ceremonies, blackbird.domain_events, blackbird.audit_entries FROM " + identifier,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA blackbird REVOKE ALL ON TABLES FROM PUBLIC",
		"ALTER DEFAULT PRIVILEGES IN SCHEMA blackbird GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO " + identifier,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("configure PostgreSQL application privileges: %w", err)
		}
	}
	return nil
}

func inspect(ctx context.Context, pool *pgxpool.Pool, config Config) (Diagnostics, error) {
	result := Diagnostics{ApplicationName: config.ApplicationName, SchemaVersion: SchemaVersion,
		MigrationID: initialMigrationID, MinConns: config.MinConns, MaxConns: config.MaxConns,
		AcquireTimeout: config.AcquireTimeout, ConnectTimeout: config.ConnectTimeout,
		StatementTimeout: config.StatementTimeout, LockTimeout: config.LockTimeout}
	var ssl bool
	var superuser, createDB, createRole, bypassRLS, ownsSchema, memberOfOwner, schemaCreate, databaseCreate bool
	var tableCount int
	err := pool.QueryRow(ctx, `SELECT version(), current_setting('server_version_num')::integer,
		COALESCE(s.ssl, false), COALESCE(s.version, ''), COALESCE(s.cipher, ''),
		current_setting('application_name'), current_database(), current_user,
		r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolbypassrls,
		n.nspowner = r.oid, pg_has_role(current_user, n.nspowner, 'MEMBER'),
		has_schema_privilege(current_user, 'blackbird', 'CREATE'),
		has_database_privilege(current_user, current_database(), 'CREATE'), pg_get_userbyid(n.nspowner)
		FROM pg_roles r JOIN pg_namespace n ON n.nspname = 'blackbird'
		LEFT JOIN pg_stat_ssl s ON s.pid = pg_backend_pid() WHERE r.rolname = current_user`).Scan(
		&result.ServerVersion, &result.ServerVersionNumber, &ssl, &result.TLSVersion, &result.TLSCipher,
		&result.ApplicationName, &result.DatabaseName, &result.ApplicationRole,
		&superuser, &createDB, &createRole, &bypassRLS, &ownsSchema, &memberOfOwner,
		&schemaCreate, &databaseCreate, &result.SchemaOwner)
	if err != nil {
		return Diagnostics{}, fmt.Errorf("inspect PostgreSQL runtime: %w", err)
	}
	if result.ServerVersionNumber < PostgreSQLMajor*10000 || result.ServerVersionNumber >= (PostgreSQLMajor+1)*10000 || !ssl {
		return Diagnostics{}, fmt.Errorf("%w: server_version_num=%d tls=%t", ErrEngineMismatch, result.ServerVersionNumber, ssl)
	}
	if superuser || createDB || createRole || bypassRLS || ownsSchema || memberOfOwner || schemaCreate || databaseCreate || result.SchemaOwner == result.ApplicationRole {
		return Diagnostics{}, fmt.Errorf("%w: application role is privileged", ErrPrivilegeMismatch)
	}
	_, checksum, err := initialMigration()
	if err != nil {
		return Diagnostics{}, err
	}
	if err := verifyLedger(ctx, pool, checksum); err != nil {
		return Diagnostics{}, err
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'blackbird' AND c.relkind = 'r'`).Scan(&tableCount); err != nil || tableCount != 27 {
		return Diagnostics{}, fmt.Errorf("%w: table count=%d error=%v", ErrSchemaMismatch, tableCount, err)
	}
	if err := verifyPrivileges(ctx, pool); err != nil {
		return Diagnostics{}, err
	}
	result.MigrationChecksum = checksum
	result.SchemaChecksum, err = schemaChecksum(ctx, pool)
	if err != nil {
		return Diagnostics{}, err
	}
	result.DriverVersion, result.DriverVerified, err = linkedDriverVersion()
	if err != nil {
		return Diagnostics{}, err
	}
	return result, nil
}

func verifyPrivileges(ctx context.Context, pool *pgxpool.Pool) error {
	var schemaUsage bool
	if err := pool.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'blackbird', 'USAGE')`).Scan(&schemaUsage); err != nil || !schemaUsage {
		return fmt.Errorf("%w: schema usage error=%v", ErrPrivilegeMismatch, err)
	}
	checks := []struct {
		table      string
		insertable bool
		mutable    bool
	}{
		{"principals", true, true},
		{"schema_migrations", false, false}, {"schema_manifest", false, false},
		{"command_receipts", true, false}, {"command_receipt_resources", true, false},
		{"command_receipt_ceremonies", true, false}, {"domain_events", true, false}, {"audit_entries", true, false},
	}
	for _, check := range checks {
		var selectPrivilege, insertPrivilege, updatePrivilege, deletePrivilege, truncatePrivilege bool
		err := pool.QueryRow(ctx, `SELECT
			has_table_privilege(current_user, $1, 'SELECT'), has_table_privilege(current_user, $1, 'INSERT'),
			has_table_privilege(current_user, $1, 'UPDATE'), has_table_privilege(current_user, $1, 'DELETE'),
			has_table_privilege(current_user, $1, 'TRUNCATE')`, applicationSchema+"."+check.table).Scan(
			&selectPrivilege, &insertPrivilege, &updatePrivilege, &deletePrivilege, &truncatePrivilege)
		if err != nil || !selectPrivilege || insertPrivilege != check.insertable ||
			updatePrivilege != check.mutable || deletePrivilege != check.mutable || truncatePrivilege {
			return fmt.Errorf("%w: effective grants for %s error=%v", ErrPrivilegeMismatch, check.table, err)
		}
	}
	return nil
}

func linkedDriverVersion() (string, bool, error) {
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return DriverVersion, false, nil
	}
	for _, dependency := range build.Deps {
		if dependency.Path != "github.com/jackc/pgx/v5" {
			continue
		}
		version := dependency.Version
		if dependency.Replace != nil {
			version = dependency.Replace.Version
		}
		if version != DriverVersion {
			return "", false, fmt.Errorf("%w: driver version=%q", ErrEngineMismatch, version)
		}
		return version, true, nil
	}
	return DriverVersion, false, nil
}

func (store *Store) Diagnostics() Diagnostics { return store.diagnostics }

func (store *Store) Close() error {
	store.closeOnce.Do(func() { store.pool.Close() })
	return nil
}
