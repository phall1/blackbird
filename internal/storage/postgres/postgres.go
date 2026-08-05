package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	SchemaVersion       = 1
	DriverVersion       = "v5.10.0"
	PostgreSQLMajor     = 18
	initialMigrationID  = "0001_w0.sql"
	applicationSchema   = "blackbird"
	migrationLockID     = int64(0x42424d4c)
	MaxCanonicalInteger = int64(9_007_199_254_740_991)

	defaultApplicationName   = "blackbird"
	defaultAcquireTimeout    = 5 * time.Second
	defaultConnectTimeout    = 5 * time.Second
	defaultStatementTimeout  = 10 * time.Second
	defaultLockTimeout       = 5 * time.Second
	defaultIdleTxTimeout     = 10 * time.Second
	defaultHealthCheck       = 30 * time.Second
	defaultMaxConnLifetime   = 30 * time.Minute
	defaultMaxConnIdleTime   = 5 * time.Minute
	contextProjectionVersion = uint32(1)
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

type eventCursorWire struct {
	Workspace string `json:"workspace"`
	Epoch     string `json:"epoch"`
	Sequence  uint64 `json:"sequence"`
	Digest    string `json:"digest"`
	Check     string `json:"check"`
}

type authorizedQueryState struct {
	view       application.AuthorizedSessionView
	workspace  domain.WorkspaceID
	authority  domain.AuthorityID
	epoch      domain.AuthorityEpoch
	serverTime time.Time
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

func (store *Store) GetContext(ctx context.Context, query application.ContextGetQuery) (application.ContextPage, error) {
	if err := ctx.Err(); err != nil {
		return application.ContextPage{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return application.ContextPage{}, fmt.Errorf("begin PostgreSQL context query: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	authorized, err := authorizeSessionQuery(ctx, tx, query.Subject(), "context:read")
	if err != nil {
		return application.ContextPage{}, err
	}
	headSequence, headDigest, retainedFrom, err := streamHead(ctx, tx, authorized.workspace, authorized.authority,
		authorized.epoch)
	if err != nil {
		return application.ContextPage{}, err
	}
	head, err := encodeEventCursor(authorized.workspace, authorized.epoch, headSequence, headDigest)
	if err != nil {
		return application.ContextPage{}, err
	}
	if query.Cursor().IsZero() {
		records, loadErr := loadContextRecords(ctx, tx, authorized)
		if loadErr != nil {
			return application.ContextPage{}, loadErr
		}
		checkpoint, checkpointErr := application.NewContextCheckpoint(application.ContextCheckpointParams{
			CheckpointID: query.CheckpointID(), AuthorityID: authorized.authority,
			AuthorityEpoch: authorized.epoch, ThroughCursor: head, ProjectionVersion: contextProjectionVersion,
			ServerTime: authorized.serverTime, Session: authorized.view, Records: records,
		})
		if checkpointErr != nil {
			return application.ContextPage{}, checkpointErr
		}
		return application.NewContextCheckpointPage(checkpoint, head)
	}
	afterSequence, _, err := validateEventCursor(ctx, tx, query.Cursor(), authorized.workspace, authorized.epoch,
		headSequence, retainedFrom)
	if err != nil {
		return application.ContextPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT event_id::text, stream_sequence, aggregate_kind, aggregate_id::text,
		aggregate_version, payload, stream_digest FROM domain_events
		WHERE scope_kind = 'workspace' AND scope_id = $1 AND authority_epoch = $2 AND stream_sequence > $3
		ORDER BY stream_sequence ASC LIMIT $4`, authorized.workspace.String(), authorized.epoch.String(),
		afterSequence, int(query.Limit())+1)
	if err != nil {
		return application.ContextPage{}, fmt.Errorf("query PostgreSQL context delta page: %w", err)
	}
	defer rows.Close()
	deltas := make([]application.ContextDelta, 0, query.Limit())
	next := query.Cursor()
	hasMore := false
	for rows.Next() {
		var eventText, aggregateKind, aggregateID string
		var sequence, aggregateVersion uint64
		var payload, digestBytes []byte
		if err := rows.Scan(&eventText, &sequence, &aggregateKind, &aggregateID, &aggregateVersion, &payload, &digestBytes); err != nil {
			return application.ContextPage{}, fmt.Errorf("scan PostgreSQL context delta page: %w", err)
		}
		if len(deltas) == int(query.Limit()) {
			hasMore = true
			break
		}
		if len(digestBytes) != sha256.Size {
			return application.ContextPage{}, application.ErrInvalidQuery
		}
		eventID, eventErr := domain.ParseEventID(eventText)
		version, versionErr := domain.NewVersion(aggregateVersion)
		aggregate, aggregateErr := aggregateRefFromParts(domain.AggregateKind(aggregateKind), aggregateID, version)
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		after, cursorErr := encodeEventCursor(authorized.workspace, authorized.epoch, sequence, digest)
		if eventErr != nil || versionErr != nil || aggregateErr != nil || cursorErr != nil {
			return application.ContextPage{}, application.ErrInvalidQuery
		}
		delta, deltaErr := application.NewContextDelta(eventID, application.ContextDeltaUpsert,
			aggregate.Target(), version, payload, after)
		if deltaErr != nil {
			return application.ContextPage{}, deltaErr
		}
		deltas = append(deltas, delta)
		next = after
	}
	if err := rows.Err(); err != nil {
		return application.ContextPage{}, fmt.Errorf("iterate PostgreSQL context delta page: %w", err)
	}
	return application.NewContextDeltaPage(deltas, next, head, hasMore)
}

func (store *Store) SyncEvents(ctx context.Context, query application.EventsSyncQuery) (application.EventsPage, error) {
	if err := ctx.Err(); err != nil {
		return application.EventsPage{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return application.EventsPage{}, fmt.Errorf("begin PostgreSQL event sync query: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	authorized, err := authorizeSessionQuery(ctx, tx, query.Subject(), "events:sync")
	if err != nil {
		return application.EventsPage{}, err
	}
	headSequence, headDigest, retainedFrom, err := streamHead(ctx, tx, authorized.workspace, authorized.authority,
		authorized.epoch)
	if err != nil {
		return application.EventsPage{}, err
	}
	afterSequence := retainedFrom - 1
	var afterDigest [sha256.Size]byte
	if query.AfterCursor().IsZero() {
		afterDigest, err = digestBeforeSequence(ctx, tx, authorized.workspace, authorized.epoch, retainedFrom)
	} else {
		afterSequence, afterDigest, err = validateEventCursor(ctx, tx, query.AfterCursor(), authorized.workspace,
			authorized.epoch, headSequence, retainedFrom)
	}
	if err != nil {
		return application.EventsPage{}, err
	}
	head, err := encodeEventCursor(authorized.workspace, authorized.epoch, headSequence, headDigest)
	if err != nil {
		return application.EventsPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT event.event_id::text, event.stream_sequence, event.event_type, event.aggregate_kind,
		event.aggregate_id::text, event.aggregate_version, event.payload, event.recorded_at_us, event.stream_digest, event.event_schema,
		event.authority_id::text, event.authority_epoch::text, event.scope_kind, event.scope_id::text, event.principal_id::text,
		event.actor_session_id::text, session.actor_id::text, command_id::text, causation_event_id::text,
		correlation_id::text FROM domain_events AS event
		LEFT JOIN actor_sessions AS session ON session.session_id = event.actor_session_id
		WHERE event.scope_kind = 'workspace' AND event.scope_id = $1 AND event.authority_epoch = $2
		AND event.stream_sequence > $3 ORDER BY event.stream_sequence ASC LIMIT $4`, authorized.workspace.String(),
		authorized.epoch.String(), afterSequence, int(query.Limit())+1)
	if err != nil {
		return application.EventsPage{}, fmt.Errorf("query PostgreSQL event page: %w", err)
	}
	defer rows.Close()
	events := make([]application.SyncedEvent, 0, query.Limit())
	nextSequence, nextDigest := afterSequence, afterDigest
	hasMore := false
	for rows.Next() {
		var eventID, eventType, aggregateKind, aggregateID, authorityID, authorityEpoch string
		var scopeKind, scopeID, principalID, commandID, correlationID string
		var actorSessionID, actorID, causationID *string
		var sequence, aggregateVersion uint64
		var eventVersion uint16
		var payload, streamDigest []byte
		var recordedAt int64
		if err := rows.Scan(&eventID, &sequence, &eventType, &aggregateKind, &aggregateID, &aggregateVersion,
			&payload, &recordedAt, &streamDigest, &eventVersion, &authorityID, &authorityEpoch, &scopeKind,
			&scopeID, &principalID, &actorSessionID, &actorID, &commandID, &causationID, &correlationID); err != nil {
			return application.EventsPage{}, fmt.Errorf("scan PostgreSQL event page: %w", err)
		}
		if len(events) == int(query.Limit()) {
			hasMore = true
			break
		}
		id, idErr := domain.ParseEventID(eventID)
		version, versionErr := domain.NewVersion(aggregateVersion)
		schema, schemaErr := domain.NewEventSchemaVersion(eventVersion)
		authority, authorityErr := domain.ParseAuthorityID(authorityID)
		epoch, epochErr := domain.ParseAuthorityEpoch(authorityEpoch)
		workspace, workspaceErr := domain.ParseWorkspaceID(scopeID)
		scope, scopeErr := domain.WorkspaceScope(workspace)
		position, positionErr := domain.NewStreamPosition(sequence)
		aggregate, aggregateErr := aggregateRefFromParts(domain.AggregateKind(aggregateKind), aggregateID, version)
		principal, principalErr := domain.ParsePrincipalID(principalID)
		command, commandErr := domain.ParseCommandID(commandID)
		correlation, correlationErr := domain.ParseCorrelationID(correlationID)
		if idErr != nil || versionErr != nil || schemaErr != nil || authorityErr != nil || epochErr != nil ||
			workspaceErr != nil || scopeErr != nil || positionErr != nil || aggregateErr != nil || principalErr != nil ||
			commandErr != nil || correlationErr != nil || scopeKind != string(domain.ScopeKindWorkspace) ||
			scope.ID() != authorized.workspace.String() || authority != authorized.authority || epoch != authorized.epoch ||
			len(streamDigest) != sha256.Size {
			return application.EventsPage{}, application.ErrInvalidQuery
		}
		params := application.SyncedEventParams{EventID: id, EventType: domain.EventType(eventType), EventVersion: schema,
			AuthorityID: authority, AuthorityEpoch: epoch, Scope: scope, OriginPosition: position, Aggregate: aggregate,
			PrincipalID: principal, CommandID: command, CorrelationID: correlation,
			// Authority journal events occur when they are atomically recorded; recorded_at_us is the persisted time for both semantics.
			OccurredAt: microsTime(recordedAt), RecordedAt: microsTime(recordedAt), Payload: payload}
		if actorSessionID != nil {
			if actorID == nil {
				return application.EventsPage{}, application.ErrInvalidQuery
			}
			session, sessionErr := domain.ParseActorSessionID(*actorSessionID)
			actor, actorErr := domain.ParseActorID(*actorID)
			if sessionErr != nil || actorErr != nil {
				return application.EventsPage{}, application.ErrInvalidQuery
			}
			params.ActorSessionID, params.ActorID = &session, &actor
		}
		if causationID != nil {
			cause, causeErr := domain.ParseEventID(*causationID)
			if causeErr != nil {
				return application.EventsPage{}, application.ErrInvalidQuery
			}
			params.CausationID = &cause
		}
		event, eventErr := application.NewSyncedEvent(params)
		if eventErr != nil {
			return application.EventsPage{}, eventErr
		}
		events = append(events, event)
		nextSequence = sequence
		copy(nextDigest[:], streamDigest)
	}
	if err := rows.Err(); err != nil {
		return application.EventsPage{}, fmt.Errorf("iterate PostgreSQL event page: %w", err)
	}
	if nextSequence > headSequence {
		return application.EventsPage{}, application.ErrInvalidQuery
	}
	next, err := encodeEventCursor(authorized.workspace, authorized.epoch, nextSequence, nextDigest)
	if err != nil {
		return application.EventsPage{}, err
	}
	return application.NewEventsPage(authorized.view, query.AfterCursor(), next, head, events, hasMore)
}

func authorizeSessionQuery(ctx context.Context, tx pgx.Tx, subject application.QuerySubject,
	requiredCapability string) (authorizedQueryState, error) {
	var workspaceText, principalText, actorText, sessionText, authorityText, epochText, policyText string
	var membershipID, delegationID string
	var sessionVersion, membershipVersion, delegationVersion, currentMembershipVersion, currentDelegationVersion uint64
	var expiresAt, authorityMicros int64
	var capabilitiesJSON []byte
	var sessionStatus, workspaceStatus, principalStatus, actorStatus, membershipStatus, delegationStatus string
	var workspacePolicy string
	var deviceID, deviceStatus *string
	var deviceVersion, deviceTrustRevision, currentDeviceVersion, currentDeviceTrustRevision *int64
	err := tx.QueryRow(ctx, `SELECT session.workspace_id::text, session.principal_id::text, session.actor_id::text,
		session.session_id::text, session.authority_id::text, session.authority_epoch::text, session.policy_revision, session.expires_at_us,
		session.capabilities_json, session.version, session.membership_id::text, session.membership_version,
		session.delegation_id::text, session.delegation_version, session.status, workspace.status, workspace.policy_revision,
		principal.status, actor.status, membership.status, membership.version, delegation.status, delegation.version,
		session.device_id::text, session.device_version, session.device_trust_revision, device.status, device.version,
		device.trust_revision
		FROM actor_sessions AS session
		JOIN workspaces AS workspace ON workspace.workspace_id = session.workspace_id
		JOIN principals AS principal ON principal.principal_id = session.principal_id
		JOIN actors AS actor ON actor.workspace_id = session.workspace_id AND actor.actor_id = session.actor_id
		JOIN workspace_memberships AS membership ON membership.workspace_id = session.workspace_id
			AND membership.membership_id = session.membership_id AND membership.principal_id = session.principal_id
		JOIN actor_delegations AS delegation ON delegation.workspace_id = session.workspace_id
			AND delegation.delegation_id = session.delegation_id AND delegation.principal_id = session.principal_id
			AND delegation.actor_id = session.actor_id
		LEFT JOIN device_registrations AS device ON device.device_id = session.device_id
		WHERE session.session_id = $1`, subject.ActorSessionID().String()).Scan(&workspaceText, &principalText,
		&actorText, &sessionText, &authorityText, &epochText, &policyText, &expiresAt, &capabilitiesJSON, &sessionVersion,
		&membershipID, &membershipVersion, &delegationID, &delegationVersion, &sessionStatus, &workspaceStatus,
		&workspacePolicy, &principalStatus, &actorStatus, &membershipStatus, &currentMembershipVersion,
		&delegationStatus, &currentDelegationVersion, &deviceID, &deviceVersion, &deviceTrustRevision, &deviceStatus,
		&currentDeviceVersion, &currentDeviceTrustRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return authorizedQueryState{}, queryError(domain.ErrorCodeUnauthenticated, "actor session is not authenticated")
	}
	if err != nil {
		return authorizedQueryState{}, fmt.Errorf("authorize PostgreSQL query session: %w", err)
	}
	if principalText != subject.PrincipalID().String() {
		return authorizedQueryState{}, queryError(domain.ErrorCodeForbidden, "actor session belongs to another principal")
	}
	if err := tx.QueryRow(ctx, `SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint`).Scan(&authorityMicros); err != nil {
		return authorizedQueryState{}, fmt.Errorf("read PostgreSQL query authority time: %w", err)
	}
	if sessionStatus != "active" || expiresAt <= authorityMicros {
		return authorizedQueryState{}, queryError(domain.ErrorCodeSessionExpired, "actor session is no longer active")
	}
	if workspaceStatus != "active" || principalStatus != "active" || actorStatus != "active" ||
		membershipStatus != "active" || delegationStatus != "active" || workspacePolicy != policyText ||
		currentMembershipVersion != membershipVersion || currentDelegationVersion != delegationVersion {
		return authorizedQueryState{}, queryError(domain.ErrorCodeForbidden, "query authorization is no longer current")
	}
	if deviceID != nil && (deviceVersion == nil || deviceTrustRevision == nil || deviceStatus == nil ||
		*deviceStatus != "trusted" || currentDeviceVersion == nil || currentDeviceTrustRevision == nil ||
		*deviceVersion != *currentDeviceVersion || *deviceTrustRevision != *currentDeviceTrustRevision) {
		return authorizedQueryState{}, queryError(domain.ErrorCodeForbidden, "query device authorization is no longer current")
	}
	var capabilities []string
	if err := json.Unmarshal(capabilitiesJSON, &capabilities); err != nil || !containsString(capabilities, requiredCapability) {
		return authorizedQueryState{}, queryError(domain.ErrorCodeCapabilityRequired, "query capability is required")
	}
	workspace, workspaceErr := domain.ParseWorkspaceID(workspaceText)
	principal, principalErr := domain.ParsePrincipalID(principalText)
	actor, actorErr := domain.ParseActorID(actorText)
	session, sessionErr := domain.ParseActorSessionID(sessionText)
	authority, authorityErr := domain.ParseAuthorityID(authorityText)
	epoch, epochErr := domain.ParseAuthorityEpoch(epochText)
	policy, policyErr := domain.NewPolicyRevision(policyText)
	if workspaceErr != nil || principalErr != nil || actorErr != nil || sessionErr != nil || authorityErr != nil || epochErr != nil || policyErr != nil {
		return authorizedQueryState{}, application.ErrInvalidQuery
	}
	revisions := make([]application.AuthorizationRevision, 0, application.MaxContextGrantRevisions+4)
	addRevision := func(kind domain.AggregateKind, id string, value uint64) error {
		version, versionErr := domain.NewVersion(value)
		if versionErr != nil {
			return versionErr
		}
		revision, revisionErr := application.NewAuthorizationRevision(kind, id, version)
		if revisionErr == nil {
			revisions = append(revisions, revision)
		}
		return revisionErr
	}
	if err := addRevision(domain.AggregateKindMembership, membershipID, membershipVersion); err != nil {
		return authorizedQueryState{}, err
	}
	if err := addRevision(domain.AggregateKindActorDelegation, delegationID, delegationVersion); err != nil {
		return authorizedQueryState{}, err
	}
	if err := addRevision(domain.AggregateKindActorSession, sessionText, sessionVersion); err != nil {
		return authorizedQueryState{}, err
	}
	if deviceID != nil {
		if err := addRevision(domain.AggregateKindDevice, *deviceID, uint64(*deviceVersion)); err != nil {
			return authorizedQueryState{}, err
		}
	}
	grantRows, err := tx.Query(ctx, `SELECT revision.grant_id::text, revision.grant_version, current_grant.version,
		current_grant.status, current_grant.expires_at_us FROM actor_session_grant_revisions AS revision
		JOIN grants AS current_grant ON current_grant.grant_id = revision.grant_id WHERE revision.session_id = $1
		ORDER BY revision.grant_id LIMIT $2`, sessionText, application.MaxContextGrantRevisions+1)
	if err != nil {
		return authorizedQueryState{}, fmt.Errorf("read PostgreSQL query grant revisions: %w", err)
	}
	defer grantRows.Close()
	grantCount := 0
	for grantRows.Next() {
		var grantID, status string
		var expected, current uint64
		var grantExpiry *int64
		if err := grantRows.Scan(&grantID, &expected, &current, &status, &grantExpiry); err != nil {
			return authorizedQueryState{}, err
		}
		grantCount++
		if grantCount > application.MaxContextGrantRevisions {
			return authorizedQueryState{}, queryError(domain.ErrorCodeBackpressure, "session authorization revision set exceeds query bound")
		}
		if expected != current || status != "active" || grantExpiry != nil && *grantExpiry <= authorityMicros {
			return authorizedQueryState{}, queryError(domain.ErrorCodeForbidden, "query grant revision is no longer current")
		}
		if err := addRevision(domain.AggregateKindGrant, grantID, current); err != nil {
			return authorizedQueryState{}, err
		}
	}
	if err := grantRows.Err(); err != nil {
		return authorizedQueryState{}, err
	}
	sort.Slice(revisions, func(i, j int) bool {
		if revisions[i].Kind() != revisions[j].Kind() {
			return revisions[i].Kind() < revisions[j].Kind()
		}
		return revisions[i].ID() < revisions[j].ID()
	})
	view, err := application.NewAuthorizedSessionView(workspace, principal, actor, session, policy,
		microsTime(expiresAt), revisions)
	if err != nil {
		return authorizedQueryState{}, err
	}
	return authorizedQueryState{view: view, workspace: workspace, authority: authority, epoch: epoch,
		serverTime: microsTime(authorityMicros)}, nil
}

func loadContextRecords(ctx context.Context, tx pgx.Tx, state authorizedQueryState) ([]application.ContextRecord, error) {
	rows, err := tx.Query(ctx, `SELECT kind, id, version, payload FROM (
		SELECT 'workspace' AS kind, workspace_id::text AS id, version,
			json_build_object('alias', alias, 'policy_revision', policy_revision, 'status', status)::text AS payload
			FROM workspaces WHERE workspace_id = $1
		UNION ALL SELECT 'principal', principal_id::text, version,
			json_build_object('display_name', display_name, 'kind', kind, 'status', status)::text
			FROM principals WHERE principal_id = $2
		UNION ALL SELECT 'actor', actor_id::text, version,
			json_build_object('display_name', display_name, 'kind', kind, 'status', status)::text
			FROM actors WHERE workspace_id = $1 AND actor_id = $3
		UNION ALL SELECT 'membership', membership_id::text, version,
			json_build_object('capabilities', capabilities_json, 'principal_id', principal_id, 'status', status)::text
			FROM workspace_memberships WHERE workspace_id = $1 AND principal_id = $2
		UNION ALL SELECT 'actor_delegation', delegation_id::text, version,
			json_build_object('actor_id', actor_id, 'capabilities', capabilities_json, 'principal_id', principal_id, 'status', status)::text
			FROM actor_delegations WHERE workspace_id = $1 AND principal_id = $2 AND actor_id = $3
		UNION ALL SELECT 'actor_session', session_id::text, version,
			json_build_object('actor_id', actor_id, 'capabilities', capabilities_json, 'expires_at_us', expires_at_us,
			'principal_id', principal_id, 'status', status)::text
			FROM actor_sessions WHERE workspace_id = $1 AND session_id = $4
	) AS identity ORDER BY kind, id`, state.workspace.String(), state.view.PrincipalID().String(),
		state.view.ActorID().String(), state.view.ActorSessionID().String())
	if err != nil {
		return nil, fmt.Errorf("read PostgreSQL context identity: %w", err)
	}
	defer rows.Close()
	records := make([]application.ContextRecord, 0, 6)
	for rows.Next() {
		var kind, id, payload string
		var version uint64
		if err := rows.Scan(&kind, &id, &version, &payload); err != nil {
			return nil, err
		}
		domainVersion, versionErr := domain.NewVersion(version)
		record, recordErr := application.NewContextRecord(application.ContextRecordKind(kind), id, domainVersion, []byte(payload))
		if versionErr != nil || recordErr != nil {
			return nil, application.ErrInvalidQuery
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(records) != 6 {
		return nil, application.ErrInvalidQuery
	}
	collaborators, err := tx.Query(ctx, `SELECT actor_id::text, version,
		json_build_object('display_name', display_name, 'kind', kind, 'status', status)::text FROM actors
		WHERE workspace_id = $1 AND actor_id <> $2 ORDER BY actor_id LIMIT $3`, state.workspace.String(),
		state.view.ActorID().String(), application.MaxContextCollaborators+1)
	if err != nil {
		return nil, fmt.Errorf("read PostgreSQL context collaborators: %w", err)
	}
	defer collaborators.Close()
	count := 0
	for collaborators.Next() {
		var id, payload string
		var version uint64
		if err := collaborators.Scan(&id, &version, &payload); err != nil {
			return nil, err
		}
		count++
		if count > application.MaxContextCollaborators {
			return nil, queryError(domain.ErrorCodeBackpressure, "context collaborator set exceeds query bound")
		}
		domainVersion, versionErr := domain.NewVersion(version)
		record, recordErr := application.NewContextRecord(application.ContextRecordCollaborator, id, domainVersion, []byte(payload))
		if versionErr != nil || recordErr != nil {
			return nil, application.ErrInvalidQuery
		}
		records = append(records, record)
	}
	if err := collaborators.Err(); err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind() != records[j].Kind() {
			return records[i].Kind() < records[j].Kind()
		}
		return records[i].ID() < records[j].ID()
	})
	return records, nil
}

func streamHead(ctx context.Context, tx pgx.Tx, workspace domain.WorkspaceID, authority domain.AuthorityID,
	epoch domain.AuthorityEpoch) (uint64, [sha256.Size]byte, uint64, error) {
	var next, retained uint64
	var digestBytes []byte
	err := tx.QueryRow(ctx, `SELECT next_sequence, retained_from_sequence, head_digest FROM authority_streams
		WHERE scope_kind = 'workspace' AND scope_id = $1 AND authority_id = $2 AND authority_epoch = $3`,
		workspace.String(), authority.String(), epoch.String()).Scan(&next, &retained, &digestBytes)
	if err != nil {
		return 0, [sha256.Size]byte{}, 0, fmt.Errorf("read PostgreSQL workspace stream head: %w", err)
	}
	if next == 0 || retained == 0 || retained > next || len(digestBytes) != sha256.Size {
		return 0, [sha256.Size]byte{}, 0, application.ErrInvalidQuery
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	return next - 1, digest, retained, nil
}

func digestBeforeSequence(ctx context.Context, tx pgx.Tx, workspace domain.WorkspaceID, epoch domain.AuthorityEpoch, sequence uint64) ([sha256.Size]byte, error) {
	var digestBytes []byte
	var err error
	if sequence == 1 {
		err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT previous_stream_digest FROM domain_events
			WHERE scope_kind = 'workspace' AND scope_id = $1 AND authority_epoch = $2 ORDER BY stream_sequence LIMIT 1),
			(SELECT head_digest FROM authority_streams WHERE scope_kind = 'workspace' AND scope_id = $1 AND authority_epoch = $2))`,
			workspace.String(), epoch.String()).Scan(&digestBytes)
	} else {
		err = tx.QueryRow(ctx, `SELECT stream_digest FROM domain_events WHERE scope_kind = 'workspace'
			AND scope_id = $1 AND authority_epoch = $2 AND stream_sequence = $3`, workspace.String(), epoch.String(), sequence-1).Scan(&digestBytes)
	}
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if len(digestBytes) != sha256.Size {
		return [sha256.Size]byte{}, application.ErrInvalidQuery
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	return digest, nil
}

func encodeEventCursor(workspace domain.WorkspaceID, epoch domain.AuthorityEpoch, sequence uint64, digest [sha256.Size]byte) (application.EventCursor, error) {
	wire := eventCursorWire{Workspace: workspace.String(), Epoch: epoch.String(), Sequence: sequence, Digest: hex.EncodeToString(digest[:])}
	wire.Check = cursorChecksum(wire)
	canonical, err := json.Marshal(wire)
	if err != nil {
		return application.EventCursor{}, err
	}
	return application.NewEventCursor("bbec1_" + base64.RawURLEncoding.EncodeToString(canonical))
}

func validateEventCursor(ctx context.Context, tx pgx.Tx, cursor application.EventCursor, workspace domain.WorkspaceID,
	epoch domain.AuthorityEpoch, head, retained uint64) (uint64, [sha256.Size]byte, error) {
	const prefix = "bbec1_"
	if !strings.HasPrefix(cursor.String(), prefix) {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorInvalid, "event cursor is invalid")
	}
	canonical, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cursor.String(), prefix))
	var wire eventCursorWire
	if err != nil || json.Unmarshal(canonical, &wire) != nil || wire.Check != cursorChecksum(wire) {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorInvalid, "event cursor is invalid")
	}
	if wire.Workspace != workspace.String() {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorScopeMismatch, "event cursor belongs to another workspace")
	}
	if wire.Epoch != epoch.String() {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorExpired, "event cursor authority epoch has expired; fetch context.get.v1")
	}
	if wire.Sequence < retained-1 {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorExpired, "event cursor was pruned; fetch context.get.v1")
	}
	if wire.Sequence > head {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorInvalid, "event cursor is ahead of the workspace stream")
	}
	digestBytes, decodeErr := hex.DecodeString(wire.Digest)
	if decodeErr != nil || len(digestBytes) != sha256.Size {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorInvalid, "event cursor digest is invalid")
	}
	want, err := digestBeforeSequence(ctx, tx, workspace, epoch, wire.Sequence+1)
	if err != nil || !bytes.Equal(want[:], digestBytes) {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorInvalid, "event cursor does not match the workspace journal")
	}
	return wire.Sequence, want, nil
}

func cursorChecksum(wire eventCursorWire) string {
	digest := sha256.Sum256([]byte("blackbird-event-cursor/v1\x00" + wire.Workspace + "\x00" + wire.Epoch + "\x00" +
		strconv.FormatUint(wire.Sequence, 10) + "\x00" + wire.Digest))
	return hex.EncodeToString(digest[:])
}

func queryError(code domain.ErrorCode, message string) error {
	rejection, err := domain.NewCommandError(code, message, nil)
	if err != nil {
		return application.ErrInvalidQuery
	}
	return rejection
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
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
		WHERE n.nspname = 'blackbird' AND c.relkind = 'r'`).Scan(&tableCount); err != nil || tableCount != 33 {
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
