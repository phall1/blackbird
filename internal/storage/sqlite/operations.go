package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

var ErrFilesystemQualification = errors.New("SQLite filesystem qualification failed")

type eventCursorWire struct {
	Workspace string `json:"workspace"`
	Epoch     string `json:"epoch"`
	Sequence  uint64 `json:"sequence"`
	Digest    string `json:"digest"`
	Check     string `json:"check"`
}

type authorizedQueryState struct {
	view      application.AuthorizedSessionView
	workspace domain.WorkspaceID
	authority domain.AuthorityID
	epoch     domain.AuthorityEpoch
}

const contextProjectionVersion uint32 = 1

func (store *Store) GetContext(ctx context.Context, query application.ContextGetQuery) (application.ContextPage, error) {
	if err := ctx.Err(); err != nil {
		return application.ContextPage{}, err
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return application.ContextPage{}, fmt.Errorf("begin SQLite context query: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	authorized, err := authorizeSessionQuery(ctx, tx, query.Subject(), "context:read")
	if err != nil {
		return application.ContextPage{}, err
	}
	headSequence, headDigest, retainedFrom, err := streamHead(ctx, tx, authorized.workspace, authorized.epoch)
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
		var serverMicros int64
		if err := tx.QueryRowContext(ctx, "SELECT CAST(unixepoch('subsec') * 1000000 AS INTEGER)").Scan(&serverMicros); err != nil {
			return application.ContextPage{}, fmt.Errorf("read SQLite context server time: %w", err)
		}
		checkpoint, checkpointErr := application.NewContextCheckpoint(application.ContextCheckpointParams{
			CheckpointID: query.CheckpointID(), AuthorityID: authorized.authority, AuthorityEpoch: authorized.epoch,
			ThroughCursor: head, ProjectionVersion: contextProjectionVersion, ServerTime: microsTime(serverMicros),
			Session: authorized.view, Records: records,
		})
		if checkpointErr != nil {
			return application.ContextPage{}, checkpointErr
		}
		return application.NewContextCheckpointPage(checkpoint, head)
	}
	afterSequence, _, err := validateEventCursor(ctx, tx, query.Cursor(), authorized.workspace,
		authorized.epoch, headSequence, retainedFrom)
	if err != nil {
		return application.ContextPage{}, err
	}
	return loadContextDeltas(ctx, tx, query, authorized, afterSequence, head)
}

func (store *Store) SyncEvents(ctx context.Context, query application.EventsSyncQuery) (application.EventsPage, error) {
	if err := ctx.Err(); err != nil {
		return application.EventsPage{}, err
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return application.EventsPage{}, fmt.Errorf("begin SQLite event sync query: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	authorized, err := authorizeSessionQuery(ctx, tx, query.Subject(), "events:sync")
	if err != nil {
		return application.EventsPage{}, err
	}
	headSequence, headDigest, retainedFrom, err := streamHead(ctx, tx, authorized.workspace, authorized.epoch)
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
	rows, err := tx.QueryContext(ctx, `SELECT event.event_id, event.stream_sequence, event.event_type, event.aggregate_kind,
		event.aggregate_id, event.aggregate_version, event.payload, event.event_schema, event.authority_id,
		event.authority_epoch, event.scope_kind, event.scope_id, event.principal_id, event.actor_session_id, session.actor_id,
		event.command_id, event.causation_event_id, event.correlation_id,
		receipt.committed_at_us, event.recorded_at_us, stream_digest
		FROM domain_events AS event JOIN command_receipts AS receipt USING (receipt_id)
		LEFT JOIN actor_sessions AS session ON session.session_id = event.actor_session_id
		WHERE event.scope_kind = 'workspace' AND event.scope_id = ? AND event.authority_epoch = ?
		AND stream_sequence > ? ORDER BY stream_sequence ASC LIMIT ?`, authorized.workspace.String(),
		authorized.epoch.String(), afterSequence, int(query.Limit())+1)
	if err != nil {
		return application.EventsPage{}, fmt.Errorf("query SQLite event page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	events := make([]application.SyncedEvent, 0, query.Limit())
	nextSequence, nextDigest := afterSequence, afterDigest
	hasMore := false
	for rows.Next() {
		var eventID, eventType, aggregateKind, aggregateID, authorityID, authorityEpoch, scopeKind, scopeID string
		var principalID, commandID, correlationID string
		var actorSessionID, actorID, causationID sql.NullString
		var sequence, aggregateVersion uint64
		var eventSchema uint16
		var payload, streamDigest []byte
		var occurredAt, recordedAt int64
		if err := rows.Scan(&eventID, &sequence, &eventType, &aggregateKind, &aggregateID, &aggregateVersion,
			&payload, &eventSchema, &authorityID, &authorityEpoch, &scopeKind, &scopeID, &principalID, &actorSessionID, &actorID,
			&commandID, &causationID, &correlationID, &occurredAt, &recordedAt, &streamDigest); err != nil {
			return application.EventsPage{}, fmt.Errorf("scan SQLite event page: %w", err)
		}
		if len(events) == int(query.Limit()) {
			hasMore = true
			break
		}
		event, parseErr := decodeSyncedEvent(syncedEventRow{eventID: eventID, eventType: eventType,
			eventSchema: eventSchema, authorityID: authorityID, authorityEpoch: authorityEpoch,
			scopeKind: scopeKind, scopeID: scopeID, sequence: sequence, aggregateKind: aggregateKind,
			aggregateID: aggregateID, aggregateVersion: aggregateVersion, principalID: principalID,
			actorID: actorID, actorSessionID: actorSessionID, commandID: commandID, causationID: causationID,
			correlationID: correlationID, occurredAt: occurredAt, recordedAt: recordedAt, payload: payload})
		if parseErr != nil || len(streamDigest) != sha256.Size {
			return application.EventsPage{}, application.ErrInvalidQuery
		}
		events = append(events, event)
		nextSequence = sequence
		copy(nextDigest[:], streamDigest)
	}
	if err := rows.Err(); err != nil {
		return application.EventsPage{}, fmt.Errorf("iterate SQLite event page: %w", err)
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

type syncedEventRow struct {
	eventID, eventType, authorityID, authorityEpoch, scopeKind, scopeID string
	aggregateKind, aggregateID, principalID, commandID, correlationID   string
	eventSchema                                                         uint16
	sequence, aggregateVersion                                          uint64
	actorID, actorSessionID, causationID                                sql.NullString
	occurredAt, recordedAt                                              int64
	payload                                                             []byte
}

func decodeSyncedEvent(row syncedEventRow) (application.SyncedEvent, error) {
	eventID, eventErr := domain.ParseEventID(row.eventID)
	eventVersion, schemaErr := domain.NewEventSchemaVersion(row.eventSchema)
	authorityID, authorityErr := domain.ParseAuthorityID(row.authorityID)
	epoch, epochErr := domain.ParseAuthorityEpoch(row.authorityEpoch)
	position, positionErr := domain.NewStreamPosition(row.sequence)
	version, versionErr := domain.NewVersion(row.aggregateVersion)
	aggregate, aggregateErr := aggregateRefFromParts(domain.AggregateKind(row.aggregateKind), row.aggregateID, version)
	principalID, principalErr := domain.ParsePrincipalID(row.principalID)
	commandID, commandErr := domain.ParseCommandID(row.commandID)
	correlationID, correlationErr := domain.ParseCorrelationID(row.correlationID)
	var scope domain.AuthorityScope
	var scopeErr error
	switch domain.ScopeKind(row.scopeKind) {
	case domain.ScopeKindWorkspace:
		workspaceID, err := domain.ParseWorkspaceID(row.scopeID)
		if err == nil {
			scope, scopeErr = domain.WorkspaceScope(workspaceID)
		} else {
			scopeErr = err
		}
	case domain.ScopeKindInstallation:
		installationID, err := domain.ParseInstallationID(row.scopeID)
		if err == nil {
			scope, scopeErr = domain.InstallationScope(installationID)
		} else {
			scopeErr = err
		}
	default:
		scopeErr = application.ErrInvalidQuery
	}
	if eventErr != nil || schemaErr != nil || authorityErr != nil || epochErr != nil || scopeErr != nil ||
		positionErr != nil || versionErr != nil || aggregateErr != nil || principalErr != nil || commandErr != nil ||
		correlationErr != nil {
		return application.SyncedEvent{}, application.ErrInvalidQuery
	}
	params := application.SyncedEventParams{EventID: eventID, EventType: domain.EventType(row.eventType),
		EventVersion: eventVersion, AuthorityID: authorityID, AuthorityEpoch: epoch, Scope: scope,
		OriginPosition: position, Aggregate: aggregate, PrincipalID: principalID, CommandID: commandID,
		CorrelationID: correlationID, OccurredAt: microsTime(row.occurredAt), RecordedAt: microsTime(row.recordedAt),
		Payload: row.payload}
	if row.actorID.Valid {
		value, err := domain.ParseActorID(row.actorID.String)
		if err != nil {
			return application.SyncedEvent{}, application.ErrInvalidQuery
		}
		params.ActorID = &value
	}
	if row.actorSessionID.Valid {
		value, err := domain.ParseActorSessionID(row.actorSessionID.String)
		if err != nil {
			return application.SyncedEvent{}, application.ErrInvalidQuery
		}
		params.ActorSessionID = &value
	}
	if row.causationID.Valid {
		value, err := domain.ParseEventID(row.causationID.String)
		if err != nil {
			return application.SyncedEvent{}, application.ErrInvalidQuery
		}
		params.CausationID = &value
	}
	return application.NewSyncedEvent(params)
}

func loadContextDeltas(ctx context.Context, tx *sql.Tx, query application.ContextGetQuery,
	state authorizedQueryState, afterSequence uint64, head application.EventCursor) (application.ContextPage, error) {
	// Reuse the checkpoint visibility read to enforce the same collaborator bound
	// and authorization snapshot before exposing incremental facts.
	if _, err := loadContextRecords(ctx, tx, state); err != nil {
		return application.ContextPage{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_id, stream_sequence, stream_digest, aggregate_kind,
		aggregate_id, aggregate_version, payload FROM domain_events WHERE scope_kind = 'workspace' AND scope_id = ?
		AND authority_epoch = ? AND stream_sequence > ? AND (
			(aggregate_kind = 'workspace' AND aggregate_id = ?) OR
			(aggregate_kind = 'principal' AND aggregate_id = ?) OR
			(aggregate_kind = 'actor') OR
			(aggregate_kind = 'workspace_membership' AND aggregate_id IN
				(SELECT membership_id FROM workspace_memberships WHERE workspace_id = ? AND principal_id = ?)) OR
			(aggregate_kind = 'actor_delegation' AND aggregate_id IN
				(SELECT delegation_id FROM actor_delegations WHERE workspace_id = ? AND principal_id = ? AND actor_id = ?)) OR
			(aggregate_kind = 'actor_session' AND aggregate_id = ?)
		) ORDER BY stream_sequence ASC LIMIT ?`, state.workspace.String(), state.epoch.String(), afterSequence,
		state.workspace.String(), state.view.PrincipalID().String(), state.workspace.String(), state.view.PrincipalID().String(),
		state.workspace.String(), state.view.PrincipalID().String(), state.view.ActorID().String(),
		state.view.ActorSessionID().String(), int(query.Limit())+1)
	if err != nil {
		return application.ContextPage{}, fmt.Errorf("query SQLite context deltas: %w", err)
	}
	defer func() { _ = rows.Close() }()
	deltas := make([]application.ContextDelta, 0, query.Limit())
	next := query.Cursor()
	hasMore := false
	for rows.Next() {
		var eventText, kindText, id string
		var sequence, versionValue uint64
		var digestBytes, payload []byte
		if err := rows.Scan(&eventText, &sequence, &digestBytes, &kindText, &id, &versionValue, &payload); err != nil {
			return application.ContextPage{}, fmt.Errorf("scan SQLite context delta: %w", err)
		}
		if len(deltas) == int(query.Limit()) {
			hasMore = true
			break
		}
		if len(digestBytes) != sha256.Size {
			return application.ContextPage{}, application.ErrInvalidQuery
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		after, cursorErr := encodeEventCursor(state.workspace, state.epoch, sequence, digest)
		eventID, eventErr := domain.ParseEventID(eventText)
		version, versionErr := domain.NewVersion(versionValue)
		ref, refErr := aggregateRefFromParts(domain.AggregateKind(kindText), id, version)
		if cursorErr != nil || eventErr != nil || versionErr != nil || refErr != nil {
			return application.ContextPage{}, application.ErrInvalidQuery
		}
		delta, deltaErr := application.NewContextDelta(eventID, application.ContextDeltaUpsert, ref.Target(),
			version, payload, after)
		if deltaErr != nil {
			return application.ContextPage{}, deltaErr
		}
		deltas = append(deltas, delta)
		next = after
	}
	if err := rows.Err(); err != nil {
		return application.ContextPage{}, fmt.Errorf("iterate SQLite context deltas: %w", err)
	}
	if !hasMore && len(deltas) != 0 && next != head {
		last := deltas[len(deltas)-1]
		last, err = application.NewContextDelta(last.EventID(), last.DeltaType(), last.Resource(),
			last.Version(), last.Value(), head)
		if err != nil {
			return application.ContextPage{}, err
		}
		deltas[len(deltas)-1] = last
		next = head
	}
	return application.NewContextDeltaPage(deltas, next, head, hasMore)
}

func authorizeSessionQuery(ctx context.Context, tx *sql.Tx, subject application.QuerySubject,
	requiredCapability string) (authorizedQueryState, error) {
	var workspaceText, principalText, actorText, sessionText, epochText, policyText string
	var membershipID, delegationID string
	var sessionVersion, membershipVersion, delegationVersion, currentMembershipVersion, currentDelegationVersion uint64
	var expiresAt int64
	var capabilitiesJSON string
	var sessionStatus, workspaceStatus, principalStatus, actorStatus, membershipStatus, delegationStatus string
	var workspacePolicy string
	var deviceID, deviceStatus sql.NullString
	var deviceVersion, deviceTrustRevision, currentDeviceVersion, currentDeviceTrustRevision sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT session.workspace_id, session.principal_id, session.actor_id,
		session.session_id, session.authority_epoch, session.policy_revision, session.expires_at_us,
		session.capabilities_json, session.version, session.membership_id, session.membership_version,
		session.delegation_id, session.delegation_version, session.status, workspace.status, workspace.policy_revision,
		principal.status, actor.status, membership.status, membership.version, delegation.status, delegation.version,
		session.device_id, session.device_version, session.device_trust_revision, device.status, device.version,
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
		WHERE session.session_id = ?`, subject.ActorSessionID().String()).Scan(&workspaceText, &principalText,
		&actorText, &sessionText, &epochText, &policyText, &expiresAt, &capabilitiesJSON, &sessionVersion,
		&membershipID, &membershipVersion, &delegationID, &delegationVersion, &sessionStatus, &workspaceStatus,
		&workspacePolicy, &principalStatus, &actorStatus, &membershipStatus, &currentMembershipVersion,
		&delegationStatus, &currentDelegationVersion, &deviceID, &deviceVersion, &deviceTrustRevision, &deviceStatus,
		&currentDeviceVersion, &currentDeviceTrustRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return authorizedQueryState{}, queryError(domain.ErrorCodeUnauthenticated, "actor session is not authenticated")
	}
	if err != nil {
		return authorizedQueryState{}, fmt.Errorf("authorize SQLite query session: %w", err)
	}
	if principalText != subject.PrincipalID().String() {
		return authorizedQueryState{}, queryError(domain.ErrorCodeForbidden, "actor session belongs to another principal")
	}
	var authorityMicros int64
	if err := tx.QueryRowContext(ctx, "SELECT CAST(unixepoch('subsec') * 1000000 AS INTEGER)").Scan(&authorityMicros); err != nil {
		return authorizedQueryState{}, fmt.Errorf("read SQLite query authority time: %w", err)
	}
	if sessionStatus != "active" || expiresAt <= authorityMicros {
		return authorizedQueryState{}, queryError(domain.ErrorCodeSessionExpired, "actor session is no longer active")
	}
	if workspaceStatus != "active" || principalStatus != "active" || actorStatus != "active" ||
		membershipStatus != "active" || delegationStatus != "active" || workspacePolicy != policyText ||
		currentMembershipVersion != membershipVersion || currentDelegationVersion != delegationVersion {
		return authorizedQueryState{}, queryError(domain.ErrorCodeForbidden, "query authorization is no longer current")
	}
	if deviceID.Valid && (!deviceVersion.Valid || !deviceTrustRevision.Valid || !deviceStatus.Valid ||
		deviceStatus.String != "trusted" || !currentDeviceVersion.Valid || !currentDeviceTrustRevision.Valid ||
		deviceVersion.Int64 != currentDeviceVersion.Int64 || deviceTrustRevision.Int64 != currentDeviceTrustRevision.Int64) {
		return authorizedQueryState{}, queryError(domain.ErrorCodeForbidden, "query device authorization is no longer current")
	}
	var capabilities []string
	if err := json.Unmarshal([]byte(capabilitiesJSON), &capabilities); err != nil || !containsString(capabilities, requiredCapability) {
		return authorizedQueryState{}, queryError(domain.ErrorCodeCapabilityRequired, "query capability is required")
	}
	workspace, workspaceErr := domain.ParseWorkspaceID(workspaceText)
	principal, principalErr := domain.ParsePrincipalID(principalText)
	actor, actorErr := domain.ParseActorID(actorText)
	session, sessionErr := domain.ParseActorSessionID(sessionText)
	epoch, epochErr := domain.ParseAuthorityEpoch(epochText)
	policy, policyErr := domain.NewPolicyRevision(policyText)
	if workspaceErr != nil || principalErr != nil || actorErr != nil || sessionErr != nil || epochErr != nil || policyErr != nil {
		return authorizedQueryState{}, application.ErrInvalidQuery
	}
	var authorityText string
	if err := tx.QueryRowContext(ctx, `SELECT authority_id FROM authority_streams WHERE scope_kind = 'workspace'
		AND scope_id = ? AND authority_epoch = ?`, workspace.String(), epoch.String()).Scan(&authorityText); err != nil {
		return authorizedQueryState{}, fmt.Errorf("read SQLite query authority: %w", err)
	}
	authority, authorityErr := domain.ParseAuthorityID(authorityText)
	if authorityErr != nil {
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
	if deviceID.Valid {
		if err := addRevision(domain.AggregateKindDevice, deviceID.String, uint64(deviceVersion.Int64)); err != nil {
			return authorizedQueryState{}, err
		}
	}
	grantRows, err := tx.QueryContext(ctx, `SELECT revision.grant_id, revision.grant_version, grant.version,
		grant.status, grant.expires_at_us FROM actor_session_grant_revisions AS revision
		JOIN grants AS grant ON grant.grant_id = revision.grant_id WHERE revision.session_id = ?
		ORDER BY revision.grant_id LIMIT ?`, sessionText, application.MaxContextGrantRevisions+1)
	if err != nil {
		return authorizedQueryState{}, fmt.Errorf("read SQLite query grant revisions: %w", err)
	}
	defer func() { _ = grantRows.Close() }()
	grantCount := 0
	for grantRows.Next() {
		var grantID, status string
		var expected, current uint64
		var grantExpiry sql.NullInt64
		if err := grantRows.Scan(&grantID, &expected, &current, &status, &grantExpiry); err != nil {
			return authorizedQueryState{}, err
		}
		grantCount++
		if grantCount > application.MaxContextGrantRevisions {
			return authorizedQueryState{}, queryError(domain.ErrorCodeBackpressure, "session authorization revision set exceeds query bound")
		}
		if expected != current || status != "active" || grantExpiry.Valid && grantExpiry.Int64 <= authorityMicros {
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
	return authorizedQueryState{view: view, workspace: workspace, authority: authority, epoch: epoch}, nil
}

func loadContextRecords(ctx context.Context, tx *sql.Tx, state authorizedQueryState) ([]application.ContextRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT kind, id, version, lifecycle_state, payload FROM (
		SELECT 'workspace' AS kind, workspace_id AS id, version, status AS lifecycle_state,
			json_object('alias', alias, 'policy_revision', policy_revision, 'status', status) AS payload
			FROM workspaces WHERE workspace_id = ?
		UNION ALL SELECT 'principal', principal_id, version, status,
			json_object('display_name', display_name, 'kind', kind, 'status', status)
			FROM principals WHERE principal_id = ?
		UNION ALL SELECT 'actor', actor_id, version, status,
			json_object('display_name', display_name, 'kind', kind, 'status', status)
			FROM actors WHERE workspace_id = ? AND actor_id = ?
		UNION ALL SELECT 'membership', membership_id, version, status,
			json_object('capabilities', json(capabilities_json), 'principal_id', principal_id, 'status', status)
			FROM workspace_memberships WHERE workspace_id = ? AND principal_id = ?
		UNION ALL SELECT 'actor_delegation', delegation_id, version, status,
			json_object('actor_id', actor_id, 'capabilities', json(capabilities_json), 'principal_id', principal_id, 'status', status)
			FROM actor_delegations WHERE workspace_id = ? AND principal_id = ? AND actor_id = ?
		UNION ALL SELECT 'actor_session', session_id, version, status,
			json_object('actor_id', actor_id, 'capabilities', json(capabilities_json), 'expires_at_us', expires_at_us,
			'principal_id', principal_id, 'status', status)
			FROM actor_sessions WHERE workspace_id = ? AND session_id = ?
		UNION ALL SELECT 'device', device.device_id, device.version, device.status,
			json_object('display_name', device.display_name, 'principal_id', device.principal_id, 'status', device.status)
			FROM device_registrations AS device JOIN actor_sessions AS session ON session.device_id = device.device_id
			WHERE session.session_id = ?
		UNION ALL SELECT 'grant', grant_state.grant_id, grant_state.version, grant_state.status,
			json_object('capabilities', json(grant_state.capabilities_json), 'principal_id', grant_state.principal_id,
			'status', grant_state.status)
			FROM grants AS grant_state JOIN actor_session_grant_revisions AS revision
			ON revision.grant_id = grant_state.grant_id WHERE revision.session_id = ?
	) ORDER BY kind, id`, state.workspace.String(), state.view.PrincipalID().String(), state.workspace.String(),
		state.view.ActorID().String(), state.workspace.String(), state.view.PrincipalID().String(), state.workspace.String(),
		state.view.PrincipalID().String(), state.view.ActorID().String(), state.workspace.String(), state.view.ActorSessionID().String(),
		state.view.ActorSessionID().String(), state.view.ActorSessionID().String())
	if err != nil {
		return nil, fmt.Errorf("read SQLite context identity: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := make([]application.ContextRecord, 0, 7+application.MaxContextGrantRevisions)
	for rows.Next() {
		var kind, id, lifecycleState, payload string
		var version uint64
		if err := rows.Scan(&kind, &id, &version, &lifecycleState, &payload); err != nil {
			return nil, err
		}
		domainVersion, versionErr := domain.NewVersion(version)
		record, recordErr := application.NewTypedContextRecord(application.ContextRecordParams{
			Kind: application.ContextRecordKind(kind), ID: id, Version: domainVersion,
			LifecycleState: application.ContextLifecycleState(lifecycleState), CanonicalPayload: []byte(payload),
		})
		if versionErr != nil || recordErr != nil {
			return nil, application.ErrInvalidQuery
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(records) < 6 {
		return nil, application.ErrInvalidQuery
	}
	collaborators, err := tx.QueryContext(ctx, `SELECT actor_id, version, status,
		json_object('display_name', display_name, 'kind', kind, 'status', status) FROM actors
		WHERE workspace_id = ? AND actor_id <> ? ORDER BY actor_id LIMIT ?`, state.workspace.String(),
		state.view.ActorID().String(), application.MaxContextCollaborators+1)
	if err != nil {
		return nil, fmt.Errorf("read SQLite context collaborators: %w", err)
	}
	defer func() { _ = collaborators.Close() }()
	count := 0
	for collaborators.Next() {
		var id, lifecycleState, payload string
		var version uint64
		if err := collaborators.Scan(&id, &version, &lifecycleState, &payload); err != nil {
			return nil, err
		}
		count++
		if count > application.MaxContextCollaborators {
			return nil, queryError(domain.ErrorCodeBackpressure, "context collaborator set exceeds query bound")
		}
		domainVersion, versionErr := domain.NewVersion(version)
		record, recordErr := application.NewTypedContextRecord(application.ContextRecordParams{
			Kind: application.ContextRecordCollaborator, ID: id, Version: domainVersion,
			LifecycleState: application.ContextLifecycleState(lifecycleState), CanonicalPayload: []byte(payload),
		})
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

func streamHead(ctx context.Context, tx *sql.Tx, workspace domain.WorkspaceID, epoch domain.AuthorityEpoch) (uint64, [sha256.Size]byte, uint64, error) {
	var next, retained uint64
	var digestBytes []byte
	err := tx.QueryRowContext(ctx, `SELECT next_sequence, retained_from_sequence, head_digest FROM authority_streams
		WHERE scope_kind = 'workspace' AND scope_id = ? AND authority_epoch = ?`, workspace.String(), epoch.String()).Scan(&next, &retained, &digestBytes)
	if err != nil || next == 0 || retained == 0 || retained > next || len(digestBytes) != sha256.Size {
		return 0, [sha256.Size]byte{}, 0, fmt.Errorf("read SQLite workspace stream head: %w", err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	return next - 1, digest, retained, nil
}

func digestBeforeSequence(ctx context.Context, tx *sql.Tx, workspace domain.WorkspaceID, epoch domain.AuthorityEpoch, sequence uint64) ([sha256.Size]byte, error) {
	var digestBytes []byte
	if sequence == 1 {
		err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT previous_stream_digest FROM domain_events
			WHERE scope_kind = 'workspace' AND scope_id = ? AND authority_epoch = ? ORDER BY stream_sequence LIMIT 1),
			(SELECT head_digest FROM authority_streams WHERE scope_kind = 'workspace' AND scope_id = ? AND authority_epoch = ?))`,
			workspace.String(), epoch.String(), workspace.String(), epoch.String()).Scan(&digestBytes)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
	} else {
		err := tx.QueryRowContext(ctx, `SELECT stream_digest FROM domain_events WHERE scope_kind = 'workspace'
			AND scope_id = ? AND authority_epoch = ? AND stream_sequence = ?`, workspace.String(), epoch.String(), sequence-1).Scan(&digestBytes)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
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

func validateEventCursor(ctx context.Context, tx *sql.Tx, cursor application.EventCursor, workspace domain.WorkspaceID,
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
	if wire.Sequence > head {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorInvalid, "event cursor is ahead of the workspace stream")
	}
	if wire.Sequence+1 < retained {
		return 0, [sha256.Size]byte{}, queryError(domain.ErrorCodeCursorExpired, "event cursor was pruned; fetch context.get.v1")
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

type CheckpointMode string

const (
	CheckpointPassive  CheckpointMode = "passive"
	CheckpointTruncate CheckpointMode = "truncate"
)

type CheckpointReport struct {
	Mode               CheckpointMode
	Busy               bool
	BusyStatus         int
	BusyTime           time.Duration
	LogFrames          int
	CheckpointedFrames int
	RemainingFrames    int
	OldestReaderKnown  bool
	OldestReaderAge    time.Duration
	WALBytes           int64
	FreeBytes          uint64
	Duration           time.Duration
}

type IntegrityReport struct {
	Full     bool
	Duration time.Duration
}

type PathQualification struct {
	Path           string
	Exists         bool
	Directory      bool
	OwnerUID       uint32
	Permissions    os.FileMode
	FilesystemType uint64
	FilesystemName string
	FreeBytes      uint64
	LockVerified   bool
}

type FilesystemQualification struct {
	DatabaseDirectory PathQualification
	Database          PathQualification
	WAL               PathQualification
	SharedMemory      PathQualification
	Artifacts         PathQualification
	SameOwner         bool
	Local             bool
	QualifiedAt       time.Time
}

func (store *Store) Checkpoint(ctx context.Context, mode CheckpointMode) (CheckpointReport, error) {
	if mode != CheckpointPassive && mode != CheckpointTruncate {
		return CheckpointReport{}, fmt.Errorf("invalid SQLite checkpoint mode %q", mode)
	}
	if mode == CheckpointTruncate {
		if _, bounded := ctx.Deadline(); !bounded {
			return CheckpointReport{}, errors.New("SQLite truncating checkpoint requires a bounded context")
		}
		if err := store.acquireWrite(ctx, false); err != nil {
			return CheckpointReport{}, err
		}
		defer store.releaseWrite()
	}

	started := time.Now()
	report := CheckpointReport{Mode: mode}
	pragma := "PRAGMA wal_checkpoint(PASSIVE)"
	if mode == CheckpointTruncate {
		pragma = "PRAGMA wal_checkpoint(TRUNCATE)"
	}
	if err := store.db.QueryRowContext(ctx, pragma).Scan(
		&report.BusyStatus, &report.LogFrames, &report.CheckpointedFrames,
	); err != nil {
		return CheckpointReport{}, fmt.Errorf("run SQLite %s checkpoint: %w", mode, err)
	}
	report.Duration = time.Since(started)
	report.Busy = report.BusyStatus != 0
	if report.Busy {
		report.BusyTime = report.Duration
	}
	if report.LogFrames > report.CheckpointedFrames {
		report.RemainingFrames = report.LogFrames - report.CheckpointedFrames
	}
	if info, err := os.Stat(store.path + "-wal"); err == nil {
		report.WALBytes = info.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return CheckpointReport{}, fmt.Errorf("inspect SQLite WAL after checkpoint: %w", err)
	}
	freeBytes, _, _, err := filesystemStats(store.path)
	if err != nil {
		return CheckpointReport{}, fmt.Errorf("inspect SQLite free space after checkpoint: %w", err)
	}
	report.FreeBytes = freeBytes
	return report, nil
}

func (store *Store) FullIntegrityCheck(ctx context.Context) (IntegrityReport, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		return IntegrityReport{Full: true}, errors.New("full SQLite integrity check requires a bounded context")
	}
	if err := store.acquireWrite(ctx, false); err != nil {
		return IntegrityReport{Full: true}, err
	}
	defer store.releaseWrite()

	started := time.Now()
	err := store.IntegrityCheck(ctx)
	report := IntegrityReport{Full: true, Duration: time.Since(started)}
	if err != nil {
		return report, err
	}
	return report, nil
}

func QualifyFilesystem(databasePath, artifactDirectory string) (FilesystemQualification, error) {
	if err := validateQualifiedPath(databasePath); err != nil {
		return FilesystemQualification{}, err
	}
	if err := validateQualifiedPath(artifactDirectory); err != nil {
		return FilesystemQualification{}, err
	}

	databaseDirectory, err := qualifyPath(filepath.Dir(databasePath), true, true)
	if err != nil {
		return FilesystemQualification{}, err
	}
	database, err := qualifyPath(databasePath, false, true)
	if err != nil {
		return FilesystemQualification{}, err
	}
	wal, err := qualifyPath(databasePath+"-wal", false, false)
	if err != nil {
		return FilesystemQualification{}, err
	}
	sharedMemory, err := qualifyPath(databasePath+"-shm", false, false)
	if err != nil {
		return FilesystemQualification{}, err
	}
	artifacts, err := qualifyPath(artifactDirectory, true, true)
	if err != nil {
		return FilesystemQualification{}, err
	}

	owner := uint32(os.Geteuid())
	result := FilesystemQualification{
		DatabaseDirectory: databaseDirectory, Database: database, WAL: wal,
		SharedMemory: sharedMemory, Artifacts: artifacts,
		SameOwner: true, Local: true, QualifiedAt: time.Now().UTC(),
	}
	for _, path := range []PathQualification{databaseDirectory, database, wal, sharedMemory, artifacts} {
		if path.OwnerUID != owner {
			result.SameOwner = false
		}
		if unsupportedFilesystem(path.FilesystemType, path.FilesystemName) {
			result.Local = false
		}
	}
	if !result.SameOwner {
		return result, fmt.Errorf("%w: paths are not owned by effective uid %d", ErrFilesystemQualification, owner)
	}
	if !result.Local {
		return result, fmt.Errorf("%w: network or userspace filesystem is unsupported", ErrFilesystemQualification)
	}
	return result, nil
}

func validateQualifiedPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: path must be absolute and clean: %q", ErrFilesystemQualification, path)
	}
	return nil
}

func qualifyPath(path string, directory, required bool) (PathQualification, error) {
	result := PathQualification{Path: path, Directory: directory}
	info, err := os.Lstat(path)
	exists := err == nil
	if errors.Is(err, os.ErrNotExist) && !required {
		info, err = os.Lstat(filepath.Dir(path))
	}
	if err != nil {
		return result, fmt.Errorf("%w: inspect %q: %v", ErrFilesystemQualification, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return result, fmt.Errorf("%w: symlink is unsupported: %q", ErrFilesystemQualification, path)
	}
	if exists && directory != info.IsDir() {
		return result, fmt.Errorf("%w: unexpected file type: %q", ErrFilesystemQualification, path)
	}
	if !exists && !info.IsDir() {
		return result, fmt.Errorf("%w: sidecar parent is not a directory: %q", ErrFilesystemQualification, path)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return result, fmt.Errorf("%w: path is not regular: %q", ErrFilesystemQualification, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return result, fmt.Errorf("%w: group or other permissions on %q are not allowed", ErrFilesystemQualification, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return result, fmt.Errorf("%w: ownership unavailable for %q", ErrFilesystemQualification, path)
	}
	result.Exists = exists
	result.OwnerUID = stat.Uid
	result.Permissions = info.Mode().Perm()
	result.FreeBytes, result.FilesystemType, result.FilesystemName, err = filesystemStats(path)
	if err != nil {
		return result, fmt.Errorf("%w: filesystem stats for %q: %v", ErrFilesystemQualification, path, err)
	}
	if required && !directory {
		if err := verifyAdvisoryLocks(path); err != nil {
			return result, err
		}
		result.LockVerified = true
	}
	return result, nil
}

func filesystemStats(path string) (uint64, uint64, string, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		if !errors.Is(err, syscall.ENOENT) {
			return 0, 0, "", err
		}
		if err := syscall.Statfs(filepath.Dir(path), &stat); err != nil {
			return 0, 0, "", err
		}
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), uint64(stat.Type), filesystemName(stat), nil
}

func filesystemName(stat syscall.Statfs_t) string {
	field := reflect.ValueOf(stat).FieldByName("Fstypename")
	if !field.IsValid() || field.Kind() != reflect.Array {
		return ""
	}
	name := make([]byte, 0, field.Len())
	for index := range field.Len() {
		value := byte(field.Index(index).Int())
		if value == 0 {
			break
		}
		name = append(name, value)
	}
	return strings.ToLower(string(name))
}

func verifyAdvisoryLocks(path string) error {
	probe := func() (*sql.DB, error) {
		db, err := sql.Open("sqlite", databaseURL(Config{Path: path, BusyTimeout: time.Millisecond}))
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		return db, nil
	}
	first, err := probe()
	if err != nil {
		return fmt.Errorf("%w: open SQLite lock probe: %v", ErrFilesystemQualification, err)
	}
	defer func() { _ = first.Close() }()
	second, err := probe()
	if err != nil {
		return fmt.Errorf("%w: open competing SQLite lock probe: %v", ErrFilesystemQualification, err)
	}
	defer func() { _ = second.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), defaultBusyTimeout)
	defer cancel()
	firstTx, err := first.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin SQLite lock probe: %v", ErrFilesystemQualification, err)
	}
	defer func() { _ = firstTx.Rollback() }()
	if competing, err := second.BeginTx(ctx, nil); err == nil {
		_ = competing.Rollback()
		return fmt.Errorf("%w: filesystem did not enforce competing SQLite write locks", ErrFilesystemQualification)
	} else if ctx.Err() != nil {
		return fmt.Errorf("%w: competing SQLite lock probe exceeded its bound: %v", ErrFilesystemQualification, ctx.Err())
	}
	return nil
}

func unsupportedFilesystem(filesystemType uint64, filesystemName string) bool {
	switch filesystemName {
	case "nfs", "smbfs", "webdav", "afpfs", "osxfuse", "macfuse":
		return true
	}
	switch filesystemType {
	case 0x6969, 0x517b, 0xff534d42, 0x65735546, 0x9fa0:
		// NFS, SMB, CIFS, FUSE, and procfs are not supported authority storage.
		return true
	default:
		return false
	}
}

func (store *Store) OpenConversation(ctx context.Context, params application.OpenConversationParams) (application.Conversation, error) {
	var result application.Conversation
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		result, err = application.NewConversation(params, now)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO conversations(conversation_id, workspace_id, run_id,
			opened_by_actor_id, opened_by_session_id, topic, opened_at_us) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			params.ConversationID.String(), params.WorkspaceID.String(), params.RunID.String(), params.OpenedBy.String(),
			params.OpenedBySession.String(), params.Topic, timeMicros(now))
		if err != nil {
			return fmt.Errorf("insert SQLite conversation: %w", err)
		}
		return nil
	})
	return result, err
}

func (store *Store) SendMessage(ctx context.Context, params application.SendMessageParams) (application.Message, error) {
	if err := application.ValidateSendMessage(params); err != nil {
		return application.Message{}, err
	}
	var result application.Message
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		var status, workspace string
		if err := tx.QueryRowContext(ctx, `SELECT status, workspace_id FROM conversations WHERE conversation_id = ?`,
			params.ConversationID.String()).Scan(&status, &workspace); errors.Is(err, sql.ErrNoRows) {
			return coordinationError(domain.ErrorCodeNotFound, "conversation was not found")
		} else if err != nil {
			return err
		}
		if workspace != params.WorkspaceID.String() {
			return coordinationError(domain.ErrorCodeForbidden, "conversation belongs to another workspace")
		}
		if status != "open" {
			return coordinationConflict(domain.ErrorCodeStateConflict, domain.ConflictConversationClosed, "conversation is closed")
		}
		if params.ReplyTo != nil {
			var parentConversation string
			if err := tx.QueryRowContext(ctx, `SELECT conversation_id FROM messages WHERE message_id = ?`, params.ReplyTo.String()).Scan(&parentConversation); err != nil || parentConversation != params.ConversationID.String() {
				return application.ErrInvalidCoordination
			}
		}
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		digest := application.DigestBytes([]byte(params.Body))
		var reply any
		if params.ReplyTo != nil {
			reply = params.ReplyTo.String()
		}
		insert, err := tx.ExecContext(ctx, `INSERT INTO messages(message_id, conversation_id, workspace_id,
			author_actor_id, author_session_id, subject, body, body_digest, reply_to_message_id, sent_at_us)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, params.MessageID.String(), params.ConversationID.String(),
			params.WorkspaceID.String(), params.Author.String(), params.AuthorSession.String(), params.Subject, params.Body,
			digest[:], reply, timeMicros(now))
		if err != nil {
			return fmt.Errorf("insert SQLite message: %w", err)
		}
		position, err := insert.LastInsertId()
		if err != nil || position <= 0 {
			return application.ErrInvalidCoordination
		}
		deliveries := make([]application.Delivery, 0, len(params.Recipients))
		for _, recipient := range params.Recipients {
			if _, err := tx.ExecContext(ctx, `INSERT INTO message_deliveries(message_id, recipient_actor_id,
				recipient_kind, acknowledgement_required) VALUES (?, ?, ?, ?)`, params.MessageID.String(),
				recipient.ActorID().String(), string(recipient.Kind()), params.AcknowledgementRequired); err != nil {
				return fmt.Errorf("insert SQLite message delivery: %w", err)
			}
			delivery, _ := application.NewDeliveryView(recipient, params.AcknowledgementRequired, nil, nil, nil)
			deliveries = append(deliveries, delivery)
		}
		result, err = application.NewMessageView(application.MessageViewParams{MessageID: params.MessageID,
			ConversationID: params.ConversationID, WorkspaceID: params.WorkspaceID, Author: params.Author,
			Subject: params.Subject, Body: params.Body, ReplyTo: params.ReplyTo, SentAt: now,
			Position: uint64(position), Deliveries: deliveries})
		return err
	})
	return result, err
}

func (store *Store) Inbox(ctx context.Context, query application.InboxQuery) (application.CoordinationPage, error) {
	if query.WorkspaceID.IsZero() || query.Recipient.IsZero() || query.Limit == 0 || query.Limit > application.MaxQueryPageSize {
		return application.CoordinationPage{}, application.ErrInvalidCoordination
	}
	return store.loadMessages(ctx, query.WorkspaceID, domain.ConversationID{}, query.Recipient, query.After, query.Limit, true, query.UnreadOnly)
}

func (store *Store) Thread(ctx context.Context, query application.ThreadQuery) (application.CoordinationPage, error) {
	if query.WorkspaceID.IsZero() || query.ConversationID.IsZero() || query.Viewer.IsZero() || query.Limit == 0 || query.Limit > application.MaxQueryPageSize {
		return application.CoordinationPage{}, application.ErrInvalidCoordination
	}
	return store.loadMessages(ctx, query.WorkspaceID, query.ConversationID, query.Viewer, query.After, query.Limit, false, false)
}

func (store *Store) loadMessages(ctx context.Context, workspace domain.WorkspaceID, conversation domain.ConversationID,
	viewer domain.ActorID, after uint64, limit uint16, inbox, unreadOnly bool) (application.CoordinationPage, error) {
	base := `SELECT DISTINCT message.message_id, message.conversation_id, message.author_actor_id, message.subject,
		message.body, message.reply_to_message_id, message.sent_at_us, message.position FROM messages AS message
		LEFT JOIN message_deliveries AS own ON own.message_id = message.message_id AND own.recipient_actor_id = ?
		WHERE message.workspace_id = ? AND message.position > ? AND (message.author_actor_id = ? OR own.message_id IS NOT NULL)`
	args := []any{viewer.String(), workspace.String(), after, viewer.String()}
	if inbox {
		base += ` AND own.message_id IS NOT NULL`
		if unreadOnly {
			base += ` AND own.read_at_us IS NULL`
		}
	} else {
		base += ` AND message.conversation_id = ?`
		args = append(args, conversation.String())
	}
	base += ` ORDER BY message.position LIMIT ?`
	args = append(args, int(limit)+1)
	rows, err := store.db.QueryContext(ctx, base, args...)
	if err != nil {
		return application.CoordinationPage{}, fmt.Errorf("query SQLite coordination messages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type row struct {
		message, conversation, author, subject, body string
		reply                                        sql.NullString
		sent                                         int64
		position                                     uint64
	}
	values := make([]row, 0, limit)
	hasMore := false
	for rows.Next() {
		var value row
		if err := rows.Scan(&value.message, &value.conversation, &value.author, &value.subject, &value.body,
			&value.reply, &value.sent, &value.position); err != nil {
			return application.CoordinationPage{}, err
		}
		if len(values) == int(limit) {
			hasMore = true
			break
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return application.CoordinationPage{}, err
	}
	result := make([]application.Message, 0, len(values))
	for _, value := range values {
		messageID, e1 := domain.ParseMessageID(value.message)
		conversationID, e2 := domain.ParseConversationID(value.conversation)
		author, e3 := domain.ParseActorID(value.author)
		if e1 != nil || e2 != nil || e3 != nil {
			return application.CoordinationPage{}, application.ErrInvalidCoordination
		}
		deliveries, err := store.loadVisibleDeliveries(ctx, messageID, author, viewer)
		if err != nil {
			return application.CoordinationPage{}, err
		}
		params := application.MessageViewParams{MessageID: messageID, ConversationID: conversationID, WorkspaceID: workspace,
			Author: author, Subject: value.subject, Body: value.body, SentAt: microsTime(value.sent), Position: value.position,
			Deliveries: deliveries}
		if value.reply.Valid {
			id, parseErr := domain.ParseMessageID(value.reply.String)
			if parseErr != nil {
				return application.CoordinationPage{}, parseErr
			}
			params.ReplyTo = &id
		}
		message, err := application.NewMessageView(params)
		if err != nil {
			return application.CoordinationPage{}, err
		}
		result = append(result, message)
	}
	next := after
	if len(result) != 0 {
		next = result[len(result)-1].Position()
	}
	return application.NewCoordinationPage(result, next, hasMore)
}

func (store *Store) loadVisibleDeliveries(ctx context.Context, message domain.MessageID, author, viewer domain.ActorID) ([]application.Delivery, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT recipient_actor_id, recipient_kind, acknowledgement_required,
		available_at_us, read_at_us, acknowledged_at_us FROM message_deliveries WHERE message_id = ?
		AND (? = ? OR recipient_kind <> 'bcc' OR recipient_actor_id = ?) ORDER BY recipient_kind, recipient_actor_id`,
		message.String(), viewer.String(), author.String(), viewer.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var result []application.Delivery
	for rows.Next() {
		var actorText, kind string
		var required bool
		var available, read, acknowledged sql.NullInt64
		if err := rows.Scan(&actorText, &kind, &required, &available, &read, &acknowledged); err != nil {
			return nil, err
		}
		actor, err := domain.ParseActorID(actorText)
		if err != nil {
			return nil, err
		}
		recipient, err := application.NewRecipient(actor, application.RecipientKind(kind))
		if err != nil {
			return nil, err
		}
		delivery, err := application.NewDeliveryView(recipient, required, nullableTime(available), nullableTime(read), nullableTime(acknowledged))
		if err != nil {
			return nil, err
		}
		result = append(result, delivery)
	}
	return result, rows.Err()
}

func nullableTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	result := microsTime(value.Int64)
	return &result
}

func (store *Store) RecordDeliveryFact(ctx context.Context, params application.RecordDeliveryFactParams) (application.Delivery, error) {
	if params.WorkspaceID.IsZero() || params.MessageID.IsZero() || params.Recipient.IsZero() ||
		params.Kind != application.DeliveryAvailable && params.Kind != application.DeliveryRead && params.Kind != application.DeliveryAcknowledged {
		return application.Delivery{}, application.ErrInvalidCoordination
	}
	if params.Kind != application.DeliveryAvailable && (params.ActorSessionID == nil || params.ActorSessionID.IsZero()) {
		return application.Delivery{}, application.ErrInvalidCoordination
	}
	if params.Kind == application.DeliveryAcknowledged && params.MessageDigest.IsZero() {
		return application.Delivery{}, application.ErrInvalidCoordination
	}
	var result application.Delivery
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		var kind string
		var required bool
		var digest []byte
		var acknowledgedSession sql.NullString
		var acknowledgedDigest []byte
		var workspace string
		var available, read, acknowledged sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT delivery.recipient_kind, delivery.acknowledgement_required,
			delivery.available_at_us, delivery.read_at_us, delivery.acknowledged_at_us,
			delivery.acknowledged_by_session_id, delivery.acknowledged_message_digest, message.body_digest, message.workspace_id
			FROM message_deliveries AS delivery JOIN messages AS message USING(message_id)
			WHERE delivery.message_id = ? AND delivery.recipient_actor_id = ?`, params.MessageID.String(), params.Recipient.String()).Scan(
			&kind, &required, &available, &read, &acknowledged, &acknowledgedSession, &acknowledgedDigest, &digest, &workspace)
		if errors.Is(err, sql.ErrNoRows) {
			return coordinationError(domain.ErrorCodeForbidden, "message delivery belongs to another recipient")
		}
		if err != nil {
			return err
		}
		if workspace != params.WorkspaceID.String() {
			return coordinationError(domain.ErrorCodeForbidden, "message belongs to another workspace")
		}
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		switch params.Kind {
		case application.DeliveryAvailable:
			_, err = tx.ExecContext(ctx, `UPDATE message_deliveries SET available_at_us = COALESCE(available_at_us, ?) WHERE message_id = ? AND recipient_actor_id = ?`, timeMicros(now), params.MessageID.String(), params.Recipient.String())
		case application.DeliveryRead:
			_, err = tx.ExecContext(ctx, `UPDATE message_deliveries SET read_at_us = COALESCE(read_at_us, ?) WHERE message_id = ? AND recipient_actor_id = ?`, timeMicros(now), params.MessageID.String(), params.Recipient.String())
		case application.DeliveryAcknowledged:
			if !bytes.Equal(digest, params.MessageDigest[:]) {
				return coordinationConflict(domain.ErrorCodeStateConflict, domain.ConflictDeliveryFact, "message digest does not match")
			}
			if acknowledged.Valid && (acknowledgedSession.String != params.ActorSessionID.String() ||
				!bytes.Equal(acknowledgedDigest, params.MessageDigest[:])) {
				return coordinationConflict(domain.ErrorCodeStateConflict, domain.ConflictDeliveryFact, "acknowledgement fact already differs")
			}
			_, err = tx.ExecContext(ctx, `UPDATE message_deliveries SET acknowledged_at_us = COALESCE(acknowledged_at_us, ?),
				acknowledged_by_session_id = COALESCE(acknowledged_by_session_id, ?), acknowledged_message_digest = COALESCE(acknowledged_message_digest, ?)
				WHERE message_id = ? AND recipient_actor_id = ?`, timeMicros(now), params.ActorSessionID.String(), digest,
				params.MessageID.String(), params.Recipient.String())
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT available_at_us, read_at_us, acknowledged_at_us FROM message_deliveries
			WHERE message_id = ? AND recipient_actor_id = ?`, params.MessageID.String(), params.Recipient.String()).Scan(&available, &read, &acknowledged); err != nil {
			return err
		}
		actorRecipient, _ := application.NewRecipient(params.Recipient, application.RecipientKind(kind))
		result, err = application.NewDeliveryView(actorRecipient, required, nullableTime(available), nullableTime(read), nullableTime(acknowledged))
		return err
	})
	return result, err
}

func (store *Store) AcquireLease(ctx context.Context, params application.AcquireLeaseParams) (application.Lease, error) {
	if err := application.ValidateAcquireLease(params); err != nil {
		return application.Lease{}, err
	}
	var result application.Lease
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		if err := requireCurrentLeaseEpoch(ctx, tx, params.WorkspaceID, params.AuthorityEpoch); err != nil {
			return err
		}
		type existingSelector struct {
			lease, mode, kind, value string
			expires                  int64
		}
		rows, err := tx.QueryContext(ctx, `SELECT lease.lease_id, lease.mode, selector.selector_kind, selector.selector_path, lease.expires_at_us
			FROM leases AS lease JOIN lease_selectors AS selector USING(lease_id)
			WHERE lease.workspace_id = ? AND lease.authority_epoch = ? AND lease.status = 'active'`,
			params.WorkspaceID.String(), params.AuthorityEpoch.String())
		if err != nil {
			return err
		}
		var existing []existingSelector
		for rows.Next() {
			var value existingSelector
			if err := rows.Scan(&value.lease, &value.mode, &value.kind, &value.value, &value.expires); err != nil {
				_ = rows.Close()
				return err
			}
			existing = append(existing, value)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		keys := make(map[string]struct{}, len(params.Selectors))
		for _, requested := range params.Selectors {
			keys[requested.Key()] = struct{}{}
			for _, prior := range existing {
				selector, parseErr := application.NewLeaseSelector(application.LeaseSelectorKind(prior.kind), prior.value)
				if parseErr != nil {
					return parseErr
				}
				if !application.LeaseSelectorsOverlap(requested, selector) {
					continue
				}
				keys[selector.Key()] = struct{}{}
				if prior.expires > timeMicros(now) && (params.Mode == application.LeaseExclusive || application.LeaseMode(prior.mode) == application.LeaseExclusive) {
					return coordinationConflict(domain.ErrorCodeLeaseConflict, domain.ConflictLease, "an active overlapping lease exists")
				}
			}
		}
		expires := now.Add(params.TTL)
		if _, err := tx.ExecContext(ctx, `INSERT INTO leases(lease_id, workspace_id, holder_actor_id, holder_session_id,
			authority_epoch, mode, status, acquired_at_us, expires_at_us) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
			params.LeaseID.String(), params.WorkspaceID.String(), params.Holder.String(), params.HolderSession.String(),
			params.AuthorityEpoch.String(), string(params.Mode), timeMicros(now), timeMicros(expires)); err != nil {
			return fmt.Errorf("insert SQLite lease: %w", err)
		}
		selectors := append([]application.LeaseSelector(nil), params.Selectors...)
		sort.Slice(selectors, func(i, j int) bool { return selectors[i].Key() < selectors[j].Key() })
		for index, selector := range selectors {
			if _, err := tx.ExecContext(ctx, `INSERT INTO lease_selectors(lease_id, selector_ordinal, selector_kind, selector_path) VALUES (?, ?, ?, ?)`,
				params.LeaseID.String(), index, string(selector.Kind()), selector.Path()); err != nil {
				return err
			}
		}
		var fences []application.Fence
		if params.Mode == application.LeaseExclusive {
			ordered := make([]string, 0, len(keys))
			for key := range keys {
				ordered = append(ordered, key)
			}
			sort.Strings(ordered)
			for _, key := range ordered {
				_, err := tx.ExecContext(ctx, `INSERT INTO lease_fence_counters(workspace_id, authority_epoch, conflict_key, counter)
					VALUES (?, ?, ?, 1) ON CONFLICT(workspace_id, authority_epoch, conflict_key) DO UPDATE SET counter = counter + 1`,
					params.WorkspaceID.String(), params.AuthorityEpoch.String(), key)
				if err != nil {
					return err
				}
				var counter uint64
				if err := tx.QueryRowContext(ctx, `SELECT counter FROM lease_fence_counters WHERE workspace_id = ? AND authority_epoch = ? AND conflict_key = ?`,
					params.WorkspaceID.String(), params.AuthorityEpoch.String(), key).Scan(&counter); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO lease_fences(lease_id, conflict_key, counter) VALUES (?, ?, ?)`, params.LeaseID.String(), key, counter); err != nil {
					return err
				}
				fence, _ := application.NewFence(key, counter)
				fences = append(fences, fence)
			}
		}
		result, err = application.NewLeaseView(application.LeaseViewParams{LeaseID: params.LeaseID, WorkspaceID: params.WorkspaceID,
			Holder: params.Holder, HolderSession: params.HolderSession, AuthorityEpoch: params.AuthorityEpoch, Mode: params.Mode,
			Selectors: selectors, Fences: fences, AcquiredAt: now, ExpiresAt: expires})
		return err
	})
	return result, err
}

func (store *Store) RenewLease(ctx context.Context, params application.ChangeLeaseParams) (application.Lease, error) {
	if params.TTL <= 0 || params.TTL > application.MaxLeaseTTL {
		return application.Lease{}, application.ErrInvalidCoordination
	}
	return store.changeLease(ctx, params, false)
}

func (store *Store) ReleaseLease(ctx context.Context, params application.ChangeLeaseParams) (application.Lease, error) {
	if params.TTL != 0 {
		return application.Lease{}, application.ErrInvalidCoordination
	}
	return store.changeLease(ctx, params, true)
}

func (store *Store) changeLease(ctx context.Context, params application.ChangeLeaseParams, release bool) (application.Lease, error) {
	if params.LeaseID.IsZero() || params.HolderSession.IsZero() || params.AuthorityEpoch.IsZero() {
		return application.Lease{}, application.ErrInvalidCoordination
	}
	var result application.Lease
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		lease, err := loadLease(ctx, tx, params.LeaseID)
		if err != nil {
			return err
		}
		if lease.HolderSession() != params.HolderSession {
			return coordinationError(domain.ErrorCodeForbidden, "lease belongs to another holder")
		}
		if lease.AuthorityEpoch() != params.AuthorityEpoch {
			return coordinationConflict(domain.ErrorCodeFenceRejected, domain.ConflictFence, "lease authority epoch is stale")
		}
		if err := requireCurrentLeaseEpoch(ctx, tx, lease.WorkspaceID(), params.AuthorityEpoch); err != nil {
			return err
		}
		if !equalFences(lease.Fences(), params.Fences) {
			return coordinationConflict(domain.ErrorCodeFenceRejected, domain.ConflictFence, "lease fence is stale")
		}
		if _, released := lease.ReleasedAt(); released {
			result = lease
			return nil
		}
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		if !now.Before(lease.ExpiresAt()) {
			return coordinationConflict(domain.ErrorCodeLeaseExpired, domain.ConflictLeaseTerminal, "lease has expired")
		}
		if release {
			if _, err := tx.ExecContext(ctx, `UPDATE leases SET status = 'released', released_at_us = ? WHERE lease_id = ? AND status = 'active'`, timeMicros(now), params.LeaseID.String()); err != nil {
				return err
			}
		} else {
			expires := now.Add(params.TTL)
			maximum := lease.AcquiredAt().Add(application.MaxLeaseLifetime)
			if expires.After(maximum) {
				return application.ErrInvalidCoordination
			}
			if _, err := tx.ExecContext(ctx, `UPDATE leases SET expires_at_us = ? WHERE lease_id = ? AND status = 'active'`, timeMicros(expires), params.LeaseID.String()); err != nil {
				return err
			}
		}
		result, err = loadLease(ctx, tx, params.LeaseID)
		return err
	})
	return result, err
}

func (store *Store) ValidateFence(ctx context.Context, leaseID domain.LeaseID, epoch domain.AuthorityEpoch, fences []application.Fence) error {
	if leaseID.IsZero() || epoch.IsZero() {
		return application.ErrInvalidCoordination
	}
	lease, err := loadLease(ctx, store.db, leaseID)
	if err != nil {
		return err
	}
	if lease.AuthorityEpoch() != epoch || !equalFences(lease.Fences(), fences) {
		return coordinationConflict(domain.ErrorCodeFenceRejected, domain.ConflictFence, "lease fence is stale")
	}
	if err := requireCurrentLeaseEpoch(ctx, store.db, lease.WorkspaceID(), epoch); err != nil {
		return err
	}
	now, err := sqliteNow(ctx, store.db)
	if err != nil {
		return err
	}
	if _, released := lease.ReleasedAt(); released || !now.Before(lease.ExpiresAt()) {
		return coordinationConflict(domain.ErrorCodeFenceRejected, domain.ConflictFence, "lease is not active")
	}
	for _, fence := range fences {
		var current uint64
		if err := store.db.QueryRowContext(ctx, `SELECT counter FROM lease_fence_counters WHERE workspace_id = ? AND authority_epoch = ? AND conflict_key = ?`,
			lease.WorkspaceID().String(), epoch.String(), fence.ConflictKey()).Scan(&current); err != nil || current != fence.Counter() {
			return coordinationConflict(domain.ErrorCodeFenceRejected, domain.ConflictFence, "lease fence has been superseded")
		}
	}
	return nil
}

type leaseQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadLease(ctx context.Context, query leaseQuery, id domain.LeaseID) (application.Lease, error) {
	var workspaceText, holderText, sessionText, epochText, mode, status string
	var acquired, expires int64
	var released sql.NullInt64
	err := query.QueryRowContext(ctx, `SELECT workspace_id, holder_actor_id, holder_session_id, authority_epoch, mode,
		status, acquired_at_us, expires_at_us, released_at_us FROM leases WHERE lease_id = ?`, id.String()).Scan(
		&workspaceText, &holderText, &sessionText, &epochText, &mode, &status, &acquired, &expires, &released)
	if errors.Is(err, sql.ErrNoRows) {
		return application.Lease{}, coordinationError(domain.ErrorCodeNotFound, "lease was not found")
	}
	if err != nil {
		return application.Lease{}, err
	}
	workspace, e1 := domain.ParseWorkspaceID(workspaceText)
	holder, e2 := domain.ParseActorID(holderText)
	session, e3 := domain.ParseActorSessionID(sessionText)
	epoch, e4 := domain.ParseAuthorityEpoch(epochText)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return application.Lease{}, application.ErrInvalidCoordination
	}
	selectorRows, err := query.QueryContext(ctx, `SELECT selector_kind, selector_path FROM lease_selectors WHERE lease_id = ? ORDER BY selector_ordinal`, id.String())
	if err != nil {
		return application.Lease{}, err
	}
	defer func() { _ = selectorRows.Close() }()
	var selectors []application.LeaseSelector
	for selectorRows.Next() {
		var kind, value string
		if err := selectorRows.Scan(&kind, &value); err != nil {
			return application.Lease{}, err
		}
		selector, err := application.NewLeaseSelector(application.LeaseSelectorKind(kind), value)
		if err != nil {
			return application.Lease{}, err
		}
		selectors = append(selectors, selector)
	}
	if err := selectorRows.Close(); err != nil {
		return application.Lease{}, err
	}
	fenceRows, err := query.QueryContext(ctx, `SELECT conflict_key, counter FROM lease_fences WHERE lease_id = ? ORDER BY conflict_key`, id.String())
	if err != nil {
		return application.Lease{}, err
	}
	defer func() { _ = fenceRows.Close() }()
	var fences []application.Fence
	for fenceRows.Next() {
		var key string
		var counter uint64
		if err := fenceRows.Scan(&key, &counter); err != nil {
			return application.Lease{}, err
		}
		fence, err := application.NewFence(key, counter)
		if err != nil {
			return application.Lease{}, err
		}
		fences = append(fences, fence)
	}
	params := application.LeaseViewParams{LeaseID: id, WorkspaceID: workspace, Holder: holder, HolderSession: session,
		AuthorityEpoch: epoch, Mode: application.LeaseMode(mode), Selectors: selectors, Fences: fences,
		AcquiredAt: microsTime(acquired), ExpiresAt: microsTime(expires), ReleasedAt: nullableTime(released)}
	return application.NewLeaseView(params)
}

func equalFences(left, right []application.Fence) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]application.Fence(nil), left...)
	right = append([]application.Fence(nil), right...)
	sort.Slice(left, func(i, j int) bool { return left[i].ConflictKey() < left[j].ConflictKey() })
	sort.Slice(right, func(i, j int) bool { return right[i].ConflictKey() < right[j].ConflictKey() })
	for index := range left {
		if left[index].ConflictKey() != right[index].ConflictKey() || left[index].Counter() != right[index].Counter() {
			return false
		}
	}
	return true
}

func sqliteNow(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (time.Time, error) {
	var micros int64
	if err := query.QueryRowContext(ctx, `SELECT CAST(unixepoch('subsec') * 1000000 AS INTEGER)`).Scan(&micros); err != nil {
		return time.Time{}, err
	}
	return microsTime(micros), nil
}

func requireCurrentLeaseEpoch(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, workspace domain.WorkspaceID, epoch domain.AuthorityEpoch) error {
	var current string
	err := query.QueryRowContext(ctx, `SELECT authority_epoch FROM scope_guards WHERE scope_kind = 'workspace' AND scope_id = ?`, workspace.String()).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return coordinationError(domain.ErrorCodeNotFound, "workspace lease authority was not found")
	}
	if err != nil {
		return err
	}
	if current != epoch.String() {
		return coordinationConflict(domain.ErrorCodeFenceRejected, domain.ConflictFence, "workspace authority epoch is stale")
	}
	return nil
}

func (store *Store) RegisterLocalAgent(ctx context.Context, projectKey, agentName, registrationToken string) (application.LocalAgentSession, string, error) {
	if !validLocalCoordinationText(projectKey, application.MaxCoordinationKeyBytes) ||
		!validLocalCoordinationText(agentName, application.MaxCoordinationNameBytes) {
		return application.LocalAgentSession{}, "", application.ErrInvalidCoordination
	}
	actorID, err := domain.NewActorID()
	if err != nil {
		return application.LocalAgentSession{}, "", err
	}
	sessionID, err := domain.NewActorSessionID()
	if err != nil {
		return application.LocalAgentSession{}, "", err
	}
	workspaceID, err := domain.NewWorkspaceID()
	if err != nil {
		return application.LocalAgentSession{}, "", err
	}
	runID, err := domain.NewRunID()
	if err != nil {
		return application.LocalAgentSession{}, "", err
	}
	authorityID, err := domain.NewAuthorityID()
	if err != nil {
		return application.LocalAgentSession{}, "", err
	}
	epoch, err := domain.ParseAuthorityEpoch(authorityID.String())
	if err != nil {
		return application.LocalAgentSession{}, "", err
	}
	issuedToken := ""
	var result application.LocalAgentSession
	err = store.withImmediate(ctx, func(tx *sql.Tx) error {
		now, nowErr := sqliteNow(ctx, tx)
		if nowErr != nil {
			return nowErr
		}
		var workspaceText, runText, authorityText, epochText string
		projectErr := tx.QueryRowContext(ctx, `SELECT workspace_id, run_id, authority_id, authority_epoch
			FROM coordination_projects WHERE project_key = ?`, projectKey).Scan(&workspaceText, &runText, &authorityText, &epochText)
		if errors.Is(projectErr, sql.ErrNoRows) {
			workspaceText, runText, authorityText, epochText = workspaceID.String(), runID.String(), authorityID.String(), epoch.String()
			if _, insertErr := tx.ExecContext(ctx, `INSERT INTO coordination_projects(project_key, workspace_id, run_id,
				authority_id, authority_epoch, created_at_us) VALUES (?, ?, ?, ?, ?, ?)`, projectKey, workspaceText,
				runText, authorityText, epochText, timeMicros(now)); insertErr != nil {
				return fmt.Errorf("insert SQLite coordination project: %w", insertErr)
			}
			if _, insertErr := tx.ExecContext(ctx, `INSERT INTO scope_guards(scope_kind, scope_id, authority_id,
				authority_epoch, write_status, guard_generation, updated_at_us) VALUES ('workspace', ?, ?, ?, 'open', 1, ?)`,
				workspaceText, authorityText, epochText, timeMicros(now)); insertErr != nil {
				return fmt.Errorf("insert SQLite coordination authority: %w", insertErr)
			}
		} else if projectErr != nil {
			return projectErr
		}

		var actorText string
		var storedDigest []byte
		agentErr := tx.QueryRowContext(ctx, `SELECT actor_id, registration_token_digest FROM coordination_agents
			WHERE project_key = ? AND agent_name = ?`, projectKey, agentName).Scan(&actorText, &storedDigest)
		if errors.Is(agentErr, sql.ErrNoRows) {
			if registrationToken != "" {
				return coordinationError(domain.ErrorCodeUnauthenticated, "registration token is not valid")
			}
			issuedToken, err = newLocalCoordinationToken()
			if err != nil {
				return err
			}
			digest := sha256.Sum256([]byte(issuedToken))
			actorText = actorID.String()
			if _, insertErr := tx.ExecContext(ctx, `INSERT INTO coordination_agents(actor_id, project_key, agent_name,
				registration_token_digest, created_at_us) VALUES (?, ?, ?, ?, ?)`, actorText, projectKey, agentName,
				digest[:], timeMicros(now)); insertErr != nil {
				return fmt.Errorf("insert SQLite coordination agent: %w", insertErr)
			}
		} else if agentErr != nil {
			return agentErr
		} else {
			provided := sha256.Sum256([]byte(registrationToken))
			if registrationToken == "" || len(storedDigest) != sha256.Size || subtle.ConstantTimeCompare(provided[:], storedDigest) != 1 {
				return coordinationError(domain.ErrorCodeUnauthenticated, "registration token is not valid")
			}
		}
		if _, updateErr := tx.ExecContext(ctx, `UPDATE coordination_agent_sessions SET ended_at_us = ?
			WHERE actor_id = ? AND ended_at_us IS NULL`, timeMicros(now), actorText); updateErr != nil {
			return updateErr
		}
		if _, updateErr := tx.ExecContext(ctx, `UPDATE leases SET holder_session_id = ?
			WHERE holder_actor_id = ? AND workspace_id = ? AND status = 'active' AND expires_at_us > ?`,
			sessionID.String(), actorText, workspaceText, timeMicros(now)); updateErr != nil {
			return updateErr
		}
		if _, insertErr := tx.ExecContext(ctx, `INSERT INTO coordination_agent_sessions(session_id, actor_id,
			started_at_us, last_seen_at_us) VALUES (?, ?, ?, ?)`, sessionID.String(), actorText, timeMicros(now),
			timeMicros(now)); insertErr != nil {
			return fmt.Errorf("insert SQLite coordination session: %w", insertErr)
		}
		result, err = localAgentSession(projectKey, agentName, workspaceText, runText, actorText, sessionID.String(), epochText,
			timeMicros(now), timeMicros(now))
		return err
	})
	return result, issuedToken, err
}

func (store *Store) AuthenticateLocalAgent(ctx context.Context, token string) (application.LocalAgentSession, error) {
	if token == "" || len(token) > 256 {
		return application.LocalAgentSession{}, coordinationError(domain.ErrorCodeUnauthenticated, "agent token is not valid")
	}
	digest := sha256.Sum256([]byte(token))
	var result application.LocalAgentSession
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		var projectKey, agentName, workspaceText, runText, actorText, sessionText, epochText string
		var started, lastSeen int64
		err = tx.QueryRowContext(ctx, `SELECT project.project_key, agent.agent_name, project.workspace_id, project.run_id,
			agent.actor_id, session.session_id, project.authority_epoch, session.started_at_us, session.last_seen_at_us
			FROM coordination_agents AS agent JOIN coordination_projects AS project USING(project_key)
			JOIN coordination_agent_sessions AS session USING(actor_id)
			WHERE agent.registration_token_digest = ? AND session.ended_at_us IS NULL
			ORDER BY session.started_at_us DESC LIMIT 1`, digest[:]).Scan(&projectKey, &agentName, &workspaceText, &runText,
			&actorText, &sessionText, &epochText, &started, &lastSeen)
		if errors.Is(err, sql.ErrNoRows) {
			return coordinationError(domain.ErrorCodeUnauthenticated, "agent token is not valid")
		}
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE coordination_agent_sessions SET last_seen_at_us = ? WHERE session_id = ?`,
			timeMicros(now), sessionText); err != nil {
			return err
		}
		result, err = localAgentSession(projectKey, agentName, workspaceText, runText, actorText, sessionText, epochText,
			started, timeMicros(now))
		return err
	})
	return result, err
}

func (store *Store) ListActiveLocalAgents(ctx context.Context, session application.LocalAgentSession) ([]application.ActiveAgent, error) {
	if session.WorkspaceID.IsZero() || session.ProjectKey == "" {
		return nil, application.ErrInvalidCoordination
	}
	cutoff := time.Now().UTC().Add(-5 * time.Minute)
	rows, err := store.db.QueryContext(ctx, `SELECT agent.agent_name, agent.actor_id, session.session_id,
		session.started_at_us, session.last_seen_at_us FROM coordination_agents AS agent
		JOIN coordination_agent_sessions AS session USING(actor_id)
		WHERE agent.project_key = ? AND session.ended_at_us IS NULL AND session.last_seen_at_us >= ?
		ORDER BY agent.agent_name`, session.ProjectKey, timeMicros(cutoff))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var result []application.ActiveAgent
	for rows.Next() {
		var value application.ActiveAgent
		var actorText, sessionText string
		var started, seen int64
		if err := rows.Scan(&value.Name, &actorText, &sessionText, &started, &seen); err != nil {
			return nil, err
		}
		value.ActorID, err = domain.ParseActorID(actorText)
		if err != nil {
			return nil, err
		}
		value.SessionID, err = domain.ParseActorSessionID(sessionText)
		if err != nil {
			return nil, err
		}
		value.StartedAt, value.LastSeenAt = microsTime(started), microsTime(seen)
		result = append(result, value)
	}
	return result, rows.Err()
}

func (store *Store) ResolveLocalAgentNames(ctx context.Context, session application.LocalAgentSession, names []string) ([]domain.ActorID, error) {
	if session.ProjectKey == "" || len(names) == 0 || len(names) > application.MaxMessageRecipients {
		return nil, application.ErrInvalidCoordination
	}
	result := make([]domain.ActorID, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if !validLocalCoordinationText(name, application.MaxCoordinationNameBytes) {
			return nil, application.ErrInvalidCoordination
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, application.ErrInvalidCoordination
		}
		seen[name] = struct{}{}
		var actorText string
		if err := store.db.QueryRowContext(ctx, `SELECT actor_id FROM coordination_agents WHERE project_key = ? AND agent_name = ?`,
			session.ProjectKey, name).Scan(&actorText); errors.Is(err, sql.ErrNoRows) {
			return nil, coordinationError(domain.ErrorCodeNotFound, "agent was not found")
		} else if err != nil {
			return nil, err
		}
		actor, err := domain.ParseActorID(actorText)
		if err != nil {
			return nil, err
		}
		result = append(result, actor)
	}
	return result, nil
}

func validLocalCoordinationText(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func newLocalCoordinationToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "bbm_" + hex.EncodeToString(value[:]), nil
}

func localAgentSession(projectKey, agentName, workspaceText, runText, actorText, sessionText, epochText string,
	started, lastSeen int64) (application.LocalAgentSession, error) {
	workspace, e1 := domain.ParseWorkspaceID(workspaceText)
	run, e2 := domain.ParseRunID(runText)
	actor, e3 := domain.ParseActorID(actorText)
	session, e4 := domain.ParseActorSessionID(sessionText)
	epoch, e5 := domain.ParseAuthorityEpoch(epochText)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return application.LocalAgentSession{}, application.ErrInvalidCoordination
	}
	return application.LocalAgentSession{ProjectKey: projectKey, AgentName: agentName, WorkspaceID: workspace, RunID: run,
		ActorID: actor, ActorSessionID: session, AuthorityEpoch: epoch, StartedAt: microsTime(started),
		LastSeenAt: microsTime(lastSeen)}, nil
}

func coordinationError(code domain.ErrorCode, message string) error {
	result, _ := domain.NewCommandError(code, message, nil)
	return result
}
func coordinationConflict(code domain.ErrorCode, kind domain.ConflictKind, message string) error {
	result, _ := domain.NewConflictError(code, kind, message, nil)
	return result
}
