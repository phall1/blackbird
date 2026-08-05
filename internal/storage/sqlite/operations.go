package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
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
