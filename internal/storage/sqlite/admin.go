package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const adminStorageBackend = "sqlite"

var _ application.LocalAdminStore = (*Store)(nil)

func (store *Store) CheckReadiness(ctx context.Context) (int, error) {
	var version int
	if err := store.db.QueryRowContext(ctx,
		`SELECT COALESCE(max(schema_version), 0) FROM schema_manifest`).Scan(&version); err != nil {
		return 0, fmt.Errorf("probe SQLite readiness: %w", err)
	}
	if version != SchemaVersion {
		return version, fmt.Errorf("%w: live schema version %d", ErrSchemaMismatch, version)
	}
	return version, nil
}

func (store *Store) AdminStorageIdentity(ctx context.Context) (application.AdminStorageIdentity, error) {
	identity := application.AdminStorageIdentity{StorageBackend: adminStorageBackend, DatabasePath: store.path}
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, _ time.Time) error {
		return tx.QueryRowContext(ctx,
			`SELECT COALESCE(max(schema_version), 0) FROM schema_manifest`).Scan(&identity.SchemaVersion)
	})
	if err != nil {
		return application.AdminStorageIdentity{}, err
	}
	identity.ObservedAtUS = observed
	return identity, nil
}

func (store *Store) AdminOverview(ctx context.Context) (application.AdminOverview, error) {
	var overview application.AdminOverview
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, now time.Time) error {
		cutoff := timeMicros(now.Add(-application.LocalAgentActiveWindow))
		nowMicros := timeMicros(now)
		return tx.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM coordination_projects),
			(SELECT count(*) FROM coordination_agents),
			(SELECT count(DISTINCT actor_id) FROM coordination_agent_sessions
			   WHERE ended_at_us IS NULL AND last_seen_at_us >= ?),
			(SELECT count(*) FROM conversations),
			(SELECT count(*) FROM messages),
			(SELECT count(*) FROM message_deliveries),
			(SELECT count(*) FROM message_deliveries WHERE read_at_us IS NULL),
			(SELECT count(*) FROM message_deliveries
			   WHERE acknowledgement_required = 1 AND acknowledged_at_us IS NULL),
			(SELECT count(*) FROM leases AS l WHERE 1 = 1`+adminReservationActive+`),
			(SELECT count(*) FROM leases AS l WHERE 1 = 1`+adminReservationExpired+`),
			(SELECT count(*) FROM coordination_events)`, cutoff, nowMicros, nowMicros).Scan(
			&overview.Projects, &overview.Agents, &overview.ActiveAgents, &overview.Conversations,
			&overview.Messages, &overview.Deliveries, &overview.UnreadDeliveries, &overview.UnackedDeliveries,
			&overview.ActiveReservations, &overview.ExpiredReservations, &overview.CoordinationEvents)
	})
	if err != nil {
		return application.AdminOverview{}, fmt.Errorf("query SQLite admin overview: %w", err)
	}
	overview.ObservedAtUS = observed
	return overview, nil
}

func (store *Store) ListAdminProjects(ctx context.Context) (application.AdminProjectsPage, error) {
	var projects []application.AdminProject
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, now time.Time) error {
		rows, err := tx.QueryContext(ctx, `SELECT p.project_key, p.workspace_id, p.run_id, p.created_at_us,
			(SELECT count(*) FROM coordination_agents AS a WHERE a.project_key = p.project_key),
			(SELECT count(DISTINCT s.actor_id) FROM coordination_agent_sessions AS s
			   JOIN coordination_agents AS a ON a.actor_id = s.actor_id
			  WHERE a.project_key = p.project_key AND s.ended_at_us IS NULL AND s.last_seen_at_us >= ?),
			(SELECT count(*) FROM conversations AS c WHERE c.workspace_id = p.workspace_id),
			COALESCE((SELECT max(e.occurred_at_us) FROM coordination_events AS e
			   WHERE e.workspace_id = p.workspace_id), 0)
			FROM coordination_projects AS p ORDER BY p.project_key`,
			timeMicros(now.Add(-application.LocalAgentActiveWindow)))
		if err != nil {
			return fmt.Errorf("query SQLite admin projects: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var project application.AdminProject
			var workspaceText, runText string
			if err := rows.Scan(&project.ProjectKey, &workspaceText, &runText, &project.CreatedAtUS,
				&project.Agents, &project.ActiveAgents, &project.Conversations, &project.LastEventAtUS); err != nil {
				return fmt.Errorf("scan SQLite admin project: %w", err)
			}
			workspace, workspaceErr := domain.ParseWorkspaceID(workspaceText)
			run, runErr := domain.ParseRunID(runText)
			if workspaceErr != nil || runErr != nil {
				return application.ErrInvalidCoordination
			}
			project.WorkspaceID, project.RunID = workspace, run
			projects = append(projects, project)
		}
		return rows.Err()
	})
	if err != nil {
		return application.AdminProjectsPage{}, err
	}
	return application.AdminProjectsPage{Projects: projects, ObservedAtUS: observed}, nil
}

func (store *Store) ListAdminAgents(ctx context.Context,
	query application.AdminAgentsQuery) (application.AdminAgentsPage, error) {
	limit, err := adminFilters(query.ProjectKey, query.AgentName, query.Limit)
	if err != nil {
		return application.AdminAgentsPage{}, err
	}
	var agents []application.AdminAgent
	truncated := false
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, now time.Time) error {
		agents, truncated, err = adminAgentRows(ctx, tx, query, limit, now)
		return err
	})
	if err != nil {
		return application.AdminAgentsPage{}, err
	}
	return application.AdminAgentsPage{Agents: agents, Truncated: truncated, ObservedAtUS: observed}, nil
}

// Liveness is derived from the store's own clock inside the snapshot
// transaction and pushed into the WHERE clause for the same reason lease expiry
// is: an active-only page filtered in Go after LIMIT comes back empty whenever
// the head of the result set is offline.
func adminAgentRows(ctx context.Context, tx *sql.Tx, query application.AdminAgentsQuery, limit uint16,
	now time.Time) ([]application.AdminAgent, bool, error) {
	cutoff := timeMicros(now.Add(-application.LocalAgentActiveWindow))
	statement := `SELECT a.project_key, a.agent_name, a.actor_id, a.created_at_us,
		COALESCE(s.session_id, ''), COALESCE(s.started_at_us, 0), COALESCE(s.last_seen_at_us, 0),
		(SELECT count(*) FROM message_deliveries AS d
		  WHERE d.recipient_actor_id = a.actor_id AND d.read_at_us IS NULL),
		(SELECT count(*) FROM message_deliveries AS d
		  WHERE d.recipient_actor_id = a.actor_id AND d.acknowledgement_required = 1
		    AND d.acknowledged_at_us IS NULL),
		(SELECT count(*) FROM leases AS l
		  WHERE l.holder_actor_id = a.actor_id AND l.status = 'active' AND l.expires_at_us > ?)
		FROM coordination_agents AS a
		LEFT JOIN coordination_agent_sessions AS s ON s.session_id =
		  (SELECT s2.session_id FROM coordination_agent_sessions AS s2
		    WHERE s2.actor_id = a.actor_id AND s2.ended_at_us IS NULL
		    ORDER BY s2.started_at_us DESC LIMIT 1)
		WHERE (? = '' OR a.project_key = ?) AND (? = '' OR a.agent_name = ?)`
	arguments := []any{timeMicros(now), query.ProjectKey, query.ProjectKey, query.AgentName, query.AgentName}
	if query.ActiveOnly {
		statement += ` AND s.session_id IS NOT NULL AND s.last_seen_at_us >= ?`
		arguments = append(arguments, cutoff)
	}
	statement += ` ORDER BY a.project_key, a.agent_name LIMIT ?`
	arguments = append(arguments, int(limit)+1)
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("query SQLite admin agents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var agents []application.AdminAgent
	truncated := false
	for rows.Next() {
		var agent application.AdminAgent
		var actorText, sessionText string
		if err := rows.Scan(&agent.ProjectKey, &agent.AgentName, &actorText, &agent.CreatedAtUS,
			&sessionText, &agent.StartedAtUS, &agent.LastSeenAtUS, &agent.UnreadDeliveries,
			&agent.UnackedDeliveries, &agent.ActiveLeases); err != nil {
			return nil, false, fmt.Errorf("scan SQLite admin agent: %w", err)
		}
		if len(agents) == int(limit) {
			truncated = true
			break
		}
		actor, actorErr := domain.ParseActorID(actorText)
		if actorErr != nil {
			return nil, false, application.ErrInvalidCoordination
		}
		agent.ActorID = actor
		if sessionText != "" {
			session, sessionErr := domain.ParseActorSessionID(sessionText)
			if sessionErr != nil {
				return nil, false, application.ErrInvalidCoordination
			}
			agent.SessionID = session
			agent.Active = agent.LastSeenAtUS >= cutoff
		}
		agents = append(agents, agent)
	}
	return agents, truncated, rows.Err()
}

func (store *Store) AdminInbox(ctx context.Context,
	query application.AdminInboxQuery) (application.AdminInboxPage, error) {
	limit, err := adminFilters(query.ProjectKey, query.AgentName, query.Limit)
	if err != nil {
		return application.AdminInboxPage{}, err
	}
	if query.ProjectKey == "" {
		return application.AdminInboxPage{}, application.ErrInvalidCoordination
	}
	page := application.AdminInboxPage{ProjectKey: query.ProjectKey}
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, _ time.Time) error {
		summaries, err := adminInboxSummaries(ctx, tx, query)
		if err != nil {
			return err
		}
		page.Summaries = summaries
		pending, truncated, err := adminInboxPending(ctx, tx, query, limit)
		if err != nil {
			return err
		}
		page.Pending, page.Truncated = pending, truncated
		return nil
	})
	if err != nil {
		return application.AdminInboxPage{}, err
	}
	page.ObservedAtUS = observed
	return page, nil
}

// The delivery counts must aggregate d.message_id rather than the row: this is a
// LEFT JOIN, and count(*) FILTER (WHERE d.read_at_us IS NULL) also counts the
// NULL-padded row, reporting one unread delivery for every agent with no mail.
func adminInboxSummaries(ctx context.Context, tx *sql.Tx,
	query application.AdminInboxQuery) ([]application.AdminInboxSummary, error) {
	rows, err := tx.QueryContext(ctx, `SELECT a.agent_name, a.actor_id,
		count(d.message_id) FILTER (WHERE d.read_at_us IS NULL),
		count(d.message_id) FILTER (WHERE d.acknowledgement_required = 1 AND d.acknowledged_at_us IS NULL),
		COALESCE(min(CASE WHEN d.read_at_us IS NULL THEN m.sent_at_us END), 0)
		FROM coordination_agents AS a
		LEFT JOIN message_deliveries AS d ON d.recipient_actor_id = a.actor_id
		LEFT JOIN messages AS m ON m.message_id = d.message_id
		WHERE a.project_key = ? AND (? = '' OR a.agent_name = ?)
		GROUP BY a.actor_id, a.agent_name ORDER BY a.agent_name`,
		query.ProjectKey, query.AgentName, query.AgentName)
	if err != nil {
		return nil, fmt.Errorf("query SQLite admin inbox summaries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var summaries []application.AdminInboxSummary
	for rows.Next() {
		summary := application.AdminInboxSummary{ProjectKey: query.ProjectKey}
		var actorText string
		if err := rows.Scan(&summary.AgentName, &actorText, &summary.UnreadDeliveries,
			&summary.UnackedDeliveries, &summary.OldestUnreadAtUS); err != nil {
			return nil, fmt.Errorf("scan SQLite admin inbox summary: %w", err)
		}
		actor, actorErr := domain.ParseActorID(actorText)
		if actorErr != nil {
			return nil, application.ErrInvalidCoordination
		}
		summary.ActorID = actor
		summaries = append(summaries, summary)
	}
	return summaries, rows.Err()
}

// The unread and unacknowledged predicates narrow the pending set in SQL: the
// newest deliveries are the ones most likely to be read already, so filtering
// after LIMIT renders an empty inbox while dozens of matches sit behind it.
func adminInboxPending(ctx context.Context, tx *sql.Tx, query application.AdminInboxQuery,
	limit uint16) ([]application.AdminInboxItem, bool, error) {
	statement := `SELECT m.message_id, m.conversation_id, a.agent_name, a.actor_id,
		COALESCE(author.agent_name, ''), m.author_actor_id, m.subject, d.recipient_kind,
		d.read_at_us IS NOT NULL, d.acknowledged_at_us IS NOT NULL, d.acknowledgement_required, m.sent_at_us
		FROM message_deliveries AS d
		JOIN messages AS m ON m.message_id = d.message_id
		JOIN coordination_agents AS a ON a.actor_id = d.recipient_actor_id
		LEFT JOIN coordination_agents AS author ON author.actor_id = m.author_actor_id
		WHERE a.project_key = ? AND (? = '' OR a.agent_name = ?)
		  AND (d.read_at_us IS NULL OR (d.acknowledgement_required = 1 AND d.acknowledged_at_us IS NULL))`
	arguments := []any{query.ProjectKey, query.AgentName, query.AgentName}
	if query.UnreadOnly {
		statement += ` AND d.read_at_us IS NULL`
	}
	if query.UnackedOnly {
		statement += ` AND d.acknowledgement_required = 1 AND d.acknowledged_at_us IS NULL`
	}
	statement += ` ORDER BY m.sent_at_us DESC, m.position DESC LIMIT ?`
	arguments = append(arguments, int(limit)+1)
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("query SQLite admin inbox: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var items []application.AdminInboxItem
	truncated := false
	for rows.Next() {
		item := application.AdminInboxItem{ProjectKey: query.ProjectKey}
		var messageText, conversationText, recipientText, authorText, kindText string
		if err := rows.Scan(&messageText, &conversationText, &item.RecipientAgentName, &recipientText,
			&item.AuthorAgentName, &authorText, &item.Subject, &kindText, &item.Read, &item.Acknowledged,
			&item.AcknowledgementRequired, &item.SentAtUS); err != nil {
			return nil, false, fmt.Errorf("scan SQLite admin inbox item: %w", err)
		}
		if len(items) == int(limit) {
			truncated = true
			break
		}
		message, messageErr := domain.ParseMessageID(messageText)
		conversation, conversationErr := domain.ParseConversationID(conversationText)
		recipient, recipientErr := domain.ParseActorID(recipientText)
		author, authorErr := domain.ParseActorID(authorText)
		if messageErr != nil || conversationErr != nil || recipientErr != nil || authorErr != nil {
			return nil, false, application.ErrInvalidCoordination
		}
		item.MessageID, item.ConversationID = message, conversation
		item.RecipientActorID, item.AuthorActorID = recipient, author
		item.Kind = application.RecipientKind(kindText)
		items = append(items, item)
	}
	return items, truncated, rows.Err()
}

func (store *Store) ListAdminConversations(ctx context.Context,
	query application.AdminConversationsQuery) (application.AdminConversationsPage, error) {
	limit, err := adminFilters(query.ProjectKey, "", query.Limit)
	if err != nil {
		return application.AdminConversationsPage{}, err
	}
	var conversations []application.AdminConversation
	truncated := false
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, _ time.Time) error {
		conversations, truncated, err = adminConversationRows(ctx, tx, query, limit)
		if err != nil {
			return err
		}
		return adminConversationDetails(ctx, tx, conversations)
	})
	if err != nil {
		return application.AdminConversationsPage{}, err
	}
	return application.AdminConversationsPage{Conversations: conversations, Truncated: truncated,
		ObservedAtUS: observed}, nil
}

func adminConversationRows(ctx context.Context, tx *sql.Tx, query application.AdminConversationsQuery,
	limit uint16) ([]application.AdminConversation, bool, error) {
	conversationFilter := ""
	if !query.ConversationID.IsZero() {
		conversationFilter = query.ConversationID.String()
	}
	statement := `SELECT c.conversation_id, c.workspace_id, COALESCE(p.project_key, ''),
		c.topic, c.status, COALESCE(o.agent_name, ''), c.opened_by_actor_id, c.opened_at_us,
		(SELECT count(*) FROM messages AS m WHERE m.conversation_id = c.conversation_id),
		(SELECT count(*) FROM message_deliveries AS d JOIN messages AS m ON m.message_id = d.message_id
		  WHERE m.conversation_id = c.conversation_id AND d.read_at_us IS NULL)
		FROM conversations AS c
		LEFT JOIN coordination_projects AS p ON p.workspace_id = c.workspace_id
		LEFT JOIN coordination_agents AS o ON o.actor_id = c.opened_by_actor_id
		WHERE (? = '' OR p.project_key = ?) AND (? = '' OR c.conversation_id = ?)`
	arguments := []any{query.ProjectKey, query.ProjectKey, conversationFilter, conversationFilter}
	if query.OpenOnly {
		statement += ` AND c.status = ?`
		arguments = append(arguments, string(application.AdminConversationOpen))
	}
	statement += ` ORDER BY c.opened_at_us DESC, c.conversation_id LIMIT ?`
	arguments = append(arguments, int(limit)+1)
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("query SQLite admin conversations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var conversations []application.AdminConversation
	truncated := false
	for rows.Next() {
		var conversation application.AdminConversation
		var conversationText, workspaceText, statusText, openedByText string
		if err := rows.Scan(&conversationText, &workspaceText, &conversation.ProjectKey, &conversation.Topic,
			&statusText, &conversation.OpenedByAgentName, &openedByText, &conversation.OpenedAtUS,
			&conversation.Messages, &conversation.UnreadDeliveries); err != nil {
			return nil, false, fmt.Errorf("scan SQLite admin conversation: %w", err)
		}
		if len(conversations) == int(limit) {
			truncated = true
			break
		}
		id, idErr := domain.ParseConversationID(conversationText)
		workspace, workspaceErr := domain.ParseWorkspaceID(workspaceText)
		openedBy, openedByErr := domain.ParseActorID(openedByText)
		if idErr != nil || workspaceErr != nil || openedByErr != nil {
			return nil, false, application.ErrInvalidCoordination
		}
		conversation.ConversationID, conversation.WorkspaceID = id, workspace
		conversation.OpenedByActorID = openedBy
		conversation.Status = application.AdminConversationStatus(statusText)
		conversations = append(conversations, conversation)
	}
	return conversations, truncated, rows.Err()
}

func adminConversationDetails(ctx context.Context, tx *sql.Tx, conversations []application.AdminConversation) error {
	if len(conversations) == 0 {
		return nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(conversations)), ",")
	arguments := make([]any, 0, len(conversations))
	index := make(map[string]int, len(conversations))
	for position, conversation := range conversations {
		arguments = append(arguments, conversation.ConversationID.String())
		index[conversation.ConversationID.String()] = position
	}
	participants, err := tx.QueryContext(ctx, `SELECT conversation_id, count(*) FROM (
		SELECT m.conversation_id AS conversation_id, m.author_actor_id AS actor FROM messages AS m
		 WHERE m.conversation_id IN (`+placeholders+`)
		UNION
		SELECT m.conversation_id, d.recipient_actor_id FROM message_deliveries AS d
		 JOIN messages AS m ON m.message_id = d.message_id
		 WHERE m.conversation_id IN (`+placeholders+`)) GROUP BY conversation_id`,
		append(append([]any(nil), arguments...), arguments...)...)
	if err != nil {
		return fmt.Errorf("query SQLite admin conversation participants: %w", err)
	}
	defer func() { _ = participants.Close() }()
	for participants.Next() {
		var conversationText string
		var count int
		if err := participants.Scan(&conversationText, &count); err != nil {
			return fmt.Errorf("scan SQLite admin conversation participants: %w", err)
		}
		if position, ok := index[conversationText]; ok {
			conversations[position].Participants = count
		}
	}
	if err := participants.Err(); err != nil {
		return err
	}
	if err := participants.Close(); err != nil {
		return err
	}
	return adminConversationLastMessage(ctx, tx, conversations, placeholders, arguments, index)
}

func adminConversationLastMessage(ctx context.Context, tx *sql.Tx, conversations []application.AdminConversation,
	placeholders string, arguments []any, index map[string]int) error {
	rows, err := tx.QueryContext(ctx, `SELECT m.conversation_id, m.sent_at_us, COALESCE(a.agent_name, ''), m.subject
		FROM messages AS m LEFT JOIN coordination_agents AS a ON a.actor_id = m.author_actor_id
		WHERE m.conversation_id IN (`+placeholders+`) AND m.position =
		  (SELECT max(latest.position) FROM messages AS latest WHERE latest.conversation_id = m.conversation_id)`,
		arguments...)
	if err != nil {
		return fmt.Errorf("query SQLite admin conversation tail: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var conversationText, author, subject string
		var sent int64
		if err := rows.Scan(&conversationText, &sent, &author, &subject); err != nil {
			return fmt.Errorf("scan SQLite admin conversation tail: %w", err)
		}
		if position, ok := index[conversationText]; ok {
			conversations[position].LastMessageAtUS = sent
			conversations[position].LastMessageAuthor = author
			conversations[position].LastMessageSubject = subject
		}
	}
	return rows.Err()
}

func (store *Store) ListAdminReservations(ctx context.Context,
	query application.AdminReservationsQuery) (application.AdminReservationsPage, error) {
	limit, err := adminFilters(query.ProjectKey, query.AgentName, query.Limit)
	if err != nil {
		return application.AdminReservationsPage{}, err
	}
	state := query.State.Normalized()
	if !state.Valid() || !application.ValidAdminReservationMode(query.Mode) {
		return application.AdminReservationsPage{}, application.ErrInvalidCoordination
	}
	if query.Path != "" && !validLocalCoordinationText(query.Path, application.MaxLeaseSelectorBytes) {
		return application.AdminReservationsPage{}, application.ErrInvalidCoordination
	}
	return store.reservationsPage(ctx, query, state, limit, reservationScope{})
}

// ForceReleaseAdminReservation is the operator escape hatch for a live lease
// whose holder disappeared with its session credentials. The admin token is
// the authorization boundary, so this deliberately bypasses holder and fence
// checks while retaining the normal release row and journal fact.
func (store *Store) ForceReleaseAdminReservation(ctx context.Context,
	leaseID domain.LeaseID) (application.Lease, error) {
	if leaseID.IsZero() {
		return application.Lease{}, application.ErrInvalidCoordination
	}
	var result application.Lease
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		lease, err := loadLease(ctx, tx, leaseID)
		if err != nil {
			return err
		}
		if _, released := lease.ReleasedAt(); released {
			result = lease
			return nil
		}
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		changed, err := tx.ExecContext(ctx, `UPDATE leases SET status = 'released', released_at_us = ?
			WHERE lease_id = ? AND status = 'active'`, timeMicros(now), leaseID.String())
		if err != nil {
			return fmt.Errorf("force release SQLite lease: %w", err)
		}
		if rows, err := changed.RowsAffected(); err != nil || rows != 1 {
			if err != nil {
				return fmt.Errorf("count force released SQLite leases: %w", err)
			}
			return application.ErrInvalidCoordination
		}
		result, err = loadLease(ctx, tx, leaseID)
		if err != nil {
			return err
		}
		fields := leaseCoordinationFields(result)
		fields["forced"] = true
		payload, err := coordinationPayload(fields)
		if err != nil {
			return err
		}
		return appendCoordinationEvent(ctx, tx, result.WorkspaceID(), result.Holder(),
			application.CoordinationEventLeaseReleased, result.ID().String(), now, payload,
			coordinationVisibilityWorkspace, nil)
	})
	return result, err
}

// LocalAgentReservations is the same read scoped to one agent's own workspace.
// An agent refused a lease used to be told only that it lost; who holds the
// path, in what mode, and for how much longer was reachable exclusively from
// the operator's loopback CLI, which is not a surface the blocked agent has.
//
// The caller's project key and workspace both replace whatever the query
// carried, so this cannot read across workspaces no matter what a transport
// forwards, and the workspace predicate is applied to the lease row itself
// rather than to the project it joins -- a lease whose project row is missing
// must not fall out of a scoped read as if it were unscoped.
func (store *Store) LocalAgentReservations(ctx context.Context, session application.LocalAgentSession,
	query application.AdminReservationsQuery) (application.AdminReservationsPage, error) {
	if session.ProjectKey == "" || session.WorkspaceID.IsZero() || session.ActorID.IsZero() {
		return application.AdminReservationsPage{}, application.ErrInvalidCoordination
	}
	query.ProjectKey = session.ProjectKey
	limit, err := adminFilters(query.ProjectKey, query.AgentName, query.Limit)
	if err != nil {
		return application.AdminReservationsPage{}, err
	}
	state := query.State.Normalized()
	if !state.Valid() || !application.ValidAdminReservationMode(query.Mode) {
		return application.AdminReservationsPage{}, application.ErrInvalidCoordination
	}
	if query.Path != "" && !validLocalCoordinationText(query.Path, application.MaxLeaseSelectorBytes) {
		return application.AdminReservationsPage{}, application.ErrInvalidCoordination
	}
	return store.reservationsPage(ctx, query, state, limit,
		reservationScope{workspaceID: session.WorkspaceID.String()})
}

// reservationsPage is the one body behind both surfaces, so the boundary-correct
// path matching and the server-computed ExpiresInMS cannot drift between the
// operator's answer and the agent's.
// reservationScope is the part of a reservation read that no caller supplies:
// the workspace the answer is confined to, and the holder whose own leases are
// not blockers. Both are predicates rather than post-LIMIT filters, because a
// page filtered after the fact comes back empty whenever the head of the
// unfiltered result set is the wrong row.
type reservationScope struct {
	workspaceID   string
	excludeHolder string
}

func (store *Store) reservationsPage(ctx context.Context, query application.AdminReservationsQuery,
	state application.AdminReservationState, limit uint16,
	scope reservationScope) (application.AdminReservationsPage, error) {
	var reservations []application.AdminReservation
	truncated := false
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, now time.Time) error {
		var rowErr error
		reservations, truncated, rowErr = adminReservationRows(ctx, tx, query, state, limit, timeMicros(now), scope)
		if rowErr != nil {
			return rowErr
		}
		for position := range reservations {
			selectors, selectorErr := adminLeaseSelectors(ctx, tx, reservations[position].LeaseID)
			if selectorErr != nil {
				return selectorErr
			}
			reservations[position].Selectors = selectors
		}
		return nil
	})
	if err != nil {
		return application.AdminReservationsPage{}, err
	}
	return application.AdminReservationsPage{Reservations: reservations, Truncated: truncated,
		ObservedAtUS: observed}, nil
}

// A path predicate matches on separator boundaries in both directions, so a
// query on "a/f" covers "a/f" and "a/f/g" but never the sibling "a/foo". LIKE
// is unusable for it: a selector path may legitimately contain % or _, and the
// escaping that would fix that is a second place for the boundary rule to rot.
// A reservation's bucket is a fact about the lease, not about whether the
// expiry reaper has visited it yet. AcquireLease retires expired leases in its
// workspace and epoch to 'released', so a lease nobody released changes rows
// the moment some unrelated agent acquires one — and classifying on status
// alone would move it from "expired" to "released" for that reason, hiding the
// abandoned reservations an operator is looking for and inflating the released
// count with corpses.
//
// The timestamps separate the two, and they are the only thing that does: an
// explicit release is stamped strictly before the deadline, because changeLease
// refuses one after it, while the reaper stamps at or after the deadline by
// construction. The three predicates below are therefore disjoint and total
// over every lease row, and each is stable across a reap.
const (
	adminReservationActive   = ` AND l.status = 'active' AND l.expires_at_us > ?`
	adminReservationExpired  = ` AND ((l.status = 'active' AND l.expires_at_us <= ?) OR (l.status = 'released' AND l.released_at_us >= l.expires_at_us))`
	adminReservationReleased = ` AND l.status = 'released' AND l.released_at_us < l.expires_at_us`
)

const adminSelectorCoversPath = ` AND EXISTS (SELECT 1 FROM lease_selectors AS sel
	WHERE sel.lease_id = l.lease_id AND (sel.selector_path = ?
	  OR substr(?, 1, length(sel.selector_path) + 1) = sel.selector_path || '/'
	  OR substr(sel.selector_path, 1, length(?) + 1) = ? || '/'))`

// Expiry is derived from the store's own clock inside the snapshot transaction
// and pushed into the WHERE clause: filtering in Go after LIMIT would silently
// return an empty page whenever the head of the result set is the wrong state.
func adminReservationRows(ctx context.Context, tx *sql.Tx, query application.AdminReservationsQuery,
	state application.AdminReservationState, limit uint16, nowMicros int64,
	scope reservationScope) ([]application.AdminReservation, bool, error) {
	statement := `SELECT l.lease_id, COALESCE(p.project_key, ''), l.workspace_id, COALESCE(a.agent_name, ''),
		l.holder_actor_id, l.holder_session_id, l.mode, l.status, l.acquired_at_us, l.expires_at_us,
		COALESCE(l.released_at_us, 0)
		FROM leases AS l
		LEFT JOIN coordination_projects AS p ON p.workspace_id = l.workspace_id
		LEFT JOIN coordination_agents AS a ON a.actor_id = l.holder_actor_id
		WHERE (? = '' OR p.project_key = ?) AND (? = '' OR a.agent_name = ?)`
	arguments := []any{query.ProjectKey, query.ProjectKey, query.AgentName, query.AgentName}
	if scope.workspaceID != "" {
		statement += ` AND l.workspace_id = ?`
		arguments = append(arguments, scope.workspaceID)
	}
	if scope.excludeHolder != "" {
		statement += ` AND l.holder_actor_id <> ?`
		arguments = append(arguments, scope.excludeHolder)
	}
	switch state {
	case application.AdminReservationActive:
		statement += adminReservationActive
		arguments = append(arguments, nowMicros)
	case application.AdminReservationExpired:
		statement += adminReservationExpired
		arguments = append(arguments, nowMicros)
	case application.AdminReservationReleased:
		statement += adminReservationReleased
	case application.AdminReservationAll:
	}
	if query.Mode != "" {
		statement += ` AND l.mode = ?`
		arguments = append(arguments, string(query.Mode))
	}
	if query.Path != "" {
		statement += adminSelectorCoversPath
		arguments = append(arguments, query.Path, query.Path, query.Path, query.Path)
	}
	statement += ` ORDER BY l.expires_at_us DESC, l.lease_id LIMIT ?`
	arguments = append(arguments, int(limit)+1)
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("query SQLite admin reservations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var reservations []application.AdminReservation
	truncated := false
	for rows.Next() {
		var reservation application.AdminReservation
		var leaseText, workspaceText, holderText, sessionText, modeText, statusText string
		if err := rows.Scan(&leaseText, &reservation.ProjectKey, &workspaceText, &reservation.HolderAgentName,
			&holderText, &sessionText, &modeText, &statusText, &reservation.AcquiredAtUS,
			&reservation.ExpiresAtUS, &reservation.ReleasedAtUS); err != nil {
			return nil, false, fmt.Errorf("scan SQLite admin reservation: %w", err)
		}
		if len(reservations) == int(limit) {
			truncated = true
			break
		}
		lease, leaseErr := domain.ParseLeaseID(leaseText)
		workspace, workspaceErr := domain.ParseWorkspaceID(workspaceText)
		holder, holderErr := domain.ParseActorID(holderText)
		session, sessionErr := domain.ParseActorSessionID(sessionText)
		if leaseErr != nil || workspaceErr != nil || holderErr != nil || sessionErr != nil {
			return nil, false, application.ErrInvalidCoordination
		}
		reservation.LeaseID, reservation.WorkspaceID = lease, workspace
		reservation.HolderActorID, reservation.HolderSessionID = holder, session
		reservation.Mode = application.LeaseMode(modeText)
		reservation.State = adminReservationState(statusText, reservation.ExpiresAtUS, nowMicros)
		reservation.Expired = reservation.State == application.AdminReservationExpired
		reservation.ExpiresInMS = (reservation.ExpiresAtUS - nowMicros) / 1000
		reservations = append(reservations, reservation)
	}
	return reservations, truncated, rows.Err()
}

func adminReservationState(status string, expiresAtUS, nowMicros int64) application.AdminReservationState {
	switch {
	case status == "released":
		return application.AdminReservationReleased
	case expiresAtUS > nowMicros:
		return application.AdminReservationActive
	default:
		return application.AdminReservationExpired
	}
}

func adminLeaseSelectors(ctx context.Context, tx *sql.Tx, lease domain.LeaseID) ([]application.LeaseSelector, error) {
	rows, err := tx.QueryContext(ctx, `SELECT selector_kind, selector_path FROM lease_selectors
		WHERE lease_id = ? ORDER BY selector_ordinal`, lease.String())
	if err != nil {
		return nil, fmt.Errorf("query SQLite admin lease selectors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var selectors []application.LeaseSelector
	for rows.Next() {
		var kind, value string
		if err := rows.Scan(&kind, &value); err != nil {
			return nil, fmt.Errorf("scan SQLite admin lease selector: %w", err)
		}
		selector, selectorErr := application.NewLeaseSelector(application.LeaseSelectorKind(kind), value)
		if selectorErr != nil {
			return nil, selectorErr
		}
		selectors = append(selectors, selector)
	}
	return selectors, rows.Err()
}

func (store *Store) ListAdminEvents(ctx context.Context,
	query application.AdminEventsQuery) (application.AdminEventsPage, error) {
	limit, err := adminFilters(query.ProjectKey, query.AgentName, query.Limit)
	if err != nil {
		return application.AdminEventsPage{}, err
	}
	if query.EventType != "" && !query.EventType.Valid() {
		return application.AdminEventsPage{}, application.ErrInvalidCoordination
	}
	var events []application.AdminEvent
	truncated := false
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, _ time.Time) error {
		rows, queryErr := tx.QueryContext(ctx, `SELECT e.position, COALESCE(p.project_key, ''), e.workspace_id,
			COALESCE(a.agent_name, ''), e.actor_id, e.event_type, e.subject_id, e.occurred_at_us, e.payload
			FROM coordination_events AS e
			LEFT JOIN coordination_projects AS p ON p.workspace_id = e.workspace_id
			LEFT JOIN coordination_agents AS a ON a.actor_id = e.actor_id
			WHERE (? = '' OR p.project_key = ?) AND (? = '' OR a.agent_name = ?) AND (? = '' OR e.event_type = ?)
			ORDER BY e.position DESC LIMIT ?`, query.ProjectKey, query.ProjectKey, query.AgentName,
			query.AgentName, string(query.EventType), string(query.EventType), int(limit)+1)
		if queryErr != nil {
			return fmt.Errorf("query SQLite admin events: %w", queryErr)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var event application.AdminEvent
			var workspaceText, actorText, typeText string
			if err := rows.Scan(&event.Position, &event.ProjectKey, &workspaceText, &event.AgentName,
				&actorText, &typeText, &event.SubjectID, &event.OccurredAtUS, &event.Payload); err != nil {
				return fmt.Errorf("scan SQLite admin event: %w", err)
			}
			if len(events) == int(limit) {
				truncated = true
				break
			}
			workspace, workspaceErr := domain.ParseWorkspaceID(workspaceText)
			actor, actorErr := domain.ParseActorID(actorText)
			if workspaceErr != nil || actorErr != nil {
				return application.ErrInvalidCoordination
			}
			event.WorkspaceID, event.ActorID = workspace, actor
			event.EventType = application.CoordinationEventType(typeText)
			events = append(events, event)
		}
		return rows.Err()
	})
	if err != nil {
		return application.AdminEventsPage{}, err
	}
	return application.AdminEventsPage{Events: events, Truncated: truncated, ObservedAtUS: observed}, nil
}

func (store *Store) adminSnapshot(ctx context.Context, snapshot func(*sql.Tx, time.Time) error) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, fmt.Errorf("begin SQLite admin snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now, err := sqliteNow(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("read SQLite admin clock: %w", err)
	}
	if err := snapshot(tx, now); err != nil {
		return 0, err
	}
	return timeMicros(now), nil
}

func adminFilters(projectKey, agentName string, limit uint16) (uint16, error) {
	if projectKey != "" && !validLocalCoordinationText(projectKey, application.MaxCoordinationKeyBytes) {
		return 0, application.ErrInvalidCoordination
	}
	if agentName != "" && !validLocalCoordinationText(agentName, application.MaxCoordinationNameBytes) {
		return 0, application.ErrInvalidCoordination
	}
	return application.AdminPageLimit(limit)
}
