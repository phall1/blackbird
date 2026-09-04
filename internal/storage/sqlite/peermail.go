package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

// Cross-host mail, stored.
//
// The whole of it is ordinary coordination writes plus one queue. A message
// that crosses a host boundary is a row in `messages` with a delivery in
// `message_deliveries`, exactly like one that does not, and the only thing the
// three tables from migration 0013 add is: which conversation a remote thread
// key names here, what is still owed to the wire, and which inbound messages
// have already been accepted so a retry appends nothing.
//
// Nothing in this file reads or writes another machine. The peer is reached by
// the transport adapter the dispatcher holds; storage only records what it is
// told, which is why a peer being unreachable can never leave a partial write
// behind.

// peerMailRetention is how long a settled outbox entry is kept. It is swept
// inside the transaction that settles the next one, so the table is bounded by
// traffic rather than by a background job nobody composed. Long enough that an
// operator asking "did that get there" the next morning still has an answer;
// short enough that a host talking to a busy peer does not accumulate a year of
// receipts.
const peerMailRetention = 14 * 24 * time.Hour

// SendPeerMail appends the message and queues one entry per remote recipient in
// a single transaction.
//
// The ordering is the guarantee: the message is durable HERE before anything is
// attempted on the wire. So a peer that is down cannot fail a send, a crash
// mid-attempt loses nothing but an attempt, and the queue can never point at a
// message body that was never written.
func (store *Store) SendPeerMail(
	ctx context.Context,
	session coordination.LocalAgentSession,
	params coordination.SendPeerMailParams,
) (coordination.PeerMailSend, error) {
	if err := params.Validate(); err != nil {
		return coordination.PeerMailSend{}, err
	}
	if session.ProjectKey == "" || session.WorkspaceID.IsZero() || session.ActorID.IsZero() ||
		session.ActorSessionID.IsZero() {
		return coordination.PeerMailSend{}, coordination.ErrInvalid
	}
	peerProject := params.PeerProjectKey
	if peerProject == "" {
		// The sender's own project key is the default because the common fleet
		// is one person's machines with one checkout layout. It is put ON THE
		// WIRE rather than assumed by the receiver, so a host whose checkout
		// lives somewhere else refuses by name instead of resolving a recipient
		// in whichever project it happened to guess.
		peerProject = session.ProjectKey
	}
	var result coordination.PeerMailSend
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		recipients := make([]coordination.Recipient, 0, len(params.LocalRecipients)+len(params.PeerRecipients))
		for _, name := range params.LocalRecipients {
			actor, resolveErr := resolveAgentActor(ctx, tx, session.ProjectKey, name)
			if resolveErr != nil {
				return resolveErr
			}
			recipient, recipientErr := coordination.NewRecipient(actor, coordination.RecipientTo)
			if recipientErr != nil {
				return recipientErr
			}
			recipients = append(recipients, recipient)
		}
		peerActors := make([]domain.ActorID, len(params.PeerRecipients))
		for index, address := range params.PeerRecipients {
			actor, _, peerErr := ensurePeerAgent(ctx, tx, session.ProjectKey, address.String(), now)
			if peerErr != nil {
				return peerErr
			}
			recipient, recipientErr := coordination.NewRecipient(actor, coordination.RecipientTo)
			if recipientErr != nil {
				return recipientErr
			}
			peerActors[index] = actor
			recipients = append(recipients, recipient)
		}
		message, err := sendMessageTx(ctx, tx, coordination.SendMessageParams{
			MessageID: params.MessageID, ConversationID: params.ConversationID,
			WorkspaceID: session.WorkspaceID, Author: session.ActorID, AuthorSession: session.ActorSessionID,
			Subject: params.Subject, Body: params.Body, Recipients: recipients, ReplyTo: params.ReplyTo,
			AcknowledgementRequired: params.AcknowledgementRequired,
		})
		if err != nil {
			return err
		}
		threadKey, err := ensurePeerThread(ctx, tx, session.WorkspaceID, params.ConversationID, now)
		if err != nil {
			return err
		}
		topic, err := conversationTopic(ctx, tx, params.ConversationID)
		if err != nil {
			return err
		}
		queued := make([]coordination.PeerMailEntry, 0, len(params.PeerRecipients))
		for index, address := range params.PeerRecipients {
			// The first attempt is due immediately. A queued entry always
			// carries a due time -- the schema refuses one that does not -- so
			// an entry that the send path delivers inline is settled a moment
			// later rather than waiting for the drain.
			if _, insertErr := tx.ExecContext(ctx, `INSERT INTO coordination_peer_outbox(message_id, peer_actor_id,
				peer_host, peer_agent, peer_project_key, thread_key, state, attempts, queued_at_us, next_attempt_at_us)
				VALUES (?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?)`,
				params.MessageID.String(), peerActors[index].String(), address.Host, address.Agent,
				peerProject, threadKey, timeMicros(now), timeMicros(now)); insertErr != nil {
				return fmt.Errorf("insert SQLite peer mail entry: %w", insertErr)
			}
			queued = append(queued, coordination.PeerMailEntry{
				MessageID: params.MessageID, Address: address, ProjectKey: peerProject,
				ThreadKey: threadKey, Topic: topic, FromAgent: session.AgentName,
				Subject: params.Subject, Body: params.Body,
				AcknowledgementRequired: params.AcknowledgementRequired,
				State:                   coordination.PeerDeliveryQueued, Attempts: 0,
				QueuedAt: now, NextAttemptAt: now,
			})
		}
		result = coordination.PeerMailSend{Message: message, ThreadKey: threadKey, Queued: queued}
		return nil
	})
	if err != nil {
		return coordination.PeerMailSend{}, err
	}
	return result, nil
}

// ClaimPeerMail reads the entries whose next attempt is due. It CLAIMS nothing
// in the durable sense -- no lease, no in-flight flag -- because there is
// exactly one drain per daemon and the cost of getting that wrong is bounded by
// the receiving host's idempotency key. A marker would instead risk the failure
// that has no bound: a daemon killed mid-attempt leaving an entry marked
// in-flight that nothing ever un-marks.
func (store *Store) ClaimPeerMail(
	ctx context.Context,
	now time.Time,
	limit int,
) ([]coordination.PeerMailEntry, error) {
	if limit <= 0 || limit > coordination.PeerMailBatch {
		limit = coordination.PeerMailBatch
	}
	rows, err := store.db.QueryContext(ctx, peerMailSelect+`
		WHERE outbox.state = 'queued' AND outbox.next_attempt_at_us <= ?
		ORDER BY outbox.next_attempt_at_us, outbox.queued_at_us
		LIMIT ?`, timeMicros(now), limit)
	if err != nil {
		return nil, fmt.Errorf("read SQLite peer mail queue: %w", err)
	}
	return scanPeerMailEntries(rows)
}

// PeerMailQueue reports what one project is holding, newest first.
//
// It is the READ MODEL an operator surface needs -- "what is this repository's
// mail doing" -- and it is deliberately not part of coordination.PeerMailStore:
// nothing the daemon composes today asks the question, and a port method with
// no caller is a contract nobody is keeping. A route that wants it asserts this
// capability rather than widening the port for everyone.
//
// It filters on the project the MESSAGE belongs to rather than the project the
// recipient is resolved in over there, because the remote project key is a
// property of the address and not of the asker.
func (store *Store) PeerMailQueue(
	ctx context.Context,
	projectKey string,
	limit int,
) ([]coordination.PeerMailEntry, error) {
	if projectKey == "" {
		return nil, coordination.ErrInvalid
	}
	if limit <= 0 || limit > coordination.MaxQueryPageSize {
		limit = coordination.PeerMailBatch
	}
	rows, err := store.db.QueryContext(ctx, peerMailSelect+`
		JOIN coordination_projects AS project ON project.workspace_id = message.workspace_id
		WHERE project.project_key = ?
		ORDER BY outbox.queued_at_us DESC
		LIMIT ?`, projectKey, limit)
	if err != nil {
		return nil, fmt.Errorf("read SQLite peer mail queue: %w", err)
	}
	return scanPeerMailEntries(rows)
}

// peerMailSelect reads an entry and everything an attempt needs. Subject, body,
// topic, sender name and the acknowledgement flag are JOINED rather than stored
// on the entry, so an outbox row can never disagree with the message it is
// supposed to be carrying.
const peerMailSelect = `SELECT outbox.message_id, outbox.peer_host, outbox.peer_agent, outbox.peer_project_key,
	outbox.thread_key, outbox.state, outbox.attempts, outbox.queued_at_us, outbox.next_attempt_at_us,
	outbox.last_error, outbox.remote_message_id, message.subject, message.body, conversation.topic,
	author.agent_name, delivery.acknowledgement_required
	FROM coordination_peer_outbox AS outbox
	JOIN messages AS message ON message.message_id = outbox.message_id
	JOIN conversations AS conversation ON conversation.conversation_id = message.conversation_id
	JOIN coordination_agents AS author ON author.actor_id = message.author_actor_id
	JOIN message_deliveries AS delivery ON delivery.message_id = outbox.message_id
		AND delivery.recipient_actor_id = outbox.peer_actor_id`

func scanPeerMailEntries(rows *sql.Rows) ([]coordination.PeerMailEntry, error) {
	defer func() { _ = rows.Close() }()
	var entries []coordination.PeerMailEntry
	for rows.Next() {
		var entry coordination.PeerMailEntry
		var messageText, state string
		var nextAttempt sql.NullInt64
		var lastError, remoteMessage sql.NullString
		var queuedAt int64
		var acknowledge bool
		if err := rows.Scan(&messageText, &entry.Address.Host, &entry.Address.Agent, &entry.ProjectKey,
			&entry.ThreadKey, &state, &entry.Attempts, &queuedAt, &nextAttempt, &lastError, &remoteMessage,
			&entry.Subject, &entry.Body, &entry.Topic, &entry.FromAgent, &acknowledge); err != nil {
			return nil, fmt.Errorf("read SQLite peer mail entry: %w", err)
		}
		messageID, err := domain.ParseMessageID(messageText)
		if err != nil {
			return nil, err
		}
		entry.MessageID, entry.AcknowledgementRequired = messageID, acknowledge
		entry.State = coordination.PeerDeliveryState(state)
		entry.QueuedAt = microsTime(queuedAt)
		// A null stays absent rather than becoming a zero value that reads as a
		// measurement: no next attempt, no failure yet, no receipt.
		if nextAttempt.Valid {
			entry.NextAttemptAt = microsTime(nextAttempt.Int64)
		}
		if lastError.Valid {
			entry.LastError = lastError.String
		}
		if remoteMessage.Valid {
			entry.RemoteMessageID = remoteMessage.String
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// SettlePeerMail records one attempt's outcome and sweeps expired receipts.
//
// The update is conditional on the entry still being queued, so a settle that
// arrives after another has already made the entry terminal is a no-op rather
// than a resurrection.
func (store *Store) SettlePeerMail(ctx context.Context, outcome coordination.PeerMailOutcome) error {
	if outcome.MessageID.IsZero() || outcome.Address.IsZero() || !outcome.State.Valid() {
		return coordination.ErrInvalid
	}
	if outcome.State == coordination.PeerDeliveryQueued && outcome.NextAttemptAt.IsZero() {
		return coordination.ErrInvalid
	}
	// A receipt names a row on another machine, so it is only ever meaningful
	// alongside a delivery that actually happened.
	if outcome.RemoteMessageID != "" && outcome.State != coordination.PeerDeliveryDelivered {
		return coordination.ErrInvalid
	}
	return store.withImmediate(ctx, func(tx *sql.Tx) error {
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		settledAt := outcome.SettledAt
		if settledAt.IsZero() {
			settledAt = now
		}
		var nextAttempt, settled any
		if outcome.State == coordination.PeerDeliveryQueued {
			nextAttempt = timeMicros(outcome.NextAttemptAt)
		} else {
			settled = timeMicros(settledAt)
		}
		var detail, receipt any
		if trimmed := truncatePeerDetail(outcome.Detail); trimmed != "" {
			detail = trimmed
		}
		if outcome.State == coordination.PeerDeliveryDelivered && outcome.RemoteMessageID != "" {
			receipt = truncatePeerReceipt(outcome.RemoteMessageID)
		}
		if _, execErr := tx.ExecContext(ctx, `UPDATE coordination_peer_outbox
			SET state = ?, attempts = attempts + 1, next_attempt_at_us = ?, settled_at_us = ?,
				last_error = ?, remote_message_id = ?
			WHERE message_id = ? AND peer_host = ? AND peer_agent = ? AND state = 'queued'`,
			string(outcome.State), nextAttempt, settled, detail, receipt,
			outcome.MessageID.String(), outcome.Address.Host, outcome.Address.Agent); execErr != nil {
			return fmt.Errorf("settle SQLite peer mail entry: %w", execErr)
		}
		if _, execErr := tx.ExecContext(ctx, `DELETE FROM coordination_peer_outbox
			WHERE settled_at_us IS NOT NULL AND settled_at_us < ?`,
			timeMicros(now.Add(-peerMailRetention))); execErr != nil {
			return fmt.Errorf("sweep SQLite peer mail receipts: %w", execErr)
		}
		return nil
	})
}

// AcceptPeerMail appends one message that arrived from a verified peer.
//
// Every refusal here is a REFUSAL, never a repair. This host does not create a
// project because a remote machine named one, does not create a recipient
// because a remote machine addressed one, and does not accept an unbounded
// number of remote senders. Each of those would be a peer writing into this
// host's authority rather than into its mailbox.
func (store *Store) AcceptPeerMail(
	ctx context.Context,
	params coordination.AcceptPeerMailParams,
) (coordination.AcceptedPeerMail, error) {
	if err := params.Validate(); err != nil {
		return coordination.AcceptedPeerMail{}, err
	}
	messageID, err := domain.NewMessageID()
	if err != nil {
		return coordination.AcceptedPeerMail{}, err
	}
	conversationID, err := domain.NewConversationID()
	if err != nil {
		return coordination.AcceptedPeerMail{}, err
	}
	var result coordination.AcceptedPeerMail
	err = store.withImmediate(ctx, func(tx *sql.Tx) error {
		now, nowErr := sqliteNow(ctx, tx)
		if nowErr != nil {
			return nowErr
		}
		workspace, run, projectErr := peerProjectIdentity(ctx, tx, params.ProjectKey)
		if projectErr != nil {
			return projectErr
		}
		accepted, duplicate, dedupeErr := acceptedPeerMessage(ctx, tx, params)
		if dedupeErr != nil {
			return dedupeErr
		}
		recipients := make([]coordination.Recipient, 0, len(params.ToAgents))
		for _, name := range params.ToAgents {
			actor, resolveErr := resolveAgentActor(ctx, tx, params.ProjectKey, name)
			if resolveErr != nil {
				return resolveErr
			}
			recipient, recipientErr := coordination.NewRecipient(actor, coordination.RecipientTo)
			if recipientErr != nil {
				return recipientErr
			}
			recipients = append(recipients, recipient)
		}
		if duplicate {
			// Idempotency is PER RECIPIENT, not per message, and the difference
			// is a silently dropped recipient. A sender's queue holds one entry
			// per remote recipient and settles them one at a time, so a lost
			// response or a failed settle can leave two recipients of one
			// message being retried in separate requests. Both carry the same
			// origin id -- they are the same message -- and answering the
			// second with "already accepted" while nobody had delivered it to
			// that agent would lose it with no error anywhere.
			if err := deliverAcceptedPeerMail(ctx, tx, accepted.MessageID,
				recipients, params.AcknowledgementRequired, now); err != nil {
				return err
			}
			accepted.Delivered = append([]string(nil), params.ToAgents...)
			result = accepted
			return nil
		}
		authorName := coordination.PeerAuthorName(params.FromAgent, params.OriginHost)
		author, authorSession, authorErr := ensurePeerAgent(ctx, tx, params.ProjectKey, authorName, now)
		if authorErr != nil {
			return authorErr
		}
		conversation, conversationErr := peerThreadConversation(ctx, tx, peerThreadParams{
			WorkspaceID: workspace, RunID: run, ThreadKey: params.ThreadKey,
			ConversationID: conversationID, Author: author, AuthorSession: authorSession,
			Topic: params.Topic, Fallback: params.Subject, Now: now,
		})
		if conversationErr != nil {
			return conversationErr
		}
		message, sendErr := sendMessageTx(ctx, tx, coordination.SendMessageParams{
			MessageID: messageID, ConversationID: conversation, WorkspaceID: workspace,
			Author: author, AuthorSession: authorSession, Subject: params.Subject, Body: params.Body,
			Recipients: recipients, AcknowledgementRequired: params.AcknowledgementRequired,
		})
		if sendErr != nil {
			return sendErr
		}
		if _, insertErr := tx.ExecContext(ctx, `INSERT INTO coordination_peer_inbound(origin_host,
			origin_message_id, message_id, accepted_at_us) VALUES (?, ?, ?, ?)`,
			strings.ToLower(params.OriginHost), params.OriginMessageID, messageID.String(),
			timeMicros(now)); insertErr != nil {
			return fmt.Errorf("record accepted SQLite peer mail: %w", insertErr)
		}
		result = coordination.AcceptedPeerMail{MessageID: message.ID(), ConversationID: conversation,
			Delivered: append([]string(nil), params.ToAgents...)}
		return nil
	})
	if err != nil {
		return coordination.AcceptedPeerMail{}, err
	}
	return result, nil
}

// acceptedPeerMessage answers the idempotency question. A sender whose response
// was lost retries with the same origin id, and this is what makes that retry
// append nothing while still answering with the ids from the first time.
func acceptedPeerMessage(ctx context.Context, tx *sql.Tx,
	params coordination.AcceptPeerMailParams) (coordination.AcceptedPeerMail, bool, error) {
	var messageText, conversationText string
	err := tx.QueryRowContext(ctx, `SELECT accepted.message_id, message.conversation_id
		FROM coordination_peer_inbound AS accepted
		JOIN messages AS message ON message.message_id = accepted.message_id
		WHERE accepted.origin_host = ? AND accepted.origin_message_id = ?`,
		strings.ToLower(params.OriginHost), params.OriginMessageID).Scan(&messageText, &conversationText)
	if errors.Is(err, sql.ErrNoRows) {
		return coordination.AcceptedPeerMail{}, false, nil
	}
	if err != nil {
		return coordination.AcceptedPeerMail{}, false, fmt.Errorf("read accepted SQLite peer mail: %w", err)
	}
	messageID, e1 := domain.ParseMessageID(messageText)
	conversationID, e2 := domain.ParseConversationID(conversationText)
	if e1 != nil || e2 != nil {
		return coordination.AcceptedPeerMail{}, false, coordination.ErrInvalid
	}
	return coordination.AcceptedPeerMail{MessageID: messageID, ConversationID: conversationID,
		Delivered: append([]string(nil), params.ToAgents...), Duplicate: true}, true, nil
}

// deliverAcceptedPeerMail adds any delivery rows an already-accepted message is
// missing, and wakes exactly those recipients. A recipient that already has one
// is left completely alone: its read and acknowledgement facts are its own, and
// a re-delivery would reset them.
func deliverAcceptedPeerMail(ctx context.Context, tx *sql.Tx, message domain.MessageID,
	recipients []coordination.Recipient, acknowledge bool, now time.Time) error {
	var workspaceText, authorText string
	if err := tx.QueryRowContext(ctx, `SELECT workspace_id, author_actor_id FROM messages
		WHERE message_id = ?`, message.String()).Scan(&workspaceText, &authorText); err != nil {
		return fmt.Errorf("read accepted SQLite peer message: %w", err)
	}
	workspace, e1 := domain.ParseWorkspaceID(workspaceText)
	author, e2 := domain.ParseActorID(authorText)
	if e1 != nil || e2 != nil {
		return coordination.ErrInvalid
	}
	added := make([]domain.ActorID, 0, len(recipients))
	for _, recipient := range recipients {
		var existing int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM message_deliveries
			WHERE message_id = ? AND recipient_actor_id = ?`,
			message.String(), recipient.ActorID().String()).Scan(&existing); err != nil {
			return fmt.Errorf("read SQLite peer message delivery: %w", err)
		}
		if existing > 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO message_deliveries(message_id, recipient_actor_id,
			recipient_kind, acknowledgement_required, available_at_us) VALUES (?, ?, ?, ?, ?)`,
			message.String(), recipient.ActorID().String(), string(recipient.Kind()),
			acknowledge, timeMicros(now)); err != nil {
			return fmt.Errorf("insert SQLite peer message delivery: %w", err)
		}
		added = append(added, recipient.ActorID())
	}
	if len(added) == 0 {
		return nil
	}
	payload, err := coordinationPayload(map[string]any{"message_id": message.String()})
	if err != nil {
		return err
	}
	return appendCoordinationEvent(ctx, tx, workspace, author, coordination.EventMessageAvailable,
		message.String(), now, payload, coordinationVisibilityRecipients, added)
}

func peerProjectIdentity(ctx context.Context, tx *sql.Tx,
	projectKey string) (domain.WorkspaceID, domain.RunID, error) {
	var workspaceText, runText string
	err := tx.QueryRowContext(ctx, `SELECT workspace_id, run_id FROM coordination_projects WHERE project_key = ?`,
		projectKey).Scan(&workspaceText, &runText)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.WorkspaceID{}, domain.RunID{}, coordinationError(domain.ErrorCodeNotFound,
			"this host has no agent registered under that project key, so it has no mailbox to deliver into")
	}
	if err != nil {
		return domain.WorkspaceID{}, domain.RunID{}, fmt.Errorf("read SQLite coordination project: %w", err)
	}
	workspace, e1 := domain.ParseWorkspaceID(workspaceText)
	run, e2 := domain.ParseRunID(runText)
	if e1 != nil || e2 != nil {
		return domain.WorkspaceID{}, domain.RunID{}, coordination.ErrInvalid
	}
	return workspace, run, nil
}

func resolveAgentActor(ctx context.Context, tx *sql.Tx, projectKey, name string) (domain.ActorID, error) {
	var actorText string
	err := tx.QueryRowContext(ctx, `SELECT actor_id FROM coordination_agents
		WHERE project_key = ? AND agent_name = ?`, projectKey, name).Scan(&actorText)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ActorID{}, coordinationError(domain.ErrorCodeNotFound, "agent was not found")
	}
	if err != nil {
		return domain.ActorID{}, fmt.Errorf("read SQLite coordination agent: %w", err)
	}
	return domain.ParseActorID(actorText)
}

// ensurePeerAgent returns the local actor that stands for an agent on another
// host, creating it the first time that agent is addressed or heard from.
//
// Two properties keep the row from being a way in. Its registration token
// digest is 32 random bytes rather than the digest of any token, so no string
// authenticates as it -- an attacker would have to invert SHA-256. And its
// session is closed at the instant it is opened, so it never appears in the
// active roster as though something were running here; the session exists only
// because a message needs an author session, and this one honestly says "not
// running".
func ensurePeerAgent(ctx context.Context, tx *sql.Tx, projectKey, name string,
	now time.Time) (domain.ActorID, domain.ActorSessionID, error) {
	var actorText, sessionText string
	err := tx.QueryRowContext(ctx, `SELECT agent.actor_id, session.session_id
		FROM coordination_agents AS agent
		JOIN coordination_agent_sessions AS session USING(actor_id)
		WHERE agent.project_key = ? AND agent.agent_name = ?
		ORDER BY session.started_at_us LIMIT 1`, projectKey, name).Scan(&actorText, &sessionText)
	switch {
	case err == nil:
		actor, e1 := domain.ParseActorID(actorText)
		session, e2 := domain.ParseActorSessionID(sessionText)
		if e1 != nil || e2 != nil {
			return domain.ActorID{}, domain.ActorSessionID{}, coordination.ErrInvalid
		}
		return actor, session, nil
	case !errors.Is(err, sql.ErrNoRows):
		return domain.ActorID{}, domain.ActorSessionID{}, fmt.Errorf("read SQLite peer agent: %w", err)
	}
	var known int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM coordination_agents
		WHERE project_key = ? AND agent_name LIKE '%'||?||'%'`,
		projectKey, coordination.PeerAddressSeparator).Scan(&known); err != nil {
		return domain.ActorID{}, domain.ActorSessionID{}, fmt.Errorf("count SQLite peer agents: %w", err)
	}
	if known >= coordination.MaxPeerAgentsPerProject {
		return domain.ActorID{}, domain.ActorSessionID{}, coordinationError(domain.ErrorCodeBackpressure,
			"this project already knows the maximum number of agents on other hosts")
	}
	actor, err := domain.NewActorID()
	if err != nil {
		return domain.ActorID{}, domain.ActorSessionID{}, err
	}
	session, err := domain.NewActorSessionID()
	if err != nil {
		return domain.ActorID{}, domain.ActorSessionID{}, err
	}
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		return domain.ActorID{}, domain.ActorSessionID{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO coordination_agents(actor_id, project_key, agent_name,
		registration_token_digest, created_at_us) VALUES (?, ?, ?, ?, ?)`,
		actor.String(), projectKey, name, digest[:], timeMicros(now)); err != nil {
		return domain.ActorID{}, domain.ActorSessionID{}, fmt.Errorf("insert SQLite peer agent: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO coordination_agent_sessions(session_id, actor_id,
		started_at_us, last_seen_at_us, ended_at_us) VALUES (?, ?, ?, ?, ?)`,
		session.String(), actor.String(), timeMicros(now), timeMicros(now), timeMicros(now)); err != nil {
		return domain.ActorID{}, domain.ActorSessionID{}, fmt.Errorf("insert SQLite peer agent session: %w", err)
	}
	return actor, session, nil
}

// ensurePeerThread returns the correlator for a conversation, minting one the
// first time that conversation crosses a host boundary. The key is 128 bits of
// randomness rather than anything derived: derived from the conversation id it
// would leak this host's identifiers, and derived from a name it would collide.
func ensurePeerThread(ctx context.Context, tx *sql.Tx, workspace domain.WorkspaceID,
	conversation domain.ConversationID, now time.Time) (string, error) {
	var key string
	err := tx.QueryRowContext(ctx, `SELECT thread_key FROM coordination_peer_threads
		WHERE workspace_id = ? AND conversation_id = ?`,
		workspace.String(), conversation.String()).Scan(&key)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("read SQLite peer thread: %w", err)
	}
	var value [coordination.PeerThreadKeyBytes]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	key = hex.EncodeToString(value[:])
	if _, err := tx.ExecContext(ctx, `INSERT INTO coordination_peer_threads(workspace_id, thread_key,
		conversation_id, created_at_us) VALUES (?, ?, ?, ?)`,
		workspace.String(), key, conversation.String(), timeMicros(now)); err != nil {
		return "", fmt.Errorf("insert SQLite peer thread: %w", err)
	}
	return key, nil
}

type peerThreadParams struct {
	WorkspaceID    domain.WorkspaceID
	RunID          domain.RunID
	ThreadKey      string
	ConversationID domain.ConversationID
	Author         domain.ActorID
	AuthorSession  domain.ActorSessionID
	Topic          string
	Fallback       string
	Now            time.Time
}

// peerThreadConversation maps an inbound thread key onto a conversation THIS
// host owns, opening one the first time a key is seen.
//
// The lookup is scoped to the workspace the peer named, which is what stops a
// key from reaching a conversation in another project. The conversation it
// opens is an ordinary one: its id is minted here, its opener is the peer's
// local actor, and nothing about it refers to the conversation on the other
// side beyond the correlator itself.
func peerThreadConversation(ctx context.Context, tx *sql.Tx,
	params peerThreadParams) (domain.ConversationID, error) {
	var conversationText string
	err := tx.QueryRowContext(ctx, `SELECT conversation_id FROM coordination_peer_threads
		WHERE workspace_id = ? AND thread_key = ?`,
		params.WorkspaceID.String(), params.ThreadKey).Scan(&conversationText)
	if err == nil {
		return domain.ParseConversationID(conversationText)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.ConversationID{}, fmt.Errorf("read SQLite peer thread: %w", err)
	}
	topic := strings.TrimSpace(params.Topic)
	if topic == "" {
		topic = params.Fallback
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO conversations(conversation_id, workspace_id, run_id,
		opened_by_actor_id, opened_by_session_id, topic, opened_at_us) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		params.ConversationID.String(), params.WorkspaceID.String(), params.RunID.String(),
		params.Author.String(), params.AuthorSession.String(), topic,
		timeMicros(params.Now)); err != nil {
		return domain.ConversationID{}, fmt.Errorf("insert SQLite peer conversation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO coordination_peer_threads(workspace_id, thread_key,
		conversation_id, created_at_us) VALUES (?, ?, ?, ?)`,
		params.WorkspaceID.String(), params.ThreadKey, params.ConversationID.String(),
		timeMicros(params.Now)); err != nil {
		return domain.ConversationID{}, fmt.Errorf("insert SQLite peer thread: %w", err)
	}
	return params.ConversationID, nil
}

func conversationTopic(ctx context.Context, tx *sql.Tx, conversation domain.ConversationID) (string, error) {
	var topic string
	err := tx.QueryRowContext(ctx, `SELECT topic FROM conversations WHERE conversation_id = ?`,
		conversation.String()).Scan(&topic)
	if errors.Is(err, sql.ErrNoRows) {
		return "", coordinationError(domain.ErrorCodeNotFound, "conversation was not found")
	}
	if err != nil {
		return "", fmt.Errorf("read SQLite conversation topic: %w", err)
	}
	return topic, nil
}

// truncatePeerDetail bounds a failure string the far side partly controls. It
// truncates on a byte boundary that keeps the text valid UTF-8, because the
// column is TEXT and a torn rune would fail the write and lose the outcome
// entirely -- turning a recorded failure into an infinitely retried one.
func truncatePeerDetail(detail string) string { return truncateUTF8(strings.TrimSpace(detail), 2048) }

func truncatePeerReceipt(receipt string) string { return truncateUTF8(strings.TrimSpace(receipt), 128) }

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8Start(value[cut]) {
		cut--
	}
	return value[:cut]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
