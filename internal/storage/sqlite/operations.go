package sqlite

import (
	"bytes"
	"context"
	"crypto/hmac"
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

type coordinationCursorWire struct {
	Workspace string `json:"workspace"`
	Actor     string `json:"actor"`
	Position  uint64 `json:"position"`
	MAC       string `json:"mac"`
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

// OpenConversation is an upsert on (workspace, slug) when the caller supplies a
// slug, and the plain insert it always was when it does not. The lookup and the
// insert share the one write transaction, so two agents racing to open the same
// slug cannot both create a thread: the write arbiter serializes them and the
// second sees the first's row.
//
// A reused open returns the stored conversation, whose ID is not the one the
// caller proposed. That difference is the caller's signal, and it is why the
// proposed UUID is discarded rather than recorded anywhere -- a second identity
// for one thread is exactly the failure the slug exists to prevent.
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
		if params.Slug != "" {
			existing, found, lookupErr := conversationBySlug(ctx, tx, params)
			if lookupErr != nil {
				return lookupErr
			}
			if found {
				result = existing
				return nil
			}
		}
		var slug any
		if params.Slug != "" {
			slug = params.Slug
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO conversations(conversation_id, workspace_id, run_id,
			opened_by_actor_id, opened_by_session_id, topic, slug, opened_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			params.ConversationID.String(), params.WorkspaceID.String(), params.RunID.String(), params.OpenedBy.String(),
			params.OpenedBySession.String(), params.Topic, slug, timeMicros(now))
		if err != nil {
			return fmt.Errorf("insert SQLite conversation: %w", err)
		}
		return nil
	})
	return result, err
}

// conversationBySlug rebuilds the stored conversation rather than the requested
// one, so a reopen reports the topic and opener the thread actually has instead
// of whatever the returning caller happened to type this time.
func conversationBySlug(ctx context.Context, tx *sql.Tx,
	params application.OpenConversationParams) (application.Conversation, bool, error) {
	var conversationText, runText, openedByText, sessionText, topic string
	var openedAt int64
	err := tx.QueryRowContext(ctx, `SELECT conversation_id, run_id, opened_by_actor_id, opened_by_session_id,
		topic, opened_at_us FROM conversations WHERE workspace_id = ? AND slug = ?`,
		params.WorkspaceID.String(), params.Slug).Scan(&conversationText, &runText, &openedByText, &sessionText,
		&topic, &openedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return application.Conversation{}, false, nil
	}
	if err != nil {
		return application.Conversation{}, false, fmt.Errorf("read SQLite conversation slug: %w", err)
	}
	conversationID, e1 := domain.ParseConversationID(conversationText)
	run, e2 := domain.ParseRunID(runText)
	openedBy, e3 := domain.ParseActorID(openedByText)
	openedBySession, e4 := domain.ParseActorSessionID(sessionText)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return application.Conversation{}, false, application.ErrInvalidCoordination
	}
	stored, err := application.NewConversation(application.OpenConversationParams{ConversationID: conversationID,
		WorkspaceID: params.WorkspaceID, RunID: run, OpenedBy: openedBy, OpenedBySession: openedBySession,
		Topic: topic, Slug: params.Slug}, microsTime(openedAt))
	if err != nil {
		return application.Conversation{}, false, err
	}
	return stored, true, nil
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
			// A missing row means the caller named a reply target that does not
			// exist; any other failure is the database, and reporting it as an
			// invalid argument sends the caller to fix a correct request.
			replyErr := tx.QueryRowContext(ctx, `SELECT conversation_id FROM messages WHERE message_id = ?`,
				params.ReplyTo.String()).Scan(&parentConversation)
			if replyErr != nil && !errors.Is(replyErr, sql.ErrNoRows) {
				return fmt.Errorf("read SQLite reply target: %w", replyErr)
			}
			if replyErr != nil || parentConversation != params.ConversationID.String() {
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
		if err != nil {
			return fmt.Errorf("read SQLite message position: %w", err)
		}
		if position <= 0 {
			return application.ErrInvalidCoordination
		}
		deliveries := make([]application.Delivery, 0, len(params.Recipients))
		recipients := make([]domain.ActorID, 0, len(params.Recipients))
		for _, recipient := range params.Recipients {
			if _, err := tx.ExecContext(ctx, `INSERT INTO message_deliveries(message_id, recipient_actor_id,
				recipient_kind, acknowledgement_required, available_at_us) VALUES (?, ?, ?, ?, ?)`, params.MessageID.String(),
				recipient.ActorID().String(), string(recipient.Kind()), params.AcknowledgementRequired, timeMicros(now)); err != nil {
				return fmt.Errorf("insert SQLite message delivery: %w", err)
			}
			recipients = append(recipients, recipient.ActorID())
			delivery, _ := application.NewDeliveryView(recipient, params.AcknowledgementRequired, &now, nil, nil)
			deliveries = append(deliveries, delivery)
		}
		payload, payloadErr := coordinationPayload(map[string]any{"conversation_id": params.ConversationID.String(),
			"message_id": params.MessageID.String()})
		if payloadErr != nil {
			return payloadErr
		}
		if err := appendCoordinationEvent(ctx, tx, params.WorkspaceID, params.Author,
			application.CoordinationEventMessageAvailable, params.MessageID.String(), now, payload,
			coordinationVisibilityRecipients, recipients); err != nil {
			return err
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

func (store *Store) GetVisibleMessage(ctx context.Context, workspace domain.WorkspaceID, viewer domain.ActorID,
	messageID domain.MessageID) (application.Message, error) {
	if workspace.IsZero() || viewer.IsZero() || messageID.IsZero() {
		return application.Message{}, application.ErrInvalidCoordination
	}
	var conversationText, authorText, subject, body string
	var reply sql.NullString
	var sent int64
	var position uint64
	err := store.db.QueryRowContext(ctx, `SELECT message.conversation_id, message.author_actor_id, message.subject,
		message.body, message.reply_to_message_id, message.sent_at_us, message.position FROM messages AS message
		LEFT JOIN message_deliveries AS own ON own.message_id = message.message_id AND own.recipient_actor_id = ?
		WHERE message.message_id = ? AND message.workspace_id = ?
		AND (message.author_actor_id = ? OR own.message_id IS NOT NULL)`, viewer.String(), messageID.String(),
		workspace.String(), viewer.String()).Scan(&conversationText, &authorText, &subject, &body, &reply, &sent, &position)
	if errors.Is(err, sql.ErrNoRows) {
		return application.Message{}, coordinationError(domain.ErrorCodeNotFound, "message was not found")
	}
	if err != nil {
		return application.Message{}, fmt.Errorf("query visible SQLite coordination message: %w", err)
	}
	conversation, conversationErr := domain.ParseConversationID(conversationText)
	author, authorErr := domain.ParseActorID(authorText)
	if conversationErr != nil || authorErr != nil {
		return application.Message{}, application.ErrInvalidCoordination
	}
	deliveries, err := loadVisibleDeliveries(ctx, store.db, messageID, author, viewer)
	if err != nil {
		return application.Message{}, err
	}
	params := application.MessageViewParams{MessageID: messageID, ConversationID: conversation, WorkspaceID: workspace,
		Author: author, Subject: subject, Body: body, SentAt: microsTime(sent), Position: position, Deliveries: deliveries}
	if reply.Valid {
		replyID, parseErr := domain.ParseMessageID(reply.String)
		if parseErr != nil {
			return application.Message{}, parseErr
		}
		params.ReplyTo = &replyID
	}
	return application.NewMessageView(params)
}

func (store *Store) Thread(ctx context.Context, query application.ThreadQuery) (application.CoordinationPage, error) {
	if query.WorkspaceID.IsZero() || query.ConversationID.IsZero() || query.Viewer.IsZero() || query.Limit == 0 || query.Limit > application.MaxQueryPageSize {
		return application.CoordinationPage{}, application.ErrInvalidCoordination
	}
	return store.loadMessages(ctx, query.WorkspaceID, query.ConversationID, query.Viewer, query.After, query.Limit, false, false)
}

func (store *Store) loadMessages(ctx context.Context, workspace domain.WorkspaceID, conversation domain.ConversationID,
	viewer domain.ActorID, after uint64, limit uint16, inbox, unreadOnly bool) (application.CoordinationPage, error) {
	// The page, its deliveries and the journal head are read from one snapshot.
	// The cursor advance below is only sound if no message can commit between
	// reading the page and reading the head, which a read-only transaction
	// guarantees; SQLite defers its BEGIN, so no writer waits on this.
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return application.CoordinationPage{}, fmt.Errorf("begin SQLite coordination message read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
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
	rows, err := tx.QueryContext(ctx, base, args...)
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
	// The delivery and head reads below share this transaction's single
	// connection, so the page statement is finished with first.
	if err := rows.Close(); err != nil {
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
		deliveries, err := loadVisibleDeliveries(ctx, tx, messageID, author, viewer)
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
	if !hasMore {
		// A page that ran out of rows before its limit scanned the journal to
		// its head, so every position at or below that head has already been
		// judged against this viewer and the cursor may skip the ones the
		// filter rejected. That is sound because message.position is an
		// AUTOINCREMENT rowid assigned at insert, messages are immutable, and a
		// message's deliveries are written by the transaction that inserts it:
		// a row this scan rejected can never become visible later, and every
		// message committed after this snapshot takes a strictly greater
		// position. Leaving the cursor where it was instead makes a quiet agent
		// rescan every message the workspace has accumulated on every poll.
		var head uint64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(position), 0) FROM messages`).Scan(&head); err != nil {
			return application.CoordinationPage{}, fmt.Errorf("read SQLite coordination message head: %w", err)
		}
		if head > next {
			next = head
		}
	}
	return application.NewCoordinationPage(result, next, hasMore)
}

func loadVisibleDeliveries(ctx context.Context, query coordinationQuery, message domain.MessageID,
	author, viewer domain.ActorID) ([]application.Delivery, error) {
	rows, err := query.QueryContext(ctx, `SELECT recipient_actor_id, recipient_kind, acknowledgement_required,
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
		// Expiry is a state transition, not a filter. Nothing else retires a
		// lease, so an agent that crashed leaves its row 'active' forever: every
		// later acquisition pays to read and parse the corpse, and every
		// reservation listing reports work nobody is doing. Reaping here rides
		// the write lock this transaction already holds and costs one statement.
		if _, err := tx.ExecContext(ctx, `UPDATE leases SET status = 'released', released_at_us = ?
			WHERE workspace_id = ? AND authority_epoch = ? AND status = 'active' AND expires_at_us <= ?`,
			timeMicros(now), params.WorkspaceID.String(), params.AuthorityEpoch.String(), timeMicros(now)); err != nil {
			return fmt.Errorf("reap expired SQLite leases: %w", err)
		}
		type existingSelector struct {
			lease, holder, mode string
			selector            application.LeaseSelector
			expires             int64
		}
		rows, err := tx.QueryContext(ctx, `SELECT lease.lease_id, lease.holder_actor_id, lease.mode,
			selector.selector_kind, selector.selector_path, lease.expires_at_us
			FROM leases AS lease JOIN lease_selectors AS selector USING(lease_id)
			WHERE lease.workspace_id = ? AND lease.authority_epoch = ? AND lease.status = 'active'
			AND lease.expires_at_us > ?`,
			params.WorkspaceID.String(), params.AuthorityEpoch.String(), timeMicros(now))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		var existing []existingSelector
		for rows.Next() {
			var value existingSelector
			var kind, selectorPath string
			if err := rows.Scan(&value.lease, &value.holder, &value.mode, &kind, &selectorPath, &value.expires); err != nil {
				return err
			}
			// Parsed once per stored selector rather than once per requested
			// selector per stored selector, which is what the overlap loop below
			// would otherwise pay for.
			value.selector, err = application.NewLeaseSelector(application.LeaseSelectorKind(kind), selectorPath)
			if err != nil {
				return err
			}
			existing = append(existing, value)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// A lease this same actor already holds is not a conflict. Agents retry
		// after a timeout or a lost response constantly, and without this an
		// agent is refused by a reservation it owns -- on the commonest
		// acquisition path there is, with no recovery but waiting out its own
		// TTL. Holder identity is the actor rather than the session because a
		// re-registration mints a new session for the same agent name and
		// rebinds these very leases to it.
		held := make(map[string][]application.LeaseSelector)
		keys := make(map[string]struct{}, len(params.Selectors))
		for _, prior := range existing {
			if prior.holder == params.Holder.String() {
				held[prior.lease] = append(held[prior.lease], prior.selector)
			}
		}
		for _, requested := range params.Selectors {
			keys[requested.Key()] = struct{}{}
			for _, prior := range existing {
				// Another claim by this actor is not a blocker. Its generation is
				// advanced only when this request names the same selector key.
				if prior.holder == params.Holder.String() || !application.LeaseSelectorsOverlap(requested, prior.selector) {
					continue
				}
				keys[prior.selector.Key()] = struct{}{}
				if params.Mode == application.LeaseExclusive || application.LeaseMode(prior.mode) == application.LeaseExclusive {
					return coordinationConflict(domain.ErrorCodeLeaseConflict, domain.ConflictLease,
						fmt.Sprintf("an active overlapping %s lease exists: lease %s held by actor %s over %s %s, free in %s",
							prior.mode, prior.lease, prior.holder, prior.selector.Kind(), evidenceText(prior.selector.Path()),
							microsTime(prior.expires).Sub(now).Round(time.Millisecond)))
				}
			}
		}
		if err := supersedeHeldLeases(ctx, tx, params, held, now); err != nil {
			return err
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
		generations := make(map[string]uint64, len(selectors))
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
				generations[key] = counter
			}
		}
		result, err = application.NewLeaseView(application.LeaseViewParams{LeaseID: params.LeaseID, WorkspaceID: params.WorkspaceID,
			Holder: params.Holder, HolderSession: params.HolderSession, AuthorityEpoch: params.AuthorityEpoch, Mode: params.Mode,
			Selectors: selectors, ClaimGenerations: generations, AcquiredAt: now, ExpiresAt: expires})
		if err != nil {
			return err
		}
		payload, err := leaseCoordinationPayload(result)
		if err != nil {
			return err
		}
		return appendCoordinationEvent(ctx, tx, params.WorkspaceID, params.Holder,
			application.CoordinationEventLeaseAcquired, params.LeaseID.String(), now, payload,
			coordinationVisibilityWorkspace, nil)
	})
	return result, err
}

// supersedeHeldLeases retires the acquirer's own active leases whose every
// selector the new request already covers. Skipping a self-conflict without
// this leaks: the agent releases the lease it was just handed, forgets the one
// it retried over, and that forgotten row keeps the same paths reserved against
// every other agent for the rest of its TTL -- which is the whole failure the
// retry fix is meant to remove. A lease covering anything outside the request
// is left alone, because retiring it would silently drop paths its holder still
// believes it has reserved.
func supersedeHeldLeases(ctx context.Context, tx *sql.Tx, params application.AcquireLeaseParams,
	held map[string][]application.LeaseSelector, now time.Time) error {
	superseded := make([]string, 0, len(held))
	for lease, selectors := range held {
		if sameSelectorSet(params.Selectors, selectors) {
			superseded = append(superseded, lease)
		}
	}
	// Sorted so the journal records the same order on every replay of the same
	// acquisition; map iteration order would make the event stream depend on
	// nothing an agent can observe.
	sort.Strings(superseded)
	for _, lease := range superseded {
		leaseID, err := domain.ParseLeaseID(lease)
		if err != nil {
			return err
		}
		// Stamped strictly before the deadline, which is what separates an
		// explicit release from the expiry reaper's terminal retirement.
		if _, err := tx.ExecContext(ctx, `UPDATE leases SET status = 'released', released_at_us = ?
			WHERE lease_id = ? AND status = 'active'`, timeMicros(now), lease); err != nil {
			return fmt.Errorf("supersede SQLite lease: %w", err)
		}
		retired, err := loadLease(ctx, tx, leaseID)
		if err != nil {
			return err
		}
		payload, err := leaseCoordinationPayload(retired)
		if err != nil {
			return err
		}
		if err := appendCoordinationEvent(ctx, tx, params.WorkspaceID, params.Holder,
			application.CoordinationEventLeaseReleased, lease, now, payload,
			coordinationVisibilityWorkspace, nil); err != nil {
			return err
		}
	}
	return nil
}

func sameSelectorSet(left, right []application.LeaseSelector) bool {
	if len(left) != len(right) {
		return false
	}
	keys := make(map[string]struct{}, len(left))
	for _, selector := range left {
		keys[selector.Key()] = struct{}{}
	}
	for _, selector := range right {
		if _, ok := keys[selector.Key()]; !ok {
			return false
		}
	}
	return true
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
	if params.WorkspaceID.IsZero() || params.Holder.IsZero() || params.HolderSession.IsZero() ||
		params.AuthorityEpoch.IsZero() || len(params.Selectors) == 0 || len(params.Selectors) > application.MaxLeaseSelectors {
		return application.Lease{}, application.ErrInvalidCoordination
	}
	var result application.Lease
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		if err := requireCurrentLeaseEpoch(ctx, tx, params.WorkspaceID, params.AuthorityEpoch); err != nil {
			return err
		}
		lease, err := findHeldLease(ctx, tx, params)
		if err != nil {
			return err
		}
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		if !now.Before(lease.ExpiresAt()) {
			return coordinationConflict(domain.ErrorCodeLeaseExpired, domain.ConflictLeaseTerminal,
				fmt.Sprintf("claim has expired: selector set expired at %s", instantEvidence(lease.ExpiresAt())))
		}
		if release {
			_, err = tx.ExecContext(ctx, `UPDATE leases SET status = 'released', released_at_us = ? WHERE lease_id = ? AND status = 'active'`,
				timeMicros(now), lease.ID().String())
		} else {
			expires := now.Add(params.TTL)
			if expires.After(lease.AcquiredAt().Add(application.MaxLeaseLifetime)) {
				return application.ErrInvalidCoordination
			}
			_, err = tx.ExecContext(ctx, `UPDATE leases SET holder_session_id = ?, expires_at_us = ? WHERE lease_id = ? AND status = 'active'`,
				params.HolderSession.String(), timeMicros(expires), lease.ID().String())
		}
		if err != nil {
			return err
		}
		result, err = loadLease(ctx, tx, lease.ID())
		if err != nil {
			return err
		}
		payload, err := leaseCoordinationPayload(result)
		if err != nil {
			return err
		}
		eventType := application.CoordinationEventLeaseRenewed
		if release {
			eventType = application.CoordinationEventLeaseReleased
		}
		return appendCoordinationEvent(ctx, tx, result.WorkspaceID(), result.Holder(), eventType,
			result.ID().String(), now, payload, coordinationVisibilityWorkspace, nil)
	})
	return result, err
}

func findHeldLease(ctx context.Context, tx *sql.Tx, params application.ChangeLeaseParams) (application.Lease, error) {
	rows, err := tx.QueryContext(ctx, `SELECT lease_id FROM leases WHERE workspace_id = ? AND holder_actor_id = ?
		AND authority_epoch = ? AND status = 'active' ORDER BY acquired_at_us DESC`,
		params.WorkspaceID.String(), params.Holder.String(), params.AuthorityEpoch.String())
	if err != nil {
		return application.Lease{}, err
	}
	defer func() { _ = rows.Close() }()
	var ids []domain.LeaseID
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return application.Lease{}, err
		}
		id, err := domain.ParseLeaseID(text)
		if err != nil {
			return application.Lease{}, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return application.Lease{}, err
	}
	if err := rows.Close(); err != nil {
		return application.Lease{}, err
	}
	partial := false
	for _, id := range ids {
		lease, err := loadLease(ctx, tx, id)
		if err != nil {
			return application.Lease{}, err
		}
		if sameSelectorSet(params.Selectors, lease.Selectors()) {
			return lease, nil
		}
		for _, requested := range params.Selectors {
			for _, held := range lease.Selectors() {
				partial = partial || application.LeaseSelectorsOverlap(requested, held)
			}
		}
	}
	if partial {
		return application.Lease{}, coordinationError(domain.ErrorCodeInvalidArgument,
			"selectors must exactly match one active claim; partial release or renewal is not allowed")
	}
	return application.Lease{}, coordinationError(domain.ErrorCodeNotFound, "no active claim matches the exact selector set")
}

// coordinationQuery is satisfied by both the pool and a transaction, so a
// coordination read can be served from a caller's snapshot instead of silently
// opening its own on another pooled connection.
type coordinationQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadLease(ctx context.Context, query coordinationQuery, id domain.LeaseID) (application.Lease, error) {
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
	if err := selectorRows.Err(); err != nil {
		return application.Lease{}, err
	}
	if err := selectorRows.Close(); err != nil {
		return application.Lease{}, err
	}
	generationRows, err := query.QueryContext(ctx, `SELECT conflict_key, counter FROM lease_fences WHERE lease_id = ? ORDER BY conflict_key`, id.String())
	if err != nil {
		return application.Lease{}, err
	}
	defer func() { _ = generationRows.Close() }()
	generations := make(map[string]uint64)
	for generationRows.Next() {
		var key string
		var counter uint64
		if err := generationRows.Scan(&key, &counter); err != nil {
			return application.Lease{}, err
		}
		generations[key] = counter
	}
	if err := generationRows.Err(); err != nil {
		return application.Lease{}, err
	}
	params := application.LeaseViewParams{LeaseID: id, WorkspaceID: workspace, Holder: holder, HolderSession: session,
		AuthorityEpoch: epoch, Mode: application.LeaseMode(mode), Selectors: selectors, ClaimGenerations: generations,
		AcquiredAt: microsTime(acquired), ExpiresAt: microsTime(expires), ReleasedAt: nullableTime(released)}
	return application.NewLeaseView(params)
}

func staleEpochError(scope, current, supplied string) error {
	return coordinationConflict(domain.ErrorCodeStateConflict, domain.ConflictAuthorityMismatch,
		fmt.Sprintf("%s authority epoch is stale: %s holds %s, request supplied %s", scope, scope,
			evidenceText(current), evidenceText(supplied)))
}

// maxLocalAgentTokenBytes bounds a bearer token before it is ever hashed or
// compared, so a caller cannot make the daemon digest an arbitrary payload.
const maxLocalAgentTokenBytes = 256

// maxEvidenceTextBytes bounds one interpolated fact. A selector path or a
// conflict key runs to thousands of bytes while a command error message is
// capped at 512, and an over-long message is rejected by the constructor --
// which would leave the caller with no message at all rather than a long one.
const maxEvidenceTextBytes = 120

func evidenceText(value string) string {
	if len(value) <= maxEvidenceTextBytes {
		return value
	}
	trimmed := value[:maxEvidenceTextBytes]
	for len(trimmed) > 0 {
		last, size := utf8.DecodeLastRuneInString(trimmed)
		if last != utf8.RuneError || size > 1 {
			break
		}
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed + "..."
}

func instantEvidence(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

const (
	coordinationVisibilityRecipients = "recipients"
	coordinationVisibilityWorkspace  = "workspace"
)

func appendCoordinationEvent(ctx context.Context, tx *sql.Tx, workspace domain.WorkspaceID, actor domain.ActorID,
	eventType application.CoordinationEventType, subjectID string, occurredAt time.Time, payload []byte,
	visibility string, recipients []domain.ActorID) error {
	insert, err := tx.ExecContext(ctx, `INSERT INTO coordination_events(workspace_id, actor_id, event_type,
		subject_id, occurred_at_us, payload, visibility) VALUES (?, ?, ?, ?, ?, ?, ?)`, workspace.String(), actor.String(),
		string(eventType), subjectID, timeMicros(occurredAt), payload, visibility)
	if err != nil {
		return fmt.Errorf("append SQLite coordination event: %w", err)
	}
	position, err := insert.LastInsertId()
	if err != nil {
		return fmt.Errorf("read SQLite coordination event position: %w", err)
	}
	for _, recipient := range recipients {
		if _, err := tx.ExecContext(ctx, `INSERT INTO coordination_event_recipients(position, actor_id) VALUES (?, ?)`,
			position, recipient.String()); err != nil {
			return fmt.Errorf("append SQLite coordination event recipient: %w", err)
		}
	}
	return nil
}

func coordinationPayload(value map[string]any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode SQLite coordination event: %w", err)
	}
	return payload, nil
}

func leaseCoordinationPayload(lease application.Lease) ([]byte, error) {
	return coordinationPayload(leaseCoordinationFields(lease))
}

func leaseCoordinationFields(lease application.Lease) map[string]any {
	selectors := make([]map[string]any, 0, len(lease.Selectors()))
	for _, selector := range lease.Selectors() {
		selectors = append(selectors, map[string]any{"kind": string(selector.Kind()), "path": selector.Path(),
			"claim_generation": lease.ClaimGeneration(selector)})
	}
	return map[string]any{"expires_at_us": timeMicros(lease.ExpiresAt()),
		"lease_id": lease.ID().String(), "mode": lease.Mode(), "selectors": selectors}
}

func (store *Store) SyncCoordinationEvents(ctx context.Context,
	query application.CoordinationEventsQuery) (application.CoordinationEventsPage, error) {
	if query.WorkspaceID().IsZero() || query.ActorID().IsZero() || query.Limit() == 0 ||
		query.Limit() > application.MaxQueryPageSize {
		return application.CoordinationEventsPage{}, application.ErrInvalidCoordination
	}
	if err := ctx.Err(); err != nil {
		return application.CoordinationEventsPage{}, err
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return application.CoordinationEventsPage{}, fmt.Errorf("begin SQLite coordination event sync: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	after := uint64(0)
	if !query.AfterCursor().IsZero() {
		after, err = decodeCoordinationCursor(ctx, tx, query.AfterCursor(), query.WorkspaceID(), query.ActorID())
		if err != nil {
			return application.CoordinationEventsPage{}, err
		}
	} else if query.ConsumerID() != "" {
		err = tx.QueryRowContext(ctx, `SELECT position FROM coordination_event_consumers
			WHERE workspace_id = ? AND actor_id = ? AND consumer_id = ?`, query.WorkspaceID().String(),
			query.ActorID().String(), query.ConsumerID().String()).Scan(&after)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return application.CoordinationEventsPage{}, fmt.Errorf("read SQLite coordination consumer: %w", err)
		}
		if err == nil {
			retainedFrom, _, boundsErr := coordinationJournalBounds(ctx, tx, query.WorkspaceID())
			if boundsErr != nil {
				return application.CoordinationEventsPage{}, boundsErr
			}
			if after < retainedFrom-1 {
				return application.CoordinationEventsPage{}, coordinationError(domain.ErrorCodeCursorExpired,
					"coordination consumer position has expired; restart from the retained journal boundary")
			}
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT event.position, event.actor_id, event.event_type, event.subject_id,
		event.occurred_at_us, event.payload FROM coordination_events AS event
		WHERE event.workspace_id = ? AND event.position > ? AND (
			event.visibility = 'workspace'
			OR event.visibility = 'actor' AND event.actor_id = ?
			OR event.visibility = 'recipients' AND EXISTS (
				SELECT 1 FROM coordination_event_recipients AS recipient
				WHERE recipient.position = event.position AND recipient.actor_id = ?))
		ORDER BY event.position LIMIT ?`, query.WorkspaceID().String(), after, query.ActorID().String(),
		query.ActorID().String(), int(query.Limit())+1)
	if err != nil {
		return application.CoordinationEventsPage{}, fmt.Errorf("query SQLite coordination events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	events := make([]application.CoordinationEvent, 0, query.Limit())
	eventCursors := make([]application.CoordinationEventCursor, 0, query.Limit())
	hasMore := false
	nextPosition := after
	for rows.Next() {
		var position uint64
		var actorText, eventType, subjectID string
		var occurredAt int64
		var payload []byte
		if err := rows.Scan(&position, &actorText, &eventType, &subjectID, &occurredAt, &payload); err != nil {
			return application.CoordinationEventsPage{}, err
		}
		if len(events) == int(query.Limit()) {
			hasMore = true
			break
		}
		actor, actorErr := domain.ParseActorID(actorText)
		if actorErr != nil {
			return application.CoordinationEventsPage{}, actorErr
		}
		event, eventErr := application.NewCoordinationEvent(application.CoordinationEventParams{Position: position,
			Workspace: query.WorkspaceID(), Actor: actor, EventType: application.CoordinationEventType(eventType),
			SubjectID: subjectID, OccurredAt: microsTime(occurredAt), Payload: payload})
		if eventErr != nil {
			return application.CoordinationEventsPage{}, eventErr
		}
		cursor, cursorErr := encodeCoordinationCursor(ctx, tx, query.WorkspaceID(), query.ActorID(), position)
		if cursorErr != nil {
			return application.CoordinationEventsPage{}, cursorErr
		}
		events = append(events, event)
		eventCursors = append(eventCursors, cursor)
		nextPosition = position
	}
	if err := rows.Err(); err != nil {
		return application.CoordinationEventsPage{}, err
	}
	if !hasMore {
		_, head, boundsErr := coordinationJournalBounds(ctx, tx, query.WorkspaceID())
		if boundsErr != nil {
			return application.CoordinationEventsPage{}, boundsErr
		}
		if head > nextPosition {
			nextPosition = head
		}
	}
	next, err := encodeCoordinationCursor(ctx, tx, query.WorkspaceID(), query.ActorID(), nextPosition)
	if err != nil {
		return application.CoordinationEventsPage{}, err
	}
	return application.NewCoordinationEventsPage(events, eventCursors, next, hasMore)
}

// CommitCoordinationConsumer advances one authenticated adapter monotonically.
// Replaying the same or an older acknowledgement is idempotent and can never
// move delivery backwards.
func (store *Store) CommitCoordinationConsumer(ctx context.Context, commit application.CoordinationConsumerCommit) error {
	if commit.WorkspaceID().IsZero() || commit.ActorID().IsZero() || commit.ConsumerID() == "" || commit.Cursor().IsZero() {
		return application.ErrInvalidCoordination
	}
	return store.withImmediate(ctx, func(tx *sql.Tx) error {
		position, err := decodeCoordinationCursor(ctx, tx, commit.Cursor(), commit.WorkspaceID(), commit.ActorID())
		if err != nil {
			return err
		}
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO coordination_event_consumers(
			workspace_id, actor_id, consumer_id, position, updated_at_us) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(workspace_id, actor_id, consumer_id) DO UPDATE SET
			position = excluded.position, updated_at_us = excluded.updated_at_us
			WHERE excluded.position > coordination_event_consumers.position`, commit.WorkspaceID().String(),
			commit.ActorID().String(), commit.ConsumerID().String(), position, timeMicros(now))
		if err != nil {
			return fmt.Errorf("commit SQLite coordination consumer: %w", err)
		}
		return nil
	})
}

func encodeCoordinationCursor(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, workspace domain.WorkspaceID, actor domain.ActorID, position uint64) (application.CoordinationEventCursor, error) {
	key, err := coordinationCursorKey(ctx, query)
	if err != nil {
		return application.CoordinationEventCursor{}, err
	}
	wire := coordinationCursorWire{Workspace: workspace.String(), Actor: actor.String(), Position: position}
	wire.MAC = coordinationCursorMAC(key, wire)
	encoded, err := json.Marshal(wire)
	if err != nil {
		return application.CoordinationEventCursor{}, err
	}
	return application.NewCoordinationEventCursor("bbcc1_" + base64.RawURLEncoding.EncodeToString(encoded))
}

func decodeCoordinationCursor(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, cursor application.CoordinationEventCursor, workspace domain.WorkspaceID, actor domain.ActorID) (uint64, error) {
	const prefix = "bbcc1_"
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cursor.String(), prefix))
	var wire coordinationCursorWire
	if !strings.HasPrefix(cursor.String(), prefix) || err != nil || json.Unmarshal(encoded, &wire) != nil {
		return 0, coordinationError(domain.ErrorCodeCursorInvalid, "coordination event cursor is invalid")
	}
	key, err := coordinationCursorKey(ctx, query)
	if err != nil {
		return 0, err
	}
	want := coordinationCursorMAC(key, wire)
	if subtle.ConstantTimeCompare([]byte(wire.MAC), []byte(want)) != 1 {
		return 0, coordinationError(domain.ErrorCodeCursorInvalid, "coordination event cursor is invalid")
	}
	if wire.Workspace != workspace.String() || wire.Actor != actor.String() {
		return 0, coordinationError(domain.ErrorCodeCursorScopeMismatch, "coordination event cursor belongs to another actor or workspace")
	}
	retainedFrom, head, err := coordinationJournalBounds(ctx, query, workspace)
	if err != nil {
		return 0, err
	}
	if wire.Position < retainedFrom-1 {
		return 0, coordinationError(domain.ErrorCodeCursorExpired,
			"coordination event cursor has expired; restart from the retained journal boundary")
	}
	if wire.Position > head {
		return 0, coordinationError(domain.ErrorCodeCursorInvalid, "coordination event cursor is ahead of the journal")
	}
	return wire.Position, nil
}

func coordinationJournalBounds(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, workspace domain.WorkspaceID) (uint64, uint64, error) {
	var retainedFrom, head uint64
	if err := query.QueryRowContext(ctx, `SELECT retention.retained_from_position,
		MAX(COALESCE((SELECT max(position) FROM coordination_events WHERE workspace_id = ?), 0),
			retention.retained_from_position - 1)
		FROM coordination_event_retention AS retention WHERE retention.singleton = 1`, workspace.String()).Scan(
		&retainedFrom, &head); err != nil {
		return 0, 0, fmt.Errorf("read SQLite coordination journal bounds: %w", err)
	}
	return retainedFrom, head, nil
}

func coordinationCursorKey(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) ([]byte, error) {
	var key []byte
	if err := query.QueryRowContext(ctx, `SELECT key FROM coordination_event_cursor_keys WHERE singleton = 1`).Scan(&key); err != nil {
		return nil, fmt.Errorf("read SQLite coordination cursor key: %w", err)
	}
	if len(key) != sha256.Size {
		return nil, application.ErrInvalidCoordination
	}
	return key, nil
}

func coordinationCursorMAC(key []byte, wire coordinationCursorWire) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("blackbird-coordination-cursor/v1\x00" + wire.Workspace + "\x00" + wire.Actor + "\x00" +
		strconv.FormatUint(wire.Position, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
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
		return staleEpochError("workspace", current, epoch.String())
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
				return coordinationError(domain.ErrorCodeUnauthenticated,
					"registration token names no existing agent; call blackbird_agent_register without registration_token to create it")
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
				return coordinationError(domain.ErrorCodeUnauthenticated,
					"registration token does not match this agent; use the registration_token originally returned for this project and agent name")
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

// AuthenticateLocalAgent is the first statement of every MCP tool call and of
// the whole HTTP local API, so its cost is a floor under every operation the
// daemon performs. It reads in a deferred read-only transaction: nothing about
// verifying a bearer token needs a write lock, registration_token_digest is
// uniquely indexed, and the read pool serves these concurrently.
//
// It used to run inside a BEGIN IMMEDIATE solely to stamp the session's
// last_seen_at_us. That made every read pay one durable fullfsync commit and
// one turn of the daemon-wide write arbiter -- measured at roughly five
// milliseconds on this machine against a tenth of a millisecond without the
// barrier -- so an inbox poll paid five milliseconds before it read anything
// and a send paid it twice. The heartbeat is now coalesced through
// flushLocalHeartbeat; see application.LocalAgentHeartbeatInterval for why a
// lagging heartbeat is safe and a lost one is safe in the same direction.
//
// The returned LastSeenAt is this call's own instant rather than the stored
// one, because the caller is asking when the session was last seen and the
// answer is "now"; only the durable row is allowed to lag.
func (store *Store) AuthenticateLocalAgent(ctx context.Context, token string) (application.LocalAgentSession, error) {
	if token == "" || len(token) > maxLocalAgentTokenBytes {
		return application.LocalAgentSession{}, coordinationError(domain.ErrorCodeUnauthenticated,
			"agent token is missing or too long; call blackbird_agent_register to get the current token")
	}
	digest := sha256.Sum256([]byte(token))
	if err := ctx.Err(); err != nil {
		return application.LocalAgentSession{}, err
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return application.LocalAgentSession{}, fmt.Errorf("begin SQLite agent authentication: %w", err)
	}
	finished := false
	defer func() {
		if !finished {
			_ = tx.Rollback()
		}
	}()
	now, err := sqliteNow(ctx, tx)
	if err != nil {
		return application.LocalAgentSession{}, err
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
		return application.LocalAgentSession{}, coordinationError(domain.ErrorCodeUnauthenticated,
			"agent token was not found; call blackbird_agent_register to start or resume this agent")
	}
	if err != nil {
		return application.LocalAgentSession{}, err
	}
	result, err := localAgentSession(projectKey, agentName, workspaceText, runText, actorText, sessionText, epochText,
		started, timeMicros(now))
	if err != nil {
		return application.LocalAgentSession{}, err
	}
	// The read transaction is finished with before any heartbeat write, so a
	// flush never holds two of the five pooled connections at once and never
	// waits on the write arbiter while pinning a reader.
	finished = true
	if err := tx.Rollback(); err != nil {
		return application.LocalAgentSession{}, fmt.Errorf("finish SQLite agent authentication: %w", err)
	}
	if err := store.flushLocalHeartbeat(ctx, sessionText, now); err != nil {
		return application.LocalAgentSession{}, err
	}
	return result, nil
}

// flushLocalHeartbeat writes a session's liveness at most once per
// application.LocalAgentHeartbeatInterval. The claim is taken before the write
// and given back if the write fails, so a failed flush is retried by the next
// call rather than suppressed for a whole interval.
func (store *Store) flushLocalHeartbeat(ctx context.Context, sessionText string, now time.Time) error {
	if !store.claimHeartbeat(sessionText, now) {
		return nil
	}
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		if _, execErr := tx.ExecContext(ctx, `UPDATE coordination_agent_sessions SET last_seen_at_us = ?
			WHERE session_id = ? AND ended_at_us IS NULL`, timeMicros(now), sessionText); execErr != nil {
			return fmt.Errorf("write SQLite session heartbeat: %w", execErr)
		}
		return nil
	})
	if err != nil {
		store.releaseHeartbeat(sessionText)
		return err
	}
	return nil
}

// claimHeartbeat reports whether this call owes a durable heartbeat write. A
// clock that moved backwards flushes rather than stalls: the comparison asks
// whether the recorded flush is in the past and recent, not merely how far
// apart the two instants are.
func (store *Store) claimHeartbeat(sessionText string, now time.Time) bool {
	store.heartbeats.Lock()
	defer store.heartbeats.Unlock()
	if store.heartbeats.flushed == nil {
		store.heartbeats.flushed = make(map[string]time.Time)
	}
	if flushed, known := store.heartbeats.flushed[sessionText]; known &&
		now.After(flushed) && now.Sub(flushed) < application.LocalAgentHeartbeatInterval {
		return false
	}
	// Sessions that stopped calling are dropped here rather than by a sweeper,
	// which bounds the ledger by the number of agents actually talking to the
	// daemon. An entry older than the liveness horizon can only ever produce a
	// flush anyway, so forgetting it changes nothing but the memory it held.
	for session, flushed := range store.heartbeats.flushed {
		if now.Sub(flushed) > application.LocalAgentActiveWindow {
			delete(store.heartbeats.flushed, session)
		}
	}
	store.heartbeats.flushed[sessionText] = now
	return true
}

func (store *Store) releaseHeartbeat(sessionText string) {
	store.heartbeats.Lock()
	defer store.heartbeats.Unlock()
	delete(store.heartbeats.flushed, sessionText)
}

// LocalAgentSnapshot answers the one question a resuming agent cannot answer
// from its own memory: what is still bound to it. Registration rebinds the
// agent's live leases to its new session, so without this an agent that
// restarted or was compacted holds an exclusive reservation it does not know
// about and cannot release, and every other agent waits out its TTL.
//
// The whole projection is read from one read-only snapshot against the store's
// own clock, so the remaining lease time, the inbox counts and the roster all
// describe the same instant.
func (store *Store) LocalAgentSnapshot(ctx context.Context,
	session application.LocalAgentSession) (application.LocalAgentSnapshot, error) {
	if session.ProjectKey == "" || session.WorkspaceID.IsZero() || session.ActorID.IsZero() {
		return application.LocalAgentSnapshot{}, application.ErrInvalidCoordination
	}
	var snapshot application.LocalAgentSnapshot
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, now time.Time) error {
		reservations, err := localAgentReservations(ctx, tx, session, now)
		if err != nil {
			return err
		}
		snapshot.Reservations = reservations
		inbox, err := localAgentInbox(ctx, tx, session)
		if err != nil {
			return err
		}
		snapshot.Inbox = inbox
		conversations, err := localAgentConversations(ctx, tx, session)
		if err != nil {
			return err
		}
		snapshot.Conversations = conversations
		peers, err := localAgentPeers(ctx, tx, session, now)
		if err != nil {
			return err
		}
		snapshot.Peers = peers
		return nil
	})
	if err != nil {
		return application.LocalAgentSnapshot{}, err
	}
	snapshot.ObservedAtUS = observed
	return snapshot, nil
}

// The lease rows are read first and then loaded whole so each selector carries
// its informational claim generation in the registration snapshot.
func localAgentReservations(ctx context.Context, tx *sql.Tx, session application.LocalAgentSession,
	now time.Time) ([]application.LocalAgentReservation, error) {
	rows, err := tx.QueryContext(ctx, `SELECT lease_id FROM leases
		WHERE holder_actor_id = ? AND workspace_id = ? AND status = 'active' AND expires_at_us > ?
		ORDER BY expires_at_us, lease_id`, session.ActorID.String(), session.WorkspaceID.String(), timeMicros(now))
	if err != nil {
		return nil, fmt.Errorf("query SQLite held reservations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var identifiers []domain.LeaseID
	for rows.Next() {
		var leaseText string
		if err := rows.Scan(&leaseText); err != nil {
			return nil, fmt.Errorf("scan SQLite held reservation: %w", err)
		}
		leaseID, parseErr := domain.ParseLeaseID(leaseText)
		if parseErr != nil {
			return nil, application.ErrInvalidCoordination
		}
		identifiers = append(identifiers, leaseID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	reservations := make([]application.LocalAgentReservation, 0, len(identifiers))
	for _, leaseID := range identifiers {
		lease, loadErr := loadLease(ctx, tx, leaseID)
		if loadErr != nil {
			return nil, loadErr
		}
		generations := make(map[string]uint64, len(lease.Selectors()))
		for _, selector := range lease.Selectors() {
			generations[selector.Key()] = lease.ClaimGeneration(selector)
		}
		reservations = append(reservations, application.LocalAgentReservation{LeaseID: lease.ID(), Mode: lease.Mode(),
			Selectors: lease.Selectors(), ClaimGenerations: generations,
			ExpiresInMS: lease.ExpiresAt().Sub(now).Milliseconds()})
	}
	return reservations, nil
}

// The counts aggregate d.message_id rather than the row so an agent with no
// mail reports zero rather than one, matching the admin summaries.
func localAgentInbox(ctx context.Context, tx *sql.Tx,
	session application.LocalAgentSession) (application.LocalAgentInbox, error) {
	var inbox application.LocalAgentInbox
	if err := tx.QueryRowContext(ctx, `SELECT
		count(d.message_id) FILTER (WHERE d.read_at_us IS NULL),
		count(d.message_id) FILTER (WHERE d.acknowledgement_required = 1 AND d.acknowledged_at_us IS NULL)
		FROM message_deliveries AS d WHERE d.recipient_actor_id = ?`,
		session.ActorID.String()).Scan(&inbox.UnreadDeliveries, &inbox.UnackedDeliveries); err != nil {
		return application.LocalAgentInbox{}, fmt.Errorf("query SQLite agent inbox counts: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.message_id, m.conversation_id, COALESCE(author.agent_name, ''),
		m.subject, d.read_at_us IS NOT NULL, d.acknowledgement_required, d.acknowledged_at_us IS NOT NULL, m.sent_at_us
		FROM message_deliveries AS d
		JOIN messages AS m ON m.message_id = d.message_id
		LEFT JOIN coordination_agents AS author ON author.actor_id = m.author_actor_id
		WHERE d.recipient_actor_id = ?
		  AND (d.read_at_us IS NULL OR (d.acknowledgement_required = 1 AND d.acknowledged_at_us IS NULL))
		ORDER BY m.position DESC LIMIT ?`, session.ActorID.String(), application.MaxLocalAgentSnapshotItems)
	if err != nil {
		return application.LocalAgentInbox{}, fmt.Errorf("query SQLite agent inbox: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var item application.LocalAgentInboxItem
		var messageText, conversationText string
		if err := rows.Scan(&messageText, &conversationText, &item.AuthorAgentName, &item.Subject, &item.Read,
			&item.AcknowledgementRequired, &item.Acknowledged, &item.SentAtUS); err != nil {
			return application.LocalAgentInbox{}, fmt.Errorf("scan SQLite agent inbox item: %w", err)
		}
		message, messageErr := domain.ParseMessageID(messageText)
		conversation, conversationErr := domain.ParseConversationID(conversationText)
		if messageErr != nil || conversationErr != nil {
			return application.LocalAgentInbox{}, application.ErrInvalidCoordination
		}
		item.MessageID, item.ConversationID = message, conversation
		inbox.Recent = append(inbox.Recent, item)
	}
	return inbox, rows.Err()
}

// Participation, not the workspace, decides what belongs here: a conversation
// this agent opened, wrote to, or was addressed in. A conversation it has never
// touched is somebody else's work item and would only cost it context.
func localAgentConversations(ctx context.Context, tx *sql.Tx,
	session application.LocalAgentSession) ([]application.LocalAgentConversation, error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.conversation_id, c.topic,
		(SELECT count(*) FROM messages AS m WHERE m.conversation_id = c.conversation_id),
		COALESCE((SELECT max(m.sent_at_us) FROM messages AS m WHERE m.conversation_id = c.conversation_id),
			c.opened_at_us) AS last_message_at_us
		FROM conversations AS c
		WHERE c.workspace_id = ? AND c.status = 'open' AND (c.opened_by_actor_id = ?
			OR EXISTS (SELECT 1 FROM messages AS m WHERE m.conversation_id = c.conversation_id
				AND m.author_actor_id = ?)
			OR EXISTS (SELECT 1 FROM message_deliveries AS d JOIN messages AS m ON m.message_id = d.message_id
				WHERE m.conversation_id = c.conversation_id AND d.recipient_actor_id = ?))
		ORDER BY last_message_at_us DESC, c.conversation_id LIMIT ?`,
		session.WorkspaceID.String(), session.ActorID.String(), session.ActorID.String(), session.ActorID.String(),
		application.MaxLocalAgentSnapshotItems)
	if err != nil {
		return nil, fmt.Errorf("query SQLite agent conversations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var conversations []application.LocalAgentConversation
	for rows.Next() {
		var conversation application.LocalAgentConversation
		var conversationText string
		if err := rows.Scan(&conversationText, &conversation.Topic, &conversation.Messages,
			&conversation.LastMessageAtUS); err != nil {
			return nil, fmt.Errorf("scan SQLite agent conversation: %w", err)
		}
		id, parseErr := domain.ParseConversationID(conversationText)
		if parseErr != nil {
			return nil, application.ErrInvalidCoordination
		}
		conversation.ConversationID = id
		conversations = append(conversations, conversation)
	}
	return conversations, rows.Err()
}

// The liveness horizon is the shared one, and the clock is the store's, so this
// roster and the admin roster cannot disagree about who is present.
func localAgentPeers(ctx context.Context, tx *sql.Tx, session application.LocalAgentSession,
	now time.Time) ([]application.ActiveAgent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT agent.agent_name, agent.actor_id, session.session_id,
		session.started_at_us, session.last_seen_at_us FROM coordination_agents AS agent
		JOIN coordination_agent_sessions AS session USING(actor_id)
		WHERE agent.project_key = ? AND agent.actor_id <> ? AND session.ended_at_us IS NULL
		AND session.last_seen_at_us >= ? ORDER BY agent.agent_name`,
		session.ProjectKey, session.ActorID.String(), timeMicros(now.Add(-application.LocalAgentActiveWindow)))
	if err != nil {
		return nil, fmt.Errorf("query SQLite agent peers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var peers []application.ActiveAgent
	for rows.Next() {
		var peer application.ActiveAgent
		var actorText, sessionText string
		var started, seen int64
		if err := rows.Scan(&peer.Name, &actorText, &sessionText, &started, &seen); err != nil {
			return nil, fmt.Errorf("scan SQLite agent peer: %w", err)
		}
		actor, actorErr := domain.ParseActorID(actorText)
		peerSession, sessionErr := domain.ParseActorSessionID(sessionText)
		if actorErr != nil || sessionErr != nil {
			return nil, application.ErrInvalidCoordination
		}
		peer.ActorID, peer.SessionID = actor, peerSession
		peer.StartedAt, peer.LastSeenAt = microsTime(started), microsTime(seen)
		peers = append(peers, peer)
	}
	return peers, rows.Err()
}

func (store *Store) ListActiveLocalAgents(ctx context.Context, session application.LocalAgentSession) ([]application.ActiveAgent, error) {
	if session.WorkspaceID.IsZero() || session.ProjectKey == "" {
		return nil, application.ErrInvalidCoordination
	}
	cutoff := time.Now().UTC().Add(-application.LocalAgentActiveWindow)
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
	result, err := domain.NewCommandError(code, message, nil)
	if err != nil {
		return fmt.Errorf("construct coordination error: %w", err)
	}
	return result
}
func coordinationConflict(code domain.ErrorCode, kind domain.ConflictKind, message string) error {
	result, err := domain.NewConflictError(code, kind, message, nil)
	if err != nil {
		return fmt.Errorf("construct coordination conflict: %w", err)
	}
	return result
}
