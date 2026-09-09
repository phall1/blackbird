package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

func (store *Store) AdminThread(ctx context.Context, query coordination.AdminThreadQuery) (coordination.AdminThreadPage, error) {
	limit, err := adminFilters(query.ProjectKey, "", query.Limit)
	if err != nil {
		return coordination.AdminThreadPage{}, err
	}
	if query.ProjectKey == "" || query.ConversationID.IsZero() || query.After > coordination.AdminThreadMaxPosition {
		return coordination.AdminThreadPage{}, coordination.ErrInvalid
	}
	page := coordination.AdminThreadPage{ProjectKey: query.ProjectKey, ConversationID: query.ConversationID, Next: query.After}
	observed, err := store.adminSnapshot(ctx, func(tx *sql.Tx, _ time.Time) error {
		workspace, err := adminThreadWorkspace(ctx, tx, query)
		if err != nil {
			return err
		}
		return adminThreadMessages(ctx, tx, workspace, query, limit, &page)
	})
	if err != nil {
		return coordination.AdminThreadPage{}, err
	}
	page.ObservedAtUS = observed
	return page, nil
}

func adminThreadWorkspace(ctx context.Context, tx *sql.Tx, query coordination.AdminThreadQuery) (string, error) {
	var workspace string
	err := tx.QueryRowContext(ctx, `SELECT c.workspace_id FROM conversations AS c
		JOIN coordination_projects AS p ON p.workspace_id = c.workspace_id
		WHERE p.project_key = ? AND c.conversation_id = ?`, query.ProjectKey, query.ConversationID.String()).Scan(&workspace)
	if errors.Is(err, sql.ErrNoRows) {
		return "", coordinationError(domain.ErrorCodeNotFound, "conversation was not found")
	}
	if err != nil {
		return "", fmt.Errorf("query SQLite admin thread scope: %w", err)
	}
	return workspace, nil
}

func adminThreadMessages(ctx context.Context, tx *sql.Tx, workspace string, query coordination.AdminThreadQuery,
	limit uint16, page *coordination.AdminThreadPage) error {
	rows, err := tx.QueryContext(ctx, `SELECT m.message_id, m.position,
		COALESCE(a.agent_name, ''), m.subject, m.body, m.sent_at_us
		FROM messages AS m LEFT JOIN coordination_agents AS a ON a.actor_id = m.author_actor_id
		WHERE m.workspace_id = ? AND m.conversation_id = ? AND m.position > ?
		ORDER BY m.position LIMIT ?`, workspace, query.ConversationID.String(), query.After, int(limit)+1)
	if err != nil {
		return fmt.Errorf("query SQLite admin thread messages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if len(page.Messages) == int(limit) {
			page.HasMore = true
			break
		}
		var message coordination.AdminThreadMessage
		var messageText string
		if err := rows.Scan(&messageText, &message.Position, &message.AuthorAgentName,
			&message.Subject, &message.Body, &message.SentAtUS); err != nil {
			return fmt.Errorf("scan SQLite admin thread message: %w", err)
		}
		messageID, err := domain.ParseMessageID(messageText)
		if err != nil {
			return coordination.ErrInvalid
		}
		message.MessageID = messageID
		page.Messages = append(page.Messages, message)
		page.Next = message.Position
	}
	return rows.Err()
}
