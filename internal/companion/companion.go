// Package companion delivers Blackbird messages to durable Claude Code sessions.
package companion

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	registerPath = "/api/v1/local/agents/register"
	eventsPath   = "/api/v1/local/coordination/events"
	streamPath   = "/api/v1/local/coordination/events/stream"
	messagesPath = "/api/v1/local/messages/"
	maxAttempts  = 5
)

// Config defines one stable Blackbird-to-Claude delivery session.
type Config struct {
	ProjectPath string
	AgentName   string
	StateDir    string
	APIBaseURL  string
	ClaudePath  string
	HTTPClient  *http.Client
	Now         func() time.Time
}

// Companion consumes the local wake/catch-up API and serializes Claude invocations.
type Companion struct {
	config Config
	db     *sql.DB
	token  string
	client *http.Client
}

type registration struct {
	RegistrationToken string `json:"registration_token"`
}

type eventPage struct {
	Events []struct {
		Type    string `json:"type"`
		Subject string `json:"subject"`
	} `json:"events"`
	NextCursor string `json:"next_cursor"`
	HasMore    bool   `json:"has_more"`
}

type message struct {
	MessageID      string `json:"message_id"`
	ConversationID string `json:"conversation_id"`
	AuthorActorID  string `json:"author_actor_id"`
	Subject        string `json:"subject"`
	Body           string `json:"body"`
	BodyDigest     string `json:"body_digest"`
	ReplyTo        string `json:"reply_to,omitempty"`
	SentAt         string `json:"sent_at"`
}

// New opens private durable state and conservatively quarantines interrupted deliveries.
func New(config Config) (*Companion, error) {
	if config.ProjectPath == "" || config.AgentName == "" || config.StateDir == "" {
		return nil, errors.New("project path, agent name, and state directory are required")
	}
	project, err := filepath.Abs(config.ProjectPath)
	if err != nil {
		return nil, fmt.Errorf("resolve project path: %w", err)
	}
	info, err := os.Stat(project)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("project path is not a directory: %s", project)
	}
	config.ProjectPath = project
	if config.APIBaseURL == "" {
		config.APIBaseURL = "http://127.0.0.1:8080"
	}
	if config.ClaudePath == "" {
		config.ClaudePath = "claude"
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if err := os.MkdirAll(config.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create companion state: %w", err)
	}
	if err := os.Chmod(config.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure companion state: %w", err)
	}
	databasePath := filepath.Join(config.StateDir, "deliveries.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(databasePath)+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open delivery state: %w", err)
	}
	companion := &Companion{config: config, db: db, client: config.HTTPClient}
	if err := companion.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	_ = os.Chmod(databasePath, 0o600)
	return companion, nil
}

func (companion *Companion) initialize() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sessions (conversation_id TEXT PRIMARY KEY, session_id TEXT NOT NULL UNIQUE, initialized INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS deliveries (
			message_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, status TEXT NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL DEFAULT '',
			started_at TEXT NOT NULL DEFAULT '', completed_at TEXT NOT NULL DEFAULT '',
			transcript_path TEXT NOT NULL DEFAULT '', result_json TEXT NOT NULL DEFAULT '', last_error TEXT NOT NULL DEFAULT '')`,
	}
	for _, statement := range statements {
		if _, err := companion.db.Exec(statement); err != nil {
			return fmt.Errorf("initialize delivery state: %w", err)
		}
	}
	_, err := companion.db.Exec(`UPDATE deliveries SET status='ambiguous', last_error='companion stopped while Claude execution outcome was unknown' WHERE status='running'`)
	return err
}

// Close releases the SQLite database.
func (companion *Companion) Close() error { return companion.db.Close() }

// Run registers, catches up durably, and uses SSE only as a wake signal.
func (companion *Companion) Run(ctx context.Context) error {
	if err := companion.register(ctx); err != nil {
		return err
	}
	backoff := time.Second
	for ctx.Err() == nil {
		if err := companion.catchUp(ctx); err != nil {
			if !sleep(ctx, backoff) {
				break
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if err := companion.processReady(ctx); err != nil && ctx.Err() != nil {
			break
		}
		waitContext, cancel := companion.retryWaitContext(ctx)
		err := companion.waitForWake(waitContext)
		cancel()
		if ctx.Err() != nil {
			break
		}
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !sleep(ctx, backoff) {
			break
		}
	}
	return nil
}

func (companion *Companion) register(ctx context.Context) error {
	var saved string
	_ = companion.db.QueryRow(`SELECT value FROM metadata WHERE key='registration_token'`).Scan(&saved)
	payload := map[string]any{"project_key": companion.config.ProjectPath, "agent_name": companion.config.AgentName}
	if saved != "" {
		payload["registration_token"] = saved
	}
	var response registration
	if err := companion.jsonRequest(ctx, http.MethodPost, registerPath, "", payload, &response); err != nil {
		return fmt.Errorf("register companion: %w", err)
	}
	if response.RegistrationToken != "" {
		saved = response.RegistrationToken
	}
	if saved == "" {
		return errors.New("registration returned no reusable token")
	}
	if _, err := companion.db.Exec(`INSERT INTO metadata(key,value) VALUES('registration_token',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, saved); err != nil {
		return fmt.Errorf("persist registration token: %w", err)
	}
	companion.token = saved
	return nil
}

func (companion *Companion) catchUp(ctx context.Context) error {
	var cursor string
	_ = companion.db.QueryRow(`SELECT value FROM metadata WHERE key='cursor'`).Scan(&cursor)
	for {
		var page eventPage
		path := eventsPath + "?limit=100"
		if cursor != "" {
			path += "&after=" + url.QueryEscape(cursor)
		}
		if err := companion.jsonRequest(ctx, http.MethodGet, path, companion.token, nil, &page); err != nil {
			return err
		}
		tx, err := companion.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if event.Type == "message.available" {
				if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO deliveries(message_id,conversation_id,status) VALUES(?, '', 'pending')`, event.Subject); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, page.NextCursor); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		cursor = page.NextCursor
		if !page.HasMore {
			return nil
		}
	}
}

func (companion *Companion) processReady(ctx context.Context) error {
	rows, err := companion.db.QueryContext(ctx, `SELECT message_id FROM deliveries WHERE status IN ('pending','retry') AND attempts < ? AND (next_attempt_at='' OR next_attempt_at<=?) ORDER BY rowid`, maxAttempts, companion.config.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := companion.deliver(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (companion *Companion) deliver(ctx context.Context, messageID string) error {
	var value message
	if err := companion.jsonRequest(ctx, http.MethodGet, messagesPath+messageID, companion.token, nil, &value); err != nil {
		return companion.retry(messageID, fmt.Errorf("fetch message: %w", err))
	}
	sessionID, initialized, err := companion.session(value.ConversationID)
	if err != nil {
		return companion.retry(messageID, err)
	}
	transcript := filepath.Join(companion.config.StateDir, "transcripts", messageID+".json")
	if err := os.MkdirAll(filepath.Dir(transcript), 0o700); err != nil {
		return companion.retry(messageID, err)
	}
	now := companion.config.Now().UTC().Format(time.RFC3339Nano)
	if _, err := companion.db.Exec(`UPDATE deliveries SET status='running', conversation_id=?, attempts=attempts+1, started_at=?, transcript_path=?, last_error='' WHERE message_id=?`, value.ConversationID, now, transcript, messageID); err != nil {
		return err
	}
	prompt := fmt.Sprintf("Blackbird durable message ID: %s\nConversation ID: %s\nAuthor actor ID: %s\nSent at: %s\nSubject: %s\nBody digest: %s\n\n%s", value.MessageID, value.ConversationID, value.AuthorActorID, value.SentAt, value.Subject, value.BodyDigest, value.Body)
	args := []string{"-p"}
	if initialized {
		args = append(args, "--resume", sessionID)
	} else {
		args = append(args, "--session-id", sessionID)
	}
	args = append(args, "--output-format", "json", prompt)
	command := exec.CommandContext(ctx, companion.config.ClaudePath, args...)
	command.Dir = companion.config.ProjectPath
	var outputBuffer bytes.Buffer
	command.Stdout = &outputBuffer
	command.Stderr = &outputBuffer
	if err := command.Start(); err != nil {
		return companion.retry(messageID, fmt.Errorf("start Claude invocation: %w", err))
	}
	if !initialized {
		if _, err := companion.db.Exec(`UPDATE sessions SET initialized=1 WHERE conversation_id=?`, value.ConversationID); err != nil {
			_ = command.Process.Kill()
			_, _ = companion.db.Exec(`UPDATE deliveries SET status='ambiguous', last_error=? WHERE message_id=?`, "Claude started but session initialization could not be persisted: "+err.Error(), messageID)
			return err
		}
	}
	runErr := command.Wait()
	output := outputBuffer.Bytes()
	evidence, err := json.Marshal(map[string]any{"message_id": messageID, "session_id": sessionID, "arguments": args[:len(args)-1], "output": json.RawMessage(output), "completed_at": companion.config.Now().UTC().Format(time.RFC3339Nano)})
	if !json.Valid(output) {
		evidence, err = json.Marshal(map[string]any{"message_id": messageID, "session_id": sessionID, "output_text": string(output), "completed_at": companion.config.Now().UTC().Format(time.RFC3339Nano)})
	}
	if err != nil {
		return companion.retry(messageID, fmt.Errorf("marshal transcript evidence: %w", err))
	}
	if writeErr := os.WriteFile(transcript, evidence, 0o600); writeErr != nil {
		_, _ = companion.db.Exec(`UPDATE deliveries SET status='ambiguous', last_error=? WHERE message_id=?`, "Claude completed but transcript evidence could not be written: "+writeErr.Error(), messageID)
		return writeErr
	}
	if runErr != nil {
		if ctx.Err() != nil {
			_, _ = companion.db.Exec(`UPDATE deliveries SET status='ambiguous', last_error=? WHERE message_id=?`, "Claude was interrupted after starting; delivery outcome is unknown: "+runErr.Error(), messageID)
			return ctx.Err()
		}
		return companion.retry(messageID, fmt.Errorf("claude invocation failed: %w", runErr))
	}
	_, err = companion.db.Exec(`UPDATE deliveries SET status='delivered', completed_at=?, result_json=? WHERE message_id=?`, companion.config.Now().UTC().Format(time.RFC3339Nano), string(evidence), messageID)
	return err
}

func (companion *Companion) session(conversationID string) (string, bool, error) {
	var id string
	var initialized bool
	err := companion.db.QueryRow(`SELECT session_id,initialized FROM sessions WHERE conversation_id=?`, conversationID).Scan(&id, &initialized)
	if err == nil {
		return id, initialized, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	id, err = randomUUID()
	if err != nil {
		return "", false, err
	}
	_, err = companion.db.Exec(`INSERT INTO sessions(conversation_id,session_id,created_at) VALUES(?,?,?)`, conversationID, id, companion.config.Now().UTC().Format(time.RFC3339Nano))
	return id, false, err
}

func (companion *Companion) retryWaitContext(ctx context.Context) (context.Context, context.CancelFunc) {
	var next sql.NullString
	err := companion.db.QueryRow(`SELECT MIN(next_attempt_at) FROM deliveries WHERE status='retry' AND attempts < ?`, maxAttempts).Scan(&next)
	if err != nil || !next.Valid || next.String == "" {
		return context.WithCancel(ctx)
	}
	when, err := time.Parse(time.RFC3339Nano, next.String)
	if err != nil {
		return context.WithCancel(ctx)
	}
	delay := when.Sub(companion.config.Now())
	if delay < 0 {
		delay = 0
	}
	return context.WithTimeout(ctx, delay)
}

func (companion *Companion) retry(messageID string, cause error) error {
	var attempts int
	var previous string
	_ = companion.db.QueryRow(`SELECT attempts,status FROM deliveries WHERE message_id=?`, messageID).Scan(&attempts, &previous)
	if previous != "running" {
		attempts++
	}
	status := "retry"
	if attempts >= maxAttempts {
		status = "failed"
	}
	delay := time.Second << min(attempts, 6)
	_, err := companion.db.Exec(`UPDATE deliveries SET status=?, attempts=?, next_attempt_at=?, last_error=? WHERE message_id=?`, status, attempts, companion.config.Now().Add(delay).UTC().Format(time.RFC3339Nano), cause.Error(), messageID)
	if err != nil {
		return err
	}
	return cause
}

func (companion *Companion) waitForWake(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, companion.config.APIBaseURL+streamPath, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+companion.token)
	request.Header.Set("Accept", "text/event-stream")
	response, err := companion.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("SSE stream returned HTTP %d", response.StatusCode)
	}
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data:") {
			return nil
		}
	}
	return scanner.Err()
}

func (companion *Companion) jsonRequest(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, companion.config.APIBaseURL+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := companion.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	return json.NewDecoder(response.Body).Decode(output)
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func sleep(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
