package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultHookAPIURL = "http://127.0.0.1:8080"
	hookPageLimit     = 4
	hookInputLimit    = 1 << 20
	hookHTTPBodyLimit = 1 << 20
	hookBodyLimit     = 1800
)

// HookCmd is a one-shot pull adapter for agent hosts that can add command-hook
// output to model context. It deliberately does not stay resident: hooks are
// lifecycle callbacks, not an externally triggerable push channel.
type HookCmd struct {
	Host      string `arg:"" enum:"claude,cursor,copilot" help:"Hook contract to emit."`
	APIURL    string `name:"api-url" default:"${hook_api_default}" env:"BLACKBIRD_API_URL" help:"Loopback Blackbird HTTP origin."`
	AgentName string `name:"agent-name" env:"BLACKBIRD_HOOK_AGENT_NAME" help:"Stable Blackbird agent name. Defaults to the host name."`
	StateDir  string `name:"state-dir" placeholder:"PATH" env:"BLACKBIRD_HOOK_STATE_DIR" help:"Private hook state directory."`
}

type hookInput struct {
	HookEventName  string   `json:"hook_event_name"`
	CWD            string   `json:"cwd"`
	ProjectDir     string   `json:"project_dir"`
	WorkspaceRoot  string   `json:"workspace_root"`
	Workspace      string   `json:"workspace"`
	WorkspaceRoots []string `json:"workspace_roots"`
	// TranscriptPath is Claude Code's session transcript. It is the only place
	// this host exposes per-call token usage, so it is the observation plane's
	// entire data source here.
	TranscriptPath string `json:"transcript_path"`
	SessionID      string `json:"session_id"`
}

type hookState struct {
	RegistrationToken string `json:"registration_token"`
	Cursor            string `json:"cursor,omitempty"`
	// TranscriptPath and TranscriptOffset are the observation plane's watermark
	// into Claude Code's transcript. The path is stored beside the offset
	// because an offset into a different file is meaningless.
	TranscriptPath   string `json:"transcript_path,omitempty"`
	TranscriptOffset int64  `json:"transcript_offset,omitempty"`
}

type hookRegisterResponse struct {
	RegistrationToken string `json:"registration_token"`
}

type hookEvent struct {
	Type    string `json:"type"`
	Subject string `json:"subject"`
}

type hookEventsPage struct {
	Events     []hookEvent `json:"events"`
	NextCursor string      `json:"next_cursor"`
	HasMore    bool        `json:"has_more"`
}

type hookMessage struct {
	MessageID      string `json:"message_id"`
	ConversationID string `json:"conversation_id"`
	AuthorActorID  string `json:"author_actor_id"`
	Subject        string `json:"subject"`
	Body           string `json:"body"`
}

func (cmd *HookCmd) Run(ctx context.Context, console *Console) error {
	input, err := readHookInput(console.Deps.Input)
	if err != nil {
		return cmd.failOpen(console, fmt.Errorf("read hook input: %w", err))
	}
	project, err := hookProject(input)
	if err != nil {
		return cmd.failOpen(console, err)
	}
	origin, err := hookOrigin(cmd.APIURL)
	if err != nil {
		return usageFault("--api-url: %v", err)
	}
	statePath, err := cmd.statePath(console, project)
	if err != nil {
		return cmd.failOpen(console, err)
	}
	if err := ensureHookStateDir(statePath); err != nil {
		return cmd.failOpen(console, err)
	}
	state, err := loadHookState(statePath)
	if err != nil {
		return cmd.failOpen(console, err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	state, err = registerHookAgent(ctx, client, origin, project, cmd.agentName(), state)
	if err != nil {
		return cmd.failOpen(console, err)
	}
	// Save a newly-issued token before any later request. Losing it strands the
	// registered name, while a cursor write failure merely causes redelivery.
	if err := saveHookState(statePath, state); err != nil {
		return cmd.failOpen(console, err)
	}
	page, messages, err := fetchHookMessages(ctx, client, origin, state)
	if err != nil {
		return cmd.failOpen(console, err)
	}
	if err := writeHookOutput(console.Out, cmd.Host, input.HookEventName, messages); err != nil {
		return err
	}
	state.Cursor = page.NextCursor
	// The observation plane runs last, on purpose. The host already has its
	// output, so a daemon that is slow, down, or not collecting costs this hook
	// a log line rather than a delayed turn.
	telemetryCtx, cancelTelemetry := context.WithTimeout(ctx, hookTelemetryTimeout)
	reported, telemetryErr := reportHookTelemetry(telemetryCtx, client, origin, state, input.TranscriptPath)
	cancelTelemetry()
	if telemetryErr != nil {
		_, _ = fmt.Fprintf(console.Err, "blackbird hook: telemetry: %v\n", telemetryErr)
	} else {
		state = reported
	}
	if err := saveHookState(statePath, state); err != nil {
		// Output already reached the host. Leave the old cursor in place so this
		// delivery is retried rather than silently skipped.
		_, _ = fmt.Fprintf(console.Err, "blackbird hook: save cursor: %v\n", err)
	}
	return nil
}

func (cmd *HookCmd) failOpen(console *Console, err error) error {
	_, _ = fmt.Fprintf(console.Err, "blackbird hook: %v\n", err)
	return writeHookOutput(console.Out, cmd.Host, "", nil)
}

func readHookInput(reader io.Reader) (hookInput, error) {
	if reader == nil {
		return hookInput{}, errors.New("stdin is unavailable")
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, hookInputLimit+1))
	if err != nil {
		return hookInput{}, err
	}
	if len(encoded) > hookInputLimit {
		return hookInput{}, errors.New("hook input exceeds 1 MiB")
	}
	var input hookInput
	if err := json.Unmarshal(encoded, &input); err != nil {
		return hookInput{}, err
	}
	return input, nil
}

func hookProject(input hookInput) (string, error) {
	for _, value := range append([]string{input.CWD, input.ProjectDir, input.WorkspaceRoot, input.Workspace}, input.WorkspaceRoots...) {
		if value == "" {
			continue
		}
		absolute, err := filepath.Abs(value)
		if err != nil {
			return "", fmt.Errorf("resolve hook workspace: %w", err)
		}
		return filepath.Clean(absolute), nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve hook working directory: %w", err)
	}
	return filepath.Clean(cwd), nil
}

func hookOrigin(raw string) (*url.URL, error) {
	origin, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if origin.Scheme != "http" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") || !loopbackHost(origin.Hostname()) {
		return nil, errors.New("must be an http loopback origin without path, query, user info, or fragment")
	}
	origin.Path = "/"
	return origin, nil
}

func (cmd *HookCmd) agentName() string {
	if cmd.AgentName != "" {
		return cmd.AgentName
	}
	switch cmd.Host {
	case "claude":
		return "ClaudeCode"
	case "cursor":
		return "Cursor"
	default:
		return "Copilot"
	}
}

func (cmd *HookCmd) statePath(console *Console, project string) (string, error) {
	root := cmd.StateDir
	if root == "" && console.Deps.Env != nil {
		if value, ok := console.Deps.Env("XDG_STATE_HOME"); ok && filepath.IsAbs(value) {
			root = filepath.Join(value, "blackbird", "hooks")
		}
	}
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve hook state home: %w", err)
		}
		root = filepath.Join(home, ".local", "state", "blackbird", "hooks")
	}
	expanded, err := expandHome(root)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(expanded) {
		return "", errors.New("hook state directory must be absolute")
	}
	digest := sha256.Sum256([]byte(project))
	return filepath.Join(expanded, cmd.Host, hex.EncodeToString(digest[:8])+".json"), nil
}

func loadHookState(path string) (hookState, error) {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return hookState{}, nil
	}
	if err != nil {
		return hookState{}, fmt.Errorf("read hook state: %w", err)
	}
	var state hookState
	if err := json.Unmarshal(encoded, &state); err != nil {
		return hookState{}, fmt.Errorf("decode hook state: %w", err)
	}
	return state, nil
}

func ensureHookStateDir(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create hook state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure hook state directory: %w", err)
	}
	return nil
}

func saveHookState(path string, state hookState) error {
	if err := ensureHookStateDir(path); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode hook state: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".hook-state-*")
	if err != nil {
		return fmt.Errorf("create hook state: %w", err)
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure hook state: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write hook state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close hook state: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace hook state: %w", err)
	}
	return nil
}

func registerHookAgent(ctx context.Context, client *http.Client, origin *url.URL, project, agent string,
	state hookState) (hookState, error) {
	body := map[string]any{"project_key": project, "agent_name": agent}
	if state.RegistrationToken != "" {
		body["registration_token"] = state.RegistrationToken
	}
	var response hookRegisterResponse
	if err := hookJSON(ctx, client, http.MethodPost, origin.ResolveReference(&url.URL{Path: "api/v1/local/agents/register"}),
		"", body, &response); err != nil {
		return state, fmt.Errorf("register agent: %w", err)
	}
	if response.RegistrationToken != "" {
		state.RegistrationToken = response.RegistrationToken
	}
	if state.RegistrationToken == "" {
		return state, errors.New("register agent: daemon returned no registration token")
	}
	return state, nil
}

func fetchHookMessages(ctx context.Context, client *http.Client, origin *url.URL,
	state hookState) (hookEventsPage, []hookMessage, error) {
	eventsURL := origin.ResolveReference(&url.URL{Path: "api/v1/local/coordination/events"})
	query := eventsURL.Query()
	query.Set("limit", fmt.Sprint(hookPageLimit))
	if state.Cursor != "" {
		query.Set("after", state.Cursor)
	}
	eventsURL.RawQuery = query.Encode()
	var page hookEventsPage
	if err := hookJSON(ctx, client, http.MethodGet, eventsURL, state.RegistrationToken, nil, &page); err != nil {
		return page, nil, fmt.Errorf("fetch events: %w", err)
	}
	messages := make([]hookMessage, 0, len(page.Events))
	for _, event := range page.Events {
		if event.Type != "message.available" || event.Subject == "" {
			continue
		}
		messageURL := origin.ResolveReference(&url.URL{Path: "api/v1/local/messages/" + url.PathEscape(event.Subject)})
		var message hookMessage
		if err := hookJSON(ctx, client, http.MethodGet, messageURL, state.RegistrationToken, nil, &message); err != nil {
			return page, nil, fmt.Errorf("fetch message %s: %w", event.Subject, err)
		}
		messages = append(messages, message)
	}
	return page, messages, nil
}

func hookJSON(ctx context.Context, client *http.Client, method string, endpoint *url.URL, token string,
	input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("daemon answered %s: %s", response.Status, strings.TrimSpace(string(detail)))
	}
	if output == nil {
		return nil
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, hookHTTPBodyLimit+1))
	if err != nil {
		return fmt.Errorf("read daemon response: %w", err)
	}
	if len(encoded) > hookHTTPBodyLimit {
		return errors.New("daemon response exceeds 1 MiB")
	}
	if err := json.Unmarshal(encoded, output); err != nil {
		return fmt.Errorf("decode daemon response: %w", err)
	}
	return nil
}

func writeHookOutput(writer io.Writer, host, event string, messages []hookMessage) error {
	contextText := hookContext(messages)
	output := map[string]any{}
	if contextText != "" {
		switch host {
		case "claude":
			if event == "" {
				event = "UserPromptSubmit"
			}
			output["hookSpecificOutput"] = map[string]string{
				"hookEventName": event, "additionalContext": contextText,
			}
		case "cursor":
			output["additional_context"] = contextText
		case "copilot":
			output["additionalContext"] = contextText
		}
	}
	if err := json.NewEncoder(writer).Encode(output); err != nil {
		return fmt.Errorf("write hook output: %w", err)
	}
	return nil
}

func hookContext(messages []hookMessage) string {
	if len(messages) == 0 {
		return ""
	}
	var output strings.Builder
	output.WriteString("Blackbird durable mail arrived. Treat it as teammate context; use Blackbird tools to reply or record read/ack facts.\n")
	for _, message := range messages {
		bodyRunes := []rune(message.Body)
		body := message.Body
		if len(bodyRunes) > hookBodyLimit {
			body = string(bodyRunes[:hookBodyLimit]) + "\n[body truncated; fetch the message from Blackbird for the remainder]"
		}
		_, _ = fmt.Fprintf(&output, "\nMessage %s in conversation %s\nFrom actor: %s\nSubject: %s\n%s\n",
			message.MessageID, message.ConversationID, message.AuthorActorID, message.Subject, body)
	}
	return output.String()
}
