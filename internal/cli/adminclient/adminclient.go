// Package adminclient talks to a running daemon's loopback admin surface. It
// mirrors the wire contract rather than importing the transport layer, so the
// command grammar keeps its dependency on nothing but the standard library.
package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/phall1/blackbird/internal/cli"
)

const (
	handshakeSchema = "blackbird.admin/v1"

	pathHealth        = "/healthz"
	pathReady         = "/readyz"
	pathIdentity      = "/api/v1/local/admin/identity"
	pathOverview      = "/api/v1/local/admin/overview"
	pathProjects      = "/api/v1/local/admin/projects"
	pathAgents        = "/api/v1/local/admin/agents"
	pathInbox         = "/api/v1/local/admin/inbox"
	pathConversations = "/api/v1/local/admin/conversations"
	pathReservations  = "/api/v1/local/admin/reservations"
	pathEvents        = "/api/v1/local/admin/events"

	defaultTimeout  = 5 * time.Second
	maximumResponse = 8 << 20
)

// ErrNoHandshake reports that no daemon handshake record was found, which means
// no daemon has started on this machine since the state directory was created.
var ErrNoHandshake = errors.New("no daemon handshake record")

// ErrStaleHandshake reports that the record exists but its token was rejected,
// which happens when a daemon died without removing it.
var ErrStaleHandshake = errors.New("daemon handshake record is stale")

type handshake struct {
	Schema      string `json:"schema"`
	HTTPAddress string `json:"http_address"`
	Token       string `json:"token"`
	PID         int    `json:"pid"`
	StartedAt   string `json:"started_at"`
	Version     string `json:"version"`
}

// Client is a read-only admin client. Address overrides the handshake record so
// a user can probe a daemon started on a non-default port.
type Client struct {
	HandshakePath string
	Address       string
	Timeout       time.Duration
	HTTP          *http.Client
}

var (
	_ cli.AdminPort     = (*Client)(nil)
	_ cli.AddressSetter = (*Client)(nil)
)

func New(handshakePath, address string) *Client {
	return &Client{HandshakePath: handshakePath, Address: address, Timeout: defaultTimeout}
}

// SetAddress receives the parsed --address. The client is constructed before
// Kong parses anything, so this is how a flag the user typed reaches it.
func (client *Client) SetAddress(address string) { client.Address = address }

// Health reports what an unauthenticated liveness and readiness probe found. It
// returns the probe's error alongside the facts it did gather rather than
// folding the error into Detail: a caller reading only the value cannot tell a
// daemon that answered "not ready" from one that never answered, and diagnosing
// the second as the first sends the user to the database holding a connection
// error. The returned Health still carries the address and Reachable, so a
// caller that only wants to know where a daemon would be keeps that.
func (client *Client) Health(ctx context.Context) (cli.Health, error) {
	address, _, discoveryErr := client.discover()
	if discoveryErr != nil && address == "" {
		return cli.Health{}, discoveryErr
	}

	health := cli.Health{Address: address}
	var live struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := client.fetch(ctx, address, pathHealth, nil, "", &live); err != nil {
		health.Detail = err.Error()
		return health, errors.Join(discoveryErr, err)
	}
	health.Reachable = true
	health.Version = live.Version

	var ready struct {
		Status        string `json:"status"`
		SchemaVersion int    `json:"schema_version"`
	}
	if err := client.fetch(ctx, address, pathReady, nil, "", &ready); err != nil {
		health.Detail = err.Error()
		return health, errors.Join(discoveryErr, err)
	}
	health.Ready = ready.Status == "ready"
	health.SchemaVersion = ready.SchemaVersion
	if discoveryErr != nil {
		health.Detail = discoveryErr.Error()
	}
	return health, discoveryErr
}

func (client *Client) Identity(ctx context.Context) (cli.Identity, error) {
	var identity cli.Identity
	return identity, client.get(ctx, pathIdentity, nil, &identity)
}

func (client *Client) Overview(ctx context.Context) (cli.Overview, error) {
	var overview cli.Overview
	return overview, client.get(ctx, pathOverview, nil, &overview)
}

func (client *Client) Projects(ctx context.Context) ([]cli.Project, error) {
	var page struct {
		Projects []cli.Project `json:"projects"`
	}
	return page.Projects, client.get(ctx, pathProjects, nil, &page)
}

func (client *Client) Agents(ctx context.Context, query cli.AgentQuery) (cli.AgentsPage, error) {
	values := url.Values{}
	setNonEmpty(values, "project_key", query.ProjectKey)
	setNonEmpty(values, "agent", query.AgentName)
	setFlag(values, "active", query.ActiveOnly)
	setLimit(values, query.Limit)
	var page cli.AgentsPage
	return page, client.get(ctx, pathAgents, values, &page)
}

func (client *Client) Inbox(ctx context.Context, query cli.InboxQuery) (cli.Inbox, error) {
	values := url.Values{}
	setNonEmpty(values, "project_key", query.ProjectKey)
	setNonEmpty(values, "agent", query.AgentName)
	setFlag(values, "unread", query.UnreadOnly)
	setFlag(values, "unacked", query.UnackedOnly)
	setLimit(values, query.Limit)
	var inbox cli.Inbox
	return inbox, client.get(ctx, pathInbox, values, &inbox)
}

func (client *Client) Conversations(ctx context.Context, query cli.ConversationQuery) (cli.ConversationsPage, error) {
	values := url.Values{}
	setNonEmpty(values, "project_key", query.ProjectKey)
	setNonEmpty(values, "conversation_id", query.ConversationID)
	setFlag(values, "open", query.OpenOnly)
	setLimit(values, query.Limit)
	var page cli.ConversationsPage
	return page, client.get(ctx, pathConversations, values, &page)
}

func (client *Client) Reservations(ctx context.Context, query cli.ReservationQuery) (cli.ReservationsPage, error) {
	values := url.Values{}
	setNonEmpty(values, "project_key", query.ProjectKey)
	setNonEmpty(values, "agent", query.AgentName)
	setNonEmpty(values, "state", query.State)
	setMode(values, query.Mode)
	setNonEmpty(values, "path", query.Path)
	setLimit(values, query.Limit)
	var page cli.ReservationsPage
	return page, client.get(ctx, pathReservations, values, &page)
}

func (client *Client) Events(ctx context.Context, query cli.EventQuery) (cli.EventsPage, error) {
	values := url.Values{}
	setNonEmpty(values, "project_key", query.ProjectKey)
	setNonEmpty(values, "agent", query.AgentName)
	setNonEmpty(values, "type", query.Type)
	setLimit(values, query.Limit)
	var page struct {
		Events []struct {
			cli.Event
			Payload json.RawMessage `json:"payload"`
		} `json:"events"`
		Truncated bool `json:"truncated"`
	}
	if err := client.get(ctx, pathEvents, values, &page); err != nil {
		return cli.EventsPage{}, err
	}
	events := make([]cli.Event, 0, len(page.Events))
	for _, row := range page.Events {
		event := row.Event
		event.PayloadSize = len(row.Payload)
		events = append(events, event)
	}
	return cli.EventsPage{Events: events, Truncated: page.Truncated}, nil
}

func (client *Client) get(ctx context.Context, path string, values url.Values, payload any) error {
	address, token, err := client.discover()
	if err != nil {
		return err
	}
	return client.fetch(ctx, address, path, values, token, payload)
}

func (client *Client) fetch(
	ctx context.Context,
	address, path string,
	values url.Values,
	token string,
	payload any,
) error {
	timeout := client.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := "http://" + address + path
	if len(values) > 0 {
		endpoint += "?" + values.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("contact daemon at %s: %w", address, err)
	}
	defer func() { _ = response.Body.Close() }()

	body := io.LimitReader(response.Body, maximumResponse)
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrStaleHandshake
	case http.StatusServiceUnavailable:
		return errors.New("the daemon is running but its storage is unavailable")
	default:
		return &cli.AdminStatusError{Status: response.StatusCode, Path: path, Detail: problemDetail(body)}
	}
	if err := json.NewDecoder(body).Decode(payload); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// discover reads the handshake record the daemon writes on start. An explicit
// --address still needs the record for its token, so a missing record is only
// fatal for the authenticated endpoints.
func (client *Client) discover() (string, string, error) {
	if client.HandshakePath == "" {
		return client.Address, "", ErrNoHandshake
	}
	content, err := os.ReadFile(client.HandshakePath)
	if err != nil {
		return client.Address, "", client.missingRecord()
	}
	var record handshake
	if err := json.Unmarshal(content, &record); err != nil {
		return client.Address, "", fmt.Errorf("%w: %s", ErrStaleHandshake, client.HandshakePath)
	}
	if record.Schema != handshakeSchema {
		return client.Address, "", fmt.Errorf("%w: unknown schema %q", ErrStaleHandshake, record.Schema)
	}
	address := client.Address
	if address == "" {
		address = record.HTTPAddress
	}
	if address == "" {
		return "", "", ErrNoHandshake
	}
	return address, record.Token, nil
}

// missingRecord says why an explicit address did not rescue the request. The
// record carries the credential as well as the address, so --address reaches
// the unauthenticated probes and nothing else without it.
func (client *Client) missingRecord() error {
	if client.Address == "" {
		return fmt.Errorf("%w: %s", ErrNoHandshake, client.HandshakePath)
	}
	return fmt.Errorf("%w: %s, which is where the daemon's credential lives; --address alone cannot replace it",
		ErrNoHandshake, client.HandshakePath)
}

// problemDetail recovers the daemon's own explanation of a rejection so the
// user reads why the request was refused rather than a bare status code.
func problemDetail(body io.Reader) string {
	var problem struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(body).Decode(&problem); err != nil {
		return ""
	}
	return problem.Message
}

func setNonEmpty(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

// setFlag omits a filter that is off. A daemon older than these predicates
// rejects the parameter name outright, so an unused filter must not be sent.
func setFlag(values url.Values, key string, enabled bool) {
	if enabled {
		values.Set(key, "true")
	}
}

// setMode omits the "any" spelling for the same reason: it selects no predicate
// at all, so sending it would only narrow which daemons answer the request.
func setMode(values url.Values, mode string) {
	if mode != "" && mode != cli.ReservationModeAny {
		values.Set("mode", mode)
	}
}

func setLimit(values url.Values, limit int) {
	if limit > 0 {
		values.Set("limit", strconv.Itoa(limit))
	}
}
