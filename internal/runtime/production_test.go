package runtime

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/storage/sqlite"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
)

func TestProductionCompositionRoutesHealthAndAdminAheadOfTheCatchAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	stateDir := t.TempDir()
	databasePath := filepath.Join(t.TempDir(), "blackbird.db")
	store, err := sqlite.Open(ctx, sqlite.Config{Path: databasePath})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	build := BuildInfo{Version: "0.4.0", Commit: "abc1234", BuiltAt: "2026-08-15T00:00:00Z"}
	config := Config{
		Storage: StorageSQLite, SQLitePath: databasePath, StateDir: stateDir,
		HTTPAddress: "127.0.0.1:8080", MCPAddress: "127.0.0.1:8081",
	}
	compose := composeProduction(build, config, slog.New(slog.DiscardHandler))
	bundle, err := compose(ctx, store)
	if err != nil {
		t.Fatalf("composeProduction() error = %v", err)
	}
	if len(bundle.Workers) != 1 {
		t.Fatalf("workers = %d, want 1", len(bundle.Workers))
	}
	server := httptest.NewServer(bundle.HTTP)
	t.Cleanup(server.Close)

	health := requestJSON(t, server.Client(), http.MethodGet, server.URL+httptransport.PathHealth, "")
	if health.status != http.StatusOK || health.body["version"] != "0.4.0" {
		t.Fatalf("healthz = %d %v", health.status, health.body)
	}
	ready := requestJSON(t, server.Client(), http.MethodGet, server.URL+httptransport.PathReady, "")
	if ready.status != http.StatusOK || ready.body["status"] != "ready" {
		t.Fatalf("readyz = %d %v", ready.status, ready.body)
	}
	unauthenticated := requestJSON(t, server.Client(), http.MethodGet, server.URL+httptransport.PathLocalAdminOverview, "")
	if unauthenticated.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated admin overview = %d, want 401", unauthenticated.status)
	}
	catchAll, err := server.Client().Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = catchAll.Body.Close() }()
	if catchAll.StatusCode == http.StatusOK {
		t.Fatal("the W0 catch-all answered the root as if it were the health surface")
	}

	worker := bundle.Workers[0]
	if err := worker.Start(ctx); err != nil {
		t.Fatalf("worker Start() error = %v", err)
	}
	t.Cleanup(func() { _ = worker.Stop(ctx) })
	content, err := os.ReadFile(filepath.Join(stateDir, "admin.json"))
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	var handshake adminHandshake
	if err := json.Unmarshal(content, &handshake); err != nil {
		t.Fatalf("decode handshake: %v", err)
	}
	if handshake.HTTPAddress != config.HTTPAddress || handshake.Version != build.Version {
		t.Fatalf("handshake = %#v", handshake)
	}
	authenticated := requestJSON(t, server.Client(), http.MethodGet, server.URL+httptransport.PathLocalAdminOverview, handshake.Token)
	if authenticated.status != http.StatusOK {
		t.Fatalf("admin overview with the published token = %d %v", authenticated.status, authenticated.body)
	}
}

// An ephemeral port is resolved by the kernel at bind time, so a record built
// from configuration publishes ":0" and no client can ever reach the daemon.
func TestHandshakePublishesTheBoundAddressForAnEphemeralPort(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	config := Config{
		Storage: StorageSQLite, SQLitePath: filepath.Join(t.TempDir(), "blackbird.db"), StateDir: stateDir,
		HTTPAddress: "127.0.0.1:0", MCPAddress: "localhost:0", ShutdownTimeout: 5 * time.Second,
	}
	build := BuildInfo{Version: "0.4.0", Commit: "abc1234", BuiltAt: "2026-08-15T00:00:00Z"}
	ready := make(chan struct{})
	daemon, err := NewDaemon(build, config, Dependencies{
		Logger:  slog.New(slog.DiscardHandler),
		Compose: composeProduction(build.Normalize(), config, slog.New(slog.DiscardHandler)),
		Ready:   func() { close(ready) },
	})
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run() error = %v", err)
		}
	})
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("daemon stopped before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not become ready")
	}

	content, err := os.ReadFile(filepath.Join(stateDir, "admin.json"))
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	var handshake adminHandshake
	if err := json.Unmarshal(content, &handshake); err != nil {
		t.Fatalf("decode handshake: %v", err)
	}
	_, port, err := net.SplitHostPort(handshake.HTTPAddress)
	if err != nil {
		t.Fatalf("published address %q: %v", handshake.HTTPAddress, err)
	}
	if port == "0" {
		t.Fatalf("published address = %q, want the bound port", handshake.HTTPAddress)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	overview := requestJSON(t, client,
		http.MethodGet, "http://"+handshake.HTTPAddress+httptransport.PathLocalAdminOverview, handshake.Token)
	if overview.status != http.StatusOK {
		t.Fatalf("admin overview at the published address = %d %v", overview.status, overview.body)
	}
}

type jsonResponse struct {
	status int
	body   map[string]any
}

func requestJSON(t *testing.T, client *http.Client, method, url, token string) jsonResponse {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = response.Body.Close() }()
	body := make(map[string]any)
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil && err != io.EOF {
		t.Fatalf("decode %s: %v", url, err)
	}
	return jsonResponse{status: response.StatusCode, body: body}
}
