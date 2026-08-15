package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/storage/sqlite"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
)

// nonPortStorage satisfies the daemon's Storage seam without implementing the
// application ports the production graph needs.
type nonPortStorage struct{}

func (nonPortStorage) Close() error { return nil }

func openProductionTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(context.Background(), sqlite.Config{
		Path: filepath.Join(t.TempDir(), "blackbird.db"),
	})
	if err != nil {
		t.Fatalf("open SQLite store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close SQLite store: %v", err)
		}
	})
	return store
}

// TestComposeProductionBuildsBothTransports pins the composition root: the
// real SQLite store must satisfy every application port, and composition must
// yield both a routable HTTP mux and an MCP handler. A missing dependency in
// this graph is a startup failure with no earlier signal.
func TestComposeProductionBuildsBothTransports(t *testing.T) {
	bundle, err := composeProduction(context.Background(), openProductionTestStore(t))
	if err != nil {
		t.Fatalf("composeProduction error: %v", err)
	}
	if bundle.HTTP == nil || bundle.MCP == nil {
		t.Fatalf("bundle HTTP=%v MCP=%v, want both transports composed", bundle.HTTP, bundle.MCP)
	}

	// The mux must serve the local coordination surface and the W0 command API
	// from the same listener. Both prefixes are registered, so neither may 404
	// at the mux itself.
	for method, target := range map[string]string{
		http.MethodGet:  httptransport.PathLocalCoordinationEvents,
		http.MethodPost: httptransport.PathWorkspaceCreate,
	} {
		recorder := httptest.NewRecorder()
		bundle.HTTP.ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
		if recorder.Code == http.StatusNotFound {
			t.Fatalf("%s %s was not routed by the composed mux", method, target)
		}
	}
	recorder := httptest.NewRecorder()
	bundle.MCP.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code == 0 {
		t.Fatal("the composed MCP handler did not respond")
	}
}

func TestComposeProductionRejectsStorageWithoutApplicationPorts(t *testing.T) {
	_, err := composeProduction(context.Background(), nonPortStorage{})
	if err == nil || !strings.Contains(err.Error(), "application ports") {
		t.Fatalf("composeProduction error=%v, want a port-contract failure", err)
	}
}

// TestNewProductionDaemonCleansTheSQLitePath pins that the product resolves and
// cleans the configured database path before the daemon ever opens it, so a
// relative or unclean path cannot escape the intended directory.
func TestNewProductionDaemonCleansTheSQLitePath(t *testing.T) {
	directory := t.TempDir()
	daemon, err := NewProductionDaemon(BuildInfo{Version: "test"}, Config{
		Storage:     StorageSQLite,
		SQLitePath:  filepath.Join(directory, "nested", "..", "blackbird.db"),
		HTTPAddress: "127.0.0.1:0",
		MCPAddress:  "127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("NewProductionDaemon error: %v", err)
	}
	want := filepath.Join(directory, "blackbird.db")
	if daemon.config.SQLitePath != want {
		t.Fatalf("SQLite path=%q, want %q", daemon.config.SQLitePath, want)
	}
}
