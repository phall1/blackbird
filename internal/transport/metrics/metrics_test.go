package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryRecordsBoundedHTTPOutcomesAndFileSizes(t *testing.T) {
	t.Parallel()
	registry := New()
	database := filepath.Join(t.TempDir(), "blackbird.db")
	if err := os.WriteFile(database, []byte("database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(database+"-wal", []byte("wal"), 0o600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /messages/{id}", func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "no", http.StatusConflict)
	})
	server := httptest.NewServer(registry.WrapHTTP(mux, "/events"))
	defer server.Close()
	for _, id := range []string{"one", "two"} {
		response, err := http.Get(server.URL + "/messages/" + id) //nolint:noctx // httptest request is bounded by local server lifetime.
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}

	registry.ObserveLeaseConflict()
	release := registry.TrackSSE()
	snapshot := registry.Snapshot(database)
	release()
	if got := snapshot.Requests["http GET /messages/{id}"]["4xx"]; got != 2 {
		t.Fatalf("bounded request count = %d, want 2", got)
	}
	if snapshot.LeaseConflicts != 1 || snapshot.SSEConnections != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot.DatabaseBytes != 8 || snapshot.WALBytes != 3 {
		t.Fatalf("file sizes = db %d wal %d", snapshot.DatabaseBytes, snapshot.WALBytes)
	}
	if got := registry.Snapshot(database).SSEConnections; got != 0 {
		t.Fatalf("released SSE gauge = %d", got)
	}
}

func TestHTTPWrapperTracksLiveSSEConnection(t *testing.T) {
	t.Parallel()
	registry := New()
	started := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		writer.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(registry.WrapHTTP(handler, "/events"))
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		response, err := http.Get(server.URL + "/events") //nolint:noctx // released by this test.
		if err == nil {
			_ = response.Body.Close()
		}
		done <- err
	}()
	<-started
	if got := registry.Snapshot("").SSEConnections; got != 1 {
		t.Fatalf("live SSE gauge = %d, want 1", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := registry.Snapshot("").SSEConnections; got != 0 {
		t.Fatalf("completed SSE gauge = %d, want 0", got)
	}
}
