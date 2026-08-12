package beads

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	validVersion = `{"branch":"v1.1.2","build":"Homebrew","schema_version":1,"version":"1.1.2"}`
	validIssue   = `[{"id":"bd-fam.2.2","title":"Work boundary","status":"in_progress","priority":1,"issue_type":"feature","assignee":"agent","updated_at":"2026-08-05T19:41:30Z","dependencies":[{"id":"bd-fam.2.1","status":"closed","dependency_type":"blocks"}],"provider_extra":"ignored"}]`
)

func TestMain(m *testing.M) {
	if os.Getenv("BLACKBIRD_BD_FAKE") != "" {
		runFakeExecutable()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runFakeExecutable() {
	mode := os.Getenv("BLACKBIRD_BD_FAKE")
	if mode == "sleep" {
		time.Sleep(10 * time.Second)
		return
	}
	if mode == "large" {
		_, _ = os.Stdout.WriteString(strings.Repeat("x", 4096))
		return
	}
	arguments := os.Args[1:]
	if slices.Equal(arguments, []string{"--json", "version"}) {
		response := validVersion
		if mode == "incompatible" {
			response = strings.Replace(response, `"1.1.2"`, `"2.0.0"`, 1)
		}
		if mode == "malformed" {
			response = `{"version":"1.1.2","schema_version":1,"unknown":true}`
		}
		_, _ = os.Stdout.WriteString(response)
		return
	}
	if len(arguments) == 7 && arguments[0] == "-C" && arguments[2] == "--readonly" &&
		slices.Equal(arguments[3:7], []string{"--json", "show", "--id", "bd-fam.2.2"}) {
		_, _ = os.Stdout.WriteString(validIssue)
		return
	}
	_, _ = os.Stderr.WriteString("unexpected fake invocation")
	os.Exit(42)
}

func TestProbeAndObserveContract(t *testing.T) {
	t.Setenv("BLACKBIRD_BD_FAKE", "valid")
	adapter := newTestAdapter(t, 1024)
	probe := adapter.Probe()
	if probe.Provider != ProviderName || probe.Version != SupportedVersion ||
		probe.SchemaVersion != SupportedSchemaVersion ||
		!slices.Equal(probe.Capabilities, []string{CapabilityObserveWork}) ||
		probe.BinarySHA256 == "" || !filepath.IsAbs(probe.Executable) {
		t.Fatalf("Probe() = %#v", probe)
	}
	encoded, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"schema_version":1`, `"capabilities":["work_reference.observe"]`, `"binary_sha256":"`} {
		if !strings.Contains(string(encoded), field) {
			t.Errorf("probe JSON %s lacks %s", encoded, field)
		}
	}

	observed, err := adapter.Observe(context.Background(), "bd-fam.2.2")
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if observed.Provider != ProviderName || observed.Project != "blackbird" || observed.ObjectID != "bd-fam.2.2" ||
		observed.ObservedVersion != "2026-08-05T19:41:30Z" || observed.ObservedAt.IsZero() {
		t.Fatalf("observation identity = %#v", observed)
	}
	if observed.Fields.Title != "Work boundary" || observed.Fields.Priority != 1 ||
		observed.Fields.Status != "in_progress" || observed.Fields.Assignee != "agent" ||
		!slices.Equal(observed.Fields.Dependencies, []Dependency{{ObjectID: "bd-fam.2.1", Type: "blocks", Status: "closed"}}) {
		t.Fatalf("observation fields = %#v", observed.Fields)
	}
	if observed.Provenance.BinarySHA256 != probe.BinarySHA256 {
		t.Fatal("observation lost executable provenance")
	}

	transcript := adapter.Transcript()
	if len(transcript) != 2 || transcript[0].Sequence != 1 || transcript[1].Sequence != 2 {
		t.Fatalf("Transcript() = %#v", transcript)
	}
	wantObserve := []string{"-C", testProjectDir(t), "--readonly", "--json", "show", "--id", "bd-fam.2.2"}
	if !slices.Equal(transcript[0].Arguments, []string{"--json", "version"}) ||
		!slices.Equal(transcript[1].Arguments, wantObserve) {
		t.Fatalf("transcript arguments = %#v", transcript)
	}
	for _, invocation := range transcript {
		if invocation.BinarySHA256 == "" || invocation.StdoutSHA256 == "" || invocation.StderrSHA256 == "" ||
			invocation.StdoutBytes <= 0 || invocation.OutputLimited || invocation.Canceled {
			t.Errorf("invalid transcript entry: %#v", invocation)
		}
	}
}

func TestTypedFailuresAndCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := Config{Executable: executable, ProjectDir: testProjectDir(t), Project: "blackbird", Timeout: 5 * time.Second, MaxOutputBytes: 1024}
	for _, test := range []struct {
		name string
		mode string
		kind ErrorKind
	}{
		{name: "incompatible", mode: "incompatible", kind: ErrorIncompatible},
		{name: "malformed", mode: "malformed", kind: ErrorMalformed},
		{name: "bounded", mode: "large", kind: ErrorMalformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("BLACKBIRD_BD_FAKE", test.mode)
			config := base
			if test.mode == "large" {
				config.MaxOutputBytes = 32
			}
			_, err := New(context.Background(), config)
			if !IsErrorKind(err, test.kind) {
				t.Fatalf("New() error = %v, want %s", err, test.kind)
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		config := base
		config.Executable = filepath.Join(t.TempDir(), "absent")
		_, err := New(context.Background(), config)
		if !IsErrorKind(err, ErrorUnavailable) {
			t.Fatalf("New() error = %v", err)
		}
	})

	t.Run("deadline kills process", func(t *testing.T) {
		t.Setenv("BLACKBIRD_BD_FAKE", "sleep")
		config := base
		config.Timeout = 50 * time.Millisecond
		started := time.Now()
		_, err := New(context.Background(), config)
		if !IsErrorKind(err, ErrorUnavailable) || time.Since(started) > 2*time.Second {
			t.Fatalf("New() = %v after %s", err, time.Since(started))
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				t.Fatalf("deadline cause = %v", err)
			}
		}
	})

	t.Run("cancellation kills process", func(t *testing.T) {
		t.Setenv("BLACKBIRD_BD_FAKE", "sleep")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		started := time.Now()
		_, err := New(ctx, base)
		if !IsErrorKind(err, ErrorUnavailable) || time.Since(started) > 2*time.Second {
			t.Fatalf("New() = %v after %s", err, time.Since(started))
		}
	})
}

func TestInputAndTranscriptDefensiveCopies(t *testing.T) {
	t.Setenv("BLACKBIRD_BD_FAKE", "valid")
	adapter := newTestAdapter(t, 1024)
	if _, err := adapter.Observe(context.Background(), "--help"); !IsErrorKind(err, ErrorMalformed) {
		t.Fatalf("Observe() error = %v", err)
	}
	probe := adapter.Probe()
	probe.Capabilities[0] = "changed"
	if adapter.Probe().Capabilities[0] != CapabilityObserveWork {
		t.Fatal("Probe returned shared capability storage")
	}
	transcript := adapter.Transcript()
	transcript[0].Arguments[0] = "changed"
	if adapter.Transcript()[0].Arguments[0] != "--json" {
		t.Fatal("Transcript returned shared argument storage")
	}
}

func TestStaticBoundaryHasNoShellOrProviderStorageKnowledge(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	implementation := filepath.Join(filepath.Dir(currentFile), "beads.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), implementation, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenImports := []string{"database/sql", "/storage/", "dolthub", "gastownhall", "steveyegge"}
	for _, spec := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(spec.Path.Value)
		if unquoteErr != nil {
			t.Fatal(unquoteErr)
		}
		for _, forbidden := range forbiddenImports {
			if strings.Contains(path, forbidden) {
				t.Errorf("forbidden import %q", path)
			}
		}
	}
	forbiddenLiterals := []string{".beads", "SELECT ", "INSERT ", "CREATE TABLE", "ALTER TABLE"}
	forbiddenShells := []string{"sh", "bash", "zsh", "powershell", "cmd.exe"}
	ast.Inspect(parsed, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, unquoteErr := strconv.Unquote(literal.Value)
		if unquoteErr != nil {
			return true
		}
		for _, forbidden := range forbiddenLiterals {
			if strings.Contains(value, forbidden) {
				t.Errorf("forbidden implementation literal %q", forbidden)
			}
		}
		if slices.Contains(forbiddenShells, value) {
			t.Errorf("forbidden shell literal %q", value)
		}
		return true
	})
}

func TestRealSupportedInterface(t *testing.T) {
	if os.Getenv("BLACKBIRD_RUN_EXTERNAL_TESTS") != "1" {
		t.Skip("set BLACKBIRD_RUN_EXTERNAL_TESTS=1 to probe the installed bd and live issue store")
	}
	const executable = "/opt/homebrew/bin/bd"
	if _, err := os.Stat(executable); err != nil {
		t.Skip("supported bd fixture is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	adapter, err := New(ctx, Config{
		Executable: executable, ProjectDir: repositoryRoot(t), Project: "blackbird",
		Timeout: 5 * time.Second, MaxOutputBytes: 256 << 10,
	})
	if IsErrorKind(err, ErrorIncompatible) {
		t.Skipf("installed bd does not expose the supported interface: %v", err)
	}
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	observed, err := adapter.Observe(ctx, "bd-fam.2.2")
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if observed.ObjectID != "bd-fam.2.2" || observed.ObservedVersion == "" || observed.Fields.Title == "" {
		t.Fatalf("real observation = %#v", observed)
	}
}

func newTestAdapter(t *testing.T, maxOutput int) *Adapter {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(context.Background(), Config{
		Executable: executable, ProjectDir: testProjectDir(t), Project: "blackbird",
		Timeout: 5 * time.Second, MaxOutputBytes: maxOutput,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return adapter
}

func testProjectDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("testdata", "opaque-project"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return path
}
