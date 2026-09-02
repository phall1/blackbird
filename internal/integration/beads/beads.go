// Package beads observes provider-owned work through the supported bd CLI.
package beads

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phall1/blackbird/internal/application"
)

const (
	ProviderName           = "beads"
	SupportedVersion       = "1.2.2"
	SupportedSchemaVersion = 1
	CapabilityObserveWork  = "work_reference.observe"

	defaultTimeout        = 5 * time.Second
	defaultMaxOutputBytes = 1 << 20
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ErrorKind is a stable provider-neutral dependency failure category.
type ErrorKind string

const (
	ErrorUnavailable  ErrorKind = "dependency_unavailable"
	ErrorIncompatible ErrorKind = "dependency_incompatible"
	ErrorMalformed    ErrorKind = "dependency_malformed"
)

// DependencyError reports a safe boundary failure without provider output.
type DependencyError struct {
	Kind      ErrorKind
	Operation string
	Detail    string
	Cause     error
}

func (e *DependencyError) Error() string {
	return fmt.Sprintf("%s %s: %s", ProviderName, e.Operation, e.Kind)
}

func (e *DependencyError) Unwrap() error { return e.Cause }

func IsErrorKind(err error, kind ErrorKind) bool {
	var dependencyError *DependencyError
	return errors.As(err, &dependencyError) && dependencyError.Kind == kind
}

// Config contains composition inputs; ProjectDir is an opaque CLI locator.
type Config struct {
	Executable     string
	ProjectDir     string
	Project        string
	Timeout        time.Duration
	MaxOutputBytes int
}

// Provider-neutral work observations live at the application boundary; these
// aliases preserve the adapter's public API.
type Probe = application.WorkReferenceProvenance
type Dependency = application.WorkReferenceDependency
type WorkFields = application.WorkReferenceFields
type WorkReference = application.WorkReference

// Invocation is a stable, body-free audit record of one direct execution.
type Invocation struct {
	Sequence      uint64   `json:"sequence"`
	Operation     string   `json:"operation"`
	Executable    string   `json:"executable"`
	Arguments     []string `json:"arguments"`
	BinarySHA256  string   `json:"binary_sha256"`
	ExitCode      int      `json:"exit_code"`
	StdoutBytes   int64    `json:"stdout_bytes"`
	StderrBytes   int64    `json:"stderr_bytes"`
	StdoutSHA256  string   `json:"stdout_sha256"`
	StderrSHA256  string   `json:"stderr_sha256"`
	OutputLimited bool     `json:"output_limited"`
	Canceled      bool     `json:"canceled"`
}

// Provider is the provider-neutral surface consumed by later application code.
type Provider interface {
	Probe() Probe
	Observe(context.Context, string) (WorkReference, error)
	Transcript() []Invocation
}

// Adapter executes the supported bd interface directly.
type Adapter struct {
	config Config
	probe  Probe
	runner *runner
}

var _ Provider = (*Adapter)(nil)

// New validates configuration and probes the exact supported interface.
func New(ctx context.Context, config Config) (*Adapter, error) {
	config, digest, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	r := &runner{
		executable: config.Executable,
		digest:     digest,
		timeout:    config.Timeout,
		maxOutput:  config.MaxOutputBytes,
	}
	result := r.run(ctx, "probe", "--json", "version")
	if err := classifyResult("probe", result); err != nil {
		return nil, err
	}
	var version versionResponse
	if err := decodeStrict(result.stdout, &version); err != nil {
		return nil, malformed("probe", "version response does not match schema", err)
	}
	if version.Version == "" || version.Build == "" || version.Branch == "" {
		return nil, malformed("probe", "version response omits required provenance", nil)
	}
	if version.Version != SupportedVersion || version.SchemaVersion != SupportedSchemaVersion {
		return nil, &DependencyError{
			Kind: ErrorIncompatible, Operation: "probe",
			Detail: "provider version or schema is unsupported",
		}
	}
	probe := Probe{
		Provider: ProviderName, Version: version.Version, Build: version.Build,
		Branch: version.Branch, SchemaVersion: version.SchemaVersion,
		Capabilities: []string{CapabilityObserveWork},
		Executable:   config.Executable, BinarySHA256: digest,
	}
	return &Adapter{config: config, probe: probe, runner: r}, nil
}

func validateConfig(config Config) (Config, string, error) {
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.MaxOutputBytes == 0 {
		config.MaxOutputBytes = defaultMaxOutputBytes
	}
	if !filepath.IsAbs(config.Executable) {
		return Config{}, "", &DependencyError{Kind: ErrorUnavailable, Operation: "configure", Detail: "executable must be absolute"}
	}
	if !filepath.IsAbs(config.ProjectDir) || !validProject(config.Project) ||
		config.Timeout <= 0 || config.MaxOutputBytes <= 0 {
		return Config{}, "", &DependencyError{Kind: ErrorMalformed, Operation: "configure", Detail: "configuration is invalid"}
	}
	info, err := os.Stat(config.Executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return Config{}, "", &DependencyError{Kind: ErrorUnavailable, Operation: "configure", Detail: "executable is unavailable", Cause: err}
	}
	digest, err := fileDigest(config.Executable)
	if err != nil {
		return Config{}, "", &DependencyError{Kind: ErrorUnavailable, Operation: "configure", Detail: "executable cannot be verified", Cause: err}
	}
	return config, digest, nil
}

func validProject(project string) bool {
	if identifierPattern.MatchString(project) {
		return true
	}
	return len(project) <= 4096 && filepath.IsAbs(project) && filepath.Clean(project) == project &&
		!strings.ContainsAny(project, "\x00\r\n")
}

func (a *Adapter) Probe() Probe {
	probe := a.probe
	probe.Capabilities = slices.Clone(probe.Capabilities)
	return probe
}

// Observe reads one issue through the supported read-only JSON interface.
func (a *Adapter) Observe(ctx context.Context, objectID string) (WorkReference, error) {
	if !identifierPattern.MatchString(objectID) {
		return WorkReference{}, malformed("observe", "object id is invalid", nil)
	}
	result := a.runner.run(
		ctx, "observe", "-C", a.config.ProjectDir, "--readonly", "--json", "show", "--id", objectID,
	)
	if err := classifyResult("observe", result); err != nil {
		return WorkReference{}, err
	}
	issue, err := decodeIssue(result.stdout)
	if err != nil {
		return WorkReference{}, malformed("observe", "issue response does not match schema", err)
	}
	if issue.ID != objectID {
		return WorkReference{}, malformed("observe", "provider returned a different object", nil)
	}
	dependencies := make([]Dependency, len(issue.Dependencies))
	for index, dependency := range issue.Dependencies {
		dependencies[index] = Dependency{
			ObjectID: dependency.ID, Type: dependency.DependencyType, Status: dependency.Status,
		}
	}
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].ObjectID != dependencies[j].ObjectID {
			return dependencies[i].ObjectID < dependencies[j].ObjectID
		}
		return dependencies[i].Type < dependencies[j].Type
	})
	return WorkReference{
		Provider: ProviderName, Project: a.config.Project, ObjectID: issue.ID,
		ObservedVersion: issue.UpdatedAt.UTC().Format(time.RFC3339Nano),
		ObservedAt:      time.Now().UTC(),
		Fields: WorkFields{
			Title: issue.Title, IssueType: issue.IssueType, Status: issue.Status,
			Priority: issue.Priority, Assignee: issue.Assignee, Dependencies: dependencies,
		},
		Provenance: a.Probe(),
	}, nil
}

func (a *Adapter) Transcript() []Invocation { return a.runner.transcriptCopy() }

type versionResponse struct {
	Branch        string `json:"branch"`
	Build         string `json:"build"`
	SchemaVersion int    `json:"schema_version"`
	Version       string `json:"version"`
}

type issueResponse struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Status       string    `json:"status"`
	Priority     int       `json:"priority"`
	IssueType    string    `json:"issue_type"`
	Assignee     string    `json:"assignee"`
	UpdatedAt    time.Time `json:"updated_at"`
	Dependencies []struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		DependencyType string `json:"dependency_type"`
	} `json:"dependencies"`
}

func decodeIssue(data []byte) (issueResponse, error) {
	var issues []issueResponse
	if err := decodeOneJSON(data, &issues, false); err != nil {
		return issueResponse{}, err
	}
	if len(issues) != 1 {
		return issueResponse{}, fmt.Errorf("expected one issue, got %d", len(issues))
	}
	issue := issues[0]
	if issue.ID == "" || issue.Title == "" || issue.Status == "" || issue.IssueType == "" ||
		issue.UpdatedAt.IsZero() || issue.Priority < 0 || issue.Priority > 4 {
		return issueResponse{}, errors.New("required issue field is absent or invalid")
	}
	for _, dependency := range issue.Dependencies {
		if dependency.ID == "" || dependency.Status == "" || dependency.DependencyType == "" {
			return issueResponse{}, errors.New("required dependency field is absent")
		}
	}
	return issue, nil
}

func decodeStrict(data []byte, target any) error { return decodeOneJSON(data, target, true) }

func decodeOneJSON(data []byte, target any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func malformed(operation, detail string, cause error) error {
	return &DependencyError{Kind: ErrorMalformed, Operation: operation, Detail: detail, Cause: cause}
}

type commandResult struct {
	stdout, stderr []byte
	err            error
	limited        bool
	canceled       bool
}

func classifyResult(operation string, result commandResult) error {
	if result.limited {
		return malformed(operation, "provider output exceeded configured bound", result.err)
	}
	if result.err != nil {
		return &DependencyError{Kind: ErrorUnavailable, Operation: operation, Detail: "provider invocation failed", Cause: result.err}
	}
	return nil
}

type runner struct {
	executable string
	digest     string
	timeout    time.Duration
	maxOutput  int

	mu         sync.Mutex
	transcript []Invocation
}

func (r *runner) run(ctx context.Context, operation string, arguments ...string) commandResult {
	runContext, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	stdout := newBoundedWriter(r.maxOutput)
	stderr := newBoundedWriter(r.maxOutput)
	command := exec.CommandContext(runContext, r.executable, arguments...)
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return command.Process.Kill()
	}
	command.WaitDelay = time.Second
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}
	}
	canceled := runContext.Err() != nil
	invocation := Invocation{
		Operation: operation, Executable: r.executable, Arguments: slices.Clone(arguments),
		BinarySHA256: r.digest, ExitCode: exitCode,
		StdoutBytes: stdout.totalBytes(), StderrBytes: stderr.totalBytes(),
		StdoutSHA256: stdout.digest(), StderrSHA256: stderr.digest(),
		OutputLimited: stdout.limitedOutput() || stderr.limitedOutput(), Canceled: canceled,
	}
	r.mu.Lock()
	invocation.Sequence = uint64(len(r.transcript) + 1)
	r.transcript = append(r.transcript, invocation)
	r.mu.Unlock()
	return commandResult{
		stdout: stdout.bytes(), stderr: stderr.bytes(), err: err,
		limited: invocation.OutputLimited, canceled: canceled,
	}
}

func (r *runner) transcriptCopy() []Invocation {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Invocation, len(r.transcript))
	for index, invocation := range r.transcript {
		result[index] = invocation
		result[index].Arguments = slices.Clone(invocation.Arguments)
	}
	return result
}

type boundedWriter struct {
	limit   int
	buffer  bytes.Buffer
	total   int64
	limited bool
	hash    hash.Hash
	mu      sync.Mutex
}

func newBoundedWriter(limit int) *boundedWriter {
	return &boundedWriter{limit: limit, hash: sha256.New()}
}

func (writer *boundedWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.total += int64(len(data))
	_, _ = writer.hash.Write(data)
	remaining := writer.limit - writer.buffer.Len()
	if remaining > 0 {
		_, _ = writer.buffer.Write(data[:min(remaining, len(data))])
	}
	if len(data) > remaining {
		writer.limited = true
	}
	return len(data), nil
}

func (writer *boundedWriter) bytes() []byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return bytes.Clone(writer.buffer.Bytes())
}

func (writer *boundedWriter) totalBytes() int64 {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.total
}

func (writer *boundedWriter) limitedOutput() bool {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.limited
}

func (writer *boundedWriter) digest() string {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return hex.EncodeToString(writer.hash.Sum(nil))
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hashed := sha256.New()
	_, copyErr := io.Copy(hashed, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", err
	}
	return hex.EncodeToString(hashed.Sum(nil)), nil
}
