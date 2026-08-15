package cli

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/alecthomas/kong"

	"github.com/phall1/blackbird/internal/cli/render"
)

// Exit codes are the CLI's contract with scripts and with launchd. They are
// documented in README.md and asserted by the exit-code tests.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitNotFound    = 3
	ExitUnavailable = 4
	ExitDegraded    = 5
)

var exitNames = map[int]string{
	ExitOK:          "ok",
	ExitError:       "error",
	ExitUsage:       "usage",
	ExitNotFound:    "not-found",
	ExitUnavailable: "unavailable",
	ExitDegraded:    "degraded",
}

// AdminStatusError is a rejection the daemon answered with. It is declared here
// rather than in the client so the exit contract can classify it: a 400 caused
// by user input must not be reported as an unavailable daemon.
type AdminStatusError struct {
	Status int
	Path   string
	Detail string
}

func (err *AdminStatusError) Error() string {
	if err.Detail == "" {
		return fmt.Sprintf("daemon answered %d for %s", err.Status, err.Path)
	}
	return fmt.Sprintf("daemon answered %d for %s: %s", err.Status, err.Path, err.Detail)
}

// FaultError is a command failure that names its own exit code and, where one
// exists, the remedy the user should run next.
type FaultError struct {
	Code    int
	Message string
	Remedy  string
	Cause   error
}

func (fault *FaultError) Error() string {
	if fault.Cause == nil {
		return fault.Message
	}
	return fault.Message + ": " + fault.Cause.Error()
}

func (fault *FaultError) Unwrap() error { return fault.Cause }

func fault(code int, cause error, format string, args ...any) *FaultError {
	return &FaultError{Code: code, Message: fmt.Sprintf(format, args...), Cause: cause}
}

func withRemedy(err *FaultError, remedy string) *FaultError {
	err.Remedy = remedy
	return err
}

func usageFault(format string, args ...any) *FaultError {
	return fault(ExitUsage, nil, format, args...)
}

func notFoundFault(format string, args ...any) *FaultError {
	return fault(ExitNotFound, nil, format, args...)
}

func unavailableFault(cause error, format string, args ...any) *FaultError {
	return fault(ExitUnavailable, cause, format, args...)
}

// daemonFault classifies an admin failure against the exit contract. A request
// the daemon rejected on its merits is the caller's fault and carries the
// daemon's own message; only a daemon that could not answer is unavailable, and
// only that case has a remedy worth printing.
func daemonFault(cause error, action string) error {
	var rejected *AdminStatusError
	if errors.As(cause, &rejected) {
		if code := adminExitCode(rejected.Status); code != ExitUnavailable {
			return fault(code, cause, "%s", action)
		}
	}
	return withRemedy(unavailableFault(cause, "%s", action), "run \"blackbird status\" to check the daemon")
}

func adminExitCode(status int) int {
	switch {
	case status == http.StatusBadRequest:
		return ExitUsage
	case status == http.StatusNotFound:
		return ExitNotFound
	case status >= http.StatusInternalServerError:
		return ExitUnavailable
	default:
		return ExitError
	}
}

// exitCodeFor classifies a command or parse failure. Kong's own ExitCode is 80
// for usage errors, which is not our contract, so parse errors are mapped here
// rather than through FatalIfErrorf.
func exitCodeFor(err error) int {
	if err == nil {
		return ExitOK
	}
	var carried *FaultError
	if errors.As(err, &carried) {
		return carried.Code
	}
	var parse *kong.ParseError
	if errors.As(err, &parse) {
		return ExitUsage
	}
	return ExitError
}

func exitName(code int) string {
	if name, ok := exitNames[code]; ok {
		return name
	}
	return "error"
}

// errorEnvelope is the --json failure payload. It goes to stderr so that a
// success payload piped into jq is never mixed with a failure.
type errorEnvelope struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Exit    int    `json:"exit"`
	Message string `json:"message"`
	Remedy  string `json:"remedy,omitempty"`
}

func drawErrorEnvelope(doc *render.Document, envelope errorEnvelope) {
	doc.Status(render.StatusError, envelope.Error.Message)
	if envelope.Error.Remedy != "" {
		doc.Line(render.RoleMuted, "  remedy: "+envelope.Error.Remedy)
	}
}

func newErrorEnvelope(err error, code int) errorEnvelope {
	detail := errorDetail{Code: exitName(code), Exit: code, Message: err.Error()}
	var carried *FaultError
	if errors.As(err, &carried) {
		detail.Remedy = carried.Remedy
	}
	return errorEnvelope{Error: detail}
}
