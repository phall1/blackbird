package cli

import (
	"errors"
	"strings"
	"testing"
)

// The exit codes are the contract with scripts and with launchd, and a caller
// reacts to them without reading a word of the report. These tables walk every
// command so no single one can drift: bad input is 2, a named entity that does
// not exist is 3, and a daemon that cannot answer is 4.

func TestBadInputExitsUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown command", args: []string{"nosuchthing"}},
		{name: "unknown flag", args: []string{"status", "--nosuchflag"}},
		{name: "unparsable duration", args: []string{"status", "--timeout=nonsense"}},
		{name: "unknown check name", args: []string{"doctor", "--only=nonesuch"}},
		{name: "unknown log stream", args: []string{"logs", "--stream=bogus"}},
		{name: "follow with json", args: []string{"logs", "--follow", "--json"}},
		{name: "unknown reservation mode", args: []string{"reservations", "list", "--mode=bogus"}},
		{name: "unknown shell", args: []string{"completion", "klingon"}},
		{name: "help for an unknown command", args: []string{"help", "nosuchthing"}},
		{name: "relative database path", args: []string{"--db=relative/blackbird.db", "status"}},
		{name: "address off the machine", args: []string{"--address=192.168.1.9:8080", "overview"}},
		{name: "address without a port", args: []string{"--address=nonsense", "overview"}},
		{name: "unknown color choice", args: []string{"--color=chartreuse", "status"}},
		{name: "negative width", args: []string{"--width=-1", "status"}},
		{name: "relative daemon database", args: []string{"daemon", "--sqlite-path=relative.db"}},
		{name: "empty agents page", args: []string{"agents", "list", "--limit=0"}},
		{name: "empty inbox page", args: []string{"inbox", "--limit=0"}},
		{name: "empty threads page", args: []string{"threads", "list", "--limit=0"}},
		{name: "empty reservations page", args: []string{"reservations", "list", "--limit=0"}},
		{name: "empty events page", args: []string{"events", "--limit=0"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			deps := dependencies(t)
			deps.Admin = &fakeAdmin{}
			deps.Store = &fakeStore{database: healthyDatabase()}
			deps.Product = &fakeProduct{}
			deps.Logs = &fakeLogs{}
			deps.Daemon = &recordingDaemon{}

			result := runCLI(t, deps, test.args)
			if result.code != ExitUsage {
				t.Fatalf("%v: code = %d, want %d; stderr=%q", test.args, result.code, ExitUsage, result.stderr)
			}
		})
	}
}

func TestNamedEntityThatDoesNotExistExitsNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{name: "project", args: []string{"projects", "show", "/nowhere"}},
		{name: "agent", args: []string{"agents", "show", "ghost"}},
		{name: "inbox owner", args: []string{"inbox", "ghost", "--project=/a"}},
		{name: "conversation", args: []string{"threads", "show", "c-nowhere"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			deps := dependencies(t)
			deps.Admin = &fakeAdmin{
				projects:      []Project{{ProjectKey: "/a"}},
				agents:        []Agent{{ProjectKey: "/a", AgentName: "scout"}},
				conversations: []Conversation{{ConversationID: "c1", ProjectKey: "/a"}},
				inbox:         Inbox{ProjectKey: "/a"},
			}

			result := runCLI(t, deps, test.args)
			if result.code != ExitNotFound {
				t.Fatalf("%v: code = %d, want %d; stderr=%q", test.args, result.code, ExitNotFound, result.stderr)
			}
		})
	}
}

func TestDaemonThatCannotAnswerExitsUnavailable(t *testing.T) {
	t.Parallel()

	commands := [][]string{
		{"overview"},
		{"projects"},
		{"projects", "list"},
		{"projects", "show", "/a"},
		{"agents"},
		{"agents", "list"},
		{"agents", "show", "scout"},
		{"inbox"},
		{"threads"},
		{"threads", "list"},
		{"threads", "show", "c1"},
		{"reservations"},
		{"reservations", "list"},
		{"events"},
		{"status", "--require-running"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()

			deps := dependencies(t)
			deps.Admin = &fakeAdmin{err: errors.New("connection refused")}
			deps.Store = &fakeStore{database: healthyDatabase()}
			deps.Product = &fakeProduct{}

			result := runCLI(t, deps, args)
			if result.code != ExitUnavailable {
				t.Fatalf("%v: code = %d, want %d; stderr=%q", args, result.code, ExitUnavailable, result.stderr)
			}
		})
	}
}
