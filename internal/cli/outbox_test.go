package cli

import (
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/adminapi"
)

func runOutbox(t *testing.T, page adminapi.OutboxPage, args ...string) string {
	t.Helper()
	deps := dependencies(t)
	deps.Admin = &fakeAdmin{outbox: page}
	// The table trims to the terminal, and these assertions are about what the
	// command says rather than about how narrow a window can get.
	deps.WidthProbe = func() (int, bool) { return 160, true }
	result := runCLI(t, deps, append([]string{"outbox"}, args...))
	if result.code != ExitOK {
		t.Fatalf("outbox exited %d; stderr=%q", result.code, result.stderr)
	}
	return result.stdout
}

// TestOutboxSeparatesWaitingFromTerminal is the distinction the command exists
// to draw. A queued delivery is waiting and will be retried; an undeliverable
// one is a job -- the peer answered and refused, and no amount of waiting
// changes that. An operator who cannot tell them apart cannot tell "the mail is
// on its way" from "the mail is never going to arrive".
func TestOutboxSeparatesWaitingFromTerminal(t *testing.T) {
	t.Parallel()

	output := runOutbox(t, adminapi.OutboxPage{
		ProjectKey: "/repo",
		Entries: []adminapi.OutboxItem{
			{MessageID: "01J1", Host: "phalls-mac-mini", ToAgent: "reviewer", FromAgent: "author",
				State: "queued", Attempts: 2, LastError: "connection refused",
				NextAttemptAt: "2026-09-03T10:01:00Z"},
			{MessageID: "01J2", Host: "phalls-mac-mini", ToAgent: "ghost", FromAgent: "author",
				State: "undeliverable", Attempts: 1, LastError: "no such agent"},
		},
	}, "/repo")

	for _, want := range []string{"reviewer", "ghost", "phalls-mac-mini", "queued", "undeliverable",
		"connection refused", "no such agent"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output is missing %q:\n%s", want, output)
		}
	}
	// The terminal entry is named after the table rather than left to be
	// spotted in a column, because it is the only row that names an action.
	if !strings.Contains(output, "will not be retried") {
		t.Fatalf("a terminal delivery was not called out:\n%s", output)
	}
	// A terminal entry has no next attempt, and a dash says so rather than a
	// date that would read as overdue.
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "undeliverable") && strings.Contains(line, "2026-") {
			t.Fatalf("a terminal entry named a next attempt:\n%s", line)
		}
	}
}

// TestOutboxSaysNothingIsWaitingRatherThanPrintingAnEmptyTable keeps the empty
// case readable: "no cross-host mail is waiting" is an answer, a bare header is
// a shrug.
func TestOutboxSaysNothingIsWaitingRatherThanPrintingAnEmptyTable(t *testing.T) {
	t.Parallel()

	output := runOutbox(t, adminapi.OutboxPage{ProjectKey: "/repo"}, "/repo")
	if !strings.Contains(output, "No cross-host mail is waiting") {
		t.Fatalf("an empty queue rendered nothing an operator can read:\n%s", output)
	}
	if strings.Contains(output, "will not be retried") {
		t.Fatalf("an empty queue warned about terminal deliveries:\n%s", output)
	}
}

// TestOutboxNeverRendersMessageContents holds the delivery view to being a
// delivery view. The payload carries no subject and no body, and the command
// must not invent a place to put one.
func TestOutboxNeverRendersMessageContents(t *testing.T) {
	t.Parallel()

	output := runOutbox(t, adminapi.OutboxPage{
		ProjectKey: "/repo",
		Entries: []adminapi.OutboxItem{{MessageID: "01J1", Host: "mini", ToAgent: "reviewer",
			FromAgent: "author", State: "queued"}},
	}, "/repo")
	for _, forbidden := range []string{"SUBJECT", "BODY"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("the queue view offers a place for message contents:\n%s", output)
		}
	}
}

// TestOutboxPassesTheProjectAndLimitThrough keeps the scope explicit: the
// credential is the loopback admin token, which is not scoped to a workspace,
// so the project has to reach the daemon.
func TestOutboxPassesTheProjectAndLimitThrough(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{}
	deps := dependencies(t)
	deps.Admin = admin
	if result := runCLI(t, deps, []string{"outbox", "/repo", "--limit", "7"}); result.code != ExitOK {
		t.Fatalf("outbox exited %d; stderr=%q", result.code, result.stderr)
	}
	if admin.outboxQuery.ProjectKey != "/repo" || admin.outboxQuery.Limit != 7 {
		t.Fatalf("query = %+v", admin.outboxQuery)
	}
}
