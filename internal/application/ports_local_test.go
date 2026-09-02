package application

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

func applicationUUID(index int) string {
	return fmt.Sprintf("01b8e094-9888-7000-8000-%012x", index)
}

// TestConversationSlugIsAnOptionalAlternateKey pins the two halves of the
// contract that make conversation_open idempotent: an empty slug is legal and
// means "no alternate key", and anything a caller could not reliably retype --
// untrimmed, oversized, control characters -- is not a key at all.
func TestConversationSlugIsAnOptionalAlternateKey(t *testing.T) {
	t.Parallel()
	for _, slug := range []string{"", "auth-refactor", "the auth refactor", strings.Repeat("s", MaxConversationSlugBytes)} {
		if !ValidConversationSlug(slug) {
			t.Fatalf("slug %q was rejected", slug)
		}
	}
	for _, slug := range []string{" leading", "trailing ", "with\nnewline", strings.Repeat("s", MaxConversationSlugBytes+1)} {
		if ValidConversationSlug(slug) {
			t.Fatalf("slug %q was accepted", slug)
		}
	}
}

func TestNewConversationCarriesTheSlugItWasOpenedUnder(t *testing.T) {
	t.Parallel()
	params := conversationParamsFixture(t)
	params.Slug = "auth-refactor"
	openedAt := time.Unix(1, 0).UTC()
	conversation, err := NewConversation(params, openedAt)
	if err != nil {
		t.Fatal(err)
	}
	if conversation.Slug() != "auth-refactor" || conversation.ID() != params.ConversationID ||
		conversation.Topic() != params.Topic || conversation.OpenedAt() != openedAt {
		t.Fatalf("conversation=%+v", conversation)
	}

	// An unusable slug fails the same construction every other unusable field
	// does, so a store can never persist an alternate key it could not look up.
	params.Slug = "  not a key  "
	if _, err := NewConversation(params, openedAt); err != ErrInvalidCoordination {
		t.Fatalf("error=%v, want an invalid coordination rejection", err)
	}

	// Omitting it stays the behaviour every existing caller has.
	params.Slug = ""
	unslugged, err := NewConversation(params, openedAt)
	if err != nil || unslugged.Slug() != "" {
		t.Fatalf("unslugged conversation=%+v error=%v", unslugged, err)
	}
}

// TestCoordinationWaitCeilingBoundsTheHeartbeatLag ties the two constants a
// caller reasons about to the invariants they encode: a wait can never outlive
// a client's patience, and a coalesced heartbeat can never make a session look
// stale to a roster that has not actually lost it.
func TestCoordinationWaitCeilingBoundsTheHeartbeatLag(t *testing.T) {
	t.Parallel()
	if MaxCoordinationWait <= CoordinationWaitPoll {
		t.Fatalf("wait ceiling %v does not admit a single poll of %v", MaxCoordinationWait, CoordinationWaitPoll)
	}
	if LocalAgentHeartbeatInterval >= LocalAgentActiveWindow {
		t.Fatalf("heartbeat interval %v would let a live session fall outside the %v liveness window",
			LocalAgentHeartbeatInterval, LocalAgentActiveWindow)
	}
	// A wait parks an agent for up to the ceiling without authenticating again,
	// so a heartbeat interval shorter than the ceiling would be pointless and
	// one shorter than the window is what keeps that agent on the roster.
	if LocalAgentActiveWindow-LocalAgentHeartbeatInterval <= MaxCoordinationWait {
		t.Fatalf("a %v wait plus a %v heartbeat lag exhausts the %v liveness window",
			MaxCoordinationWait, LocalAgentHeartbeatInterval, LocalAgentActiveWindow)
	}
}

func conversationParamsFixture(t *testing.T) OpenConversationParams {
	t.Helper()
	conversation, e1 := domain.ParseConversationID(applicationUUID(901))
	workspace, e2 := domain.ParseWorkspaceID(applicationUUID(902))
	run, e3 := domain.ParseRunID(applicationUUID(903))
	actor, e4 := domain.ParseActorID(applicationUUID(904))
	session, e5 := domain.ParseActorSessionID(applicationUUID(905))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		t.Fatal("conversation fixture identifiers are not parseable")
	}
	return OpenConversationParams{ConversationID: conversation, WorkspaceID: workspace, RunID: run,
		OpenedBy: actor, OpenedBySession: session, Topic: "the auth refactor"}
}
