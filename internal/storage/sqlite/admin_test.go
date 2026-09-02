package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	adminProjectA = "/Users/phall/workspace/alpha"
	adminProjectB = "/Users/phall/workspace/beta"
)

func TestAdminOverviewCountsCoordinationState(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	registerAdminAgent(t, store, adminProjectB, "carol")
	conversation := openAdminConversation(t, store, alice, "release")
	sendAdminMessage(t, store, alice, conversation, "first", true, bob.ActorID)
	sendAdminMessage(t, store, alice, conversation, "second", false, bob.ActorID)
	active := acquireAdminLease(t, store, alice, "docs/live.md")
	expired := acquireAdminLease(t, store, bob, "docs/dead.md")
	expireAdminLease(t, store, expired.ID())

	overview, err := store.AdminOverview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if overview.Projects != 2 || overview.Agents != 3 || overview.ActiveAgents != 3 {
		t.Fatalf("registry counters=%+v", overview)
	}
	if overview.Conversations != 1 || overview.Messages != 2 || overview.Deliveries != 2 ||
		overview.UnreadDeliveries != 2 || overview.UnackedDeliveries != 1 {
		t.Fatalf("mail counters=%+v", overview)
	}
	if overview.ActiveReservations != 1 || overview.ExpiredReservations != 1 {
		t.Fatalf("reservation counters=%+v (active lease %s)", overview, active.ID())
	}
	if overview.CoordinationEvents == 0 || overview.ObservedAtUS <= 0 {
		t.Fatalf("journal counters=%+v", overview)
	}
}

func TestAdminOverviewOnEmptyStoreReturnsZeros(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)

	overview, err := store.AdminOverview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if overview.Projects != 0 || overview.Agents != 0 || overview.ActiveAgents != 0 ||
		overview.Conversations != 0 || overview.Messages != 0 || overview.Deliveries != 0 ||
		overview.ActiveReservations != 0 || overview.ExpiredReservations != 0 || overview.CoordinationEvents != 0 {
		t.Fatalf("empty overview=%+v", overview)
	}
	if overview.ObservedAtUS <= 0 {
		t.Fatalf("observed at=%d", overview.ObservedAtUS)
	}
}

func TestListAdminProjectsReportsAgentConversationAndEventCounts(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	registerAdminAgent(t, store, adminProjectB, "carol")
	conversation := openAdminConversation(t, store, alice, "release")
	sendAdminMessage(t, store, alice, conversation, "first", false, bob.ActorID)

	page, err := store.ListAdminProjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Projects) != 2 {
		t.Fatalf("projects=%d", len(page.Projects))
	}
	if page.Projects[0].ProjectKey != adminProjectA || page.Projects[1].ProjectKey != adminProjectB {
		t.Fatalf("project order=%q,%q", page.Projects[0].ProjectKey, page.Projects[1].ProjectKey)
	}
	first := page.Projects[0]
	if first.Agents != 2 || first.ActiveAgents != 2 || first.Conversations != 1 || first.CreatedAtUS <= 0 {
		t.Fatalf("alpha=%+v", first)
	}
	if first.WorkspaceID != alice.WorkspaceID || first.RunID != alice.RunID {
		t.Fatalf("alpha identity=%+v", first)
	}
	if first.LastEventAtUS <= 0 {
		t.Fatalf("alpha last event=%d", first.LastEventAtUS)
	}
	if page.Projects[1].LastEventAtUS != 0 {
		t.Fatalf("beta last event=%d", page.Projects[1].LastEventAtUS)
	}
}

func TestListAdminAgentsIncludesOfflineAgentsAndDeliveryCounts(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	carol := registerAdminAgent(t, store, adminProjectA, "carol")
	conversation := openAdminConversation(t, store, alice, "release")
	sendAdminMessage(t, store, alice, conversation, "first", true, bob.ActorID)
	endAdminSession(t, store, bob)
	ageAdminSession(t, store, carol, application.LocalAgentActiveWindow+time.Minute)
	lease := acquireAdminLease(t, store, alice, "docs/live.md")

	page, err := store.ListAdminAgents(context.Background(), application.AdminAgentsQuery{ProjectKey: adminProjectA})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Agents) != 3 || page.Truncated {
		t.Fatalf("agents=%d truncated=%v", len(page.Agents), page.Truncated)
	}
	byName := map[string]application.AdminAgent{}
	for _, agent := range page.Agents {
		byName[agent.AgentName] = agent
	}
	if !byName["alice"].Active || byName["alice"].ActiveLeases != 1 || byName["alice"].SessionID.IsZero() {
		t.Fatalf("alice=%+v (lease %s)", byName["alice"], lease.ID())
	}
	if byName["bob"].Active || !byName["bob"].SessionID.IsZero() || byName["bob"].UnreadDeliveries != 1 ||
		byName["bob"].UnackedDeliveries != 1 || byName["bob"].CreatedAtUS <= 0 {
		t.Fatalf("bob=%+v", byName["bob"])
	}
	if byName["carol"].Active || byName["carol"].SessionID.IsZero() || byName["carol"].UnreadDeliveries != 0 {
		t.Fatalf("carol=%+v", byName["carol"])
	}
	agents, err := store.ListActiveLocalAgents(context.Background(), carol)
	if err != nil {
		t.Fatal(err)
	}
	for _, agent := range agents {
		if agent.Name == "carol" {
			t.Fatal("an agent past LocalAgentActiveWindow was reported as an active local agent")
		}
	}
}

func TestListAdminAgentsFiltersAndTruncates(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	registerAdminAgent(t, store, adminProjectA, "alice")
	registerAdminAgent(t, store, adminProjectA, "bob")
	registerAdminAgent(t, store, adminProjectB, "carol")

	for _, testCase := range []struct {
		name      string
		query     application.AdminAgentsQuery
		want      []string
		truncated bool
	}{
		{name: "every project", query: application.AdminAgentsQuery{}, want: []string{"alice", "bob", "carol"}},
		{name: "one project", query: application.AdminAgentsQuery{ProjectKey: adminProjectB}, want: []string{"carol"}},
		{name: "one agent", query: application.AdminAgentsQuery{AgentName: "bob"}, want: []string{"bob"}},
		{name: "truncated", query: application.AdminAgentsQuery{Limit: 2}, want: []string{"alice", "bob"}, truncated: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			page, err := store.ListAdminAgents(context.Background(), testCase.query)
			if err != nil {
				t.Fatal(err)
			}
			if page.Truncated != testCase.truncated || len(page.Agents) != len(testCase.want) {
				t.Fatalf("page=%+v want=%v", page, testCase.want)
			}
			for index, want := range testCase.want {
				if page.Agents[index].AgentName != want {
					t.Fatalf("agent %d=%q want %q", index, page.Agents[index].AgentName, want)
				}
			}
		})
	}
}

// An agent with no deliveries at all is the case that catches the LEFT JOIN
// counting bug: count(*) FILTER (WHERE d.read_at_us IS NULL) counts the
// NULL-padded row and reports one phantom unread delivery.
func TestAdminInboxSummarizesUnreadUnacknowledgedAndZeroDeliveryAgents(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	registerAdminAgent(t, store, adminProjectA, "zoe")
	conversation := openAdminConversation(t, store, alice, "release")
	first := sendAdminMessage(t, store, alice, conversation, "first", true, bob.ActorID)
	sendAdminMessage(t, store, alice, conversation, "second", false, bob.ActorID)
	readAdminDelivery(t, store, bob, first)

	page, err := store.AdminInbox(context.Background(), application.AdminInboxQuery{ProjectKey: adminProjectA})
	if err != nil {
		t.Fatal(err)
	}
	summaries := map[string]application.AdminInboxSummary{}
	for _, summary := range page.Summaries {
		summaries[summary.AgentName] = summary
	}
	if len(summaries) != 3 {
		t.Fatalf("summaries=%+v", page.Summaries)
	}
	if summaries["bob"].UnreadDeliveries != 1 || summaries["bob"].UnackedDeliveries != 1 ||
		summaries["bob"].OldestUnreadAtUS <= 0 || summaries["bob"].ActorID != bob.ActorID {
		t.Fatalf("bob=%+v", summaries["bob"])
	}
	for _, name := range []string{"alice", "zoe"} {
		if summaries[name].UnreadDeliveries != 0 || summaries[name].UnackedDeliveries != 0 ||
			summaries[name].OldestUnreadAtUS != 0 {
			t.Fatalf("%s has no deliveries yet reports %+v", name, summaries[name])
		}
	}
	if len(page.Pending) != 2 || page.Truncated || page.ProjectKey != adminProjectA {
		t.Fatalf("pending=%+v", page)
	}
}

func TestAdminInboxPendingHidesOtherRecipientsBlindCopies(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	charlie := registerAdminAgent(t, store, adminProjectA, "charlie")
	conversation := openAdminConversation(t, store, alice, "release")
	sendAdminMessageWithKinds(t, store, alice, conversation, "confidential", false,
		map[domain.ActorID]application.RecipientKind{
			bob.ActorID:     application.RecipientTo,
			charlie.ActorID: application.RecipientBcc,
		})

	bobPage, err := store.AdminInbox(context.Background(),
		application.AdminInboxQuery{ProjectKey: adminProjectA, AgentName: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bobPage.Pending) != 1 || bobPage.Pending[0].RecipientAgentName != "bob" ||
		bobPage.Pending[0].Kind != application.RecipientTo {
		t.Fatalf("bob pending=%+v", bobPage.Pending)
	}
	charliePage, err := store.AdminInbox(context.Background(),
		application.AdminInboxQuery{ProjectKey: adminProjectA, AgentName: "charlie"})
	if err != nil {
		t.Fatal(err)
	}
	if len(charliePage.Pending) != 1 || charliePage.Pending[0].Kind != application.RecipientBcc ||
		charliePage.Pending[0].RecipientActorID != charlie.ActorID {
		t.Fatalf("charlie pending=%+v", charliePage.Pending)
	}
	if charliePage.Pending[0].AuthorAgentName != "alice" || charliePage.Pending[0].Subject != "confidential" {
		t.Fatalf("charlie attribution=%+v", charliePage.Pending[0])
	}
}

func TestAdminInboxTruncatesAtLimit(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	conversation := openAdminConversation(t, store, alice, "release")
	for index := range 3 {
		sendAdminMessage(t, store, alice, conversation, "message", false, bob.ActorID)
		_ = index
	}

	truncated, err := store.AdminInbox(context.Background(),
		application.AdminInboxQuery{ProjectKey: adminProjectA, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(truncated.Pending) != 2 || !truncated.Truncated {
		t.Fatalf("truncated page=%+v", truncated)
	}
	whole, err := store.AdminInbox(context.Background(),
		application.AdminInboxQuery{ProjectKey: adminProjectA, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(whole.Pending) != 3 || whole.Truncated {
		t.Fatalf("whole page=%+v", whole)
	}
}

func TestAdminInboxRequiresProjectKey(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)

	if _, err := store.AdminInbox(context.Background(), application.AdminInboxQuery{}); !errors.Is(err,
		application.ErrInvalidCoordination) {
		t.Fatalf("missing project key error=%v", err)
	}
}

func TestForceReleaseAdminReservationClearsLeaseAndRecordsForcedFact(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	lease := acquireAdminLease(t, store, alice, "docs/live.md")

	if _, err := store.AcquireLease(ctx, acquireAdminLeaseParams(t, bob, "docs/live.md")); !errors.Is(err, domain.ErrLeaseConflict) {
		t.Fatalf("acquire before force release error=%v, want lease conflict", err)
	}
	released, err := store.ForceReleaseAdminReservation(ctx, lease.ID())
	if err != nil {
		t.Fatal(err)
	}
	releasedAt, ok := released.ReleasedAt()
	if !ok {
		t.Fatal("force-released lease has no release instant")
	}
	if _, err := store.AcquireLease(ctx, acquireAdminLeaseParams(t, bob, "docs/live.md")); err != nil {
		t.Fatalf("acquire after force release: %v", err)
	}

	events, err := store.ListAdminEvents(ctx, application.AdminEventsQuery{
		EventType: application.CoordinationEventLeaseReleased})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 1 || events.Events[0].SubjectID != lease.ID().String() ||
		events.Events[0].ActorID != alice.ActorID {
		t.Fatalf("release events=%+v, want one fact for alice's lease", events.Events)
	}
	var payload struct {
		Forced bool `json:"forced"`
	}
	if err := json.Unmarshal(events.Events[0].Payload, &payload); err != nil || !payload.Forced {
		t.Fatalf("release payload=%s error=%v, want forced=true", events.Events[0].Payload, err)
	}

	repeated, err := store.ForceReleaseAdminReservation(ctx, lease.ID())
	if err != nil {
		t.Fatal(err)
	}
	repeatedAt, ok := repeated.ReleasedAt()
	if !ok || !repeatedAt.Equal(releasedAt) {
		t.Fatalf("repeated release instant=%v present=%v, want %v", repeatedAt, ok, releasedAt)
	}
	events, err = store.ListAdminEvents(ctx, application.AdminEventsQuery{
		EventType: application.CoordinationEventLeaseReleased})
	if err != nil || len(events.Events) != 1 {
		t.Fatalf("repeated release events=%d error=%v, want one", len(events.Events), err)
	}
}

func acquireAdminLeaseParams(t *testing.T, holder application.LocalAgentSession,
	path string) application.AcquireLeaseParams {
	t.Helper()
	leaseID, err := domain.NewLeaseID()
	if err != nil {
		t.Fatal(err)
	}
	selector, err := application.NewLeaseSelector(application.LeaseSelectorExact, path)
	if err != nil {
		t.Fatal(err)
	}
	return application.AcquireLeaseParams{LeaseID: leaseID, WorkspaceID: holder.WorkspaceID,
		Holder: holder.ActorID, HolderSession: holder.ActorSessionID, AuthorityEpoch: holder.AuthorityEpoch,
		Mode: application.LeaseExclusive, Selectors: []application.LeaseSelector{selector}, TTL: time.Hour}
}

func TestListAdminReservationsDerivesExpiryFromStorageClock(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	live := acquireAdminLease(t, store, alice, "docs/live.md")
	stale := acquireAdminLease(t, store, alice, "docs/stale.md")
	expireAdminLease(t, store, stale.ID())

	page, err := store.ListAdminReservations(context.Background(), application.AdminReservationsQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Reservations) != 2 || page.ObservedAtUS <= 0 {
		t.Fatalf("page=%+v", page)
	}
	states := map[domain.LeaseID]application.AdminReservation{}
	for _, reservation := range page.Reservations {
		states[reservation.LeaseID] = reservation
	}
	if states[live.ID()].State != application.AdminReservationActive || states[live.ID()].Expired ||
		states[live.ID()].ExpiresInMS <= 0 {
		t.Fatalf("live reservation=%+v", states[live.ID()])
	}
	if states[stale.ID()].State != application.AdminReservationExpired || !states[stale.ID()].Expired ||
		states[stale.ID()].ExpiresInMS >= 0 {
		t.Fatalf("stale reservation=%+v", states[stale.ID()])
	}
	if states[live.ID()].HolderAgentName != "alice" || states[live.ID()].ProjectKey != adminProjectA ||
		states[live.ID()].Mode != application.LeaseExclusive ||
		states[live.ID()].HolderActorID != alice.ActorID {
		t.Fatalf("holder attribution=%+v", states[live.ID()])
	}
}

// state=expired with limit=1 only returns the expired lease if the predicate is
// applied in SQL: the live lease sorts ahead of it under ORDER BY expires_at_us.
func TestListAdminReservationsFiltersStateInSQL(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	acquireAdminLease(t, store, alice, "docs/live.md")
	stale := acquireAdminLease(t, store, alice, "docs/stale.md")
	expireAdminLease(t, store, stale.ID())

	page, err := store.ListAdminReservations(context.Background(), application.AdminReservationsQuery{
		State: application.AdminReservationExpired, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Reservations) != 1 || page.Reservations[0].LeaseID != stale.ID() || page.Truncated {
		t.Fatalf("expired page=%+v", page)
	}
	active, err := store.ListAdminReservations(context.Background(), application.AdminReservationsQuery{
		State: application.AdminReservationActive, ProjectKey: adminProjectB})
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Reservations) != 0 {
		t.Fatalf("other project reservations=%+v", active.Reservations)
	}
}

func TestListAdminReservationsReturnsSelectorsInOrdinalOrder(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	acquireAdminLease(t, store, alice, "docs/a.md", "docs/b.md", "docs/c.md")

	page, err := store.ListAdminReservations(context.Background(), application.AdminReservationsQuery{
		AgentName: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Reservations) != 1 || len(page.Reservations[0].Selectors) != 3 {
		t.Fatalf("page=%+v", page)
	}
	for index, want := range []string{"docs/a.md", "docs/b.md", "docs/c.md"} {
		selector := page.Reservations[0].Selectors[index]
		if selector.Path() != want || selector.Kind() != application.LeaseSelectorExact {
			t.Fatalf("selector %d=%+v want %q", index, selector, want)
		}
	}
}

func TestListAdminReservationsRejectsInvalidStateAndNormalizesZero(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	acquireAdminLease(t, store, alice, "docs/live.md")

	if _, err := store.ListAdminReservations(context.Background(),
		application.AdminReservationsQuery{State: "bogus"}); !errors.Is(err, application.ErrInvalidCoordination) {
		t.Fatalf("invalid state error=%v", err)
	}
	page, err := store.ListAdminReservations(context.Background(), application.AdminReservationsQuery{})
	if err != nil || len(page.Reservations) != 1 {
		t.Fatalf("zero-value state page=%+v error=%v", page, err)
	}
}

func TestListAdminEventsReturnsNewestFirstAndPreservesFanout(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	charlie := registerAdminAgent(t, store, adminProjectA, "charlie")
	conversation := openAdminConversation(t, store, alice, "release")
	message := sendAdminMessage(t, store, alice, conversation, "fanout", false, bob.ActorID, charlie.ActorID)
	acquireAdminLease(t, store, alice, "docs/live.md")

	page, err := store.ListAdminEvents(context.Background(), application.AdminEventsQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 3 || page.Events[0].EventType != application.CoordinationEventLeaseAcquired {
		t.Fatalf("events=%+v", page.Events)
	}
	for index := 1; index < len(page.Events); index++ {
		if page.Events[index-1].Position <= page.Events[index].Position {
			t.Fatalf("positions are not descending: %+v", page.Events)
		}
	}
	available, err := store.ListAdminEvents(context.Background(), application.AdminEventsQuery{
		EventType: application.CoordinationEventMessageAvailable})
	if err != nil {
		t.Fatal(err)
	}
	if len(available.Events) != 2 {
		t.Fatalf("per-recipient fan-out was collapsed: %+v", available.Events)
	}
	actors := map[domain.ActorID]struct{}{}
	for _, event := range available.Events {
		if event.SubjectID != message.ID().String() || event.ProjectKey != adminProjectA ||
			event.WorkspaceID != alice.WorkspaceID || len(event.Payload) == 0 {
			t.Fatalf("event=%+v", event)
		}
		actors[event.ActorID] = struct{}{}
	}
	if len(actors) != 2 {
		t.Fatalf("fan-out actors=%v", actors)
	}
	if _, err := store.ListAdminEvents(context.Background(),
		application.AdminEventsQuery{EventType: "bogus"}); !errors.Is(err, application.ErrInvalidCoordination) {
		t.Fatalf("invalid event type error=%v", err)
	}
}

func TestListAdminConversationsSummarizesThread(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	bob := registerAdminAgent(t, store, adminProjectA, "bob")
	conversation := openAdminConversation(t, store, alice, "release")
	sendAdminMessage(t, store, alice, conversation, "first", false, bob.ActorID)
	last := sendAdminMessage(t, store, alice, conversation, "second", false, bob.ActorID)
	readAdminDelivery(t, store, bob, last)

	page, err := store.ListAdminConversations(context.Background(),
		application.AdminConversationsQuery{ProjectKey: adminProjectA})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Conversations) != 1 || page.Truncated {
		t.Fatalf("page=%+v", page)
	}
	summary := page.Conversations[0]
	if summary.ConversationID != conversation || summary.Topic != "release" ||
		summary.Status != application.AdminConversationOpen || summary.ProjectKey != adminProjectA {
		t.Fatalf("summary=%+v", summary)
	}
	if summary.Messages != 2 || summary.Participants != 2 || summary.UnreadDeliveries != 1 {
		t.Fatalf("summary counters=%+v", summary)
	}
	if summary.OpenedByAgentName != "alice" || summary.LastMessageAuthor != "alice" ||
		summary.LastMessageSubject != "second" || summary.LastMessageAtUS <= 0 {
		t.Fatalf("summary attribution=%+v", summary)
	}
	single, err := store.ListAdminConversations(context.Background(),
		application.AdminConversationsQuery{ConversationID: conversation})
	if err != nil || len(single.Conversations) != 1 {
		t.Fatalf("single conversation page=%+v error=%v", single, err)
	}
}

func TestAdminQueriesRejectInvalidFilters(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	oversized := string(make([]byte, application.MaxCoordinationKeyBytes+1))
	overLimit := uint16(application.MaxQueryPageSize + 1)

	for _, testCase := range []struct {
		name string
		call func() error
	}{
		{name: "agents project key", call: func() error {
			_, err := store.ListAdminAgents(context.Background(),
				application.AdminAgentsQuery{ProjectKey: oversized})
			return err
		}},
		{name: "agents limit", call: func() error {
			_, err := store.ListAdminAgents(context.Background(), application.AdminAgentsQuery{Limit: overLimit})
			return err
		}},
		{name: "inbox agent name", call: func() error {
			_, err := store.AdminInbox(context.Background(),
				application.AdminInboxQuery{ProjectKey: adminProjectA, AgentName: " bob "})
			return err
		}},
		{name: "inbox limit", call: func() error {
			_, err := store.AdminInbox(context.Background(),
				application.AdminInboxQuery{ProjectKey: adminProjectA, Limit: overLimit})
			return err
		}},
		{name: "conversations project key", call: func() error {
			_, err := store.ListAdminConversations(context.Background(),
				application.AdminConversationsQuery{ProjectKey: oversized})
			return err
		}},
		{name: "reservations limit", call: func() error {
			_, err := store.ListAdminReservations(context.Background(),
				application.AdminReservationsQuery{Limit: overLimit})
			return err
		}},
		{name: "events project key", call: func() error {
			_, err := store.ListAdminEvents(context.Background(),
				application.AdminEventsQuery{ProjectKey: oversized})
			return err
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if err := testCase.call(); !errors.Is(err, application.ErrInvalidCoordination) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCheckReadinessReportsSchemaVersionAndFailsAfterClose(t *testing.T) {
	t.Parallel()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "readiness.db")})
	if err != nil {
		t.Fatal(err)
	}
	version, err := store.CheckReadiness(context.Background())
	if err != nil || version != SchemaVersion {
		t.Fatalf("version=%d error=%v", version, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CheckReadiness(context.Background()); err == nil {
		t.Fatal("readiness answered from a cached result after the store was closed")
	}
}

func TestAdminStorageIdentityReportsBackendAndPath(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "identity.db")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	identity, err := store.AdminStorageIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity.StorageBackend != "sqlite" || identity.DatabasePath != store.path ||
		identity.SchemaVersion != SchemaVersion || identity.ObservedAtUS <= 0 {
		t.Fatalf("identity=%+v", identity)
	}
}

func registerAdminAgent(t *testing.T, store *Store, projectKey, name string) application.LocalAgentSession {
	t.Helper()
	session, _, err := store.RegisterLocalAgent(context.Background(), projectKey, name, "")
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func openAdminConversation(t *testing.T, store *Store, opener application.LocalAgentSession,
	topic string) domain.ConversationID {
	t.Helper()
	conversationID, err := domain.NewConversationID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenConversation(context.Background(), application.OpenConversationParams{
		ConversationID: conversationID, WorkspaceID: opener.WorkspaceID, RunID: opener.RunID,
		OpenedBy: opener.ActorID, OpenedBySession: opener.ActorSessionID, Topic: topic,
	}); err != nil {
		t.Fatal(err)
	}
	return conversationID
}

func sendAdminMessage(t *testing.T, store *Store, author application.LocalAgentSession,
	conversation domain.ConversationID, subject string, acknowledgementRequired bool,
	recipients ...domain.ActorID) application.Message {
	t.Helper()
	kinds := make(map[domain.ActorID]application.RecipientKind, len(recipients))
	for _, recipient := range recipients {
		kinds[recipient] = application.RecipientTo
	}
	return sendAdminMessageWithKinds(t, store, author, conversation, subject, acknowledgementRequired, kinds)
}

func sendAdminMessageWithKinds(t *testing.T, store *Store, author application.LocalAgentSession,
	conversation domain.ConversationID, subject string, acknowledgementRequired bool,
	kinds map[domain.ActorID]application.RecipientKind) application.Message {
	t.Helper()
	messageID, err := domain.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	recipients := make([]application.Recipient, 0, len(kinds))
	for actor, kind := range kinds {
		recipient, recipientErr := application.NewRecipient(actor, kind)
		if recipientErr != nil {
			t.Fatal(recipientErr)
		}
		recipients = append(recipients, recipient)
	}
	message, err := store.SendMessage(context.Background(), application.SendMessageParams{
		MessageID: messageID, ConversationID: conversation, WorkspaceID: author.WorkspaceID,
		Author: author.ActorID, AuthorSession: author.ActorSessionID, Subject: subject,
		Body: "body of " + subject, Recipients: recipients,
		AcknowledgementRequired: acknowledgementRequired,
	})
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func readAdminDelivery(t *testing.T, store *Store, recipient application.LocalAgentSession,
	message application.Message) {
	t.Helper()
	session := recipient.ActorSessionID
	if _, err := store.RecordDeliveryFact(context.Background(), application.RecordDeliveryFactParams{
		WorkspaceID: recipient.WorkspaceID, MessageID: message.ID(), Recipient: recipient.ActorID,
		ActorSessionID: &session, Kind: application.DeliveryRead,
	}); err != nil {
		t.Fatal(err)
	}
}

func acquireAdminLease(t *testing.T, store *Store, holder application.LocalAgentSession,
	paths ...string) application.Lease {
	t.Helper()
	return acquireAdminLeaseAs(t, store, holder, application.LeaseExclusive, time.Hour, paths...)
}

func acquireAdminLeaseAs(t *testing.T, store *Store, holder application.LocalAgentSession,
	mode application.LeaseMode, ttl time.Duration, paths ...string) application.Lease {
	t.Helper()
	leaseID, err := domain.NewLeaseID()
	if err != nil {
		t.Fatal(err)
	}
	selectors := make([]application.LeaseSelector, 0, len(paths))
	for _, path := range paths {
		selector, selectorErr := application.NewLeaseSelector(application.LeaseSelectorExact, path)
		if selectorErr != nil {
			t.Fatal(selectorErr)
		}
		selectors = append(selectors, selector)
	}
	lease, err := store.AcquireLease(context.Background(), application.AcquireLeaseParams{
		LeaseID: leaseID, WorkspaceID: holder.WorkspaceID, Holder: holder.ActorID,
		HolderSession: holder.ActorSessionID, AuthorityEpoch: holder.AuthorityEpoch,
		Mode: mode, Selectors: selectors, TTL: ttl,
	})
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

// expireAdminLease backdates a lease by an hour rather than expiring it one
// microsecond after acquisition. Expiry is reported in whole milliseconds, so a
// lease that went stale within the same millisecond the query runs reports
// ExpiresInMS of exactly 0 and reads as neither overdue nor live. The row must
// keep expires_at_us > acquired_at_us to satisfy the table's own constraint,
// and SQLite evaluates every assignment against the pre-update row.
func expireAdminLease(t *testing.T, store *Store, lease domain.LeaseID) {
	t.Helper()
	const hourUS = int64(time.Hour / time.Microsecond)
	if _, err := store.db.ExecContext(context.Background(),
		`UPDATE leases SET acquired_at_us = acquired_at_us - ?, expires_at_us = acquired_at_us - ?
		 WHERE lease_id = ?`, hourUS, hourUS/2, lease.String()); err != nil {
		t.Fatal(err)
	}
}

func endAdminSession(t *testing.T, store *Store, session application.LocalAgentSession) {
	t.Helper()
	if _, err := store.db.ExecContext(context.Background(),
		`UPDATE coordination_agent_sessions SET ended_at_us = last_seen_at_us WHERE session_id = ?`,
		session.ActorSessionID.String()); err != nil {
		t.Fatal(err)
	}
}

func ageAdminSession(t *testing.T, store *Store, session application.LocalAgentSession, age time.Duration) {
	t.Helper()
	aged := timeMicros(time.Now().UTC().Add(-age))
	if _, err := store.db.ExecContext(context.Background(),
		`UPDATE coordination_agent_sessions SET started_at_us = ?, last_seen_at_us = ? WHERE session_id = ?`,
		aged, aged, session.ActorSessionID.String()); err != nil {
		t.Fatal(err)
	}
}

// Every admin predicate belongs in the WHERE clause. Each case seeds more
// matching rows than the limit and puts non-matching rows at the head of the
// unfiltered order, so a page filtered in Go after LIMIT renders empty.
func TestAdminInboxFiltersPendingBeforeLimit(t *testing.T) {
	t.Parallel()
	type delivery struct {
		subject   string
		ackNeeded bool
		read      bool
	}
	for _, testCase := range []struct {
		name      string
		matching  []delivery
		head      []delivery
		query     application.AdminInboxQuery
		want      []string
		truncated bool
	}{
		{
			name:     "unread only",
			matching: []delivery{{subject: "unread-1"}, {subject: "unread-2"}, {subject: "unread-3"}},
			head: []delivery{{subject: "read-1", ackNeeded: true, read: true},
				{subject: "read-2", ackNeeded: true, read: true}},
			query:     application.AdminInboxQuery{UnreadOnly: true, Limit: 2},
			want:      []string{"unread-3", "unread-2"},
			truncated: true,
		},
		{
			name: "unacked only",
			matching: []delivery{{subject: "unacked-1", ackNeeded: true}, {subject: "unacked-2", ackNeeded: true},
				{subject: "unacked-3", ackNeeded: true}},
			head:      []delivery{{subject: "no-ack-1"}, {subject: "no-ack-2"}},
			query:     application.AdminInboxQuery{UnackedOnly: true, Limit: 2},
			want:      []string{"unacked-3", "unacked-2"},
			truncated: true,
		},
		{
			name: "unread and unacked conjoin",
			matching: []delivery{{subject: "both-1", ackNeeded: true}, {subject: "both-2", ackNeeded: true},
				{subject: "both-3", ackNeeded: true}},
			head:      []delivery{{subject: "read-1", ackNeeded: true, read: true}, {subject: "no-ack-1"}},
			query:     application.AdminInboxQuery{UnreadOnly: true, UnackedOnly: true, Limit: 2},
			want:      []string{"both-3", "both-2"},
			truncated: true,
		},
		{
			name:     "whole filtered page is not truncated",
			matching: []delivery{{subject: "unread-1"}, {subject: "unread-2"}},
			head:     []delivery{{subject: "read-1", ackNeeded: true, read: true}},
			query:    application.AdminInboxQuery{UnreadOnly: true, Limit: 2},
			want:     []string{"unread-2", "unread-1"},
		},
		{
			name:     "no predicate keeps every pending delivery",
			matching: []delivery{{subject: "unread-1"}},
			head:     []delivery{{subject: "read-1", ackNeeded: true, read: true}},
			query:    application.AdminInboxQuery{Limit: 2},
			want:     []string{"read-1", "unread-1"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			store := newCoordinationStore(t)
			alice := registerAdminAgent(t, store, adminProjectA, "alice")
			bob := registerAdminAgent(t, store, adminProjectA, "bob")
			conversation := openAdminConversation(t, store, alice, "release")
			for _, item := range append(append([]delivery{}, testCase.matching...), testCase.head...) {
				message := sendAdminMessage(t, store, alice, conversation, item.subject, item.ackNeeded, bob.ActorID)
				if item.read {
					readAdminDelivery(t, store, bob, message)
				}
			}

			query := testCase.query
			query.ProjectKey = adminProjectA
			page, err := store.AdminInbox(context.Background(), query)
			if err != nil {
				t.Fatal(err)
			}
			if page.Truncated != testCase.truncated || len(page.Pending) != len(testCase.want) {
				t.Fatalf("pending=%+v truncated=%v want=%v truncated=%v", page.Pending, page.Truncated,
					testCase.want, testCase.truncated)
			}
			for index, want := range testCase.want {
				if page.Pending[index].Subject != want {
					t.Fatalf("pending %d=%q want %q", index, page.Pending[index].Subject, want)
				}
			}
			if len(page.Summaries) != 2 {
				t.Fatalf("a pending predicate must not narrow the per-agent summaries: %+v", page.Summaries)
			}
		})
	}
}

// Liveness sorts nowhere: the roster is ordered by name, so the offline agents
// seeded here occupy the head of every unfiltered page.
func TestListAdminAgentsFiltersActiveBeforeLimit(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	ended := registerAdminAgent(t, store, adminProjectA, "aaa-ended")
	stale := registerAdminAgent(t, store, adminProjectA, "aab-stale")
	registerAdminAgent(t, store, adminProjectA, "zza-live")
	registerAdminAgent(t, store, adminProjectA, "zzb-live")
	registerAdminAgent(t, store, adminProjectA, "zzc-live")
	endAdminSession(t, store, ended)
	ageAdminSession(t, store, stale, application.LocalAgentActiveWindow+time.Minute)

	page, err := store.ListAdminAgents(context.Background(),
		application.AdminAgentsQuery{ProjectKey: adminProjectA, ActiveOnly: true, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || len(page.Agents) != 2 || page.Agents[0].AgentName != "zza-live" ||
		page.Agents[1].AgentName != "zzb-live" {
		t.Fatalf("active page=%+v", page)
	}
	whole, err := store.ListAdminAgents(context.Background(),
		application.AdminAgentsQuery{ProjectKey: adminProjectA, ActiveOnly: true, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if whole.Truncated || len(whole.Agents) != 3 {
		t.Fatalf("whole active page=%+v", whole)
	}
	for _, agent := range whole.Agents {
		if !agent.Active {
			t.Fatalf("inactive agent on an active-only page: %+v", agent)
		}
	}
	unfiltered, err := store.ListAdminAgents(context.Background(),
		application.AdminAgentsQuery{ProjectKey: adminProjectA})
	if err != nil {
		t.Fatal(err)
	}
	if len(unfiltered.Agents) != 5 {
		t.Fatalf("unfiltered roster=%d", len(unfiltered.Agents))
	}
}

// The closed conversations are the newest, so they head every unfiltered page
// under ORDER BY opened_at_us DESC.
func TestListAdminConversationsFiltersOpenBeforeLimit(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	for _, seed := range []struct {
		topic string
		age   time.Duration
	}{{topic: "open-1", age: 3 * time.Hour}, {topic: "open-2", age: 2 * time.Hour}, {topic: "open-3", age: time.Hour}} {
		ageAdminConversation(t, store, openAdminConversation(t, store, alice, seed.topic), seed.age)
	}
	for _, topic := range []string{"closed-1", "closed-2"} {
		closeAdminConversation(t, store, openAdminConversation(t, store, alice, topic))
	}

	page, err := store.ListAdminConversations(context.Background(),
		application.AdminConversationsQuery{ProjectKey: adminProjectA, OpenOnly: true, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || len(page.Conversations) != 2 || page.Conversations[0].Topic != "open-3" ||
		page.Conversations[1].Topic != "open-2" {
		t.Fatalf("open page=%+v", page)
	}
	whole, err := store.ListAdminConversations(context.Background(),
		application.AdminConversationsQuery{ProjectKey: adminProjectA, OpenOnly: true, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if whole.Truncated || len(whole.Conversations) != 3 {
		t.Fatalf("whole open page=%+v", whole)
	}
	for _, conversation := range whole.Conversations {
		if conversation.Status != application.AdminConversationOpen {
			t.Fatalf("closed conversation on an open-only page: %+v", conversation)
		}
	}
	unfiltered, err := store.ListAdminConversations(context.Background(),
		application.AdminConversationsQuery{ProjectKey: adminProjectA, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !unfiltered.Truncated || len(unfiltered.Conversations) != 2 ||
		unfiltered.Conversations[0].Status != application.AdminConversationClosed {
		t.Fatalf("unfiltered page=%+v", unfiltered)
	}
}

// The exclusive leases outlive the shared ones, so they head every unfiltered
// page under ORDER BY expires_at_us DESC.
func TestListAdminReservationsFiltersModeBeforeLimit(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	acquireAdminLeaseAs(t, store, alice, application.LeaseExclusive, 2*time.Hour, "x/1.go")
	acquireAdminLeaseAs(t, store, alice, application.LeaseExclusive, 2*time.Hour, "x/2.go")
	shared := map[domain.LeaseID]struct{}{}
	for _, path := range []string{"s/1.go", "s/2.go", "s/3.go"} {
		shared[acquireAdminLeaseAs(t, store, alice, application.LeaseShared, time.Hour, path).ID()] = struct{}{}
	}

	page, err := store.ListAdminReservations(context.Background(),
		application.AdminReservationsQuery{ProjectKey: adminProjectA, Mode: application.LeaseShared, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || len(page.Reservations) != 2 {
		t.Fatalf("shared page=%+v", page)
	}
	whole, err := store.ListAdminReservations(context.Background(),
		application.AdminReservationsQuery{ProjectKey: adminProjectA, Mode: application.LeaseShared, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if whole.Truncated || len(whole.Reservations) != len(shared) {
		t.Fatalf("whole shared page=%+v", whole)
	}
	for _, reservation := range whole.Reservations {
		if _, ok := shared[reservation.LeaseID]; !ok || reservation.Mode != application.LeaseShared {
			t.Fatalf("exclusive lease on a shared-only page: %+v", reservation)
		}
	}
	exclusive, err := store.ListAdminReservations(context.Background(),
		application.AdminReservationsQuery{ProjectKey: adminProjectA, Mode: application.LeaseExclusive})
	if err != nil {
		t.Fatal(err)
	}
	if len(exclusive.Reservations) != 2 {
		t.Fatalf("exclusive page=%+v", exclusive)
	}
}

// The sibling leases outlive the matching ones, so they head every unfiltered
// page, and "a/foo" must never answer a query for "a/f".
func TestListAdminReservationsFiltersPathOnSeparatorBoundariesBeforeLimit(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	sibling := acquireAdminLeaseAs(t, store, alice, application.LeaseExclusive, 2*time.Hour, "a/foo/x.go")
	acquireAdminLeaseAs(t, store, alice, application.LeaseExclusive, 2*time.Hour, "b/y.go")
	exact := acquireAdminLeaseAs(t, store, alice, application.LeaseExclusive, time.Hour, "a/f")
	child := acquireAdminLeaseAs(t, store, alice, application.LeaseExclusive, time.Hour, "a/f/g.go")
	ancestor := acquireAdminLeaseAs(t, store, alice, application.LeaseExclusive, time.Hour, "a")
	covering := map[domain.LeaseID]struct{}{exact.ID(): {}, child.ID(): {}, ancestor.ID(): {}}

	page, err := store.ListAdminReservations(context.Background(),
		application.AdminReservationsQuery{ProjectKey: adminProjectA, Path: "a/f", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || len(page.Reservations) != 2 {
		t.Fatalf("path page=%+v", page)
	}
	whole, err := store.ListAdminReservations(context.Background(),
		application.AdminReservationsQuery{ProjectKey: adminProjectA, Path: "a/f", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if whole.Truncated || len(whole.Reservations) != len(covering) {
		t.Fatalf("whole path page=%+v", whole)
	}
	for _, reservation := range whole.Reservations {
		if _, ok := covering[reservation.LeaseID]; !ok {
			t.Fatalf("a sibling path answered a boundary query: %+v", reservation)
		}
		if reservation.LeaseID == sibling.ID() {
			t.Fatalf("--path=a/f matched a/foo: %+v", reservation)
		}
	}
	sub, err := store.ListAdminReservations(context.Background(),
		application.AdminReservationsQuery{ProjectKey: adminProjectA, Path: "a/foo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Reservations) != 2 {
		t.Fatalf("a/foo page=%+v", sub)
	}
	for _, reservation := range sub.Reservations {
		if reservation.LeaseID != sibling.ID() && reservation.LeaseID != ancestor.ID() {
			t.Fatalf("a/foo page=%+v", reservation)
		}
	}
}

func TestListAdminReservationsRejectsUnknownModeAndInvalidPath(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)

	for _, testCase := range []struct {
		name  string
		query application.AdminReservationsQuery
	}{
		{name: "unknown mode", query: application.AdminReservationsQuery{Mode: "any"}},
		{name: "empty-ish path", query: application.AdminReservationsQuery{Path: " "}},
		{name: "padded path", query: application.AdminReservationsQuery{Path: " a/f "}},
		{name: "oversized path", query: application.AdminReservationsQuery{
			Path: string(make([]byte, application.MaxLeaseSelectorBytes+1))}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := store.ListAdminReservations(context.Background(), testCase.query); !errors.Is(err,
				application.ErrInvalidCoordination) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func closeAdminConversation(t *testing.T, store *Store, conversation domain.ConversationID) {
	t.Helper()
	if _, err := store.db.ExecContext(context.Background(),
		`UPDATE conversations SET status = 'closed' WHERE conversation_id = ?`, conversation.String()); err != nil {
		t.Fatal(err)
	}
}

func ageAdminConversation(t *testing.T, store *Store, conversation domain.ConversationID, age time.Duration) {
	t.Helper()
	if _, err := store.db.ExecContext(context.Background(),
		`UPDATE conversations SET opened_at_us = ? WHERE conversation_id = ?`,
		timeMicros(time.Now().UTC().Add(-age)), conversation.String()); err != nil {
		t.Fatal(err)
	}
}

// TestAdminReservationBucketsSurviveTheExpiryReaper pins the classification
// against AcquireLease's reaper. The reaper retires expired leases in a
// workspace and epoch to 'released', so a bucket decided on status alone would
// move an abandoned reservation from "expired" to "released" the moment some
// unrelated agent acquired a lease — hiding exactly the reservations an
// operator runs this listing to find, and telling doctor's expired-reservation
// check that an abandoned workspace is clean.
//
// The assertion is that each lease sits in the same bucket before and after the
// reap, and that the abandoned one never counts as released.
func TestAdminReservationBucketsSurviveTheExpiryReaper(t *testing.T) {
	t.Parallel()
	store := newCoordinationStore(t)
	alice := registerAdminAgent(t, store, adminProjectA, "alice")
	live := acquireAdminLease(t, store, alice, "docs/live.md")
	releasedEarly := acquireAdminLease(t, store, alice, "docs/released.md")
	if _, err := store.ReleaseLease(context.Background(), application.ChangeLeaseParams{
		LeaseID: releasedEarly.ID(), HolderSession: alice.ActorSessionID,
		AuthorityEpoch: alice.AuthorityEpoch, Fences: releasedEarly.Fences(),
	}); err != nil {
		t.Fatal(err)
	}
	// Expiry is staged last: every AcquireLease in this workspace and epoch runs
	// the reaper, so a lease expired before one would already have been retired
	// and the pre-reap stage would assert nothing.
	abandoned := acquireAdminLease(t, store, alice, "docs/abandoned.md")
	expireAdminLease(t, store, abandoned.ID())

	bucketOf := func(t *testing.T, lease domain.LeaseID) application.AdminReservationState {
		t.Helper()
		var found application.AdminReservationState
		for _, state := range []application.AdminReservationState{
			application.AdminReservationActive,
			application.AdminReservationExpired,
			application.AdminReservationReleased,
		} {
			page, err := store.ListAdminReservations(context.Background(),
				application.AdminReservationsQuery{State: state})
			if err != nil {
				t.Fatal(err)
			}
			for _, reservation := range page.Reservations {
				if reservation.LeaseID != lease {
					continue
				}
				if found != "" {
					t.Fatalf("lease %s appears in both %s and %s; the buckets must be disjoint",
						lease, found, state)
				}
				found = state
			}
		}
		if found == "" {
			t.Fatalf("lease %s appears in no bucket; the buckets must be total", lease)
		}
		return found
	}

	assertBuckets := func(t *testing.T, stage string) {
		t.Helper()
		for lease, want := range map[domain.LeaseID]application.AdminReservationState{
			live.ID():          application.AdminReservationActive,
			abandoned.ID():     application.AdminReservationExpired,
			releasedEarly.ID(): application.AdminReservationReleased,
		} {
			if got := bucketOf(t, lease); got != want {
				t.Fatalf("%s: lease %s is %s, want %s", stage, lease, got, want)
			}
		}
		overview, err := store.AdminOverview(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if overview.ExpiredReservations != 1 {
			t.Fatalf("%s: overview expired=%d, want 1", stage, overview.ExpiredReservations)
		}
	}

	assertBuckets(t, "before the reap")

	// Any acquisition in this workspace and epoch runs the reaper.
	acquireAdminLease(t, store, alice, "docs/unrelated.md")
	var status string
	if err := store.db.QueryRowContext(context.Background(),
		`SELECT status FROM leases WHERE lease_id = ?`, abandoned.ID().String()).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "released" {
		t.Fatalf("the reaper did not retire the abandoned lease: status=%q", status)
	}

	assertBuckets(t, "after the reap")
}
