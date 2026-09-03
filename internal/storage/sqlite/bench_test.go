package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

// Seeded scales live here rather than inline so a regression hunt can widen or
// narrow the corpus without touching a benchmark body. Each scale is the volume
// at which a measured cost stopped looking like a constant.
const (
	// benchmarkInboxSmallScale and benchmarkInboxLargeScale bracket the mail
	// volume at which an empty inbox poll degenerates from a delivery-index
	// probe into a scan of the whole messages table.
	benchmarkInboxSmallScale = 10_000
	benchmarkInboxLargeScale = 100_000
	// benchmarkInboxLimit is the page an idle agent asks for while polling.
	benchmarkInboxLimit = 50
	// benchmarkInboxRecipients is how many other agents the seeded mail is
	// addressed to, so the delivery join has rows to probe that are simply
	// never the caller's.
	benchmarkInboxRecipients = 8
	// benchmarkStaleLeaseScale is how many expired-but-still-'active' leases
	// accumulate, because lease expiry is a Go-side filter and nothing reaps.
	benchmarkStaleLeaseScale = 5_000
	// benchmarkCheckpointBudget bounds the truncating checkpoint that folds
	// seeded rows out of the WAL, so the measurement is about the table rather
	// than about WAL layout left over from seeding.
	benchmarkCheckpointBudget = 60 * time.Second
)

// Identifier index space. coordinationUUID is injective over its argument, so
// disjoint bases keep the seeded corpora from colliding with one another or
// with the rows a benchmark creates while it runs.
const (
	benchmarkCommitWorkspaceIndex = 20
	benchmarkCommitEpochIndex     = 21

	benchmarkInboxWorkspaceIndex    = 1
	benchmarkInboxRunIndex          = 2
	benchmarkInboxAuthorIndex       = 3
	benchmarkInboxSessionIndex      = 4
	benchmarkInboxViewerIndex       = 5
	benchmarkInboxConversationIndex = 6
	benchmarkInboxRecipientBase     = 100
	benchmarkInboxMessageBase       = 1_000_000

	benchmarkLeaseWorkspaceIndex = 10
	benchmarkLeaseHolderIndex    = 11
	benchmarkLeaseSessionIndex   = 12
	benchmarkLeaseEpochIndex     = 13
	benchmarkLeaseAuthorityIndex = 14
	benchmarkStaleLeaseBase      = 2_000_000
	benchmarkAcquiredLeaseBase   = 3_000_000
)

const benchmarkMessageBody = "durable benchmark body"

// BenchmarkCommitLatency measures one durable write transaction under the DSN
// the daemon actually opens. The fullfsync=off arm is the same store with only
// the fullfsync pragmas stripped from that DSN: it is not a configuration the
// product ships, it is the control that says how much of the commit cost is the
// platform barrier rather than SQLite or the driver.
func BenchmarkCommitLatency(b *testing.B) {
	ctx := context.Background()
	workspace := coordinationUUID(benchmarkCommitWorkspaceIndex)
	epoch := coordinationUUID(benchmarkCommitEpochIndex)

	durable := openBenchmarkStore(b, "commit-durable.db")
	if !durable.diagnostics.FullFSync {
		b.Fatal("daemon DSN did not enable fullfsync")
	}
	relaxed := openRelaxedFsyncStore(b, "commit-relaxed.db")

	for _, variant := range []struct {
		name  string
		store *Store
	}{
		{"fullfsync=on", durable},
		{"fullfsync=off", relaxed},
	} {
		// The sub-benchmark body reruns at growing b.N, so the key counter
		// lives out here to stay unique across those reruns.
		key := 0
		b.Run(variant.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				key++
				conflictKey := "bench/" + fmt.Sprint(key)
				if err := variant.store.withImmediate(ctx, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, `INSERT INTO lease_fence_counters(workspace_id,
						authority_epoch, conflict_key, counter) VALUES (?, ?, ?, 1)`, workspace, epoch, conflictKey)
					return err
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkInboxEmptyPoll measures the common case rather than the interesting
// one: an agent polls, and there is nothing for it. The corpus is addressed
// entirely to other agents, so every seeded row is work the query does before
// returning an empty page.
func BenchmarkInboxEmptyPoll(b *testing.B) {
	ctx := context.Background()
	workspaceText := coordinationUUID(benchmarkInboxWorkspaceIndex)
	workspace, err := domain.ParseWorkspaceID(workspaceText)
	if err != nil {
		b.Fatal(err)
	}
	viewer, err := domain.ParseActorID(coordinationUUID(benchmarkInboxViewerIndex))
	if err != nil {
		b.Fatal(err)
	}

	for _, scale := range []int{benchmarkInboxSmallScale, benchmarkInboxLargeScale} {
		store := openBenchmarkStore(b, fmt.Sprintf("inbox-%d.db", scale))
		seedInboxCorpus(b, store, workspaceText, scale)
		query := coordination.InboxQuery{WorkspaceID: workspace, Recipient: viewer, Limit: benchmarkInboxLimit}
		b.Run(fmt.Sprintf("messages=%d", scale), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				page, err := store.Inbox(ctx, query)
				if err != nil {
					b.Fatal(err)
				}
				// A non-empty page would mean the corpus leaked mail to the
				// viewer, and the benchmark would be measuring a different
				// query than the one it claims to.
				if len(page.Messages()) != 0 {
					b.Fatalf("empty poll returned %d messages", len(page.Messages()))
				}
			}
		})
	}
}

// BenchmarkAcquireLeaseWithStaleLeases measures acquisition against leases that
// expired long ago and are still marked active. Nothing reaps them, and expiry
// is decided in Go after the rows are read, so each acquisition pays for every
// corpse in the workspace.
func BenchmarkAcquireLeaseWithStaleLeases(b *testing.B) {
	ctx := context.Background()
	workspaceText := coordinationUUID(benchmarkLeaseWorkspaceIndex)
	workspace, err := domain.ParseWorkspaceID(workspaceText)
	if err != nil {
		b.Fatal(err)
	}
	holder, err := domain.ParseActorID(coordinationUUID(benchmarkLeaseHolderIndex))
	if err != nil {
		b.Fatal(err)
	}
	session, err := domain.ParseActorSessionID(coordinationUUID(benchmarkLeaseSessionIndex))
	if err != nil {
		b.Fatal(err)
	}
	epoch, err := domain.ParseAuthorityEpoch(coordinationUUID(benchmarkLeaseEpochIndex))
	if err != nil {
		b.Fatal(err)
	}
	// An exact selector that overlaps none of the seeded paths, so the cost
	// being measured is reading and parsing the stale rows rather than the
	// overlap conflict they would otherwise raise.
	selector, err := coordination.NewLeaseSelector(coordination.LeaseSelectorExact, "bench/target.go")
	if err != nil {
		b.Fatal(err)
	}

	// The empty arm is the control: acquisition costs one durable commit even
	// with nothing to scan, so it is what the seeded arm must be read against.
	for _, scale := range []int{0, benchmarkStaleLeaseScale} {
		store := openBenchmarkStore(b, fmt.Sprintf("leases-%d.db", scale))
		seedStaleLeases(b, store, workspaceText, epoch.String(), scale)

		// The sub-benchmark body reruns at growing b.N, so the lease counter
		// lives out here to stay unique across those reruns.
		acquired := 0
		b.Run(fmt.Sprintf("stale=%d", scale), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				acquired++
				leaseID, parseErr := domain.ParseLeaseID(coordinationUUID(benchmarkAcquiredLeaseBase + acquired))
				if parseErr != nil {
					b.Fatal(parseErr)
				}
				if _, err := store.AcquireLease(ctx, coordination.AcquireLeaseParams{LeaseID: leaseID,
					WorkspaceID: workspace, Holder: holder, HolderSession: session, AuthorityEpoch: epoch,
					Mode: coordination.LeaseExclusive, Selectors: []coordination.LeaseSelector{selector},
					TTL: time.Hour}); err != nil {
					b.Fatal(err)
				}
				// Retire the lease outside the measurement so the stale
				// population stays at the seeded scale instead of drifting
				// upward with b.N.
				b.StopTimer()
				discardLease(b, store, leaseID.String())
				b.StartTimer()
			}
		})
	}
}

// BenchmarkAuthenticateLocalAgent measures the statement every MCP tool call and
// every HTTP local-API request executes first, so its cost is a floor under
// everything the daemon does.
//
// The heartbeat-per-call arm is the shape this path used to have: the identical
// lookup, wrapped in the BEGIN IMMEDIATE it needed only to stamp
// last_seen_at_us. It is kept here as the control, because the read-only arm's
// number means nothing without the durable commit it replaced -- and because a
// future change that quietly reintroduces a write on this path shows up as the
// two arms converging.
func BenchmarkAuthenticateLocalAgent(b *testing.B) {
	ctx := context.Background()
	for _, variant := range []struct {
		name         string
		authenticate func(*Store, string) error
	}{
		{"coalesced-heartbeat", func(store *Store, token string) error {
			_, err := store.AuthenticateLocalAgent(ctx, token)
			return err
		}},
		{"heartbeat-per-call", func(store *Store, token string) error {
			return authenticateWritingHeartbeat(ctx, store, token)
		}},
	} {
		store := openBenchmarkStore(b, "authenticate-"+variant.name+".db")
		_, token, err := store.RegisterLocalAgent(ctx, "/workspace/bench", "bench", "")
		if err != nil {
			b.Fatal(err)
		}
		foldSeedIntoDatabase(b, store)
		b.Run(variant.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := variant.authenticate(store, token); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// authenticateWritingHeartbeat reproduces the retired authentication path --
// the same lookup inside a write transaction that stamps the session heartbeat
// unconditionally -- so the benchmark compares two real implementations rather
// than a measurement against a remembered number.
func authenticateWritingHeartbeat(ctx context.Context, store *Store, token string) error {
	digest := sha256.Sum256([]byte(token))
	return store.withImmediate(ctx, func(tx *sql.Tx) error {
		now, err := sqliteNow(ctx, tx)
		if err != nil {
			return err
		}
		var projectKey, agentName, workspaceText, runText, actorText, sessionText, epochText string
		var started, lastSeen int64
		if err := tx.QueryRowContext(ctx, `SELECT project.project_key, agent.agent_name, project.workspace_id,
			project.run_id, agent.actor_id, session.session_id, project.authority_epoch, session.started_at_us,
			session.last_seen_at_us
			FROM coordination_agents AS agent JOIN coordination_projects AS project USING(project_key)
			JOIN coordination_agent_sessions AS session USING(actor_id)
			WHERE agent.registration_token_digest = ? AND session.ended_at_us IS NULL
			ORDER BY session.started_at_us DESC LIMIT 1`, digest[:]).Scan(&projectKey, &agentName, &workspaceText,
			&runText, &actorText, &sessionText, &epochText, &started, &lastSeen); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE coordination_agent_sessions SET last_seen_at_us = ?
			WHERE session_id = ?`, timeMicros(now), sessionText); err != nil {
			return err
		}
		_, err = localAgentSession(projectKey, agentName, workspaceText, runText, actorText, sessionText, epochText,
			started, timeMicros(now))
		return err
	})
}

// BenchmarkAwaitCoordination measures one poll of the bounded wait, which is
// what a parked agent pays four times a second. The blocked arm is the case
// that matters: the wait is reading conflicting reservations and their
// selectors on every turn, and that read has to stay cheap enough that parked
// agents do not become the load.
func BenchmarkAwaitCoordination(b *testing.B) {
	ctx := context.Background()
	store := openBenchmarkStore(b, "await.db")
	waiter, _, err := store.RegisterLocalAgent(ctx, "/workspace/await", "waiter", "")
	if err != nil {
		b.Fatal(err)
	}
	holder, _, err := store.RegisterLocalAgent(ctx, "/workspace/await", "holder", "")
	if err != nil {
		b.Fatal(err)
	}
	selector, err := coordination.NewLeaseSelector(coordination.LeaseSelectorSubtree, "internal/storage")
	if err != nil {
		b.Fatal(err)
	}
	leaseID, err := domain.NewLeaseID()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := store.AcquireLease(ctx, coordination.AcquireLeaseParams{LeaseID: leaseID,
		WorkspaceID: holder.WorkspaceID, Holder: holder.ActorID, HolderSession: holder.ActorSessionID,
		AuthorityEpoch: holder.AuthorityEpoch, Mode: coordination.LeaseExclusive,
		Selectors: []coordination.LeaseSelector{selector}, TTL: time.Hour}); err != nil {
		b.Fatal(err)
	}
	foldSeedIntoDatabase(b, store)

	for _, variant := range []struct {
		name    string
		request coordination.WaitRequest
	}{
		{"blocked-path", coordination.WaitRequest{Path: "internal/storage/sqlite/sqlite.go"}},
		{"free-path", coordination.WaitRequest{Path: "internal/transport/mcp/mcp.go"}},
		{"mail", coordination.WaitRequest{AwaitMail: true}},
	} {
		b.Run(variant.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				// One observation rather than a whole wait: the loop's own cost
				// is a sleep, and timing a sleep measures the clock.
				if _, err := store.coordinationWaitState(ctx, waiter, variant.request,
					coordination.LeaseExclusive); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// openBenchmarkStore opens a store exactly the way the daemon does, so the
// measured commit path is the shipped one.
func openBenchmarkStore(b *testing.B, name string) *Store {
	b.Helper()
	store, err := Open(context.Background(), Config{Path: filepath.Join(b.TempDir(), name)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := store.Close(); err != nil {
			b.Error(err)
		}
	})
	return store
}

// openRelaxedFsyncStore migrates a database through the ordinary open path and
// then reattaches to it with the fullfsync pragmas removed from the same DSN,
// so the two commit arms differ in the barrier and in nothing else.
func openRelaxedFsyncStore(b *testing.B, name string) *Store {
	b.Helper()
	migrated, err := Open(context.Background(), Config{Path: filepath.Join(b.TempDir(), name)})
	if err != nil {
		b.Fatal(err)
	}
	path := migrated.Path()
	if err := migrated.Close(); err != nil {
		b.Fatal(err)
	}
	db, err := sql.Open("sqlite", withoutFullFsync(b, databaseURL(Config{Path: path})))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := db.Close(); err != nil {
			b.Error(err)
		}
	})
	var fullFsync int
	if err := db.QueryRowContext(context.Background(), "PRAGMA fullfsync").Scan(&fullFsync); err != nil {
		b.Fatal(err)
	}
	if fullFsync != 0 {
		b.Fatal("control DSN still enabled fullfsync")
	}
	store := &Store{db: db, path: path}
	store.writes.changed = make(chan struct{})
	return store
}

// withoutFullFsync derives the control DSN from the daemon's own, so the
// comparison follows any future change to how the daemon opens SQLite.
func withoutFullFsync(b *testing.B, dsn string) string {
	b.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		b.Fatal(err)
	}
	query := parsed.Query()
	pragmas := make([]string, 0, len(query["_pragma"]))
	for _, pragma := range query["_pragma"] {
		if strings.Contains(pragma, "fullfsync") {
			continue
		}
		pragmas = append(pragmas, pragma)
	}
	if len(pragmas) == len(query["_pragma"]) {
		b.Fatal("daemon DSN no longer carries a fullfsync pragma")
	}
	query["_pragma"] = pragmas
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// seedInboxCorpus writes mail addressed to everyone except the polling agent.
// It writes through one transaction rather than through SendMessage because a
// per-message commit would cost more than the benchmark it is setting up.
func seedInboxCorpus(b *testing.B, store *Store, workspaceText string, count int) {
	b.Helper()
	ctx := context.Background()
	conversation := coordinationUUID(benchmarkInboxConversationIndex)
	author := coordinationUUID(benchmarkInboxAuthorIndex)
	session := coordinationUUID(benchmarkInboxSessionIndex)
	digest := coordination.DigestBytes([]byte(benchmarkMessageBody))
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO conversations(conversation_id, workspace_id, run_id,
			opened_by_actor_id, opened_by_session_id, topic, opened_at_us) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			conversation, workspaceText, coordinationUUID(benchmarkInboxRunIndex), author, session,
			"benchmark corpus", 1); err != nil {
			return err
		}
		message, err := tx.PrepareContext(ctx, `INSERT INTO messages(message_id, conversation_id, workspace_id,
			author_actor_id, author_session_id, subject, body, body_digest, sent_at_us)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = message.Close() }()
		delivery, err := tx.PrepareContext(ctx, `INSERT INTO message_deliveries(message_id, recipient_actor_id,
			recipient_kind, acknowledgement_required, available_at_us) VALUES (?, ?, 'to', 0, ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = delivery.Close() }()
		for index := range count {
			messageText := coordinationUUID(benchmarkInboxMessageBase + index)
			sentAt := int64(index) + 1
			if _, err := message.ExecContext(ctx, messageText, conversation, workspaceText, author, session,
				"benchmark", benchmarkMessageBody, digest[:], sentAt); err != nil {
				return err
			}
			recipient := coordinationUUID(benchmarkInboxRecipientBase + index%benchmarkInboxRecipients)
			if _, err := delivery.ExecContext(ctx, messageText, recipient, sentAt); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	foldSeedIntoDatabase(b, store)
}

// seedStaleLeases leaves behind leases that expired at the dawn of the epoch
// and were never released, each on a selector path that overlaps nothing.
func seedStaleLeases(b *testing.B, store *Store, workspaceText, epochText string, count int) {
	b.Helper()
	ctx := context.Background()
	holder := coordinationUUID(benchmarkLeaseHolderIndex)
	session := coordinationUUID(benchmarkLeaseSessionIndex)
	err := store.withImmediate(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scope_guards(scope_kind, scope_id, authority_id,
			authority_epoch, write_status, guard_generation, updated_at_us)
			VALUES ('workspace', ?, ?, ?, 'open', 1, 1)`, workspaceText,
			coordinationUUID(benchmarkLeaseAuthorityIndex), epochText); err != nil {
			return err
		}
		lease, err := tx.PrepareContext(ctx, `INSERT INTO leases(lease_id, workspace_id, holder_actor_id,
			holder_session_id, authority_epoch, mode, status, acquired_at_us, expires_at_us)
			VALUES (?, ?, ?, ?, ?, 'exclusive', 'active', 1, 2)`)
		if err != nil {
			return err
		}
		defer func() { _ = lease.Close() }()
		selector, err := tx.PrepareContext(ctx, `INSERT INTO lease_selectors(lease_id, selector_ordinal,
			selector_kind, selector_path) VALUES (?, 0, 'exact', ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = selector.Close() }()
		for index := range count {
			leaseText := coordinationUUID(benchmarkStaleLeaseBase + index)
			if _, err := lease.ExecContext(ctx, leaseText, workspaceText, holder, session, epochText); err != nil {
				return err
			}
			if _, err := selector.ExecContext(ctx, leaseText, fmt.Sprintf("stale/%06d/file.go", index)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	foldSeedIntoDatabase(b, store)
}

// discardLease removes a lease the benchmark just took, in the order the
// foreign keys allow, so the seeded population is what the next iteration sees.
func discardLease(b *testing.B, store *Store, leaseText string) {
	b.Helper()
	ctx := context.Background()
	for _, statement := range []string{
		`DELETE FROM lease_fences WHERE lease_id = ?`,
		`DELETE FROM lease_selectors WHERE lease_id = ?`,
		`DELETE FROM leases WHERE lease_id = ?`,
	} {
		if _, err := store.db.ExecContext(ctx, statement, leaseText); err != nil {
			b.Fatal(err)
		}
	}
}

// foldSeedIntoDatabase truncates the WAL the seed just filled. A daemon that
// had been running this long would have checkpointed, and leaving the seed in
// the WAL would measure WAL layout instead of the query under test.
func foldSeedIntoDatabase(b *testing.B, store *Store) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), benchmarkCheckpointBudget)
	defer cancel()
	if _, err := store.Checkpoint(ctx, CheckpointTruncate); err != nil {
		b.Fatal(err)
	}
}
