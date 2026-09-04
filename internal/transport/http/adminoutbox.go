package http

import (
	stdhttp "net/http"
	"time"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

// The operator's view of cross-host mail this daemon is still holding.
//
// Without it, a queued delivery was visible only to the agent that sent it and
// in the daemon log, and a peer being unreachable is the ORDINARY failure of
// cross-host mail: a laptop closed, a host not peered yet, a machine name
// misspelled. An operator who cannot see the queue cannot tell "the mail is
// waiting" from "the mail was never sent", and those call for opposite actions.
//
// It follows the cost route's shape for the same reasons. The reader is a
// separate, optional dependency, because a daemon composed without cross-host
// mail can still serve every other admin projection; when it is absent the
// route says the capability is missing rather than answering with an empty
// queue, which an operator would read as "nothing is stuck". And the project is
// named in the query string and required, because the credential here is the
// loopback admin token rather than an agent registration that would scope it.
//
// The payload carries no subject and no body. This is a DELIVERY view: an
// operator diagnosing why mail is stuck needs the host, the state and the last
// error, and has no business reading the contents of a message out of a queue.

const PathLocalAdminOutbox = "/api/v1/local/admin/outbox"

func (handler *adminHandler) outbox(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "limit")
	if !ok {
		return
	}
	if handler.outboxes == nil {
		writeLocalProblem(writer, stdhttp.StatusServiceUnavailable, domain.ErrorCodeDependencyUnavailable,
			"this daemon was composed without cross-host mail, so it holds no outbox")
		return
	}
	projectKey, ok := localAdminProjectKey(writer, values, true)
	if !ok {
		return
	}
	limit, ok := localAdminLimit(writer, values)
	if !ok {
		return
	}
	entries, err := handler.outboxes.PeerMailQueue(request.Context(), projectKey, int(limit))
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	writeLocalJSON(writer, stdhttp.StatusOK, adminOutboxPayload(projectKey, entries, handler.now()))
}

func adminOutboxPayload(
	projectKey string,
	entries []coordination.PeerMailEntry,
	observedAt time.Time,
) adminapi.OutboxPage {
	items := make([]adminapi.OutboxItem, 0, len(entries))
	for _, entry := range entries {
		items = append(items, adminapi.OutboxItem{
			MessageID: entry.MessageID.String(),
			Host:      entry.Address.Host,
			ToAgent:   entry.Address.Agent,
			FromAgent: entry.FromAgent,
			State:     string(entry.State),
			Attempts:  entry.Attempts,
			LastError: entry.LastError,
			QueuedAt:  adminOutboxInstant(entry.QueuedAt),
			// A terminal entry has no next attempt, and the zero time is
			// reported as absent rather than as the epoch.
			NextAttemptAt: adminOutboxInstant(entry.NextAttemptAt),
		})
	}
	return adminapi.OutboxPage{ProjectKey: projectKey, Entries: items,
		ObservedAt: adminOutboxInstant(observedAt)}
}

func adminOutboxInstant(instant time.Time) string {
	if instant.IsZero() {
		return ""
	}
	return instant.UTC().Format(time.RFC3339Nano)
}
