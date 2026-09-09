package http

import (
	stdhttp "net/http"
	"net/url"
	"strconv"

	"github.com/phall1/blackbird/internal/adminapi"
	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/domain"
)

func (handler *adminHandler) thread(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
	values, ok := handler.guard(writer, request, "project_key", "conversation_id", "after", "limit")
	if !ok {
		return
	}
	query, ok := localAdminThreadQuery(writer, values)
	if !ok {
		return
	}
	page, err := handler.admin.AdminThread(request.Context(), query)
	if err != nil {
		writeLocalError(writer, err)
		return
	}
	messages := make([]adminapi.ThreadMessage, 0, len(page.Messages))
	for _, message := range page.Messages {
		messages = append(messages, adminapi.ThreadMessage{MessageID: message.MessageID.String(),
			Position: message.Position, AuthorAgentName: message.AuthorAgentName,
			Subject: message.Subject, Body: message.Body, SentAt: localAdminInstant(message.SentAtUS)})
	}
	writeLocalJSON(writer, stdhttp.StatusOK, adminapi.ThreadPage{ProjectKey: page.ProjectKey,
		ConversationID: page.ConversationID.String(), Messages: messages, HasMore: page.HasMore,
		Next: page.Next, ObservedAt: localAdminInstant(page.ObservedAtUS)})
}

func localAdminThreadQuery(writer stdhttp.ResponseWriter, values url.Values) (coordination.AdminThreadQuery, bool) {
	var query coordination.AdminThreadQuery
	projectKey, ok := localAdminProjectKey(writer, values, true)
	if !ok {
		return query, false
	}
	conversation, err := domain.ParseConversationID(values.Get("conversation_id"))
	if err != nil {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "conversation_id is required and must be valid")
		return query, false
	}
	limit, ok := localAdminLimit(writer, values)
	if !ok {
		return query, false
	}
	after, ok := localAdminThreadAfter(writer, values)
	if !ok {
		return query, false
	}
	return coordination.AdminThreadQuery{ProjectKey: projectKey, ConversationID: conversation, After: after, Limit: limit}, true
}

func localAdminThreadAfter(writer stdhttp.ResponseWriter, values url.Values) (uint64, bool) {
	if !values.Has("after") {
		return 0, true
	}
	after, err := strconv.ParseUint(values.Get("after"), 10, 53)
	if err != nil {
		writeLocalProblem(writer, stdhttp.StatusBadRequest, domain.ErrorCodeInvalidArgument, "after must be a nonnegative safe integer")
		return 0, false
	}
	return after, true
}
