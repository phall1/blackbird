package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application/coordination"
	"github.com/phall1/blackbird/internal/application/telemetry"
	"github.com/phall1/blackbird/internal/domain"
)

type sayInput struct {
	AgentToken              string   `json:"agent_token"`
	ConversationID          string   `json:"conversation_id,omitempty" jsonschema:"Existing thread to write in; omit to open or rejoin by slug."`
	Topic                   string   `json:"topic,omitempty" jsonschema:"Short topic used when opening a thread."`
	Slug                    string   `json:"slug,omitempty" jsonschema:"Stable thread name; opening the same slug returns the same conversation."`
	To                      []string `json:"to,omitempty" jsonschema:"Registered peer names to receive the message; omit to open without sending."`
	Subject                 string   `json:"subject,omitempty" jsonschema:"One-line message subject."`
	Body                    string   `json:"body,omitempty" jsonschema:"Durable message body."`
	ReplyToMessageID        string   `json:"reply_to_message_id,omitempty" jsonschema:"Message this answers, when replying."`
	AcknowledgementRequired bool     `json:"acknowledgement_required,omitempty" jsonschema:"Require recipients to acknowledge the exact body."`
}

type sayOutput struct {
	ConversationID string           `json:"conversation_id"`
	Topic          string           `json:"topic,omitempty"`
	Slug           string           `json:"slug,omitempty"`
	Reused         bool             `json:"reused,omitempty"`
	OpenedAt       string           `json:"opened_at,omitempty"`
	MessageID      string           `json:"message_id,omitempty"`
	AuthorActorID  string           `json:"author_actor_id,omitempty"`
	Subject        string           `json:"subject,omitempty"`
	Body           string           `json:"body,omitempty"`
	BodyDigest     string           `json:"body_digest,omitempty"`
	ReplyTo        string           `json:"reply_to,omitempty"`
	SentAt         string           `json:"sent_at,omitempty"`
	Position       uint64           `json:"position,omitempty"`
	Deliveries     []deliveryOutput `json:"deliveries,omitempty"`
}

type readInput struct {
	AgentToken     string `json:"agent_token"`
	ConversationID string `json:"conversation_id,omitempty" jsonschema:"Thread to read; omit for the caller's inbox."`
	UnreadOnly     bool   `json:"unread_only,omitempty" jsonschema:"For inbox reads, return only unread deliveries."`
	After          uint64 `json:"after,omitempty" jsonschema:"Resume after the previous page position; zero starts at the beginning."`
	Limit          uint16 `json:"limit,omitempty" jsonschema:"Maximum messages to return."`
}

type statusInput struct {
	AgentToken string `json:"agent_token"`
	Path       string `json:"path,omitempty" jsonschema:"Repository-relative path used to filter active claims."`
	Limit      uint16 `json:"limit,omitempty" jsonschema:"Maximum claims, peers, or spend groups to return."`
	ObjectID   string `json:"object_id,omitempty" jsonschema:"Work item to observe in this repository's issue tracker, for example blackbird-a1u.1. The result's work_reference carries the tracker's title, status, type, priority, assignee and dependencies as of observed_at, together with the provider and version that answered, scoped to the project this agent registered under. Omit it to skip the tracker."`
	Spend      bool   `json:"spend,omitempty" jsonschema:"Include a telemetry rollup when the observation reader is available."`
	Dimension  string `json:"dimension,omitempty" jsonschema:"Spend grouping: model, agent, harness, span_kind, or span_name."`
	SinceHours uint32 `json:"since_hours,omitempty" jsonschema:"Spend lookback window in hours; zero uses the service default."`
	MineOnly   bool   `json:"mine_only,omitempty" jsonschema:"Restrict spend to the authenticated agent."`
}

type statusOutput struct {
	Agents        []activeAgentOutput         `json:"agents"`
	Reservations  []reservationHolderOutput   `json:"reservations"`
	Truncated     bool                        `json:"truncated"`
	WorkReference *coordination.WorkReference `json:"work_reference,omitempty" jsonschema:"One point-in-time observation of a tracker work item. Blackbird is not authoritative for these fields and does not retain them; observed_at and provenance say when it was read and by what."`
	SpendReport   *spendReportOutput          `json:"spend_report,omitempty"`
}

type releaseInput struct {
	AgentToken string                     `json:"agent_token"`
	Selectors  []reservationSelectorInput `json:"selectors" jsonschema:"Exact selector set returned by claim or join; partial release is rejected."`
}

type claimOutput struct {
	OK        bool                       `json:"ok"`
	LeaseID   string                     `json:"lease_id,omitempty"`
	Mode      string                     `json:"mode,omitempty"`
	Selectors []reservationSelectorInput `json:"selectors,omitempty"`
	ExpiresAt string                     `json:"expires_at,omitempty"`
	BlockedBy *reservationHolderOutput   `json:"blocked_by,omitempty"`
	Blockers  []reservationHolderOutput  `json:"blockers,omitempty"`
	Options   []string                   `json:"options,omitempty"`
}

func registerAgentNativeTools(server *sdkmcp.Server, store coordination.LocalStore,
	observations telemetry.Reader, workReferences coordination.WorkReferenceObserver, logger *slog.Logger) {
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolJoin,
		Description: "Read blackbird://coordination/protocol, then start or resume one durable repository agent and recover its compact snapshot: claims, inbox, conversations, and peers."},
		func(ctx context.Context, input registerAgentInput) (agentSessionOutput, error) {
			token := ""
			if input.RegistrationToken != nil {
				token = *input.RegistrationToken
			}
			session, issued, err := store.RegisterLocalAgent(ctx, input.ProjectKey, input.AgentName, token)
			if err != nil {
				return agentSessionOutput{}, err
			}
			snapshot, err := store.LocalAgentSnapshot(ctx, session)
			if err != nil {
				return agentSessionOutput{}, err
			}
			return localAgentSessionOutput(session, issued, snapshot), nil
		})

	claimSchema := coordinationInputSchema[reservationAcquireInput](func(properties map[string]*jsonschema.Schema) {
		properties["mode"].Default = json.RawMessage(`"exclusive"`)
		properties["mode"].Enum = []any{string(coordination.LeaseShared), string(coordination.LeaseExclusive)}
		setSelectorKindSchema(properties["selectors"].Items.Properties["kind"])
		setTTLSchema(properties["ttl_seconds"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolClaim,
		Description: "Acquire or renew the exact path selector set. A conflict is a normal ok=false result with the holder and options; never widen a claim to evade it.", InputSchema: claimSchema},
		func(ctx context.Context, input reservationAcquireInput) (claimOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return claimOutput{}, err
			}
			selectors, err := reservationSelectors(input.Selectors)
			if err != nil {
				return claimOutput{}, err
			}
			leaseID, err := domain.NewLeaseID()
			if err != nil {
				return claimOutput{}, err
			}
			mode := coordination.LeaseMode(input.Mode)
			lease, err := store.AcquireLease(ctx, coordination.AcquireLeaseParams{LeaseID: leaseID,
				WorkspaceID: session.WorkspaceID, Holder: session.ActorID, HolderSession: session.ActorSessionID,
				AuthorityEpoch: session.AuthorityEpoch, Mode: mode, Selectors: selectors,
				TTL: time.Duration(input.TTLSeconds) * time.Second})
			if err != nil {
				described := describeLeaseConflict(ctx, store, session, mode, selectors, err)
				var blocked *blockedError
				if errors.As(described, &blocked) {
					result := claimOutput{OK: false, Blockers: blocked.blockers,
						Options: []string{"wait", "narrow", "message", "force"}}
					if len(blocked.blockers) > 0 {
						result.BlockedBy = &blocked.blockers[0]
					}
					return result, nil
				}
				return claimOutput{}, described
			}
			return claimResult(lease), nil
		})

	releaseSchema := coordinationInputSchema[releaseInput](func(properties map[string]*jsonschema.Schema) {
		setSelectorKindSchema(properties["selectors"].Items.Properties["kind"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolRelease,
		Description: "Release the authenticated agent's claim identified by its exact selector set; partial sets are rejected.", InputSchema: releaseSchema},
		func(ctx context.Context, input releaseInput) (reservationOutput, error) {
			return changeLocalReservation(ctx, store, reservationChangeInput{AgentToken: input.AgentToken,
				Selectors: input.Selectors, Action: "release"})
		})

	statusSchema := coordinationInputSchema[statusInput](func(properties map[string]*jsonschema.Schema) {
		setPageLimitSchema(properties["limit"])
		properties["dimension"].Enum = []any{string(telemetry.SpendByModel), string(telemetry.SpendByAgent),
			string(telemetry.SpendByHarness), string(telemetry.SpendBySpanKind), string(telemetry.SpendBySpanName)}
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolStatus,
		Description: "Inspect peers and active claims; optionally observe one work item in this repository's issue tracker, or a telemetry rollup, without adding more tools. " +
			"A work_reference in the result is an observation, never Blackbird state: it is what the tracker said at observed_at, nothing is stored, and the tracker stays the only authority over work fields, so read it again rather than trusting an earlier copy. " +
			"Where no tracker is installed the call fails with DEPENDENCY_UNAVAILABLE and a dependency.kind naming why; that is a property of the machine, and peers, claims and spend are unaffected.",
		InputSchema: statusSchema},
		func(ctx context.Context, input statusInput) (statusOutput, error) {
			return agentStatus(ctx, store, observations, workReferences, input)
		})

	saySchema := coordinationInputSchema[sayInput](func(properties map[string]*jsonschema.Schema) {
		properties["acknowledgement_required"].Default = json.RawMessage("false")
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolSay,
		Description: "Open or rejoin a durable thread by slug and optionally send a message to named peers in that thread.", InputSchema: saySchema},
		func(ctx context.Context, input sayInput) (sayOutput, error) { return say(ctx, store, input) })

	readSchema := coordinationInputSchema[readInput](func(properties map[string]*jsonschema.Schema) {
		properties["unread_only"].Default = json.RawMessage("false")
		properties["after"].Default = json.RawMessage("0")
		setPageLimitSchema(properties["limit"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolRead,
		Description: "Read the inbox, or one whole thread when conversation_id is supplied. Page with next.", InputSchema: readSchema},
		func(ctx context.Context, input readInput) (messagePageOutput, error) {
			return readMessages(ctx, store, input)
		})

	ackSchema := coordinationInputSchema[messageFactInput](func(properties map[string]*jsonschema.Schema) {
		properties["kind"].Enum = []any{string(coordination.DeliveryRead), string(coordination.DeliveryAcknowledged)}
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolAck,
		Description: "Record read or acknowledged for one message delivered to the authenticated agent.", InputSchema: ackSchema},
		func(ctx context.Context, input messageFactInput) (deliveryFactOutput, error) {
			return recordDeliveryFact(ctx, store, input)
		})

	waitSchema := coordinationInputSchema[coordinationWaitInput](func(properties map[string]*jsonschema.Schema) {
		properties["await_mail"].Default = json.RawMessage("false")
		properties["mode"].Default = json.RawMessage(`"exclusive"`)
		properties["mode"].Enum = []any{string(coordination.LeaseShared), string(coordination.LeaseExclusive)}
		setWaitTimeoutSchema(properties["timeout_seconds"])
	})
	coordinationTool(server, logger, &sdkmcp.Tool{Name: ToolWait,
		Description: "Wait once for a path to become free, mail to arrive, or the bounded deadline; never poll claims or inboxes.", InputSchema: waitSchema},
		func(ctx context.Context, input coordinationWaitInput) (coordinationWaitOutput, error) {
			session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
			if err != nil {
				return coordinationWaitOutput{}, err
			}
			result, err := store.AwaitCoordination(ctx, session, coordination.WaitRequest{
				Path: input.Path, Mode: coordination.LeaseMode(input.Mode), AwaitMail: input.AwaitMail,
				Timeout: boundedWaitTimeout(input.TimeoutSeconds)})
			if err != nil {
				return coordinationWaitOutput{}, err
			}
			return coordinationWaitOutput{Reason: string(result.Reason), WaitedMS: result.WaitedMS,
				PendingDeliveries: result.PendingDeliveries, Blockers: reservationHolders(result.Blockers)}, nil
		})
}

func claimResult(lease coordination.Lease) claimOutput {
	value := localReservationOutput(lease)
	return claimOutput{OK: true, LeaseID: value.LeaseID, Mode: value.Mode, Selectors: value.Selectors, ExpiresAt: value.ExpiresAt}
}

func agentStatus(ctx context.Context, store coordination.LocalStore, observations telemetry.Reader,
	workReferences coordination.WorkReferenceObserver, input statusInput) (statusOutput, error) {
	session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
	if err != nil {
		return statusOutput{}, err
	}
	agents, err := store.ListActiveLocalAgents(ctx, session)
	if err != nil {
		return statusOutput{}, err
	}
	page, err := store.LocalAgentReservations(ctx, session, coordination.AdminReservationsQuery{
		State: coordination.AdminReservationActive, Path: input.Path, Limit: input.Limit})
	if err != nil {
		return statusOutput{}, err
	}
	if input.Limit > 0 && len(agents) > int(input.Limit) {
		agents = agents[:input.Limit]
		page.Truncated = true
	}
	output := statusOutput{Agents: make([]activeAgentOutput, 0, len(agents)),
		Reservations: reservationHolders(page.Reservations), Truncated: page.Truncated}
	for _, agent := range agents {
		output.Agents = append(output.Agents, activeAgentOutput{Name: agent.Name, ActorID: agent.ActorID.String(),
			SessionID: agent.SessionID.String(), LastSeenAt: agent.LastSeenAt.Format(time.RFC3339Nano)})
	}
	if input.ObjectID != "" {
		if isNil(workReferences) {
			// Not a bad argument: the request was well formed and this
			// machine simply has no work provider composed. Saying
			// INVALID_ARGUMENT would send an agent to rewrite a call that was
			// already correct, so it degrades to the same dependency failure a
			// missing provider binary produces.
			return statusOutput{}, &coordination.WorkObservationError{
				Kind: coordination.WorkObservationUnavailable, Operation: "observe",
				Detail: "no work-item provider is composed on this daemon, so object_id cannot be observed here",
			}
		}
		observed, observeErr := workReferences.ObserveWorkReference(ctx, session.ProjectKey, input.ObjectID)
		if observeErr != nil {
			return statusOutput{}, observeErr
		}
		output.WorkReference = &observed
	}
	if input.Spend || input.Dimension != "" || input.SinceHours != 0 || input.MineOnly {
		if isNil(observations) {
			return statusOutput{}, invalidInput("spend requires a configured observation reader")
		}
		query := telemetry.SpendQuery{Dimension: telemetry.SpendDimension(input.Dimension), MineOnly: input.MineOnly, Limit: input.Limit}
		if query.Dimension == "" {
			query.Dimension = telemetry.SpendByModel
		}
		if input.SinceHours > 0 {
			query.Since = time.Now().UTC().Add(-time.Duration(input.SinceHours) * time.Hour)
		}
		report, reportErr := observations.SpendReport(ctx, session, query)
		if reportErr != nil {
			return statusOutput{}, reportErr
		}
		payload := spendReportPayload(report)
		output.SpendReport = &payload
	}
	return output, nil
}

func say(ctx context.Context, store coordination.LocalStore, input sayInput) (sayOutput, error) {
	conversationID := input.ConversationID
	output := sayOutput{}
	if conversationID == "" {
		session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
		if err != nil {
			return sayOutput{}, err
		}
		id, err := domain.NewConversationID()
		if err != nil {
			return sayOutput{}, err
		}
		conversation, err := store.OpenConversation(ctx, coordination.OpenConversationParams{ConversationID: id,
			WorkspaceID: session.WorkspaceID, RunID: session.RunID, OpenedBy: session.ActorID,
			OpenedBySession: session.ActorSessionID, Topic: input.Topic, Slug: input.Slug})
		if err != nil {
			return sayOutput{}, err
		}
		conversationID = conversation.ID().String()
		output = sayOutput{ConversationID: conversationID, Topic: conversation.Topic(), Slug: conversation.Slug(),
			Reused: conversation.ID() != id, OpenedAt: conversation.OpenedAt().Format(time.RFC3339Nano)}
	}
	if len(input.To) == 0 {
		return output, nil
	}
	message, err := sendLocalMessage(ctx, store, sendMessageInput{AgentToken: input.AgentToken,
		ConversationID: conversationID, To: input.To, Subject: input.Subject, Body: input.Body,
		ReplyToMessageID: input.ReplyToMessageID, AcknowledgementRequired: input.AcknowledgementRequired})
	if err != nil {
		return sayOutput{}, err
	}
	output.ConversationID, output.MessageID, output.AuthorActorID = message.ConversationID, message.MessageID, message.AuthorActorID
	output.Subject, output.Body, output.BodyDigest = message.Subject, message.Body, message.BodyDigest
	output.ReplyTo, output.SentAt, output.Position, output.Deliveries = message.ReplyTo, message.SentAt, message.Position, message.Deliveries
	return output, nil
}

func readMessages(ctx context.Context, store coordination.LocalStore, input readInput) (messagePageOutput, error) {
	session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
	if err != nil {
		return messagePageOutput{}, err
	}
	if input.ConversationID == "" {
		page, err := store.Inbox(ctx, coordination.InboxQuery{WorkspaceID: session.WorkspaceID, Recipient: session.ActorID,
			After: input.After, Limit: input.Limit, UnreadOnly: input.UnreadOnly})
		if err != nil {
			return messagePageOutput{}, err
		}
		return coordinationPageOutput(page), nil
	}
	conversation, err := domain.ParseConversationID(input.ConversationID)
	if err != nil {
		return messagePageOutput{}, invalidInput("conversation_id must be a valid UUID")
	}
	page, err := store.Thread(ctx, coordination.ThreadQuery{WorkspaceID: session.WorkspaceID, ConversationID: conversation,
		Viewer: session.ActorID, After: input.After, Limit: input.Limit})
	if err != nil {
		return messagePageOutput{}, err
	}
	return coordinationPageOutput(page), nil
}

func recordDeliveryFact(ctx context.Context, store coordination.LocalStore, input messageFactInput) (deliveryFactOutput, error) {
	kind := coordination.DeliveryFactKind(input.Kind)
	session, err := store.AuthenticateLocalAgent(ctx, input.AgentToken)
	if err != nil {
		return deliveryFactOutput{}, err
	}
	messageID, err := domain.ParseMessageID(input.MessageID)
	if err != nil {
		return deliveryFactOutput{}, invalidInput("message_id must be a valid UUID")
	}
	params := coordination.RecordDeliveryFactParams{WorkspaceID: session.WorkspaceID, MessageID: messageID,
		Recipient: session.ActorID, ActorSessionID: &session.ActorSessionID, Kind: kind}
	if kind == coordination.DeliveryAcknowledged {
		message, findErr := store.GetVisibleMessage(ctx, session.WorkspaceID, session.ActorID, messageID)
		if findErr != nil {
			return deliveryFactOutput{}, findErr
		}
		params.MessageDigest = message.Digest()
	}
	delivery, err := store.RecordDeliveryFact(ctx, params)
	if err != nil {
		return deliveryFactOutput{}, err
	}
	_, read := delivery.ReadAt()
	_, acknowledged := delivery.AcknowledgedAt()
	return deliveryFactOutput{MessageID: input.MessageID, Read: read, Acknowledged: acknowledged}, nil
}
