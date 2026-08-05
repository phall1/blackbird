package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	OperationContextGet = "context.get.v1"
	OperationEventsSync = "events.sync.v1"

	SchemaContextGetRequest = "blackbird.query.context_get/1"
	SchemaEventsSyncRequest = "blackbird.query.events_sync/1"
	SchemaContextPage       = "blackbird.context_page/1"
	SchemaContextCheckpoint = "blackbird.context_checkpoint/1"
	SchemaContextDelta      = "blackbird.context_delta/1"
	SchemaEventPage         = "blackbird.event_page/1"

	maxContextCollaboratorCount = 256
)

type ContextGetRequestDTO struct {
	Schema         string                `json:"schema"`
	RequestID      string                `json:"request_id"`
	Operation      string                `json:"operation"`
	ActorSessionID domain.ActorSessionID `json:"actor_session_id"`
	Cursor         *string               `json:"cursor"`
	Limit          uint16                `json:"limit"`
}

type EventsSyncRequestDTO struct {
	Schema         string                `json:"schema"`
	RequestID      string                `json:"request_id"`
	Operation      string                `json:"operation"`
	ActorSessionID domain.ActorSessionID `json:"actor_session_id"`
	AfterCursor    string                `json:"after_cursor"`
	Limit          uint16                `json:"limit"`
}

func DecodeContextGetRequest(data []byte) (ContextGetRequestDTO, error) {
	var request ContextGetRequestDTO
	if err := decodeStrict(data, MaxCommandJSONBytes, &request); err != nil {
		return request, err
	}
	if err := requireTopLevelJSONMembers(data, "cursor", "limit"); err != nil {
		return ContextGetRequestDTO{}, err
	}
	if err := request.Validate(); err != nil {
		return ContextGetRequestDTO{}, err
	}
	return request, nil
}
func (request ContextGetRequestDTO) Validate() error {
	if err := validateLiteral("schema", request.Schema, SchemaContextGetRequest); err != nil {
		return err
	}
	if err := validateToken("request_id", request.RequestID, maxRequestIDBytes); err != nil {
		return err
	}
	if err := validateOperation(request.Operation, OperationContextGet); err != nil {
		return err
	}
	if err := validateRequiredID("actor_session_id", request.ActorSessionID); err != nil {
		return err
	}
	if request.Cursor != nil {
		if err := validateCursor("cursor", *request.Cursor); err != nil {
			return err
		}
	}
	if request.Limit == 0 || request.Limit > maxContextDeltaCount {
		return invalid("limit", fmt.Sprintf("must be within 1..%d", maxContextDeltaCount))
	}
	return nil
}
func DecodeEventsSyncRequest(data []byte) (EventsSyncRequestDTO, error) {
	var request EventsSyncRequestDTO
	if err := decodeStrict(data, MaxCommandJSONBytes, &request); err != nil {
		return request, err
	}
	if err := request.Validate(); err != nil {
		return EventsSyncRequestDTO{}, err
	}
	return request, nil
}
func (request EventsSyncRequestDTO) Validate() error {
	if err := validateLiteral("schema", request.Schema, SchemaEventsSyncRequest); err != nil {
		return err
	}
	if err := validateToken("request_id", request.RequestID, maxRequestIDBytes); err != nil {
		return err
	}
	if err := validateOperation(request.Operation, OperationEventsSync); err != nil {
		return err
	}
	if err := validateRequiredID("actor_session_id", request.ActorSessionID); err != nil {
		return err
	}
	if err := validateCursor("after_cursor", request.AfterCursor); err != nil {
		return err
	}
	if request.Limit == 0 || request.Limit > maxSyncPageCount {
		return invalid("limit", fmt.Sprintf("must be within 1..%d", maxSyncPageCount))
	}
	return nil
}

type ContextCheckpointIDDTO string

type ContextResourceDTO struct {
	Type    domain.AggregateKind `json:"type"`
	ID      string               `json:"id"`
	Version domain.Version       `json:"version"`
	State   string               `json:"state"`
}

type ContextCheckpointDTO struct {
	Schema            string                 `json:"schema"`
	CheckpointID      ContextCheckpointIDDTO `json:"checkpoint_id"`
	AuthorityID       domain.AuthorityID     `json:"authority_id"`
	AuthorityEpoch    domain.AuthorityEpoch  `json:"authority_epoch"`
	WorkspaceID       domain.WorkspaceID     `json:"workspace_id"`
	Workspace         ContextResourceDTO     `json:"workspace"`
	ActorSession      ContextResourceDTO     `json:"actor_session"`
	Principal         ContextResourceDTO     `json:"principal"`
	Membership        ContextResourceDTO     `json:"membership"`
	Actor             ContextResourceDTO     `json:"actor"`
	Delegation        ContextResourceDTO     `json:"delegation"`
	Device            *ContextResourceDTO    `json:"device"`
	Grants            []ContextResourceDTO   `json:"grants"`
	Collaborators     []ContextResourceDTO   `json:"collaborators"`
	ThroughCursor     string                 `json:"through_cursor"`
	ProjectionVersion uint32                 `json:"projection_version"`
	ServerTime        time.Time              `json:"server_time"`
}

func (checkpoint ContextCheckpointDTO) Validate() error {
	if err := validateLiteral("checkpoint.schema", checkpoint.Schema, SchemaContextCheckpoint); err != nil {
		return err
	}
	if err := validateCeremonyID("checkpoint.checkpoint_id", CeremonyIDDTO(checkpoint.CheckpointID)); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{"checkpoint.authority_id": checkpoint.AuthorityID, "checkpoint.authority_epoch": checkpoint.AuthorityEpoch, "checkpoint.workspace_id": checkpoint.WorkspaceID} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	resources := []struct {
		field string
		value ContextResourceDTO
		kind  domain.AggregateKind
	}{
		{"checkpoint.workspace", checkpoint.Workspace, domain.AggregateKindWorkspace},
		{"checkpoint.actor_session", checkpoint.ActorSession, domain.AggregateKindActorSession},
		{"checkpoint.principal", checkpoint.Principal, domain.AggregateKindPrincipal},
		{"checkpoint.membership", checkpoint.Membership, domain.AggregateKindMembership},
		{"checkpoint.actor", checkpoint.Actor, domain.AggregateKindActor},
		{"checkpoint.delegation", checkpoint.Delegation, domain.AggregateKindActorDelegation},
	}
	if checkpoint.Workspace.ID != checkpoint.WorkspaceID.String() {
		return invalid("checkpoint.workspace.id", "must equal checkpoint.workspace_id")
	}
	if checkpoint.Device != nil {
		resources = append(resources, struct {
			field string
			value ContextResourceDTO
			kind  domain.AggregateKind
		}{"checkpoint.device", *checkpoint.Device, domain.AggregateKindDevice})
	}
	if len(checkpoint.Grants) > maxGrantReferenceCount {
		return invalid("checkpoint.grants", fmt.Sprintf("must contain at most %d entries", maxGrantReferenceCount))
	}
	for index, grant := range checkpoint.Grants {
		resources = append(resources, struct {
			field string
			value ContextResourceDTO
			kind  domain.AggregateKind
		}{fmt.Sprintf("checkpoint.grants[%d]", index), grant, domain.AggregateKindGrant})
	}
	if checkpoint.Collaborators == nil || len(checkpoint.Collaborators) > maxContextCollaboratorCount {
		return invalid("checkpoint.collaborators", fmt.Sprintf("must be a present list with at most %d entries", maxContextCollaboratorCount))
	}
	for index, collaborator := range checkpoint.Collaborators {
		resources = append(resources, struct {
			field string
			value ContextResourceDTO
			kind  domain.AggregateKind
		}{fmt.Sprintf("checkpoint.collaborators[%d]", index), collaborator, domain.AggregateKindActor})
	}
	seen := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if resource.value.Type != resource.kind {
			return invalid(resource.field+".type", fmt.Sprintf("must equal %q", resource.kind))
		}
		if err := validateAggregateID(resource.kind, resource.value.ID); err != nil {
			return invalid(resource.field+".id", err.Error())
		}
		if err := validateVersion(resource.field+".version", resource.value.Version); err != nil {
			return err
		}
		if err := validateToken(resource.field+".state", resource.value.State, 64); err != nil {
			return err
		}
		key := string(resource.kind) + "\x00" + resource.value.ID
		if _, duplicate := seen[key]; duplicate {
			return invalid("checkpoint", "must not contain duplicate resources")
		}
		seen[key] = struct{}{}
	}
	if err := validateCursor("checkpoint.through_cursor", checkpoint.ThroughCursor); err != nil {
		return err
	}
	if checkpoint.ProjectionVersion == 0 {
		return invalid("checkpoint.projection_version", "must be positive")
	}
	return validateUTCInstant("checkpoint.server_time", checkpoint.ServerTime)
}

type ContextDeltaDTO struct {
	Schema      string           `json:"schema"`
	EventID     domain.EventID   `json:"event_id"`
	DeltaType   string           `json:"delta_type"`
	Resource    ResourceScopeDTO `json:"resource"`
	Version     domain.Version   `json:"version"`
	Value       json.RawMessage  `json:"value"`
	AfterCursor string           `json:"after_cursor"`
}

func (delta ContextDeltaDTO) Validate() error {
	if err := validateLiteral("delta.schema", delta.Schema, SchemaContextDelta); err != nil {
		return err
	}
	if err := validateRequiredID("delta.event_id", delta.EventID); err != nil {
		return err
	}
	if delta.DeltaType != "upsert" && delta.DeltaType != "remove" && delta.DeltaType != "invalidate" {
		return invalid("delta.delta_type", "is not a stable context delta type")
	}
	if err := delta.Resource.validate("delta.resource"); err != nil {
		return err
	}
	if err := validateVersion("delta.version", delta.Version); err != nil {
		return err
	}
	if !rawJSONObject(delta.Value) {
		return invalid("delta.value", "must be a JSON object")
	}
	return validateCursor("delta.after_cursor", delta.AfterCursor)
}

type ContextPageDTO struct {
	Schema     string                `json:"schema"`
	RequestID  string                `json:"request_id"`
	Operation  string                `json:"operation"`
	Checkpoint *ContextCheckpointDTO `json:"checkpoint"`
	Deltas     []ContextDeltaDTO     `json:"deltas"`
	NextCursor string                `json:"next_cursor"`
	HeadCursor string                `json:"head_cursor"`
	HasMore    bool                  `json:"has_more"`
}

func DecodeContextPage(data []byte) (ContextPageDTO, error) {
	var page ContextPageDTO
	if err := decodeOutput(data, MaxOutcomeJSONBytes, &page); err != nil {
		return page, err
	}
	if err := requireTopLevelJSONMembers(data, "checkpoint", "deltas", "has_more"); err != nil {
		return ContextPageDTO{}, err
	}
	if err := page.Validate(); err != nil {
		return ContextPageDTO{}, err
	}
	return page, nil
}
func (page ContextPageDTO) Validate() error {
	if err := validateLiteral("schema", page.Schema, SchemaContextPage); err != nil {
		return err
	}
	if err := validateToken("request_id", page.RequestID, maxRequestIDBytes); err != nil {
		return err
	}
	if err := validateOperation(page.Operation, OperationContextGet); err != nil {
		return err
	}
	if page.Deltas == nil || len(page.Deltas) > maxContextDeltaCount {
		return invalid("deltas", fmt.Sprintf("must be a present list with at most %d entries", maxContextDeltaCount))
	}
	if page.Checkpoint != nil && len(page.Deltas) != 0 {
		return invalid("checkpoint", "cannot be combined with deltas")
	}
	if page.Checkpoint == nil && len(page.Deltas) == 0 {
		return invalid("deltas", "must be non-empty when checkpoint is null")
	}
	if page.Checkpoint != nil {
		if err := page.Checkpoint.Validate(); err != nil {
			return err
		}
	}
	seen := make(map[domain.EventID]struct{}, len(page.Deltas))
	for index, delta := range page.Deltas {
		if err := delta.Validate(); err != nil {
			return invalid(fmt.Sprintf("deltas[%d]", index), err.Error())
		}
		if _, ok := seen[delta.EventID]; ok {
			return invalid("deltas", "must not contain duplicate event IDs")
		}
		seen[delta.EventID] = struct{}{}
	}
	if err := validateCursor("next_cursor", page.NextCursor); err != nil {
		return err
	}
	return validateCursor("head_cursor", page.HeadCursor)
}

type EventPageDTO struct {
	Schema     string                `json:"schema"`
	RequestID  string                `json:"request_id"`
	Operation  string                `json:"operation"`
	Events     []RawEventEnvelopeDTO `json:"events"`
	NextCursor string                `json:"next_cursor"`
	HeadCursor string                `json:"head_cursor"`
	HasMore    bool                  `json:"has_more"`
}

func DecodeEventPage(data []byte) (EventPageDTO, error) {
	var page EventPageDTO
	if err := decodeOutput(data, MaxOutcomeJSONBytes, &page); err != nil {
		return page, err
	}
	if err := requireTopLevelJSONMembers(data, "events", "has_more"); err != nil {
		return EventPageDTO{}, err
	}
	if err := page.Validate(); err != nil {
		return EventPageDTO{}, err
	}
	return page, nil
}
func (page EventPageDTO) Validate() error {
	if err := validateLiteral("schema", page.Schema, SchemaEventPage); err != nil {
		return err
	}
	if err := validateToken("request_id", page.RequestID, maxRequestIDBytes); err != nil {
		return err
	}
	if err := validateOperation(page.Operation, OperationEventsSync); err != nil {
		return err
	}
	if page.Events == nil || len(page.Events) > maxSyncPageCount {
		return invalid("events", fmt.Sprintf("must be a present list with at most %d entries", maxSyncPageCount))
	}
	seen := make(map[domain.EventID]struct{}, len(page.Events))
	for index, event := range page.Events {
		encoded, err := json.Marshal(event)
		if err != nil {
			return invalid(fmt.Sprintf("events[%d]", index), err.Error())
		}
		validated, err := DecodeEventEnvelope(encoded)
		if err != nil {
			return invalid(fmt.Sprintf("events[%d]", index), err.Error())
		}
		if _, duplicate := seen[validated.EventID]; duplicate {
			return invalid("events", "must not contain duplicate event IDs")
		}
		seen[validated.EventID] = struct{}{}
	}
	if err := validateCursor("next_cursor", page.NextCursor); err != nil {
		return err
	}
	return validateCursor("head_cursor", page.HeadCursor)
}

type EventEnvelopeDTO[Payload any] struct {
	Schema         string                 `json:"schema"`
	EventID        domain.EventID         `json:"event_id"`
	EventType      string                 `json:"event_type"`
	EventVersion   uint32                 `json:"event_version"`
	AuthorityID    domain.AuthorityID     `json:"authority_id"`
	AuthorityEpoch domain.AuthorityEpoch  `json:"authority_epoch"`
	InstallationID *domain.InstallationID `json:"installation_id,omitempty"`
	WorkspaceID    *domain.WorkspaceID    `json:"workspace_id,omitempty"`
	OriginPosition domain.StreamPosition  `json:"origin_position"`
	Aggregate      EventAggregateDTO      `json:"aggregate"`
	PrincipalID    domain.PrincipalID     `json:"principal_id"`
	ActorID        *domain.ActorID        `json:"actor_id,omitempty"`
	ActorSessionID *domain.ActorSessionID `json:"actor_session_id,omitempty"`
	CommandID      domain.CommandID       `json:"command_id"`
	CausationID    *domain.EventID        `json:"causation_id,omitempty"`
	CorrelationID  domain.CorrelationID   `json:"correlation_id"`
	OccurredAt     time.Time              `json:"occurred_at"`
	RecordedAt     time.Time              `json:"recorded_at"`
	Payload        Payload                `json:"payload"`
	Extensions     EmptyExtensionsDTO     `json:"extensions"`
}

type EmptyExtensionsDTO struct{}

// RawEventEnvelopeDTO validates and retains an event envelope whose event type
// or major version is not understood by this binary. Consumers can dispatch on
// the header and retain or ignore the opaque payload without guessing its
// schema. Known event decoders remain strict and typed.
type RawEventEnvelopeDTO struct {
	Schema         string                 `json:"schema"`
	EventID        domain.EventID         `json:"event_id"`
	EventType      string                 `json:"event_type"`
	EventVersion   uint32                 `json:"event_version"`
	AuthorityID    domain.AuthorityID     `json:"authority_id"`
	AuthorityEpoch domain.AuthorityEpoch  `json:"authority_epoch"`
	InstallationID *domain.InstallationID `json:"installation_id,omitempty"`
	WorkspaceID    *domain.WorkspaceID    `json:"workspace_id,omitempty"`
	OriginPosition domain.StreamPosition  `json:"origin_position"`
	Aggregate      EventAggregateDTO      `json:"aggregate"`
	PrincipalID    domain.PrincipalID     `json:"principal_id"`
	ActorID        *domain.ActorID        `json:"actor_id,omitempty"`
	ActorSessionID *domain.ActorSessionID `json:"actor_session_id,omitempty"`
	CommandID      domain.CommandID       `json:"command_id"`
	CausationID    *domain.EventID        `json:"causation_id,omitempty"`
	CorrelationID  domain.CorrelationID   `json:"correlation_id"`
	OccurredAt     time.Time              `json:"occurred_at"`
	RecordedAt     time.Time              `json:"recorded_at"`
	Payload        json.RawMessage        `json:"payload"`
	Extensions     json.RawMessage        `json:"extensions"`
}

type EventAggregateDTO struct {
	Type    domain.AggregateKind `json:"type"`
	ID      string               `json:"id"`
	Version domain.Version       `json:"version"`
}

// MarshalJSON keeps the exported generic DTO from becoming an unchecked event
// encoder. The alias prevents recursion; the shared decoder then applies the
// same bounded I-JSON and event-semantic checks used at every ingress boundary.
func (event EventEnvelopeDTO[Payload]) MarshalJSON() ([]byte, error) {
	type eventEnvelopeWire EventEnvelopeDTO[Payload]
	encoded, err := json.Marshal(eventEnvelopeWire(event))
	if err != nil {
		return nil, err
	}
	if _, err := DecodeEventEnvelope(encoded); err != nil {
		return nil, fmt.Errorf("marshal event envelope: %w", err)
	}
	return encoded, nil
}

// MarshalJSON subjects retained future events to the same validation as typed
// events, including opaque payload and extension number bounds.
func (event RawEventEnvelopeDTO) MarshalJSON() ([]byte, error) {
	type rawEventEnvelopeWire RawEventEnvelopeDTO
	encoded, err := json.Marshal(rawEventEnvelopeWire(event))
	if err != nil {
		return nil, err
	}
	if _, err := DecodeEventEnvelope(encoded); err != nil {
		return nil, fmt.Errorf("marshal raw event envelope: %w", err)
	}
	return encoded, nil
}

type InstallationBootstrappedPayloadDTO struct {
	InstallationID           domain.InstallationID `json:"installation_id"`
	InvitationID             domain.InvitationID   `json:"invitation_id"`
	PrincipalID              domain.PrincipalID    `json:"principal_id"`
	DeviceID                 domain.DeviceID       `json:"device_id"`
	InstallationOwnerGrantID domain.GrantID        `json:"installation_owner_grant_id"`
	TranscriptHash           string                `json:"transcript_hash"`
}

type PrincipalRegisteredPayloadDTO struct {
	PrincipalID domain.PrincipalID `json:"principal_id"`
	Kind        string             `json:"kind"`
	DisplayName string             `json:"display_name"`
}

// CeremonyIDDTO is a transport-owned, baseline-safe UUIDv7 identity. It keeps
// this wire contract independent of the later identity-state implementation.
type CeremonyIDDTO string

type DevicePairingBeganPayloadDTO struct {
	DeviceID           domain.DeviceID    `json:"device_id"`
	PrincipalID        domain.PrincipalID `json:"principal_id"`
	CeremonyID         CeremonyIDDTO      `json:"ceremony_id"`
	DisplayName        string             `json:"display_name"`
	PublicKeyReference string             `json:"public_key_reference"`
}

type DevicePairedPayloadDTO struct {
	DeviceID       domain.DeviceID    `json:"device_id"`
	PrincipalID    domain.PrincipalID `json:"principal_id"`
	DisplayName    string             `json:"display_name"`
	TranscriptHash string             `json:"transcript_hash"`
}

type WorkspaceCreatedPayloadDTO struct {
	WorkspaceID     domain.WorkspaceID    `json:"workspace_id"`
	Alias           string                `json:"alias"`
	HomeAuthorityID domain.AuthorityID    `json:"home_authority_id"`
	AuthorityEpoch  domain.AuthorityEpoch `json:"authority_epoch"`
	PolicyRevision  string                `json:"policy_revision"`
}

type WorkspaceMemberInvitedPayloadDTO struct {
	WorkspaceID       domain.WorkspaceID  `json:"workspace_id"`
	MembershipID      domain.MembershipID `json:"membership_id"`
	PrincipalID       domain.PrincipalID  `json:"principal_id"`
	CapabilityCeiling []string            `json:"capability_ceiling"`
}

type WorkspaceMembershipAcceptedPayloadDTO struct {
	WorkspaceID  domain.WorkspaceID  `json:"workspace_id"`
	MembershipID domain.MembershipID `json:"membership_id"`
	PrincipalID  domain.PrincipalID  `json:"principal_id"`
}

type ActorCreatedPayloadDTO struct {
	ActorID     domain.ActorID     `json:"actor_id"`
	WorkspaceID domain.WorkspaceID `json:"workspace_id"`
	Kind        string             `json:"kind"`
	DisplayName string             `json:"display_name"`
}

type ActorDelegationProposedPayloadDTO struct {
	DelegationID domain.ActorDelegationID `json:"delegation_id"`
	WorkspaceID  domain.WorkspaceID       `json:"workspace_id"`
	PrincipalID  domain.PrincipalID       `json:"principal_id"`
	ActorID      domain.ActorID           `json:"actor_id"`
	CeremonyID   CeremonyIDDTO            `json:"ceremony_id"`
}

type ActorDelegationActivatedPayloadDTO struct {
	DelegationID           domain.ActorDelegationID `json:"delegation_id"`
	PrincipalID            domain.PrincipalID       `json:"principal_id"`
	ActorID                domain.ActorID           `json:"actor_id"`
	SessionStartCeremonyID CeremonyIDDTO            `json:"session_start_ceremony_id"`
}

type ActorSessionStartedPayloadDTO struct {
	ActorSessionID        domain.ActorSessionID    `json:"actor_session_id"`
	WorkspaceID           domain.WorkspaceID       `json:"workspace_id"`
	PrincipalID           domain.PrincipalID       `json:"principal_id"`
	ActorID               domain.ActorID           `json:"actor_id"`
	MembershipID          domain.MembershipID      `json:"membership_id"`
	MembershipVersion     domain.Version           `json:"membership_version"`
	DelegationID          domain.ActorDelegationID `json:"delegation_id"`
	DelegationVersion     domain.Version           `json:"delegation_version"`
	DeviceID              *domain.DeviceID         `json:"device_id,omitempty"`
	DeviceVersion         *domain.Version          `json:"device_version,omitempty"`
	DeviceTrustRevision   *domain.Version          `json:"device_trust_revision,omitempty"`
	GrantRevisions        []GrantRevisionDTO       `json:"grant_revisions"`
	ClientInstanceID      domain.ClientInstanceID  `json:"client_instance_id"`
	PolicyRevision        string                   `json:"policy_revision"`
	AssuranceClass        string                   `json:"assurance_class"`
	EffectiveCapabilities []string                 `json:"effective_capabilities"`
	IssuedAt              time.Time                `json:"issued_at"`
	AbsoluteExpiry        time.Time                `json:"absolute_expiry"`
}

type InstallationBootstrappedEventDTO = EventEnvelopeDTO[InstallationBootstrappedPayloadDTO]
type PrincipalRegisteredEventDTO = EventEnvelopeDTO[PrincipalRegisteredPayloadDTO]
type DevicePairingBeganEventDTO = EventEnvelopeDTO[DevicePairingBeganPayloadDTO]
type DevicePairedEventDTO = EventEnvelopeDTO[DevicePairedPayloadDTO]
type WorkspaceCreatedEventDTO = EventEnvelopeDTO[WorkspaceCreatedPayloadDTO]
type WorkspaceMemberInvitedEventDTO = EventEnvelopeDTO[WorkspaceMemberInvitedPayloadDTO]
type WorkspaceMembershipAcceptedEventDTO = EventEnvelopeDTO[WorkspaceMembershipAcceptedPayloadDTO]
type ActorCreatedEventDTO = EventEnvelopeDTO[ActorCreatedPayloadDTO]
type ActorDelegationProposedEventDTO = EventEnvelopeDTO[ActorDelegationProposedPayloadDTO]
type ActorDelegationActivatedEventDTO = EventEnvelopeDTO[ActorDelegationActivatedPayloadDTO]
type ActorSessionStartedEventDTO = EventEnvelopeDTO[ActorSessionStartedPayloadDTO]

func DecodeEventEnvelope(data []byte) (RawEventEnvelopeDTO, error) {
	var event RawEventEnvelopeDTO
	if err := decodeOutput(data, MaxOutcomeJSONBytes, &event); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := requireTopLevelJSONMembers(data, "principal_id", "correlation_id", "payload", "extensions"); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := validateLiteral("schema", event.Schema, SchemaEventEnvelope); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := validateRequiredID("event_id", event.EventID); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := validateToken("event_type", event.EventType, 256); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if event.EventVersion == 0 {
		return RawEventEnvelopeDTO{}, invalid("event_version", "must be positive")
	}
	if knownW0EventType(event.EventType) && event.EventVersion != 1 {
		return RawEventEnvelopeDTO{}, invalid("event_version", "known event type has an unsupported major version")
	}
	if err := validateRequiredID("authority_id", event.AuthorityID); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := validateRequiredID("authority_epoch", event.AuthorityEpoch); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	installationScope := event.InstallationID != nil && !event.InstallationID.IsZero()
	workspaceScope := event.WorkspaceID != nil && !event.WorkspaceID.IsZero()
	if installationScope == workspaceScope {
		return RawEventEnvelopeDTO{}, invalid("workspace_id", "exactly one nonzero installation_id or workspace_id scope is required")
	}
	if event.OriginPosition.IsZero() {
		return RawEventEnvelopeDTO{}, invalid("origin_position", "must be positive")
	}
	if knownW0EventType(event.EventType) {
		if !event.Aggregate.Type.Valid() {
			return RawEventEnvelopeDTO{}, invalid("aggregate.type", "is not a supported aggregate kind")
		}
		if err := validateAggregateID(event.Aggregate.Type, event.Aggregate.ID); err != nil {
			return RawEventEnvelopeDTO{}, err
		}
	} else {
		if err := validateToken("aggregate.type", string(event.Aggregate.Type), 64); err != nil {
			return RawEventEnvelopeDTO{}, err
		}
		if err := validateToken("aggregate.id", event.Aggregate.ID, 256); err != nil {
			return RawEventEnvelopeDTO{}, err
		}
	}
	if err := validateVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := validateRequiredID("principal_id", event.PrincipalID); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := validateRequiredID("command_id", event.CommandID); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := validateRequiredID("correlation_id", event.CorrelationID); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if event.ActorID != nil && event.ActorID.IsZero() {
		return RawEventEnvelopeDTO{}, invalid("actor_id", "must be nonzero when present")
	}
	if event.ActorSessionID != nil && event.ActorSessionID.IsZero() {
		return RawEventEnvelopeDTO{}, invalid("actor_session_id", "must be nonzero when present")
	}
	if (event.ActorID == nil) != (event.ActorSessionID == nil) {
		return RawEventEnvelopeDTO{}, invalid("actor_id", "actor_id and actor_session_id must appear together")
	}
	if event.CausationID != nil && event.CausationID.IsZero() {
		return RawEventEnvelopeDTO{}, invalid("causation_id", "must be nonzero when present")
	}
	if err := validateUTCInstant("occurred_at", event.OccurredAt); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if err := validateUTCInstant("recorded_at", event.RecordedAt); err != nil {
		return RawEventEnvelopeDTO{}, err
	}
	if !rawJSONObject(event.Payload) {
		return RawEventEnvelopeDTO{}, invalid("payload", "must be a JSON object")
	}
	if !rawJSONObject(event.Extensions) {
		return RawEventEnvelopeDTO{}, invalid("extensions", "must be a JSON object")
	}
	if knownW0EventType(event.EventType) {
		if err := validateKnownW0Event(data, event.EventType); err != nil {
			return RawEventEnvelopeDTO{}, err
		}
	}
	return event, nil
}

func rawJSONObject(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func knownW0EventType(eventType string) bool {
	switch eventType {
	case EventTypeInstallationBootstrapped,
		EventTypePrincipalRegistered,
		EventTypeDevicePairingBegan,
		EventTypeDevicePaired,
		EventTypeWorkspaceCreated,
		EventTypeWorkspaceMemberInvited,
		EventTypeWorkspaceMembershipAccepted,
		EventTypeActorCreated,
		EventTypeActorDelegationProposed,
		EventTypeActorDelegationActivated,
		EventTypeActorSessionStarted:
		return true
	default:
		return false
	}
}

func validateKnownW0Event(data []byte, eventType string) error {
	switch eventType {
	case EventTypeInstallationBootstrapped:
		_, err := DecodeInstallationBootstrappedEvent(data)
		return err
	case EventTypePrincipalRegistered:
		_, err := DecodePrincipalRegisteredEvent(data)
		return err
	case EventTypeDevicePairingBegan:
		_, err := DecodeDevicePairingBeganEvent(data)
		return err
	case EventTypeDevicePaired:
		_, err := DecodeDevicePairedEvent(data)
		return err
	case EventTypeWorkspaceCreated:
		_, err := DecodeWorkspaceCreatedEvent(data)
		return err
	case EventTypeWorkspaceMemberInvited:
		_, err := DecodeWorkspaceMemberInvitedEvent(data)
		return err
	case EventTypeWorkspaceMembershipAccepted:
		_, err := DecodeWorkspaceMembershipAcceptedEvent(data)
		return err
	case EventTypeActorCreated:
		_, err := DecodeActorCreatedEvent(data)
		return err
	case EventTypeActorDelegationProposed:
		_, err := DecodeActorDelegationProposedEvent(data)
		return err
	case EventTypeActorDelegationActivated:
		_, err := DecodeActorDelegationActivatedEvent(data)
		return err
	case EventTypeActorSessionStarted:
		_, err := DecodeActorSessionStartedEvent(data)
		return err
	default:
		return nil
	}
}

func DecodeInstallationBootstrappedEvent(data []byte) (InstallationBootstrappedEventDTO, error) {
	event, err := decodeEvent[InstallationBootstrappedPayloadDTO](
		data,
		EventTypeInstallationBootstrapped,
		domain.AggregateKindInvitation,
		true,
	)
	if err != nil {
		return InstallationBootstrappedEventDTO{}, err
	}
	if err := rejectActorAuthorship(event); err != nil {
		return InstallationBootstrappedEventDTO{}, err
	}
	if event.InstallationID == nil || *event.InstallationID != event.Payload.InstallationID {
		return InstallationBootstrappedEventDTO{}, invalid("payload.installation_id", "must match installation_id scope")
	}
	if event.Payload.InvitationID.String() != event.Aggregate.ID {
		return InstallationBootstrappedEventDTO{}, invalid("payload.invitation_id", "must match aggregate.id")
	}
	if err := validateAdvancedVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return InstallationBootstrappedEventDTO{}, err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"payload.principal_id":                event.Payload.PrincipalID,
		"payload.device_id":                   event.Payload.DeviceID,
		"payload.installation_owner_grant_id": event.Payload.InstallationOwnerGrantID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return InstallationBootstrappedEventDTO{}, err
		}
	}
	if event.PrincipalID != event.Payload.PrincipalID {
		return InstallationBootstrappedEventDTO{}, invalid("principal_id", "must match payload.principal_id")
	}
	if err := validateRequiredID("payload.invitation_id", event.Payload.InvitationID); err != nil {
		return InstallationBootstrappedEventDTO{}, err
	}
	if err := validateSHA256Hex("payload.transcript_hash", event.Payload.TranscriptHash); err != nil {
		return InstallationBootstrappedEventDTO{}, err
	}
	return event, nil
}

func DecodePrincipalRegisteredEvent(data []byte) (PrincipalRegisteredEventDTO, error) {
	event, err := decodeEvent[PrincipalRegisteredPayloadDTO](
		data,
		EventTypePrincipalRegistered,
		domain.AggregateKindPrincipal,
		true,
	)
	if err != nil {
		return PrincipalRegisteredEventDTO{}, err
	}
	if err := rejectActorAuthorship(event); err != nil {
		return PrincipalRegisteredEventDTO{}, err
	}
	if event.Payload.PrincipalID.String() != event.Aggregate.ID {
		return PrincipalRegisteredEventDTO{}, invalid("payload.principal_id", "must match aggregate.id")
	}
	if err := validateInitialVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return PrincipalRegisteredEventDTO{}, err
	}
	if !validPrincipalKind(event.Payload.Kind) {
		return PrincipalRegisteredEventDTO{}, invalid("payload.kind", "is not a stable principal kind")
	}
	if err := validateText("payload.display_name", event.Payload.DisplayName, maxDisplayNameBytes, true); err != nil {
		return PrincipalRegisteredEventDTO{}, err
	}
	return event, nil
}

func validPrincipalKind(kind string) bool {
	return kind == PrincipalKindHuman || kind == PrincipalKindWorkload || kind == PrincipalKindService
}

func DecodeDevicePairingBeganEvent(data []byte) (DevicePairingBeganEventDTO, error) {
	event, err := decodeEvent[DevicePairingBeganPayloadDTO](
		data,
		EventTypeDevicePairingBegan,
		domain.AggregateKindDevice,
		true,
	)
	if err != nil {
		return DevicePairingBeganEventDTO{}, err
	}
	if err := rejectActorAuthorship(event); err != nil {
		return DevicePairingBeganEventDTO{}, err
	}
	if event.Payload.DeviceID.String() != event.Aggregate.ID {
		return DevicePairingBeganEventDTO{}, invalid("payload.device_id", "must match aggregate.id")
	}
	if event.PrincipalID != event.Payload.PrincipalID {
		return DevicePairingBeganEventDTO{}, invalid("principal_id", "must match payload.principal_id")
	}
	if err := validateInitialVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return DevicePairingBeganEventDTO{}, err
	}
	if err := validateCeremonyID("payload.ceremony_id", event.Payload.CeremonyID); err != nil {
		return DevicePairingBeganEventDTO{}, err
	}
	if err := validateText("payload.display_name", event.Payload.DisplayName, maxDisplayNameBytes, true); err != nil {
		return DevicePairingBeganEventDTO{}, err
	}
	if err := validateText("payload.public_key_reference", event.Payload.PublicKeyReference, 256, true); err != nil {
		return DevicePairingBeganEventDTO{}, err
	}
	return event, nil
}

func DecodeDevicePairedEvent(data []byte) (DevicePairedEventDTO, error) {
	event, err := decodeEvent[DevicePairedPayloadDTO](
		data,
		EventTypeDevicePaired,
		domain.AggregateKindDevice,
		true,
	)
	if err != nil {
		return DevicePairedEventDTO{}, err
	}
	if err := rejectActorAuthorship(event); err != nil {
		return DevicePairedEventDTO{}, err
	}
	if event.Payload.DeviceID.String() != event.Aggregate.ID {
		return DevicePairedEventDTO{}, invalid("payload.device_id", "must match aggregate.id")
	}
	if event.PrincipalID != event.Payload.PrincipalID {
		return DevicePairedEventDTO{}, invalid("principal_id", "must match payload.principal_id")
	}
	if err := validateRequiredID("payload.principal_id", event.Payload.PrincipalID); err != nil {
		return DevicePairedEventDTO{}, err
	}
	if err := validateText("payload.display_name", event.Payload.DisplayName, maxDisplayNameBytes, true); err != nil {
		return DevicePairedEventDTO{}, err
	}
	if err := validateSHA256Hex("payload.transcript_hash", event.Payload.TranscriptHash); err != nil {
		return DevicePairedEventDTO{}, err
	}
	return event, nil
}

func DecodeWorkspaceCreatedEvent(data []byte) (WorkspaceCreatedEventDTO, error) {
	event, err := decodeEvent[WorkspaceCreatedPayloadDTO](
		data,
		EventTypeWorkspaceCreated,
		domain.AggregateKindWorkspace,
		false,
	)
	if err != nil {
		return WorkspaceCreatedEventDTO{}, err
	}
	if err := rejectActorAuthorship(event); err != nil {
		return WorkspaceCreatedEventDTO{}, err
	}
	if event.Payload.WorkspaceID.String() != event.Aggregate.ID {
		return WorkspaceCreatedEventDTO{}, invalid("payload.workspace_id", "must match aggregate.id")
	}
	if event.WorkspaceID == nil || *event.WorkspaceID != event.Payload.WorkspaceID {
		return WorkspaceCreatedEventDTO{}, invalid("payload.workspace_id", "must match workspace_id")
	}
	if err := validateInitialVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return WorkspaceCreatedEventDTO{}, err
	}
	if err := validateText("payload.alias", event.Payload.Alias, maxDisplayNameBytes, true); err != nil {
		return WorkspaceCreatedEventDTO{}, err
	}
	if event.Payload.HomeAuthorityID != event.AuthorityID {
		return WorkspaceCreatedEventDTO{}, invalid("payload.home_authority_id", "must match authority_id")
	}
	if !event.Payload.AuthorityEpoch.Equal(event.AuthorityEpoch) {
		return WorkspaceCreatedEventDTO{}, invalid("payload.authority_epoch", "must match authority_epoch")
	}
	if _, err := domain.NewPolicyRevision(event.Payload.PolicyRevision); err != nil {
		return WorkspaceCreatedEventDTO{}, invalid("payload.policy_revision", err.Error())
	}
	return event, nil
}

func DecodeWorkspaceMemberInvitedEvent(data []byte) (WorkspaceMemberInvitedEventDTO, error) {
	event, err := decodeEvent[WorkspaceMemberInvitedPayloadDTO](
		data,
		EventTypeWorkspaceMemberInvited,
		domain.AggregateKindMembership,
		false,
	)
	if err != nil {
		return WorkspaceMemberInvitedEventDTO{}, err
	}
	if err := rejectActorAuthorship(event); err != nil {
		return WorkspaceMemberInvitedEventDTO{}, err
	}
	if event.Payload.MembershipID.String() != event.Aggregate.ID {
		return WorkspaceMemberInvitedEventDTO{}, invalid("payload.membership_id", "must match aggregate.id")
	}
	if err := validateInitialVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return WorkspaceMemberInvitedEventDTO{}, err
	}
	if err := validateWorkspaceMembershipPayload(
		event.WorkspaceID,
		event.Payload.WorkspaceID,
		event.Payload.PrincipalID,
	); err != nil {
		return WorkspaceMemberInvitedEventDTO{}, err
	}
	if _, err := normalizeCapabilities("payload.capability_ceiling", event.Payload.CapabilityCeiling); err != nil {
		return WorkspaceMemberInvitedEventDTO{}, err
	}
	return event, nil
}

func DecodeWorkspaceMembershipAcceptedEvent(data []byte) (WorkspaceMembershipAcceptedEventDTO, error) {
	event, err := decodeEvent[WorkspaceMembershipAcceptedPayloadDTO](
		data,
		EventTypeWorkspaceMembershipAccepted,
		domain.AggregateKindMembership,
		false,
	)
	if err != nil {
		return WorkspaceMembershipAcceptedEventDTO{}, err
	}
	if err := rejectActorAuthorship(event); err != nil {
		return WorkspaceMembershipAcceptedEventDTO{}, err
	}
	if event.Payload.MembershipID.String() != event.Aggregate.ID {
		return WorkspaceMembershipAcceptedEventDTO{}, invalid("payload.membership_id", "must match aggregate.id")
	}
	if err := validateWorkspaceMembershipPayload(
		event.WorkspaceID,
		event.Payload.WorkspaceID,
		event.Payload.PrincipalID,
	); err != nil {
		return WorkspaceMembershipAcceptedEventDTO{}, err
	}
	if event.PrincipalID != event.Payload.PrincipalID {
		return WorkspaceMembershipAcceptedEventDTO{}, invalid("principal_id", "must match payload.principal_id")
	}
	return event, nil
}

func DecodeActorCreatedEvent(data []byte) (ActorCreatedEventDTO, error) {
	event, err := decodeEvent[ActorCreatedPayloadDTO](
		data,
		EventTypeActorCreated,
		domain.AggregateKindActor,
		false,
	)
	if err != nil {
		return ActorCreatedEventDTO{}, err
	}
	if event.Payload.ActorID.String() != event.Aggregate.ID {
		return ActorCreatedEventDTO{}, invalid("payload.actor_id", "must match aggregate.id")
	}
	if event.WorkspaceID == nil || *event.WorkspaceID != event.Payload.WorkspaceID {
		return ActorCreatedEventDTO{}, invalid("payload.workspace_id", "must match workspace_id")
	}
	if err := validateInitialVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return ActorCreatedEventDTO{}, err
	}
	if !validActorKind(event.Payload.Kind) {
		return ActorCreatedEventDTO{}, invalid("payload.kind", "is not a stable actor kind")
	}
	if err := validateText("payload.display_name", event.Payload.DisplayName, maxDisplayNameBytes, true); err != nil {
		return ActorCreatedEventDTO{}, err
	}
	return event, nil
}

func DecodeActorDelegationProposedEvent(data []byte) (ActorDelegationProposedEventDTO, error) {
	event, err := decodeEvent[ActorDelegationProposedPayloadDTO](
		data,
		EventTypeActorDelegationProposed,
		domain.AggregateKindActorDelegation,
		false,
	)
	if err != nil {
		return ActorDelegationProposedEventDTO{}, err
	}
	if event.Payload.DelegationID.String() != event.Aggregate.ID {
		return ActorDelegationProposedEventDTO{}, invalid("payload.delegation_id", "must match aggregate.id")
	}
	if event.WorkspaceID == nil || *event.WorkspaceID != event.Payload.WorkspaceID {
		return ActorDelegationProposedEventDTO{}, invalid("payload.workspace_id", "must match workspace_id")
	}
	if err := validateRequiredID("payload.principal_id", event.Payload.PrincipalID); err != nil {
		return ActorDelegationProposedEventDTO{}, err
	}
	if err := validateInitialVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return ActorDelegationProposedEventDTO{}, err
	}
	if err := validateCeremonyID("payload.ceremony_id", event.Payload.CeremonyID); err != nil {
		return ActorDelegationProposedEventDTO{}, err
	}
	return event, nil
}

func DecodeActorDelegationActivatedEvent(data []byte) (ActorDelegationActivatedEventDTO, error) {
	event, err := decodeEvent[ActorDelegationActivatedPayloadDTO](
		data,
		EventTypeActorDelegationActivated,
		domain.AggregateKindActorDelegation,
		false,
	)
	if err != nil {
		return ActorDelegationActivatedEventDTO{}, err
	}
	if event.Payload.DelegationID.String() != event.Aggregate.ID {
		return ActorDelegationActivatedEventDTO{}, invalid("payload.delegation_id", "must match aggregate.id")
	}
	if event.PrincipalID != event.Payload.PrincipalID {
		return ActorDelegationActivatedEventDTO{}, invalid("principal_id", "must match payload.principal_id")
	}
	if event.Aggregate.Version.Uint64() != 2 {
		return ActorDelegationActivatedEventDTO{}, invalid("aggregate.version", "must equal post-activation version 2")
	}
	if err := validateCeremonyID("payload.session_start_ceremony_id", event.Payload.SessionStartCeremonyID); err != nil {
		return ActorDelegationActivatedEventDTO{}, err
	}
	return event, nil
}

func validActorKind(kind string) bool {
	return kind == ActorKindHuman || kind == ActorKindAgent || kind == ActorKindAutomation || kind == ActorKindService
}

func validateCeremonyID(field string, id CeremonyIDDTO) error {
	if id == "" {
		return invalid(field, "is required")
	}
	if _, err := domain.ParseCeremonyID(string(id)); err != nil {
		return invalid(field, "must be nonzero UUIDv7 text")
	}
	return nil
}

func DecodeActorSessionStartedEvent(data []byte) (ActorSessionStartedEventDTO, error) {
	event, err := decodeEvent[ActorSessionStartedPayloadDTO](
		data,
		EventTypeActorSessionStarted,
		domain.AggregateKindActorSession,
		false,
	)
	if err != nil {
		return ActorSessionStartedEventDTO{}, err
	}
	if event.Payload.ActorSessionID.String() != event.Aggregate.ID {
		return ActorSessionStartedEventDTO{}, invalid("payload.actor_session_id", "must match aggregate.id")
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != event.Payload.ActorSessionID {
		return ActorSessionStartedEventDTO{}, invalid("actor_session_id", "must match payload.actor_session_id")
	}
	if event.WorkspaceID == nil || *event.WorkspaceID != event.Payload.WorkspaceID {
		return ActorSessionStartedEventDTO{}, invalid("payload.workspace_id", "must match workspace_id")
	}
	if event.PrincipalID != event.Payload.PrincipalID {
		return ActorSessionStartedEventDTO{}, invalid("principal_id", "must match payload.principal_id")
	}
	if event.ActorID == nil || *event.ActorID != event.Payload.ActorID {
		return ActorSessionStartedEventDTO{}, invalid("actor_id", "must match payload.actor_id")
	}
	if err := validateInitialVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return ActorSessionStartedEventDTO{}, err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"payload.principal_id":       event.Payload.PrincipalID,
		"payload.actor_id":           event.Payload.ActorID,
		"payload.membership_id":      event.Payload.MembershipID,
		"payload.delegation_id":      event.Payload.DelegationID,
		"payload.client_instance_id": event.Payload.ClientInstanceID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return ActorSessionStartedEventDTO{}, err
		}
	}
	if (event.Payload.DeviceID == nil) != (event.Payload.DeviceVersion == nil) ||
		(event.Payload.DeviceID == nil) != (event.Payload.DeviceTrustRevision == nil) {
		return ActorSessionStartedEventDTO{}, invalid(
			"payload.device_version",
			"device_version and device_trust_revision must be present exactly when payload.device_id is present",
		)
	}
	if event.Payload.DeviceID != nil {
		if event.Payload.DeviceID.IsZero() {
			return ActorSessionStartedEventDTO{}, invalid("payload.device_id", "must be nonzero when present")
		}
		if err := validateVersion("payload.device_version", *event.Payload.DeviceVersion); err != nil {
			return ActorSessionStartedEventDTO{}, err
		}
		if err := validateVersion("payload.device_trust_revision", *event.Payload.DeviceTrustRevision); err != nil {
			return ActorSessionStartedEventDTO{}, err
		}
	}
	if err := validateVersion("payload.membership_version", event.Payload.MembershipVersion); err != nil {
		return ActorSessionStartedEventDTO{}, err
	}
	if err := validateVersion("payload.delegation_version", event.Payload.DelegationVersion); err != nil {
		return ActorSessionStartedEventDTO{}, err
	}
	if err := validateGrantRevisionSet("payload.grant_revisions", event.Payload.GrantRevisions); err != nil {
		return ActorSessionStartedEventDTO{}, err
	}
	if _, err := domain.NewPolicyRevision(event.Payload.PolicyRevision); err != nil {
		return ActorSessionStartedEventDTO{}, invalid("payload.policy_revision", err.Error())
	}
	if _, err := domain.NewAssuranceClass(event.Payload.AssuranceClass); err != nil {
		return ActorSessionStartedEventDTO{}, invalid("payload.assurance_class", err.Error())
	}
	if _, err := normalizeCapabilities("payload.effective_capabilities", event.Payload.EffectiveCapabilities); err != nil {
		return ActorSessionStartedEventDTO{}, err
	}
	if err := validateUTCInstant("payload.issued_at", event.Payload.IssuedAt); err != nil {
		return ActorSessionStartedEventDTO{}, err
	}
	if err := validateUTCInstant("payload.absolute_expiry", event.Payload.AbsoluteExpiry); err != nil {
		return ActorSessionStartedEventDTO{}, err
	}
	if !event.Payload.AbsoluteExpiry.After(event.Payload.IssuedAt) {
		return ActorSessionStartedEventDTO{}, invalid("payload.absolute_expiry", "must be after issued_at")
	}
	if event.Payload.IssuedAt.After(event.OccurredAt) {
		return ActorSessionStartedEventDTO{}, invalid("payload.issued_at", "must not be after occurred_at")
	}
	return event, nil
}

func decodeEvent[Payload any](
	data []byte,
	eventType string,
	aggregateKind domain.AggregateKind,
	installationScope bool,
) (EventEnvelopeDTO[Payload], error) {
	var event EventEnvelopeDTO[Payload]
	if err := decodeOutput(data, MaxOutcomeJSONBytes, &event); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := requireTopLevelJSONMembers(data, "principal_id", "correlation_id", "extensions"); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	var shape struct {
		Extensions json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(data, &shape); err != nil {
		return EventEnvelopeDTO[Payload]{}, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	if !rawJSONObject(shape.Extensions) {
		return EventEnvelopeDTO[Payload]{}, invalid("extensions", "must be a JSON object")
	}
	if err := validateLiteral("schema", event.Schema, SchemaEventEnvelope); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := validateRequiredID("event_id", event.EventID); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := validateLiteral("event_type", event.EventType, eventType); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if event.EventVersion != 1 {
		return EventEnvelopeDTO[Payload]{}, invalid("event_version", "must equal 1")
	}
	if err := validateRequiredID("authority_id", event.AuthorityID); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := validateRequiredID("authority_epoch", event.AuthorityEpoch); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if installationScope {
		if event.InstallationID == nil || event.InstallationID.IsZero() || event.WorkspaceID != nil {
			return EventEnvelopeDTO[Payload]{}, invalid("installation_id", "installation event requires only installation_id scope")
		}
	} else if event.WorkspaceID == nil || event.WorkspaceID.IsZero() || event.InstallationID != nil {
		return EventEnvelopeDTO[Payload]{}, invalid("workspace_id", "workspace event requires only workspace_id scope")
	}
	if event.OriginPosition.IsZero() {
		return EventEnvelopeDTO[Payload]{}, invalid("origin_position", "must be positive")
	}
	if event.Aggregate.Type != aggregateKind {
		return EventEnvelopeDTO[Payload]{}, invalid("aggregate.type", fmt.Sprintf("must equal %q", aggregateKind))
	}
	if err := validateAggregateID(event.Aggregate.Type, event.Aggregate.ID); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := validateVersion("aggregate.version", event.Aggregate.Version); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := validateRequiredID("command_id", event.CommandID); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := validateRequiredID("principal_id", event.PrincipalID); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if event.ActorID != nil && event.ActorID.IsZero() {
		return EventEnvelopeDTO[Payload]{}, invalid("actor_id", "must be nonzero when present")
	}
	if event.ActorSessionID != nil && event.ActorSessionID.IsZero() {
		return EventEnvelopeDTO[Payload]{}, invalid("actor_session_id", "must be nonzero when present")
	}
	if (event.ActorID == nil) != (event.ActorSessionID == nil) {
		return EventEnvelopeDTO[Payload]{}, invalid("actor_id", "actor_id and actor_session_id must appear together")
	}
	if event.CausationID != nil && event.CausationID.IsZero() {
		return EventEnvelopeDTO[Payload]{}, invalid("causation_id", "must be nonzero when present")
	}
	if err := validateRequiredID("correlation_id", event.CorrelationID); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := validateUTCInstant("occurred_at", event.OccurredAt); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	if err := validateUTCInstant("recorded_at", event.RecordedAt); err != nil {
		return EventEnvelopeDTO[Payload]{}, err
	}
	return event, nil
}

func validateWorkspaceMembershipPayload(
	envelopeWorkspace *domain.WorkspaceID,
	payloadWorkspace domain.WorkspaceID,
	principal domain.PrincipalID,
) error {
	if envelopeWorkspace == nil || *envelopeWorkspace != payloadWorkspace {
		return invalid("payload.workspace_id", "must match workspace_id")
	}
	return validateRequiredID("payload.principal_id", principal)
}

func rejectActorAuthorship[Payload any](event EventEnvelopeDTO[Payload]) error {
	if event.ActorID != nil || event.ActorSessionID != nil {
		return invalid("actor_id", "authority fact must not carry actor or actor_session authorship")
	}
	return nil
}
