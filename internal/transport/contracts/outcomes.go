package contracts

import (
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	SchemaCommandResult = "blackbird.command_result/1"
	SchemaError         = "blackbird.error/1"
	SchemaEventEnvelope = "blackbird.event_envelope/1"

	EventTypeInstallationBootstrapped    = "blackbird.installation.bootstrapped"
	EventTypePrincipalRegistered         = "blackbird.principal.registered"
	EventTypeDevicePaired                = "blackbird.device.paired"
	EventTypeDevicePairingBegan          = "blackbird.device_pairing.began"
	EventTypeWorkspaceCreated            = "blackbird.workspace.created"
	EventTypeWorkspaceMemberInvited      = "blackbird.workspace_member.invited"
	EventTypeWorkspaceMembershipAccepted = "blackbird.workspace_membership.accepted"
	EventTypeActorCreated                = "blackbird.actor.created"
	EventTypeActorDelegationProposed     = "blackbird.actor_delegation.proposed"
	EventTypeActorDelegationActivated    = "blackbird.actor_delegation.activated"
	EventTypeActorSessionStarted         = "blackbird.actor_session.started"
	EventTypeWorkRefObserved             = "blackbird.work_ref.observed"
	EventTypeObjectiveCreated            = "blackbird.objective.created"
	EventTypeWorkUnitCreated             = "blackbird.work_unit.created"
	EventTypeObjectiveActivated          = "blackbird.objective.activated"
	EventTypeRunPlanned                  = "blackbird.run.planned"
	EventTypeRunParticipantInvited       = "blackbird.run_participant.invited"
	EventTypeRuntimeBindingRequested     = "blackbird.runtime_binding.requested"
	EventTypeRunParticipantJoined        = "blackbird.run_participant.joined"
	EventTypeRunStarted                  = "blackbird.run.started"

	StateActive   = "active"
	StateTrusted  = "trusted"
	StateConsumed = "consumed"

	MaxRetryAfterMS uint32 = 5 * 60 * 1000
)

type CommandResultMetadataDTO struct {
	Schema           string           `json:"schema"`
	RequestID        string           `json:"request_id"`
	Operation        string           `json:"operation"`
	EventCursor      string           `json:"event_cursor"`
	EmittedEventIDs  []domain.EventID `json:"emitted_event_ids"`
	AcceptedAt       time.Time        `json:"accepted_at"`
	IdempotentReplay bool             `json:"idempotent_replay"`
}

func (metadata CommandResultMetadataDTO) validate(operation string, expectedEventCount int) error {
	if err := validateLiteral("schema", metadata.Schema, SchemaCommandResult); err != nil {
		return err
	}
	if err := validateToken("request_id", metadata.RequestID, maxRequestIDBytes); err != nil {
		return err
	}
	if err := validateOperation(metadata.Operation, operation); err != nil {
		return err
	}
	if err := validateCursor("event_cursor", metadata.EventCursor); err != nil {
		return err
	}
	if len(metadata.EmittedEventIDs) != expectedEventCount || len(metadata.EmittedEventIDs) > maxEventIDCount {
		return invalid("emitted_event_ids", fmt.Sprintf("must contain exactly %d event IDs", expectedEventCount))
	}
	seen := make(map[domain.EventID]struct{}, len(metadata.EmittedEventIDs))
	for index, eventID := range metadata.EmittedEventIDs {
		if eventID.IsZero() {
			return invalid(fmt.Sprintf("emitted_event_ids[%d]", index), "is required")
		}
		if _, duplicate := seen[eventID]; duplicate {
			return invalid("emitted_event_ids", "must not contain duplicates")
		}
		seen[eventID] = struct{}{}
	}
	if err := validateUTCInstant("accepted_at", metadata.AcceptedAt); err != nil {
		return err
	}
	return nil
}

type InstallationBootstrapResultDTO struct {
	CommandResultMetadataDTO
	Resource         InstallationBootstrapResourceDTO `json:"resource"`
	ResourceVersions InstallationBootstrapVersionsDTO `json:"resource_versions"`
}

type InstallationBootstrapResourceDTO struct {
	InstallationID           domain.InstallationID `json:"installation_id"`
	InvitationID             domain.InvitationID   `json:"invitation_id"`
	InvitationState          string                `json:"invitation_state"`
	PrincipalID              domain.PrincipalID    `json:"principal_id"`
	PrincipalState           string                `json:"principal_state"`
	DeviceID                 domain.DeviceID       `json:"device_id"`
	DeviceState              string                `json:"device_state"`
	InstallationOwnerGrantID domain.GrantID        `json:"installation_owner_grant_id"`
	TranscriptHash           string                `json:"transcript_hash"`
}

type InstallationBootstrapVersionsDTO struct {
	Invitation domain.Version `json:"invitation"`
	Principal  domain.Version `json:"principal"`
	Device     domain.Version `json:"device"`
	Grant      domain.Version `json:"grant"`
}

func DecodeInstallationBootstrapResult(data []byte) (InstallationBootstrapResultDTO, error) {
	var result InstallationBootstrapResultDTO
	if err := decodeOutput(data, MaxOutcomeJSONBytes, &result); err != nil {
		return InstallationBootstrapResultDTO{}, err
	}
	if err := requireTopLevelJSONMembers(data, "idempotent_replay"); err != nil {
		return InstallationBootstrapResultDTO{}, err
	}
	if err := result.Validate(); err != nil {
		return InstallationBootstrapResultDTO{}, err
	}
	return result, nil
}

func (result InstallationBootstrapResultDTO) Validate() error {
	if err := result.validate(OperationInstallationBootstrap, 3); err != nil {
		return err
	}
	if err := validateRequiredID("resource.installation_id", result.Resource.InstallationID); err != nil {
		return err
	}
	if err := validateRequiredID("resource.invitation_id", result.Resource.InvitationID); err != nil {
		return err
	}
	if err := validateLiteral("resource.invitation_state", result.Resource.InvitationState, StateConsumed); err != nil {
		return err
	}
	if err := validateRequiredID("resource.principal_id", result.Resource.PrincipalID); err != nil {
		return err
	}
	if err := validateLiteral("resource.principal_state", result.Resource.PrincipalState, StateActive); err != nil {
		return err
	}
	if err := validateRequiredID("resource.device_id", result.Resource.DeviceID); err != nil {
		return err
	}
	if err := validateLiteral("resource.device_state", result.Resource.DeviceState, StateTrusted); err != nil {
		return err
	}
	if err := validateRequiredID("resource.installation_owner_grant_id", result.Resource.InstallationOwnerGrantID); err != nil {
		return err
	}
	if err := validateSHA256Hex("resource.transcript_hash", result.Resource.TranscriptHash); err != nil {
		return err
	}
	if err := validateAdvancedVersion("resource_versions.invitation", result.ResourceVersions.Invitation); err != nil {
		return err
	}
	for field, version := range map[string]domain.Version{
		"resource_versions.principal": result.ResourceVersions.Principal,
		"resource_versions.device":    result.ResourceVersions.Device,
		"resource_versions.grant":     result.ResourceVersions.Grant,
	} {
		if err := validateInitialVersion(field, version); err != nil {
			return err
		}
	}
	return nil
}

type WorkspaceCreateResultDTO struct {
	CommandResultMetadataDTO
	Resource        WorkspaceCreateResourceDTO `json:"resource"`
	ResourceVersion domain.Version             `json:"resource_version"`
}

type WorkspaceCreateResourceDTO struct {
	InstallationID    domain.InstallationID `json:"installation_id"`
	WorkspaceID       domain.WorkspaceID    `json:"workspace_id"`
	WorkspaceState    string                `json:"workspace_state"`
	Alias             string                `json:"alias"`
	OwnerPrincipalID  domain.PrincipalID    `json:"owner_principal_id"`
	OwnerMembershipID domain.MembershipID   `json:"owner_membership_id"`
	MembershipState   string                `json:"membership_state"`
	MembershipVersion domain.Version        `json:"membership_version"`
	AuthorityID       domain.AuthorityID    `json:"authority_id"`
	AuthorityEpoch    domain.AuthorityEpoch `json:"authority_epoch"`
	PolicyRevision    string                `json:"policy_revision"`
}

func DecodeWorkspaceCreateResult(data []byte) (WorkspaceCreateResultDTO, error) {
	var result WorkspaceCreateResultDTO
	if err := decodeOutput(data, MaxOutcomeJSONBytes, &result); err != nil {
		return WorkspaceCreateResultDTO{}, err
	}
	if err := requireTopLevelJSONMembers(data, "idempotent_replay"); err != nil {
		return WorkspaceCreateResultDTO{}, err
	}
	if err := result.Validate(); err != nil {
		return WorkspaceCreateResultDTO{}, err
	}
	return result, nil
}

func (result WorkspaceCreateResultDTO) Validate() error {
	if err := result.validate(OperationWorkspaceCreate, 3); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"resource.installation_id":     result.Resource.InstallationID,
		"resource.workspace_id":        result.Resource.WorkspaceID,
		"resource.owner_principal_id":  result.Resource.OwnerPrincipalID,
		"resource.owner_membership_id": result.Resource.OwnerMembershipID,
		"resource.authority_id":        result.Resource.AuthorityID,
		"resource.authority_epoch":     result.Resource.AuthorityEpoch,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if err := validateLiteral("resource.workspace_state", result.Resource.WorkspaceState, StateActive); err != nil {
		return err
	}
	if err := validateLiteral("resource.membership_state", result.Resource.MembershipState, StateActive); err != nil {
		return err
	}
	if err := validateText("resource.alias", result.Resource.Alias, maxDisplayNameBytes, true); err != nil {
		return err
	}
	if err := validateInitialVersion("resource.membership_version", result.Resource.MembershipVersion); err != nil {
		return err
	}
	if err := validateInitialVersion("resource_version", result.ResourceVersion); err != nil {
		return err
	}
	if _, err := domain.NewPolicyRevision(result.Resource.PolicyRevision); err != nil {
		return invalid("resource.policy_revision", err.Error())
	}
	return nil
}

type PrincipalRegisterResultDTO struct {
	CommandResultMetadataDTO
	Resource PrincipalRegisterResourceDTO `json:"resource"`
}
type PrincipalRegisterResourceDTO struct {
	InstallationID  domain.InstallationID `json:"installation_id"`
	PrincipalID     domain.PrincipalID    `json:"principal_id"`
	PrincipalState  string                `json:"principal_state"`
	ResourceVersion domain.Version        `json:"resource_version"`
}

type DevicePairingBeginResultDTO struct {
	CommandResultMetadataDTO
	Resource DevicePairingBeginResourceDTO `json:"resource"`
}
type DevicePairingBeginResourceDTO struct {
	InstallationID  domain.InstallationID `json:"installation_id"`
	DeviceID        domain.DeviceID       `json:"device_id"`
	DeviceState     string                `json:"device_state"`
	ResourceVersion domain.Version        `json:"resource_version"`
	Challenge       IssuedCeremonyDTO     `json:"challenge"`
}

type DevicePairResultDTO struct {
	CommandResultMetadataDTO
	Resource DevicePairResourceDTO `json:"resource"`
}
type DevicePairResourceDTO struct {
	InstallationID  domain.InstallationID `json:"installation_id"`
	DeviceID        domain.DeviceID       `json:"device_id"`
	DeviceState     string                `json:"device_state"`
	ResourceVersion domain.Version        `json:"resource_version"`
	TrustRevision   domain.Version        `json:"trust_revision"`
}

type WorkspaceMemberInviteResultDTO struct {
	CommandResultMetadataDTO
	Resource WorkspaceMemberInviteResourceDTO `json:"resource"`
}
type WorkspaceMemberInviteResourceDTO struct {
	WorkspaceID     domain.WorkspaceID  `json:"workspace_id"`
	MembershipID    domain.MembershipID `json:"membership_id"`
	MembershipState string              `json:"membership_state"`
	ResourceVersion domain.Version      `json:"resource_version"`
	Challenge       IssuedCeremonyDTO   `json:"challenge"`
}
type WorkspaceMembershipAcceptResultDTO struct {
	CommandResultMetadataDTO
	Resource WorkspaceMembershipAcceptResourceDTO `json:"resource"`
}
type WorkspaceMembershipAcceptResourceDTO struct {
	WorkspaceID     domain.WorkspaceID  `json:"workspace_id"`
	MembershipID    domain.MembershipID `json:"membership_id"`
	MembershipState string              `json:"membership_state"`
	ResourceVersion domain.Version      `json:"resource_version"`
}

type ActorCreateResultDTO struct {
	CommandResultMetadataDTO
	Resource ActorCreateResourceDTO `json:"resource"`
}
type ActorCreateResourceDTO struct {
	WorkspaceID     domain.WorkspaceID `json:"workspace_id"`
	ActorID         domain.ActorID     `json:"actor_id"`
	ActorState      string             `json:"actor_state"`
	ResourceVersion domain.Version     `json:"resource_version"`
}
type ActorDelegationProposeResultDTO struct {
	CommandResultMetadataDTO
	Resource ActorDelegationProposeResourceDTO `json:"resource"`
}
type ActorDelegationProposeResourceDTO struct {
	WorkspaceID     domain.WorkspaceID       `json:"workspace_id"`
	DelegationID    domain.ActorDelegationID `json:"delegation_id"`
	DelegationState string                   `json:"delegation_state"`
	ResourceVersion domain.Version           `json:"resource_version"`
	Challenge       IssuedCeremonyDTO        `json:"challenge"`
}
type ActorDelegationActivateResultDTO struct {
	CommandResultMetadataDTO
	Resource ActorDelegationActivateResourceDTO `json:"resource"`
}
type ActorDelegationActivateResourceDTO struct {
	WorkspaceID           domain.WorkspaceID       `json:"workspace_id"`
	DelegationID          domain.ActorDelegationID `json:"delegation_id"`
	DelegationState       string                   `json:"delegation_state"`
	ResourceVersion       domain.Version           `json:"resource_version"`
	SessionStartChallenge IssuedCeremonyDTO        `json:"session_start_challenge"`
}
type SessionStartResultDTO struct {
	CommandResultMetadataDTO
	Resource SessionStartResourceDTO `json:"resource"`
}
type SessionStartResourceDTO struct {
	WorkspaceID     domain.WorkspaceID    `json:"workspace_id"`
	ActorSessionID  domain.ActorSessionID `json:"actor_session_id"`
	SessionState    string                `json:"session_state"`
	ResourceVersion domain.Version        `json:"resource_version"`
	AbsoluteExpiry  time.Time             `json:"absolute_expiry"`
}

type IssuedCeremonyDTO struct {
	CeremonyID domain.CeremonyID `json:"ceremony_id"`
	Purpose    string            `json:"purpose"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

func (ceremony IssuedCeremonyDTO) validate(field string) error {
	if err := validateRequiredID(field+".ceremony_id", ceremony.CeremonyID); err != nil {
		return err
	}
	if !domain.CeremonyPurpose(ceremony.Purpose).Valid() {
		return invalid(field+".purpose", "is not a stable ceremony purpose")
	}
	return validateUTCInstant(field+".expires_at", ceremony.ExpiresAt)
}

func validateSingleResult(metadata CommandResultMetadataDTO, operation string, ids map[string]interface{ IsZero() bool }, stateField, state, expectedState string, version domain.Version) error {
	if err := metadata.validate(operation, 1); err != nil {
		return err
	}
	for field, id := range ids {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if err := validateLiteral(stateField, state, expectedState); err != nil {
		return err
	}
	return validateVersion("resource.resource_version", version)
}

func (result PrincipalRegisterResultDTO) Validate() error {
	return validateSingleResult(result.CommandResultMetadataDTO, OperationPrincipalRegister, map[string]interface{ IsZero() bool }{"resource.installation_id": result.Resource.InstallationID, "resource.principal_id": result.Resource.PrincipalID}, "resource.principal_state", result.Resource.PrincipalState, string(domain.PrincipalActive), result.Resource.ResourceVersion)
}
func (result DevicePairingBeginResultDTO) Validate() error {
	if err := validateSingleResult(result.CommandResultMetadataDTO, OperationDevicePairingBegin, map[string]interface{ IsZero() bool }{"resource.installation_id": result.Resource.InstallationID, "resource.device_id": result.Resource.DeviceID}, "resource.device_state", result.Resource.DeviceState, string(domain.DevicePending), result.Resource.ResourceVersion); err != nil {
		return err
	}
	if err := result.Resource.Challenge.validate("resource.challenge"); err != nil {
		return err
	}
	return validateLiteral("resource.challenge.purpose", result.Resource.Challenge.Purpose, string(domain.CeremonyPurposeDevicePairing))
}
func (result DevicePairResultDTO) Validate() error {
	if err := validateSingleResult(result.CommandResultMetadataDTO, OperationDevicePair, map[string]interface{ IsZero() bool }{"resource.installation_id": result.Resource.InstallationID, "resource.device_id": result.Resource.DeviceID}, "resource.device_state", result.Resource.DeviceState, string(domain.DeviceTrusted), result.Resource.ResourceVersion); err != nil {
		return err
	}
	return validateVersion("resource.trust_revision", result.Resource.TrustRevision)
}
func (result WorkspaceMemberInviteResultDTO) Validate() error {
	if err := validateSingleResult(result.CommandResultMetadataDTO, OperationWorkspaceMemberInvite, map[string]interface{ IsZero() bool }{"resource.workspace_id": result.Resource.WorkspaceID, "resource.membership_id": result.Resource.MembershipID}, "resource.membership_state", result.Resource.MembershipState, string(domain.MembershipInvited), result.Resource.ResourceVersion); err != nil {
		return err
	}
	if err := result.Resource.Challenge.validate("resource.challenge"); err != nil {
		return err
	}
	return validateLiteral("resource.challenge.purpose", result.Resource.Challenge.Purpose, string(domain.CeremonyPurposeMembershipAcceptance))
}
func (result WorkspaceMembershipAcceptResultDTO) Validate() error {
	return validateSingleResult(result.CommandResultMetadataDTO, OperationWorkspaceMembershipAccept, map[string]interface{ IsZero() bool }{"resource.workspace_id": result.Resource.WorkspaceID, "resource.membership_id": result.Resource.MembershipID}, "resource.membership_state", result.Resource.MembershipState, string(domain.MembershipActive), result.Resource.ResourceVersion)
}
func (result ActorCreateResultDTO) Validate() error {
	return validateSingleResult(result.CommandResultMetadataDTO, OperationActorCreate, map[string]interface{ IsZero() bool }{"resource.workspace_id": result.Resource.WorkspaceID, "resource.actor_id": result.Resource.ActorID}, "resource.actor_state", result.Resource.ActorState, string(domain.ActorActive), result.Resource.ResourceVersion)
}
func (result ActorDelegationProposeResultDTO) Validate() error {
	if err := validateSingleResult(result.CommandResultMetadataDTO, OperationActorDelegationPropose, map[string]interface{ IsZero() bool }{"resource.workspace_id": result.Resource.WorkspaceID, "resource.delegation_id": result.Resource.DelegationID}, "resource.delegation_state", result.Resource.DelegationState, string(domain.DelegationProposed), result.Resource.ResourceVersion); err != nil {
		return err
	}
	if err := result.Resource.Challenge.validate("resource.challenge"); err != nil {
		return err
	}
	return validateLiteral("resource.challenge.purpose", result.Resource.Challenge.Purpose, string(domain.CeremonyPurposeDelegationActivation))
}
func (result ActorDelegationActivateResultDTO) Validate() error {
	if err := validateSingleResult(result.CommandResultMetadataDTO, OperationActorDelegationActivate, map[string]interface{ IsZero() bool }{"resource.workspace_id": result.Resource.WorkspaceID, "resource.delegation_id": result.Resource.DelegationID}, "resource.delegation_state", result.Resource.DelegationState, string(domain.DelegationActive), result.Resource.ResourceVersion); err != nil {
		return err
	}
	if err := result.Resource.SessionStartChallenge.validate("resource.session_start_challenge"); err != nil {
		return err
	}
	return validateLiteral("resource.session_start_challenge.purpose", result.Resource.SessionStartChallenge.Purpose, string(domain.CeremonyPurposeActorSessionStart))
}
func (result SessionStartResultDTO) Validate() error {
	if err := validateSingleResult(result.CommandResultMetadataDTO, OperationSessionStart, map[string]interface{ IsZero() bool }{"resource.workspace_id": result.Resource.WorkspaceID, "resource.actor_session_id": result.Resource.ActorSessionID}, "resource.session_state", result.Resource.SessionState, string(domain.ActorSessionActive), result.Resource.ResourceVersion); err != nil {
		return err
	}
	return validateUTCInstant("resource.absolute_expiry", result.Resource.AbsoluteExpiry)
}

func decodeCommandResult[T any](data []byte, result *T, validate func() error) error {
	if err := decodeOutput(data, MaxOutcomeJSONBytes, result); err != nil {
		return err
	}
	if err := requireTopLevelJSONMembers(data, "idempotent_replay"); err != nil {
		return err
	}
	return validate()
}
func DecodePrincipalRegisterResult(data []byte) (PrincipalRegisterResultDTO, error) {
	var value PrincipalRegisterResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}
func DecodeDevicePairingBeginResult(data []byte) (DevicePairingBeginResultDTO, error) {
	var value DevicePairingBeginResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}
func DecodeDevicePairResult(data []byte) (DevicePairResultDTO, error) {
	var value DevicePairResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}
func DecodeWorkspaceMemberInviteResult(data []byte) (WorkspaceMemberInviteResultDTO, error) {
	var value WorkspaceMemberInviteResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}
func DecodeWorkspaceMembershipAcceptResult(data []byte) (WorkspaceMembershipAcceptResultDTO, error) {
	var value WorkspaceMembershipAcceptResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}
func DecodeActorCreateResult(data []byte) (ActorCreateResultDTO, error) {
	var value ActorCreateResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}
func DecodeActorDelegationProposeResult(data []byte) (ActorDelegationProposeResultDTO, error) {
	var value ActorDelegationProposeResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}
func DecodeActorDelegationActivateResult(data []byte) (ActorDelegationActivateResultDTO, error) {
	var value ActorDelegationActivateResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}
func DecodeSessionStartResult(data []byte) (SessionStartResultDTO, error) {
	var value SessionStartResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}

type WorkRefObserveResultDTO struct {
	CommandResultMetadataDTO
	Resource WorkRefObserveResourceDTO `json:"resource"`
}
type WorkRefObserveResourceDTO struct {
	WorkspaceID        domain.WorkspaceID     `json:"workspace_id"`
	WorkReferenceID    domain.WorkReferenceID `json:"work_reference_id"`
	ResourceVersion    domain.Version         `json:"resource_version"`
	AdapterPrincipalID domain.PrincipalID     `json:"adapter_principal_id"`
	ProviderNamespace  string                 `json:"provider_namespace"`
	ProviderObjectID   string                 `json:"provider_object_id"`
	ProviderLocator    string                 `json:"provider_locator"`
	ProviderVersion    string                 `json:"provider_version"`
	ObservedAt         time.Time              `json:"observed_at"`
}

func DecodeWorkRefObserveResult(data []byte) (WorkRefObserveResultDTO, error) {
	var value WorkRefObserveResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}

func (result WorkRefObserveResultDTO) Validate() error {
	if err := result.validate(OperationWorkRefObserve, 1); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"resource.workspace_id":         result.Resource.WorkspaceID,
		"resource.work_reference_id":    result.Resource.WorkReferenceID,
		"resource.adapter_principal_id": result.Resource.AdapterPrincipalID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	for field, value := range map[string]string{
		"resource.provider_namespace": result.Resource.ProviderNamespace,
		"resource.provider_object_id": result.Resource.ProviderObjectID,
		"resource.provider_locator":   result.Resource.ProviderLocator,
		"resource.provider_version":   result.Resource.ProviderVersion,
	} {
		if err := validateText(field, value, maxOpaqueProviderValueBytes, true); err != nil {
			return err
		}
	}
	if err := validateVersion("resource.resource_version", result.Resource.ResourceVersion); err != nil {
		return err
	}
	return validateUTCInstant("resource.observed_at", result.Resource.ObservedAt)
}

type ObjectiveAndWorkCreateResultDTO struct {
	CommandResultMetadataDTO
	Resource ObjectiveAndWorkCreateResourceDTO `json:"resource"`
}
type ObjectiveAndWorkCreateResourceDTO struct {
	WorkspaceID      domain.WorkspaceID     `json:"workspace_id"`
	ObjectiveID      domain.ObjectiveID     `json:"objective_id"`
	ObjectiveState   string                 `json:"objective_state"`
	ObjectiveVersion domain.Version         `json:"objective_version"`
	WorkUnitID       domain.WorkUnitID      `json:"work_unit_id"`
	WorkUnitState    string                 `json:"work_unit_state"`
	WorkUnitVersion  domain.Version         `json:"work_unit_version"`
	WorkReferenceID  domain.WorkReferenceID `json:"work_reference_id"`
}

func DecodeObjectiveAndWorkCreateResult(data []byte) (ObjectiveAndWorkCreateResultDTO, error) {
	var value ObjectiveAndWorkCreateResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}

func (result ObjectiveAndWorkCreateResultDTO) Validate() error {
	if err := result.validate(OperationObjectiveAndWorkCreate, 2); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"resource.workspace_id":      result.Resource.WorkspaceID,
		"resource.objective_id":      result.Resource.ObjectiveID,
		"resource.work_unit_id":      result.Resource.WorkUnitID,
		"resource.work_reference_id": result.Resource.WorkReferenceID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if err := validateLiteral("resource.objective_state", result.Resource.ObjectiveState, string(domain.ObjectiveDraft)); err != nil {
		return err
	}
	if err := validateLiteral("resource.work_unit_state", result.Resource.WorkUnitState, string(domain.WorkUnitProposed)); err != nil {
		return err
	}
	if err := validateInitialVersion("resource.objective_version", result.Resource.ObjectiveVersion); err != nil {
		return err
	}
	return validateInitialVersion("resource.work_unit_version", result.Resource.WorkUnitVersion)
}

type ObjectiveActivateResultDTO struct {
	CommandResultMetadataDTO
	Resource ObjectiveActivateResourceDTO `json:"resource"`
}
type ObjectiveActivateResourceDTO struct {
	WorkspaceID     domain.WorkspaceID `json:"workspace_id"`
	ObjectiveID     domain.ObjectiveID `json:"objective_id"`
	ObjectiveState  string             `json:"objective_state"`
	ResourceVersion domain.Version     `json:"resource_version"`
}

func DecodeObjectiveActivateResult(data []byte) (ObjectiveActivateResultDTO, error) {
	var value ObjectiveActivateResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}

func (result ObjectiveActivateResultDTO) Validate() error {
	if err := result.validate(OperationObjectiveActivate, 1); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"resource.workspace_id": result.Resource.WorkspaceID,
		"resource.objective_id": result.Resource.ObjectiveID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if err := validateLiteral("resource.objective_state", result.Resource.ObjectiveState, string(domain.ObjectiveActive)); err != nil {
		return err
	}
	return validateAdvancedVersion("resource.resource_version", result.Resource.ResourceVersion)
}

type RunPlanWithBindingsResultDTO struct {
	CommandResultMetadataDTO
	Resource RunPlanWithBindingsResourceDTO `json:"resource"`
}
type RunPlanWithBindingsResourceDTO struct {
	WorkspaceID    domain.WorkspaceID            `json:"workspace_id"`
	RunID          domain.RunID                  `json:"run_id"`
	RunState       string                        `json:"run_state"`
	RunVersion     domain.Version                `json:"run_version"`
	ObjectiveID    domain.ObjectiveID            `json:"objective_id"`
	WorkUnitID     domain.WorkUnitID             `json:"work_unit_id"`
	OperatorID     domain.ActorID                `json:"operator_id"`
	Participations []RunParticipationResourceDTO `json:"participations"`
	Bindings       []RuntimeBindingResourceDTO   `json:"bindings"`
}
type RunParticipationResourceDTO struct {
	ParticipationID    domain.RunParticipationID `json:"participation_id"`
	ActorID            domain.ActorID            `json:"actor_id"`
	Role               string                    `json:"role"`
	ParticipationState string                    `json:"participation_state"`
	ResourceVersion    domain.Version            `json:"resource_version"`
}
type RuntimeBindingResourceDTO struct {
	BindingID         domain.RuntimeBindingID   `json:"binding_id"`
	ParticipationID   domain.RunParticipationID `json:"participation_id"`
	SessionID         domain.ActorSessionID     `json:"session_id"`
	RuntimeEndpointID domain.RuntimeEndpointID  `json:"runtime_endpoint_id"`
	BindingState      string                    `json:"binding_state"`
	ResourceVersion   domain.Version            `json:"resource_version"`
}

func DecodeRunPlanWithBindingsResult(data []byte) (RunPlanWithBindingsResultDTO, error) {
	var value RunPlanWithBindingsResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}

func (result RunPlanWithBindingsResultDTO) Validate() error {
	expectedEvents := 1 + len(result.Resource.Participations) + len(result.Resource.Bindings)
	if err := result.validate(OperationRunPlanWithBindings, expectedEvents); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"resource.workspace_id": result.Resource.WorkspaceID,
		"resource.run_id":       result.Resource.RunID,
		"resource.objective_id": result.Resource.ObjectiveID,
		"resource.work_unit_id": result.Resource.WorkUnitID,
		"resource.operator_id":  result.Resource.OperatorID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if err := validateLiteral("resource.run_state", result.Resource.RunState, string(domain.RunPlanned)); err != nil {
		return err
	}
	if err := validateInitialVersion("resource.run_version", result.Resource.RunVersion); err != nil {
		return err
	}
	if len(result.Resource.Participations) == 0 || len(result.Resource.Participations) > domain.MaxRunParticipants {
		return invalid("resource.participations", fmt.Sprintf("must contain between 1 and %d entries", domain.MaxRunParticipants))
	}
	seenParticipation := make(map[domain.RunParticipationID]struct{}, len(result.Resource.Participations))
	for index, participation := range result.Resource.Participations {
		prefix := fmt.Sprintf("resource.participations[%d]", index)
		if err := validateRequiredID(prefix+".participation_id", participation.ParticipationID); err != nil {
			return err
		}
		if err := validateRequiredID(prefix+".actor_id", participation.ActorID); err != nil {
			return err
		}
		if err := validateText(prefix+".role", participation.Role, maxRunRoleBytes, true); err != nil {
			return err
		}
		if err := validateLiteral(prefix+".participation_state", participation.ParticipationState, string(domain.RunParticipationInvited)); err != nil {
			return err
		}
		if err := validateInitialVersion(prefix+".resource_version", participation.ResourceVersion); err != nil {
			return err
		}
		if _, duplicate := seenParticipation[participation.ParticipationID]; duplicate {
			return invalid(prefix+".participation_id", "must not duplicate an earlier participation")
		}
		seenParticipation[participation.ParticipationID] = struct{}{}
	}
	if len(result.Resource.Bindings) == 0 || len(result.Resource.Bindings) > domain.MaxRunBindings {
		return invalid("resource.bindings", fmt.Sprintf("must contain between 1 and %d entries", domain.MaxRunBindings))
	}
	seenBinding := make(map[domain.RuntimeBindingID]struct{}, len(result.Resource.Bindings))
	for index, binding := range result.Resource.Bindings {
		prefix := fmt.Sprintf("resource.bindings[%d]", index)
		if err := validateRequiredID(prefix+".binding_id", binding.BindingID); err != nil {
			return err
		}
		if err := validateRequiredID(prefix+".participation_id", binding.ParticipationID); err != nil {
			return err
		}
		if err := validateRequiredID(prefix+".session_id", binding.SessionID); err != nil {
			return err
		}
		if err := validateRequiredID(prefix+".runtime_endpoint_id", binding.RuntimeEndpointID); err != nil {
			return err
		}
		if err := validateLiteral(prefix+".binding_state", binding.BindingState, string(domain.RuntimeBindingRequested)); err != nil {
			return err
		}
		if err := validateInitialVersion(prefix+".resource_version", binding.ResourceVersion); err != nil {
			return err
		}
		if _, duplicate := seenBinding[binding.BindingID]; duplicate {
			return invalid(prefix+".binding_id", "must not duplicate an earlier binding")
		}
		seenBinding[binding.BindingID] = struct{}{}
	}
	return nil
}

type RunJoinResultDTO struct {
	CommandResultMetadataDTO
	Resource RunJoinResourceDTO `json:"resource"`
}
type RunJoinResourceDTO struct {
	WorkspaceID        domain.WorkspaceID        `json:"workspace_id"`
	RunID              domain.RunID              `json:"run_id"`
	ParticipationID    domain.RunParticipationID `json:"participation_id"`
	ActorID            domain.ActorID            `json:"actor_id"`
	SessionID          domain.ActorSessionID     `json:"session_id"`
	ParticipationState string                    `json:"participation_state"`
	ResourceVersion    domain.Version            `json:"resource_version"`
}

func DecodeRunJoinResult(data []byte) (RunJoinResultDTO, error) {
	var value RunJoinResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}

func (result RunJoinResultDTO) Validate() error {
	if err := result.validate(OperationRunJoin, 1); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"resource.workspace_id":     result.Resource.WorkspaceID,
		"resource.run_id":           result.Resource.RunID,
		"resource.participation_id": result.Resource.ParticipationID,
		"resource.actor_id":         result.Resource.ActorID,
		"resource.session_id":       result.Resource.SessionID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if err := validateLiteral("resource.participation_state", result.Resource.ParticipationState, string(domain.RunParticipationActive)); err != nil {
		return err
	}
	return validateAdvancedVersion("resource.resource_version", result.Resource.ResourceVersion)
}

type RunStartResultDTO struct {
	CommandResultMetadataDTO
	Resource RunStartResourceDTO `json:"resource"`
}
type RunStartResourceDTO struct {
	WorkspaceID domain.WorkspaceID `json:"workspace_id"`
	RunID       domain.RunID       `json:"run_id"`
	RunState    string             `json:"run_state"`
	RunVersion  domain.Version     `json:"run_version"`
	OperatorID  domain.ActorID     `json:"operator_id"`
}

func DecodeRunStartResult(data []byte) (RunStartResultDTO, error) {
	var value RunStartResultDTO
	err := decodeCommandResult(data, &value, func() error { return value.Validate() })
	return value, err
}

func (result RunStartResultDTO) Validate() error {
	if err := result.validate(OperationRunStart, 1); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"resource.workspace_id": result.Resource.WorkspaceID,
		"resource.run_id":       result.Resource.RunID,
		"resource.operator_id":  result.Resource.OperatorID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if err := validateLiteral("resource.run_state", result.Resource.RunState, string(domain.RunStarting)); err != nil {
		return err
	}
	return validateAdvancedVersion("resource.run_version", result.Resource.RunVersion)
}

func validateUTCInstant(field string, instant time.Time) error {
	if instant.IsZero() {
		return invalid(field, "is required")
	}
	_, offset := instant.Zone()
	if offset != 0 {
		return invalid(field, "must use UTC")
	}
	return nil
}

type ErrorDTO struct {
	Schema        string                `json:"schema"`
	RequestID     string                `json:"request_id"`
	Code          domain.ErrorCode      `json:"code"`
	Category      domain.ErrorCategory  `json:"category"`
	Message       string                `json:"message"`
	Retryable     bool                  `json:"retryable"`
	RetryAfterMS  *uint32               `json:"retry_after_ms"`
	CorrelationID *domain.CorrelationID `json:"correlation_id,omitempty"`
	Details       ErrorDetailsDTO       `json:"details"`
}

type ErrorDetailsDTO struct {
	FieldViolations  []FieldViolationDTO   `json:"field_violations,omitempty"`
	DomainConflict   domain.ConflictKind   `json:"domain_conflict,omitempty"`
	Aggregate        *AggregateConflictDTO `json:"aggregate,omitempty"`
	DeniedCapability string                `json:"denied_capability,omitempty"`
	ResourceScope    *ResourceScopeDTO     `json:"resource_scope,omitempty"`
	Recovery         RecoveryAction        `json:"recovery,omitempty"`
	IdempotencyKey   string                `json:"idempotency_key,omitempty"`
	CommandID        *domain.CommandID     `json:"command_id,omitempty"`
	Dependency       string                `json:"dependency,omitempty"`
	CurrentState     string                `json:"current_state,omitempty"`
	CurrentAuthority *AuthorityRouteDTO    `json:"current_authority,omitempty"`
}

type RecoveryAction string

const (
	RecoveryReauthenticate       RecoveryAction = "reauthenticate"
	RecoveryResumeSession        RecoveryAction = "resume_session"
	RecoveryStartNewSession      RecoveryAction = "start_new_session"
	RecoveryRetryAfterDelay      RecoveryAction = "retry_after_delay"
	RecoveryDiscardCursor        RecoveryAction = "discard_cursor"
	RecoveryRestartQuery         RecoveryAction = "restart_query"
	RecoveryObtainCheckpoint     RecoveryAction = "obtain_checkpoint"
	RecoveryRetryDependency      RecoveryAction = "retry_dependency"
	RecoveryInspectCommandResult RecoveryAction = "inspect_command_result"
	RecoveryRetrySameCommand     RecoveryAction = "retry_same_command"
)

type ResourceScopeDTO struct {
	Type domain.AggregateKind `json:"type"`
	ID   string               `json:"id"`
}

type AuthorityRouteDTO struct {
	AuthorityID    domain.AuthorityID    `json:"authority_id"`
	AuthorityEpoch domain.AuthorityEpoch `json:"authority_epoch"`
	TransitionRef  string                `json:"transition_ref,omitempty"`
}

type FieldViolationDTO struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type AggregateConflictDTO struct {
	Type            domain.AggregateKind `json:"type"`
	ID              string               `json:"id"`
	ExpectedVersion *domain.Version      `json:"expected_version,omitempty"`
	ActualVersion   *domain.Version      `json:"actual_version,omitempty"`
}

func DecodeError(data []byte) (ErrorDTO, error) {
	var result ErrorDTO
	if err := decodeOutput(data, MaxOutcomeJSONBytes, &result); err != nil {
		return ErrorDTO{}, err
	}
	if err := requireTopLevelJSONMembers(data, "retryable", "retry_after_ms", "details"); err != nil {
		return ErrorDTO{}, err
	}
	if err := result.Validate(); err != nil {
		return ErrorDTO{}, err
	}
	return result, nil
}

func (result ErrorDTO) Validate() error {
	if err := validateLiteral("schema", result.Schema, SchemaError); err != nil {
		return err
	}
	if err := validateToken("request_id", result.RequestID, maxRequestIDBytes); err != nil {
		return err
	}
	category, valid := result.Code.Category()
	if !valid {
		return invalid("code", "is not a stable Blackbird error code")
	}
	if result.Category != category {
		return invalid("category", fmt.Sprintf("must equal %q for code %q", category, result.Code))
	}
	if err := validateText("message", result.Message, 512, true); err != nil {
		return err
	}
	if result.Retryable != result.Code.DefaultRetryable() {
		return invalid("retryable", "does not match the stable error-code retry posture")
	}
	if err := result.validateRetryDelay(); err != nil {
		return err
	}
	if result.CorrelationID != nil && result.CorrelationID.IsZero() {
		return invalid("correlation_id", "must be nonzero when present")
	}
	if result.Details.DomainConflict != "" && !result.Details.DomainConflict.Valid() {
		return invalid("details.domain_conflict", "is not a stable domain conflict")
	}
	if result.Details.Aggregate != nil {
		if err := result.Details.Aggregate.validate(); err != nil {
			return err
		}
	}
	if len(result.Details.FieldViolations) > maxFieldViolationCount {
		return invalid("details.field_violations", fmt.Sprintf("must contain at most %d entries", maxFieldViolationCount))
	}
	seenViolations := make(map[string]struct{}, len(result.Details.FieldViolations))
	for index, violation := range result.Details.FieldViolations {
		prefix := fmt.Sprintf("details.field_violations[%d]", index)
		if err := validateToken(prefix+".field", violation.Field, 256); err != nil {
			return err
		}
		if err := validateToken(prefix+".code", violation.Code, 64); err != nil {
			return err
		}
		if err := validateText(prefix+".message", violation.Message, 256, true); err != nil {
			return err
		}
		key := violation.Field + "\x00" + violation.Code
		if _, duplicate := seenViolations[key]; duplicate {
			return invalid("details.field_violations", "must not contain duplicate field/code entries")
		}
		seenViolations[key] = struct{}{}
	}
	if result.Details.DeniedCapability != "" {
		if err := validateCapability("details.denied_capability", result.Details.DeniedCapability); err != nil {
			return err
		}
	}
	if result.Details.Recovery != "" && !result.Details.Recovery.Valid() {
		return invalid("details.recovery", "is not a stable recovery action")
	}
	if result.Details.IdempotencyKey != "" {
		if err := validateIdempotencyKey(result.Details.IdempotencyKey); err != nil {
			return err
		}
	}
	if result.Details.CommandID != nil && result.Details.CommandID.IsZero() {
		return invalid("details.command_id", "must be nonzero when present")
	}
	if err := validateTokenIfPresent("details.dependency", result.Details.Dependency, 128); err != nil {
		return err
	}
	if err := validateTokenIfPresent("details.current_state", result.Details.CurrentState, 64); err != nil {
		return err
	}
	if result.Details.ResourceScope != nil {
		if err := result.Details.ResourceScope.validate("details.resource_scope"); err != nil {
			return err
		}
	}
	if result.Details.CurrentAuthority != nil {
		if err := result.Details.CurrentAuthority.validate(); err != nil {
			return err
		}
	}
	return result.validateCodeDetails()
}

func (action RecoveryAction) Valid() bool {
	switch action {
	case RecoveryReauthenticate,
		RecoveryResumeSession,
		RecoveryStartNewSession,
		RecoveryRetryAfterDelay,
		RecoveryDiscardCursor,
		RecoveryRestartQuery,
		RecoveryObtainCheckpoint,
		RecoveryRetryDependency,
		RecoveryInspectCommandResult,
		RecoveryRetrySameCommand:
		return true
	default:
		return false
	}
}

func (scope ResourceScopeDTO) validate(field string) error {
	if !scope.Type.Valid() {
		return invalid(field+".type", "is not a supported aggregate kind")
	}
	if err := validateAggregateID(scope.Type, scope.ID); err != nil {
		return invalid(field+".id", err.Error())
	}
	return nil
}

func (route AuthorityRouteDTO) validate() error {
	if err := validateRequiredID("details.current_authority.authority_id", route.AuthorityID); err != nil {
		return err
	}
	if err := validateRequiredID("details.current_authority.authority_epoch", route.AuthorityEpoch); err != nil {
		return err
	}
	return validateTokenIfPresent("details.current_authority.transition_ref", route.TransitionRef, 256)
}

func (aggregate AggregateConflictDTO) validate() error {
	if !aggregate.Type.Valid() {
		return invalid("details.aggregate.type", "is not a supported aggregate kind")
	}
	if err := validateAggregateID(aggregate.Type, aggregate.ID); err != nil {
		return err
	}
	if aggregate.ExpectedVersion != nil {
		if err := validateVersion("details.aggregate.expected_version", *aggregate.ExpectedVersion); err != nil {
			return err
		}
	}
	if aggregate.ActualVersion != nil {
		if err := validateVersion("details.aggregate.actual_version", *aggregate.ActualVersion); err != nil {
			return err
		}
	}
	return nil
}

func (result ErrorDTO) validateRetryDelay() error {
	requiresDelay := result.Code == domain.ErrorCodeCommandInProgress ||
		result.Code == domain.ErrorCodeRateLimited ||
		result.Code == domain.ErrorCodeBackpressure ||
		result.Code == domain.ErrorCodeDependencyUnavailable
	if !requiresDelay {
		if result.RetryAfterMS != nil {
			return invalid("retry_after_ms", "must be null unless the error code requires server-directed retry delay")
		}
		return nil
	}
	if result.RetryAfterMS == nil || *result.RetryAfterMS == 0 || *result.RetryAfterMS > MaxRetryAfterMS {
		return invalid("retry_after_ms", fmt.Sprintf("must be within 1..%d for this error code", MaxRetryAfterMS))
	}
	return nil
}

type errorDetailMask uint16

const (
	detailFieldViolations errorDetailMask = 1 << iota
	detailDomainConflict
	detailAggregate
	detailDeniedCapability
	detailResourceScope
	detailRecovery
	detailIdempotencyKey
	detailCommandID
	detailDependency
	detailCurrentState
	detailCurrentAuthority
)

func (result ErrorDTO) validateCodeDetails() error {
	details := result.Details
	switch result.Code {
	case domain.ErrorCodeInvalidArgument:
		return details.requireAndAllow(detailFieldViolations, detailFieldViolations)
	case domain.ErrorCodeInvalidSchema:
		return details.requireAndAllow(detailFieldViolations, detailFieldViolations)
	case domain.ErrorCodeUnauthenticated, domain.ErrorCodeSessionExpired:
		if result.Code == domain.ErrorCodeUnauthenticated && details.Recovery != RecoveryReauthenticate {
			return invalid("details.recovery", "must equal reauthenticate for UNAUTHENTICATED")
		}
		if result.Code == domain.ErrorCodeSessionExpired &&
			details.Recovery != RecoveryResumeSession && details.Recovery != RecoveryStartNewSession {
			return invalid("details.recovery", "must select resume_session or start_new_session for SESSION_EXPIRED")
		}
		return details.requireAndAllow(detailRecovery, detailRecovery)
	case domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired:
		return details.requireAndAllow(
			detailDeniedCapability|detailResourceScope,
			detailDeniedCapability|detailResourceScope,
		)
	case domain.ErrorCodeNotFound:
		if err := details.requireAndAllow(detailAggregate, detailAggregate); err != nil {
			return err
		}
		if details.Aggregate.ExpectedVersion != nil || details.Aggregate.ActualVersion != nil {
			return invalid("details.aggregate", "versions must be absent for NOT_FOUND")
		}
		return nil
	case domain.ErrorCodeStaleVersion:
		if details.DomainConflict != domain.ConflictVersion {
			return invalid("details.domain_conflict", "must equal VersionConflict for STALE_VERSION")
		}
		if err := details.requireAndAllow(detailDomainConflict|detailAggregate, detailDomainConflict|detailAggregate); err != nil {
			return err
		}
		if details.Aggregate.ExpectedVersion == nil || details.Aggregate.ActualVersion == nil {
			return invalid("details.aggregate", "expected_version and actual_version are required for STALE_VERSION")
		}
		return nil
	case domain.ErrorCodeStateConflict:
		switch details.DomainConflict {
		case domain.ConflictAuthorityMismatch:
			return details.requireAndAllow(
				detailDomainConflict|detailResourceScope|detailCurrentAuthority,
				detailDomainConflict|detailResourceScope|detailCurrentAuthority,
			)
		case domain.ConflictReference:
			if err := details.requireAndAllow(
				detailDomainConflict|detailAggregate,
				detailDomainConflict|detailAggregate,
			); err != nil {
				return err
			}
			if details.Aggregate.ExpectedVersion != nil {
				return invalid("details.aggregate.expected_version", "must be absent for ReferenceConflict")
			}
			return nil
		case domain.ConflictState, domain.ConflictSessionTerminal:
			if err := details.requireAndAllow(
				detailDomainConflict|detailAggregate|detailCurrentState,
				detailDomainConflict|detailAggregate|detailCurrentState,
			); err != nil {
				return err
			}
			if details.Aggregate.ExpectedVersion != nil {
				return invalid("details.aggregate.expected_version", "must be absent for current-state evidence")
			}
			return nil
		default:
			return invalid("details.domain_conflict", "does not have a frozen W0 STATE_CONFLICT evidence schema")
		}
	case domain.ErrorCodeIdempotencyKeyReused:
		if details.DomainConflict != domain.ConflictIdempotency {
			return invalid("details.domain_conflict", "must equal IdempotencyConflict for IDEMPOTENCY_KEY_REUSED")
		}
		return details.requireAndAllow(
			detailDomainConflict|detailIdempotencyKey,
			detailDomainConflict|detailIdempotencyKey,
		)
	case domain.ErrorCodeCommandIDReused:
		return details.requireAndAllow(detailCommandID, detailCommandID)
	case domain.ErrorCodeCommandInProgress:
		if details.Recovery != RecoveryRetryAfterDelay {
			return invalid("details.recovery", "must equal retry_after_delay for COMMAND_IN_PROGRESS")
		}
		return details.requireAndAllow(
			detailRecovery|detailIdempotencyKey,
			detailRecovery|detailIdempotencyKey,
		)
	case domain.ErrorCodeLeaseConflict, domain.ErrorCodeLeaseExpired, domain.ErrorCodeFenceRejected:
		return invalid("code", "does not have a frozen W0 typed evidence schema")
	case domain.ErrorCodeCursorInvalid:
		if details.Recovery != RecoveryDiscardCursor {
			return invalid("details.recovery", "must equal discard_cursor for CURSOR_INVALID")
		}
		return details.requireAndAllow(detailRecovery, detailRecovery)
	case domain.ErrorCodeCursorScopeMismatch:
		if details.Recovery != RecoveryRestartQuery {
			return invalid("details.recovery", "must equal restart_query for CURSOR_SCOPE_MISMATCH")
		}
		return details.requireAndAllow(detailRecovery, detailRecovery)
	case domain.ErrorCodeCursorExpired:
		if details.Recovery != RecoveryObtainCheckpoint {
			return invalid("details.recovery", "must equal obtain_checkpoint for CURSOR_EXPIRED")
		}
		return details.requireAndAllow(detailRecovery, detailRecovery)
	case domain.ErrorCodeRateLimited, domain.ErrorCodeBackpressure:
		if details.Recovery != RecoveryRetryAfterDelay {
			return invalid("details.recovery", "must equal retry_after_delay for capacity errors")
		}
		return details.requireAndAllow(detailRecovery, detailRecovery)
	case domain.ErrorCodeDependencyUnavailable:
		if details.Recovery != RecoveryRetryDependency {
			return invalid("details.recovery", "must equal retry_dependency for DEPENDENCY_UNAVAILABLE")
		}
		return details.requireAndAllow(detailRecovery|detailDependency, detailRecovery|detailDependency)
	case domain.ErrorCodeDeadlineExceeded:
		if details.Recovery != RecoveryInspectCommandResult {
			return invalid("details.recovery", "must equal inspect_command_result for DEADLINE_EXCEEDED")
		}
		return details.requireAndAllow(detailRecovery|detailIdempotencyKey, detailRecovery|detailIdempotencyKey)
	case domain.ErrorCodeInternal:
		if details.Recovery != RecoveryRetrySameCommand {
			return invalid("details.recovery", "must equal retry_same_command for INTERNAL")
		}
		return details.requireAndAllow(detailRecovery, detailRecovery)
	default:
		return invalid("code", "is not a stable Blackbird error code")
	}
}

func (details ErrorDetailsDTO) requireAndAllow(required, allowed errorDetailMask) error {
	present := details.presentMask()
	if missing := required &^ present; missing != 0 {
		return invalid("details", "is missing code-required fields")
	}
	if unexpected := present &^ allowed; unexpected != 0 {
		return invalid("details", "contains fields forbidden for this error code")
	}
	return nil
}

func (details ErrorDetailsDTO) presentMask() errorDetailMask {
	var present errorDetailMask
	if len(details.FieldViolations) > 0 {
		present |= detailFieldViolations
	}
	if details.DomainConflict != "" {
		present |= detailDomainConflict
	}
	if details.Aggregate != nil {
		present |= detailAggregate
	}
	if details.DeniedCapability != "" {
		present |= detailDeniedCapability
	}
	if details.ResourceScope != nil {
		present |= detailResourceScope
	}
	if details.Recovery != "" {
		present |= detailRecovery
	}
	if details.IdempotencyKey != "" {
		present |= detailIdempotencyKey
	}
	if details.CommandID != nil {
		present |= detailCommandID
	}
	if details.Dependency != "" {
		present |= detailDependency
	}
	if details.CurrentState != "" {
		present |= detailCurrentState
	}
	if details.CurrentAuthority != nil {
		present |= detailCurrentAuthority
	}
	return present
}

func validateTokenIfPresent(field, value string, maximum int) error {
	if value == "" {
		return nil
	}
	return validateToken(field, value, maximum)
}
