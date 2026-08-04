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
