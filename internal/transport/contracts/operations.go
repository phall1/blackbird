package contracts

import (
	"fmt"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	OperationInstallationBootstrap = "installation.bootstrap.v1"
	OperationWorkspaceCreate       = "workspace.create.v1"
	OperationSessionStart          = "session.start.v1"

	SchemaInstallationBootstrapCommand = "blackbird.command.installation_bootstrap/1"
	SchemaWorkspaceCreateCommand       = "blackbird.command.workspace_create/1"
	SchemaSessionStartCommand          = "blackbird.command.session_start/1"

	PairingProtocolV1     = "blackbird.pair/v1"
	PrincipalKindHuman    = "human"
	PrincipalKindWorkload = "workload"
	PrincipalKindService  = "service"

	ActorKindHuman      = "human"
	ActorKindAgent      = "agent"
	ActorKindAutomation = "automation"
	ActorKindService    = "service"
)

// CommandMetadataDTO is common retry, attribution, authority, and deadline
// metadata for the three pre-session W0.2 commands. Authentication still comes
// from the paired channel; none of these fields is credential evidence.
type CommandMetadataDTO struct {
	Schema         string                `json:"schema"`
	RequestID      string                `json:"request_id"`
	CommandID      domain.CommandID      `json:"command_id"`
	Operation      string                `json:"operation"`
	IdempotencyKey string                `json:"idempotency_key"`
	AuthorityID    domain.AuthorityID    `json:"authority_id"`
	AuthorityEpoch domain.AuthorityEpoch `json:"authority_epoch"`
	Deadline       time.Time             `json:"deadline"`
	CausationID    *domain.EventID       `json:"causation_id,omitempty"`
	CorrelationID  domain.CorrelationID  `json:"correlation_id"`
}

func (metadata CommandMetadataDTO) validate(schema, operation string) error {
	if err := validateLiteral("schema", metadata.Schema, schema); err != nil {
		return err
	}
	if err := validateToken("request_id", metadata.RequestID, maxRequestIDBytes); err != nil {
		return err
	}
	if err := validateRequiredID("command_id", metadata.CommandID); err != nil {
		return err
	}
	if err := validateOperation(metadata.Operation, operation); err != nil {
		return err
	}
	if err := validateIdempotencyKey(metadata.IdempotencyKey); err != nil {
		return err
	}
	if err := validateRequiredID("authority_id", metadata.AuthorityID); err != nil {
		return err
	}
	if err := validateRequiredID("authority_epoch", metadata.AuthorityEpoch); err != nil {
		return err
	}
	if err := validateDeadline(metadata.Deadline); err != nil {
		return err
	}
	if metadata.CausationID != nil && metadata.CausationID.IsZero() {
		return invalid("causation_id", "must be nonzero when present")
	}
	if err := validateRequiredID("correlation_id", metadata.CorrelationID); err != nil {
		return err
	}
	return nil
}

type InstallationBootstrapRequestDTO struct {
	CommandMetadataDTO
	ExpectedVersions InstallationBootstrapExpectedVersionsDTO `json:"expected_versions"`
	Body             InstallationBootstrapBodyDTO             `json:"body"`
}

type InstallationBootstrapExpectedVersionsDTO struct {
	Invitation domain.Version `json:"invitation"`
}

type InstallationBootstrapBodyDTO struct {
	InstallationID           domain.InstallationID           `json:"installation_id"`
	InvitationID             domain.InvitationID             `json:"invitation_id"`
	Principal                BootstrapPrincipalDTO           `json:"principal"`
	Device                   BootstrapDeviceDTO              `json:"device"`
	InstallationOwnerGrantID domain.GrantID                  `json:"installation_owner_grant_id"`
	Pairing                  ApprovedPairingTranscriptRefDTO `json:"pairing"`
}

type BootstrapPrincipalDTO struct {
	PrincipalID domain.PrincipalID `json:"principal_id"`
	Kind        string             `json:"kind"`
	DisplayName string             `json:"display_name"`
}

type BootstrapDeviceDTO struct {
	DeviceID      domain.DeviceID `json:"device_id"`
	DisplayName   string          `json:"display_name"`
	PublicKeySPKI string          `json:"public_key_spki"`
}

// ApprovedPairingTranscriptRefDTO contains only public or one-way transcript
// material. The invitation secret, channel-binding HMAC, signatures, and
// private keys are authenticated by the pairing transport and never enter the
// semantic command body.
type ApprovedPairingTranscriptRefDTO struct {
	Protocol       string `json:"protocol"`
	TranscriptHash string `json:"transcript_hash"`
}

// InstallationBootstrapValues is the validated transport boundary. It is not
// an application command; the later application adapter supplies authenticated
// channel facts and authority time before invoking a use case.
type InstallationBootstrapValues struct {
	Metadata          CommandMetadataDTO
	InstallationID    domain.InstallationID
	InvitationID      domain.InvitationID
	PrincipalID       domain.PrincipalID
	PrincipalName     string
	DeviceID          domain.DeviceID
	DeviceName        string
	DevicePublicKey   string
	OwnerGrantID      domain.GrantID
	TranscriptHash    string
	InvitationVersion domain.Version
	CommitSet         domain.AtomicCommitSet
}

func DecodeInstallationBootstrapRequest(data []byte) (InstallationBootstrapRequestDTO, error) {
	var request InstallationBootstrapRequestDTO
	if err := decodeStrict(data, MaxCommandJSONBytes, &request); err != nil {
		return InstallationBootstrapRequestDTO{}, err
	}
	if _, err := request.Values(); err != nil {
		return InstallationBootstrapRequestDTO{}, err
	}
	return request, nil
}

func (request InstallationBootstrapRequestDTO) Values() (InstallationBootstrapValues, error) {
	if err := request.validate(
		SchemaInstallationBootstrapCommand,
		OperationInstallationBootstrap,
	); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateVersion("expected_versions.invitation", request.ExpectedVersions.Invitation); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateRequiredID("body.installation_id", request.Body.InstallationID); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateRequiredID("body.invitation_id", request.Body.InvitationID); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateRequiredID("body.principal.principal_id", request.Body.Principal.PrincipalID); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateLiteral("body.principal.kind", request.Body.Principal.Kind, PrincipalKindHuman); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateText("body.principal.display_name", request.Body.Principal.DisplayName, maxDisplayNameBytes, true); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateRequiredID("body.device.device_id", request.Body.Device.DeviceID); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateText("body.device.display_name", request.Body.Device.DisplayName, maxDisplayNameBytes, true); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateBase64URL("body.device.public_key_spki", request.Body.Device.PublicKeySPKI, 1024); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateRequiredID("body.installation_owner_grant_id", request.Body.InstallationOwnerGrantID); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateLiteral("body.pairing.protocol", request.Body.Pairing.Protocol, PairingProtocolV1); err != nil {
		return InstallationBootstrapValues{}, err
	}
	if err := validateSHA256Hex("body.pairing.transcript_hash", request.Body.Pairing.TranscriptHash); err != nil {
		return InstallationBootstrapValues{}, err
	}

	commitSet, err := domain.BootstrapInstallationCommitSet(
		request.Body.Principal.PrincipalID,
		request.Body.Device.DeviceID,
		request.Body.InstallationOwnerGrantID,
		request.Body.InvitationID,
		request.ExpectedVersions.Invitation,
	)
	if err != nil {
		return InstallationBootstrapValues{}, invalid("body", err.Error())
	}
	return InstallationBootstrapValues{
		Metadata:          request.CommandMetadataDTO,
		InstallationID:    request.Body.InstallationID,
		InvitationID:      request.Body.InvitationID,
		PrincipalID:       request.Body.Principal.PrincipalID,
		PrincipalName:     request.Body.Principal.DisplayName,
		DeviceID:          request.Body.Device.DeviceID,
		DeviceName:        request.Body.Device.DisplayName,
		DevicePublicKey:   request.Body.Device.PublicKeySPKI,
		OwnerGrantID:      request.Body.InstallationOwnerGrantID,
		TranscriptHash:    request.Body.Pairing.TranscriptHash,
		InvitationVersion: request.ExpectedVersions.Invitation,
		CommitSet:         commitSet,
	}, nil
}

type WorkspaceCreateRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID            `json:"client_instance_id"`
	ExpectedVersions WorkspaceCreateExpectedVersionsDTO `json:"expected_versions"`
	Body             WorkspaceCreateBodyDTO             `json:"body"`
}

type WorkspaceCreateExpectedVersionsDTO struct {
	OwnerPrincipal domain.Version `json:"owner_principal"`
}

type WorkspaceCreateBodyDTO struct {
	InstallationID    domain.InstallationID `json:"installation_id"`
	WorkspaceID       domain.WorkspaceID    `json:"workspace_id"`
	OwnerPrincipalID  domain.PrincipalID    `json:"owner_principal_id"`
	OwnerMembershipID domain.MembershipID   `json:"owner_membership_id"`
	Alias             string                `json:"alias"`
	DiscoveryLocator  string                `json:"discovery_locator,omitempty"`
	PolicyRevision    string                `json:"policy_revision"`
}

type WorkspaceCreateValues struct {
	Metadata          CommandMetadataDTO
	ClientInstanceID  domain.ClientInstanceID
	InstallationID    domain.InstallationID
	WorkspaceID       domain.WorkspaceID
	OwnerPrincipalID  domain.PrincipalID
	OwnerMembershipID domain.MembershipID
	OwnerVersion      domain.Version
	Alias             string
	DiscoveryLocator  string
	PolicyRevision    domain.PolicyRevision
	CommitSet         domain.AtomicCommitSet
}

func DecodeWorkspaceCreateRequest(data []byte) (WorkspaceCreateRequestDTO, error) {
	var request WorkspaceCreateRequestDTO
	if err := decodeStrict(data, MaxCommandJSONBytes, &request); err != nil {
		return WorkspaceCreateRequestDTO{}, err
	}
	if _, err := request.Values(); err != nil {
		return WorkspaceCreateRequestDTO{}, err
	}
	return request, nil
}

func (request WorkspaceCreateRequestDTO) Values() (WorkspaceCreateValues, error) {
	if err := request.validate(SchemaWorkspaceCreateCommand, OperationWorkspaceCreate); err != nil {
		return WorkspaceCreateValues{}, err
	}
	if err := validateRequiredID("client_instance_id", request.ClientInstanceID); err != nil {
		return WorkspaceCreateValues{}, err
	}
	if err := validateVersion("expected_versions.owner_principal", request.ExpectedVersions.OwnerPrincipal); err != nil {
		return WorkspaceCreateValues{}, err
	}
	if err := validateRequiredID("body.installation_id", request.Body.InstallationID); err != nil {
		return WorkspaceCreateValues{}, err
	}
	if err := validateRequiredID("body.workspace_id", request.Body.WorkspaceID); err != nil {
		return WorkspaceCreateValues{}, err
	}
	if err := validateRequiredID("body.owner_principal_id", request.Body.OwnerPrincipalID); err != nil {
		return WorkspaceCreateValues{}, err
	}
	if err := validateRequiredID("body.owner_membership_id", request.Body.OwnerMembershipID); err != nil {
		return WorkspaceCreateValues{}, err
	}
	if err := validateText("body.alias", request.Body.Alias, maxDisplayNameBytes, true); err != nil {
		return WorkspaceCreateValues{}, err
	}
	if err := validateText("body.discovery_locator", request.Body.DiscoveryLocator, maxDiscoveryLocatorBytes, false); err != nil {
		return WorkspaceCreateValues{}, err
	}
	policy, err := domain.NewPolicyRevision(request.Body.PolicyRevision)
	if err != nil {
		return WorkspaceCreateValues{}, invalid("body.policy_revision", err.Error())
	}
	commitSet, err := domain.CreateWorkspaceOwnerCommitSet(
		request.Body.WorkspaceID,
		request.Body.OwnerMembershipID,
		request.Body.OwnerPrincipalID,
		request.ExpectedVersions.OwnerPrincipal,
	)
	if err != nil {
		return WorkspaceCreateValues{}, invalid("body", err.Error())
	}
	return WorkspaceCreateValues{
		Metadata:          request.CommandMetadataDTO,
		ClientInstanceID:  request.ClientInstanceID,
		InstallationID:    request.Body.InstallationID,
		WorkspaceID:       request.Body.WorkspaceID,
		OwnerPrincipalID:  request.Body.OwnerPrincipalID,
		OwnerMembershipID: request.Body.OwnerMembershipID,
		OwnerVersion:      request.ExpectedVersions.OwnerPrincipal,
		Alias:             request.Body.Alias,
		DiscoveryLocator:  request.Body.DiscoveryLocator,
		PolicyRevision:    policy,
		CommitSet:         commitSet,
	}, nil
}

type SessionStartRequestDTO struct {
	CommandMetadataDTO
	ExpectedVersions SessionStartExpectedVersionsDTO `json:"expected_versions"`
	Body             SessionStartBodyDTO             `json:"body"`
}

type SessionStartExpectedVersionsDTO struct {
	Membership domain.Version     `json:"membership"`
	Delegation domain.Version     `json:"delegation"`
	Device     *domain.Version    `json:"device,omitempty"`
	Grants     []GrantRevisionDTO `json:"grants"`
}

type GrantRevisionDTO struct {
	GrantID domain.GrantID `json:"grant_id"`
	Version domain.Version `json:"version"`
}

type SessionStartBodyDTO struct {
	WorkspaceID    domain.WorkspaceID       `json:"workspace_id"`
	ActorSessionID domain.ActorSessionID    `json:"actor_session_id"`
	ActorID        domain.ActorID           `json:"actor_id"`
	MembershipID   domain.MembershipID      `json:"membership_id"`
	DelegationID   domain.ActorDelegationID `json:"delegation_id"`
	DeviceID       *domain.DeviceID         `json:"device_id,omitempty"`
	Client         SessionClientDTO         `json:"client"`
}

type SessionClientDTO struct {
	InstanceID   domain.ClientInstanceID `json:"instance_id"`
	Name         string                  `json:"name"`
	Version      string                  `json:"version"`
	Capabilities []string                `json:"capabilities"`
}

type SessionStartValues struct {
	Metadata       CommandMetadataDTO
	WorkspaceID    domain.WorkspaceID
	ActorSessionID domain.ActorSessionID
	ActorID        domain.ActorID
	Membership     domain.AggregateRef
	Delegation     domain.AggregateRef
	Device         *domain.AggregateRef
	Grants         []domain.AggregateRef
	ClientInstance domain.ClientInstanceID
	ClientName     string
	ClientVersion  string
	Capabilities   []string
}

func DecodeSessionStartRequest(data []byte) (SessionStartRequestDTO, error) {
	var request SessionStartRequestDTO
	if err := decodeStrict(data, MaxCommandJSONBytes, &request); err != nil {
		return SessionStartRequestDTO{}, err
	}
	if _, err := request.Values(); err != nil {
		return SessionStartRequestDTO{}, err
	}
	return request, nil
}

func (request SessionStartRequestDTO) Values() (SessionStartValues, error) {
	if err := request.validate(SchemaSessionStartCommand, OperationSessionStart); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateRequiredID("body.workspace_id", request.Body.WorkspaceID); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateRequiredID("body.actor_session_id", request.Body.ActorSessionID); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateRequiredID("body.actor_id", request.Body.ActorID); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateRequiredID("body.membership_id", request.Body.MembershipID); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateRequiredID("body.delegation_id", request.Body.DelegationID); err != nil {
		return SessionStartValues{}, err
	}

	membership, err := domain.NewAggregateRef(request.Body.MembershipID, request.ExpectedVersions.Membership)
	if err != nil {
		return SessionStartValues{}, invalid("expected_versions.membership", err.Error())
	}
	delegation, err := domain.NewAggregateRef(request.Body.DelegationID, request.ExpectedVersions.Delegation)
	if err != nil {
		return SessionStartValues{}, invalid("expected_versions.delegation", err.Error())
	}
	var device *domain.AggregateRef
	if (request.Body.DeviceID == nil) != (request.ExpectedVersions.Device == nil) {
		return SessionStartValues{}, invalid("expected_versions.device", "must be present exactly when body.device_id is present")
	}
	if request.Body.DeviceID != nil {
		if request.Body.DeviceID.IsZero() {
			return SessionStartValues{}, invalid("body.device_id", "must be nonzero when present")
		}
		ref, refErr := domain.NewAggregateRef(*request.Body.DeviceID, *request.ExpectedVersions.Device)
		if refErr != nil {
			return SessionStartValues{}, invalid("expected_versions.device", refErr.Error())
		}
		device = &ref
	}
	if err := validateGrantRevisionSet("expected_versions.grants", request.ExpectedVersions.Grants); err != nil {
		return SessionStartValues{}, err
	}
	grants := make([]domain.AggregateRef, 0, len(request.ExpectedVersions.Grants))
	for index, grant := range request.ExpectedVersions.Grants {
		ref, refErr := domain.NewAggregateRef(grant.GrantID, grant.Version)
		if refErr != nil {
			return SessionStartValues{}, invalid(fmt.Sprintf("expected_versions.grants[%d].version", index), refErr.Error())
		}
		grants = append(grants, ref)
	}
	if err := validateRequiredID("body.client.instance_id", request.Body.Client.InstanceID); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateText("body.client.name", request.Body.Client.Name, maxClientNameBytes, true); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateToken("body.client.version", request.Body.Client.Version, maxClientVersionBytes); err != nil {
		return SessionStartValues{}, err
	}
	capabilities, err := normalizeCapabilities("body.client.capabilities", request.Body.Client.Capabilities)
	if err != nil {
		return SessionStartValues{}, err
	}
	return SessionStartValues{
		Metadata:       request.CommandMetadataDTO,
		WorkspaceID:    request.Body.WorkspaceID,
		ActorSessionID: request.Body.ActorSessionID,
		ActorID:        request.Body.ActorID,
		Membership:     membership,
		Delegation:     delegation,
		Device:         device,
		Grants:         grants,
		ClientInstance: request.Body.Client.InstanceID,
		ClientName:     request.Body.Client.Name,
		ClientVersion:  request.Body.Client.Version,
		Capabilities:   capabilities,
	}, nil
}

func validateGrantRevisionSet(field string, grants []GrantRevisionDTO) error {
	if len(grants) > maxGrantReferenceCount {
		return invalid(field, fmt.Sprintf("must contain at most %d entries", maxGrantReferenceCount))
	}
	previous := ""
	for index, grant := range grants {
		prefix := fmt.Sprintf("%s[%d]", field, index)
		if grant.GrantID.IsZero() {
			return invalid(prefix+".grant_id", "is required")
		}
		if err := validateVersion(prefix+".version", grant.Version); err != nil {
			return err
		}
		current := grant.GrantID.String()
		if index > 0 && current <= previous {
			return invalid(field, "must be sorted by grant_id and contain no duplicates")
		}
		previous = current
	}
	return nil
}
