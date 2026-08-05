package contracts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	maxAuthenticationAudienceBytes = 256
	maxFederationEnvelopeIDBytes   = 256
)

// ChannelBindingDigest is the SHA-256 digest of the verified proof-bound
// channel binding. It contains no credential or reusable bearer material.
type ChannelBindingDigest struct{ value [sha256.Size]byte }

func NewChannelBindingDigest(encoded string) (ChannelBindingDigest, error) {
	if len(encoded) != hex.EncodedLen(sha256.Size) || strings.ToLower(encoded) != encoded {
		return ChannelBindingDigest{}, invalid("channel_binding_digest", "must be nonzero lowercase SHA-256 text")
	}
	var value [sha256.Size]byte
	if _, err := hex.Decode(value[:], []byte(encoded)); err != nil || value == [sha256.Size]byte{} {
		return ChannelBindingDigest{}, invalid("channel_binding_digest", "must be nonzero lowercase SHA-256 text")
	}
	return ChannelBindingDigest{value: value}, nil
}

func (digest ChannelBindingDigest) String() string {
	if digest.value == [sha256.Size]byte{} {
		return ""
	}
	return hex.EncodeToString(digest.value[:])
}

// AuthenticationAudience is the exact resource-server audience validated by
// the authenticator. Equality is byte-for-byte; it is never inferred from a
// request target or operation body.
type AuthenticationAudience struct{ value string }

func NewAuthenticationAudience(value string) (AuthenticationAudience, error) {
	if !validCanonicalIdentifier(value, maxAuthenticationAudienceBytes) {
		return AuthenticationAudience{}, invalid("audience", "must be a canonical audience identifier")
	}
	return AuthenticationAudience{value: value}, nil
}

func (audience AuthenticationAudience) String() string { return audience.value }

// AuthenticationAuditProvenance identifies the authority that established
// trust and, for federated authentication, the already-validated envelope.
type AuthenticationAuditProvenance struct {
	sourceAuthority    domain.AuthorityID
	federationEnvelope string
	hasEnvelope        bool
}

func NewAuthenticationAuditProvenance(
	sourceAuthority domain.AuthorityID,
	federationEnvelopeID *string,
) (AuthenticationAuditProvenance, error) {
	if sourceAuthority.IsZero() {
		return AuthenticationAuditProvenance{}, invalid("audit_provenance.source_authority_id", "must be a nonzero UUIDv7 authority ID")
	}
	provenance := AuthenticationAuditProvenance{sourceAuthority: sourceAuthority}
	if federationEnvelopeID != nil {
		if !validCanonicalIdentifier(*federationEnvelopeID, maxFederationEnvelopeIDBytes) {
			return AuthenticationAuditProvenance{}, invalid("audit_provenance.federation_envelope_id", "must be a canonical identifier")
		}
		provenance.federationEnvelope = *federationEnvelopeID
		provenance.hasEnvelope = true
	}
	return provenance, nil
}

func (provenance AuthenticationAuditProvenance) SourceAuthorityID() domain.AuthorityID {
	return provenance.sourceAuthority
}

func (provenance AuthenticationAuditProvenance) FederationEnvelopeID() (string, bool) {
	return provenance.federationEnvelope, provenance.hasEnvelope
}

// AuthenticationEvidence is the immutable result of cryptographic
// authentication. Its zero value is invalid, and only this package can create
// a valid value, so transports cannot manufacture trusted identity evidence.
// It deliberately retains no plaintext secret, access token, assertion, or
// reusable bearer credential.
type AuthenticationEvidence struct {
	principal                domain.PrincipalID
	principalRevision        domain.Version
	device                   domain.DeviceID
	deviceRevision           domain.Version
	deviceTrustRevision      domain.Version
	deviceRevocationRevision domain.Version
	credentialFingerprint    domain.CredentialDigest
	hasDevice                bool
	actorSession             domain.ActorSessionID
	actorSessionRevision     domain.Version
	hasActorSession          bool
	grantRevisions           []domain.AggregateRef
	channelBinding           ChannelBindingDigest
	audience                 AuthenticationAudience
	auditProvenance          AuthenticationAuditProvenance
	verifiedAt               time.Time
}

type AuthenticationEvidenceParams struct {
	PrincipalID              domain.PrincipalID
	PrincipalRevision        domain.Version
	DeviceID                 *domain.DeviceID
	DeviceRevision           domain.Version
	DeviceTrustRevision      domain.Version
	DeviceRevocationRevision domain.Version
	CredentialFingerprint    domain.CredentialDigest
	ActorSessionID           *domain.ActorSessionID
	ActorSessionRevision     domain.Version
	GrantRevisions           []domain.AggregateRef
	ChannelBinding           ChannelBindingDigest
	Audience                 AuthenticationAudience
	AuditProvenance          AuthenticationAuditProvenance
	VerifiedAt               time.Time
}

func NewAuthenticationEvidence(params AuthenticationEvidenceParams) (AuthenticationEvidence, error) {
	if params.PrincipalID.IsZero() || !params.PrincipalRevision.Valid() ||
		params.ChannelBinding.String() == "" || params.Audience.String() == "" ||
		params.AuditProvenance.sourceAuthority.IsZero() || params.VerifiedAt.IsZero() {
		return AuthenticationEvidence{}, invalid("authentication_evidence", "contains invalid trusted evidence")
	}
	evidence := AuthenticationEvidence{
		principal: params.PrincipalID, principalRevision: params.PrincipalRevision,
		channelBinding: params.ChannelBinding, audience: params.Audience,
		auditProvenance: params.AuditProvenance, verifiedAt: params.VerifiedAt.UTC(),
	}
	if params.DeviceID != nil {
		if params.DeviceID.IsZero() || !params.DeviceRevision.Valid() || !params.DeviceTrustRevision.Valid() ||
			!params.DeviceRevocationRevision.Valid() || params.CredentialFingerprint.IsZero() {
			return AuthenticationEvidence{}, invalid("device_evidence", "must contain a complete valid device evidence tuple")
		}
		evidence.device, evidence.hasDevice = *params.DeviceID, true
		evidence.deviceRevision, evidence.deviceTrustRevision = params.DeviceRevision, params.DeviceTrustRevision
		evidence.deviceRevocationRevision = params.DeviceRevocationRevision
		evidence.credentialFingerprint = params.CredentialFingerprint
	} else if !params.DeviceRevision.IsZero() || !params.DeviceTrustRevision.IsZero() ||
		!params.DeviceRevocationRevision.IsZero() || !params.CredentialFingerprint.IsZero() {
		return AuthenticationEvidence{}, invalid("device_evidence", "must be absent when device_id is absent")
	}
	if params.ActorSessionID != nil {
		if params.ActorSessionID.IsZero() || !params.ActorSessionRevision.Valid() {
			return AuthenticationEvidence{}, invalid("actor_session_evidence", "must contain a complete valid actor-session evidence tuple")
		}
		evidence.actorSession, evidence.actorSessionRevision, evidence.hasActorSession =
			*params.ActorSessionID, params.ActorSessionRevision, true
	} else if !params.ActorSessionRevision.IsZero() {
		return AuthenticationEvidence{}, invalid("actor_session_evidence", "must be absent when actor_session_id is absent")
	}
	evidence.grantRevisions = append([]domain.AggregateRef(nil), params.GrantRevisions...)
	slices.SortFunc(evidence.grantRevisions, func(left, right domain.AggregateRef) int {
		return strings.Compare(left.Target().String(), right.Target().String())
	})
	for index, revision := range evidence.grantRevisions {
		if revision.IsZero() || revision.Kind() != domain.AggregateKindGrant ||
			(index > 0 && evidence.grantRevisions[index-1].Target() == revision.Target()) {
			return AuthenticationEvidence{}, invalid("grant_revisions", "must contain unique valid grant aggregate revisions")
		}
	}
	return evidence, nil
}

func (evidence AuthenticationEvidence) Valid() bool {
	params := AuthenticationEvidenceParams{
		PrincipalID: evidence.principal, PrincipalRevision: evidence.principalRevision,
		DeviceRevision: evidence.deviceRevision, DeviceTrustRevision: evidence.deviceTrustRevision,
		DeviceRevocationRevision: evidence.deviceRevocationRevision, CredentialFingerprint: evidence.credentialFingerprint,
		ActorSessionRevision: evidence.actorSessionRevision, GrantRevisions: evidence.grantRevisions,
		ChannelBinding: evidence.channelBinding, Audience: evidence.audience,
		AuditProvenance: evidence.auditProvenance, VerifiedAt: evidence.verifiedAt,
	}
	if evidence.hasDevice {
		device := evidence.device
		params.DeviceID = &device
	} else if !evidence.device.IsZero() {
		return false
	}
	if evidence.hasActorSession {
		session := evidence.actorSession
		params.ActorSessionID = &session
	} else if !evidence.actorSession.IsZero() {
		return false
	}
	validated, err := NewAuthenticationEvidence(params)
	return err == nil && slices.Equal(validated.grantRevisions, evidence.grantRevisions)
}

func (evidence AuthenticationEvidence) PrincipalID() domain.PrincipalID { return evidence.principal }

func (evidence AuthenticationEvidence) PrincipalRevision() domain.Version {
	return evidence.principalRevision
}

func (evidence AuthenticationEvidence) DeviceID() (domain.DeviceID, bool) {
	return evidence.device, evidence.hasDevice
}

func (evidence AuthenticationEvidence) DeviceRevision() (domain.Version, bool) {
	return evidence.deviceRevision, evidence.hasDevice
}

func (evidence AuthenticationEvidence) DeviceTrustRevision() (domain.Version, bool) {
	return evidence.deviceTrustRevision, evidence.hasDevice
}

func (evidence AuthenticationEvidence) DeviceRevocationRevision() (domain.Version, bool) {
	return evidence.deviceRevocationRevision, evidence.hasDevice
}

func (evidence AuthenticationEvidence) CredentialFingerprint() (domain.CredentialDigest, bool) {
	return evidence.credentialFingerprint, evidence.hasDevice
}

func (evidence AuthenticationEvidence) ActorSessionID() (domain.ActorSessionID, bool) {
	return evidence.actorSession, evidence.hasActorSession
}

func (evidence AuthenticationEvidence) ActorSessionRevision() (domain.Version, bool) {
	return evidence.actorSessionRevision, evidence.hasActorSession
}

func (evidence AuthenticationEvidence) GrantRevisions() []domain.AggregateRef {
	return append([]domain.AggregateRef(nil), evidence.grantRevisions...)
}

func (evidence AuthenticationEvidence) ChannelBindingDigest() ChannelBindingDigest {
	return evidence.channelBinding
}
func (evidence AuthenticationEvidence) Audience() AuthenticationAudience { return evidence.audience }
func (evidence AuthenticationEvidence) AuditProvenance() AuthenticationAuditProvenance {
	return evidence.auditProvenance
}

func (evidence AuthenticationEvidence) VerifiedAt() time.Time { return evidence.verifiedAt }

func validCanonicalIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.ToLower(value) != value {
		return false
	}
	for index, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && strings.ContainsRune("-_.:/", rune(character))) {
			continue
		}
		return false
	}
	return true
}

type InstallationBootstrapHandler interface {
	HandleInstallationBootstrap(context.Context, AuthenticationEvidence, InstallationBootstrapRequestDTO) (InstallationBootstrapResultDTO, *ErrorDTO, error)
}
type PrincipalRegisterHandler interface {
	HandlePrincipalRegister(context.Context, AuthenticationEvidence, PrincipalRegisterRequestDTO) (PrincipalRegisterResultDTO, *ErrorDTO, error)
}
type DevicePairingBeginHandler interface {
	HandleDevicePairingBegin(context.Context, AuthenticationEvidence, DevicePairingBeginRequestDTO) (DevicePairingBeginResultDTO, *ErrorDTO, error)
}
type DevicePairHandler interface {
	HandleDevicePair(context.Context, AuthenticationEvidence, DevicePairRequestDTO) (DevicePairResultDTO, *ErrorDTO, error)
}
type WorkspaceCreateHandler interface {
	HandleWorkspaceCreate(context.Context, AuthenticationEvidence, WorkspaceCreateRequestDTO) (WorkspaceCreateResultDTO, *ErrorDTO, error)
}
type WorkspaceMemberInviteHandler interface {
	HandleWorkspaceMemberInvite(context.Context, AuthenticationEvidence, WorkspaceMemberInviteRequestDTO) (WorkspaceMemberInviteResultDTO, *ErrorDTO, error)
}
type WorkspaceMembershipAcceptHandler interface {
	HandleWorkspaceMembershipAccept(context.Context, AuthenticationEvidence, WorkspaceMembershipAcceptRequestDTO) (WorkspaceMembershipAcceptResultDTO, *ErrorDTO, error)
}
type ActorCreateHandler interface {
	HandleActorCreate(context.Context, AuthenticationEvidence, ActorCreateRequestDTO) (ActorCreateResultDTO, *ErrorDTO, error)
}
type ActorDelegationProposeHandler interface {
	HandleActorDelegationPropose(context.Context, AuthenticationEvidence, ActorDelegationProposeRequestDTO) (ActorDelegationProposeResultDTO, *ErrorDTO, error)
}
type ActorDelegationActivateHandler interface {
	HandleActorDelegationActivate(context.Context, AuthenticationEvidence, ActorDelegationActivateRequestDTO) (ActorDelegationActivateResultDTO, *ErrorDTO, error)
}
type SessionStartHandler interface {
	HandleSessionStart(context.Context, AuthenticationEvidence, SessionStartRequestDTO) (SessionStartResultDTO, *ErrorDTO, error)
}
type ContextGetHandler interface {
	HandleContextGet(context.Context, AuthenticationEvidence, ContextGetRequestDTO) (ContextPageDTO, *ErrorDTO, error)
}
type EventsSyncHandler interface {
	HandleEventsSync(context.Context, AuthenticationEvidence, EventsSyncRequestDTO) (EventPageDTO, *ErrorDTO, error)
}

const (
	OperationInstallationBootstrap     = "installation.bootstrap.v1"
	OperationPrincipalRegister         = "principal.register.v1"
	OperationDevicePairingBegin        = "pairing.challenge.issue.v1"
	OperationDevicePair                = "pairing.challenge.redeem.v1"
	OperationWorkspaceCreate           = "workspace.create.v1"
	OperationWorkspaceMemberInvite     = "workspace_member.invite.v1"
	OperationWorkspaceMembershipAccept = "workspace_membership.accept.v1"
	OperationActorCreate               = "actor.create.v1"
	OperationActorDelegationPropose    = "actor_delegation.propose.v1"
	OperationActorDelegationActivate   = "actor_delegation.activate.v1"
	OperationSessionStart              = "session.start.v1"

	SchemaInstallationBootstrapCommand     = "blackbird.command.installation_bootstrap/1"
	SchemaPrincipalRegisterCommand         = "blackbird.command.principal_register/1"
	SchemaDevicePairingBeginCommand        = "blackbird.command.device_pairing_begin/1"
	SchemaDevicePairCommand                = "blackbird.command.device_pair/1"
	SchemaWorkspaceCreateCommand           = "blackbird.command.workspace_create/1"
	SchemaWorkspaceMemberInviteCommand     = "blackbird.command.workspace_member_invite/1"
	SchemaWorkspaceMembershipAcceptCommand = "blackbird.command.workspace_membership_accept/1"
	SchemaActorCreateCommand               = "blackbird.command.actor_create/1"
	SchemaActorDelegationProposeCommand    = "blackbird.command.actor_delegation_propose/1"
	SchemaActorDelegationActivateCommand   = "blackbird.command.actor_delegation_activate/1"
	SchemaSessionStartCommand              = "blackbird.command.session_start/1"

	PairingProtocolV1     = "blackbird.pair/v1"
	PrincipalKindHuman    = "human"
	PrincipalKindWorkload = "workload"
	PrincipalKindService  = "service"

	ActorKindHuman      = "human"
	ActorKindAgent      = "agent"
	ActorKindAutomation = "automation"
	ActorKindService    = "service"
)

var w0OperationInventory = []string{
	OperationInstallationBootstrap,
	OperationPrincipalRegister,
	OperationDevicePairingBegin,
	OperationDevicePair,
	OperationWorkspaceCreate,
	OperationWorkspaceMemberInvite,
	OperationWorkspaceMembershipAccept,
	OperationActorCreate,
	OperationActorDelegationPropose,
	OperationActorDelegationActivate,
	OperationSessionStart,
}

// W0OperationInventory returns the closed public command catalog in stable order.
func W0OperationInventory() []string { return append([]string(nil), w0OperationInventory...) }

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
	CausationID    *domain.EventID       `json:"causation_id"`
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
	BootstrapGenerationID    domain.BootstrapGenerationID    `json:"bootstrap_generation_id"`
	Principal                BootstrapPrincipalDTO           `json:"principal"`
	Device                   BootstrapDeviceDTO              `json:"device"`
	InstallationOwnerGrantID domain.GrantID                  `json:"installation_owner_grant_id"`
	OwnerCapabilities        []string                        `json:"owner_capabilities"`
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
	Metadata              CommandMetadataDTO
	InstallationID        domain.InstallationID
	InvitationID          domain.InvitationID
	BootstrapGenerationID domain.BootstrapGenerationID
	PrincipalID           domain.PrincipalID
	PrincipalName         string
	DeviceID              domain.DeviceID
	DeviceName            string
	DevicePublicKey       string
	OwnerGrantID          domain.GrantID
	OwnerCapabilities     []string
	TranscriptHash        string
	InvitationVersion     domain.Version
	CommitSet             domain.AtomicCommitSet
}

func DecodeInstallationBootstrapRequest(data []byte) (InstallationBootstrapRequestDTO, error) {
	var request InstallationBootstrapRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
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
	if err := validateRequiredID("body.bootstrap_generation_id", request.Body.BootstrapGenerationID); err != nil {
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
	ownerCapabilities, err := normalizeCapabilities("body.owner_capabilities", request.Body.OwnerCapabilities)
	if err != nil {
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
		Metadata:              request.CommandMetadataDTO,
		InstallationID:        request.Body.InstallationID,
		InvitationID:          request.Body.InvitationID,
		BootstrapGenerationID: request.Body.BootstrapGenerationID,
		PrincipalID:           request.Body.Principal.PrincipalID,
		PrincipalName:         request.Body.Principal.DisplayName,
		DeviceID:              request.Body.Device.DeviceID,
		DeviceName:            request.Body.Device.DisplayName,
		DevicePublicKey:       request.Body.Device.PublicKeySPKI,
		OwnerGrantID:          request.Body.InstallationOwnerGrantID,
		OwnerCapabilities:     ownerCapabilities,
		TranscriptHash:        request.Body.Pairing.TranscriptHash,
		InvitationVersion:     request.ExpectedVersions.Invitation,
		CommitSet:             commitSet,
	}, nil
}

type WorkspaceCreateRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID            `json:"client_instance_id"`
	ExpectedVersions WorkspaceCreateExpectedVersionsDTO `json:"expected_versions"`
	Body             WorkspaceCreateBodyDTO             `json:"body"`
}

type WorkspaceCreateExpectedVersionsDTO struct {
	OwnerPrincipal    domain.Version `json:"owner_principal"`
	InstallationGrant domain.Version `json:"installation_grant"`
}

type WorkspaceCreateBodyDTO struct {
	InstallationID      domain.InstallationID `json:"installation_id"`
	WorkspaceID         domain.WorkspaceID    `json:"workspace_id"`
	OwnerPrincipalID    domain.PrincipalID    `json:"owner_principal_id"`
	InstallationGrantID domain.GrantID        `json:"installation_grant_id"`
	OwnerMembershipID   domain.MembershipID   `json:"owner_membership_id"`
	Alias               string                `json:"alias"`
	DiscoveryLocator    string                `json:"discovery_locator,omitempty"`
	PolicyRevision      string                `json:"policy_revision"`
	OwnerCapabilities   []string              `json:"owner_capabilities"`
}

type WorkspaceCreateValues struct {
	Metadata                 CommandMetadataDTO
	ClientInstanceID         domain.ClientInstanceID
	InstallationID           domain.InstallationID
	WorkspaceID              domain.WorkspaceID
	OwnerPrincipalID         domain.PrincipalID
	InstallationGrantID      domain.GrantID
	OwnerMembershipID        domain.MembershipID
	OwnerVersion             domain.Version
	InstallationGrantVersion domain.Version
	Alias                    string
	DiscoveryLocator         string
	PolicyRevision           domain.PolicyRevision
	OwnerCapabilities        []string
	CommitSet                domain.AtomicCommitSet
}

func DecodeWorkspaceCreateRequest(data []byte) (WorkspaceCreateRequestDTO, error) {
	var request WorkspaceCreateRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
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
	if err := validateVersion("expected_versions.installation_grant", request.ExpectedVersions.InstallationGrant); err != nil {
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
	if err := validateRequiredID("body.installation_grant_id", request.Body.InstallationGrantID); err != nil {
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
	ownerCapabilities, err := normalizeCapabilities("body.owner_capabilities", request.Body.OwnerCapabilities)
	if err != nil {
		return WorkspaceCreateValues{}, err
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
		Metadata:                 request.CommandMetadataDTO,
		ClientInstanceID:         request.ClientInstanceID,
		InstallationID:           request.Body.InstallationID,
		WorkspaceID:              request.Body.WorkspaceID,
		OwnerPrincipalID:         request.Body.OwnerPrincipalID,
		InstallationGrantID:      request.Body.InstallationGrantID,
		OwnerMembershipID:        request.Body.OwnerMembershipID,
		OwnerVersion:             request.ExpectedVersions.OwnerPrincipal,
		InstallationGrantVersion: request.ExpectedVersions.InstallationGrant,
		Alias:                    request.Body.Alias,
		DiscoveryLocator:         request.Body.DiscoveryLocator,
		PolicyRevision:           policy,
		OwnerCapabilities:        ownerCapabilities,
		CommitSet:                commitSet,
	}, nil
}

type SessionStartRequestDTO struct {
	CommandMetadataDTO
	ExpectedVersions SessionStartExpectedVersionsDTO `json:"expected_versions"`
	Body             SessionStartBodyDTO             `json:"body"`
}

type SessionStartExpectedVersionsDTO struct {
	Workspace   domain.Version     `json:"workspace"`
	Principal   domain.Version     `json:"principal"`
	Membership  domain.Version     `json:"membership"`
	Actor       domain.Version     `json:"actor"`
	Delegation  domain.Version     `json:"delegation"`
	Device      *domain.Version    `json:"device"`
	DeviceTrust *domain.Version    `json:"device_trust"`
	Grants      []GrantRevisionDTO `json:"grants"`
}

type GrantRevisionDTO struct {
	GrantID domain.GrantID `json:"grant_id"`
	Version domain.Version `json:"version"`
}

type SessionStartBodyDTO struct {
	WorkspaceID        domain.WorkspaceID       `json:"workspace_id"`
	PrincipalID        domain.PrincipalID       `json:"principal_id"`
	ActorSessionID     domain.ActorSessionID    `json:"actor_session_id"`
	ActorID            domain.ActorID           `json:"actor_id"`
	MembershipID       domain.MembershipID      `json:"membership_id"`
	DelegationID       domain.ActorDelegationID `json:"delegation_id"`
	DeviceID           *domain.DeviceID         `json:"device_id"`
	StartAuthorityKind string                   `json:"start_authority_kind"`
	HandoffProof       *CeremonyReferenceDTO    `json:"handoff_proof"`
	AbsoluteExpiry     time.Time                `json:"absolute_expiry"`
	Client             SessionClientDTO         `json:"client"`
}

type SessionClientDTO struct {
	InstanceID   domain.ClientInstanceID `json:"instance_id"`
	Name         string                  `json:"name"`
	Version      string                  `json:"version"`
	Capabilities []string                `json:"capabilities"`
}

type SessionStartValues struct {
	Metadata           CommandMetadataDTO
	WorkspaceID        domain.WorkspaceID
	PrincipalID        domain.PrincipalID
	ActorSessionID     domain.ActorSessionID
	ActorID            domain.ActorID
	Membership         domain.AggregateRef
	Delegation         domain.AggregateRef
	Device             *domain.AggregateRef
	DeviceTrust        *domain.Version
	Grants             []domain.AggregateRef
	ClientInstance     domain.ClientInstanceID
	ClientName         string
	ClientVersion      string
	Capabilities       []string
	StartAuthorityKind string
	HandoffProof       *CeremonyReferenceDTO
	AbsoluteExpiry     time.Time
}

func DecodeSessionStartRequest(data []byte) (SessionStartRequestDTO, error) {
	var request SessionStartRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return SessionStartRequestDTO{}, err
	}
	if err := requireNestedJSONMembers(data, "expected_versions", "device", "device_trust"); err != nil {
		return SessionStartRequestDTO{}, err
	}
	if err := requireNestedJSONMembers(data, "body", "device_id", "handoff_proof"); err != nil {
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
	if err := validateRequiredID("body.principal_id", request.Body.PrincipalID); err != nil {
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

	if err := validateVersion("expected_versions.workspace", request.ExpectedVersions.Workspace); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateVersion("expected_versions.principal", request.ExpectedVersions.Principal); err != nil {
		return SessionStartValues{}, err
	}
	if err := validateVersion("expected_versions.actor", request.ExpectedVersions.Actor); err != nil {
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
	if (request.Body.DeviceID == nil) != (request.ExpectedVersions.Device == nil) ||
		(request.Body.DeviceID == nil) != (request.ExpectedVersions.DeviceTrust == nil) {
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
	if request.ExpectedVersions.DeviceTrust != nil {
		if err := validateVersion("expected_versions.device_trust", *request.ExpectedVersions.DeviceTrust); err != nil {
			return SessionStartValues{}, err
		}
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
	switch request.Body.StartAuthorityKind {
	case "trusted_device":
		if request.Body.DeviceID == nil || request.Body.HandoffProof != nil {
			return SessionStartValues{}, invalid("body.start_authority_kind", "trusted_device requires device and forbids handoff_proof")
		}
	case "one_use_handoff":
		if request.Body.DeviceID != nil || request.Body.HandoffProof == nil {
			return SessionStartValues{}, invalid("body.start_authority_kind", "handoff requires handoff_proof and forbids device")
		}
		if err := request.Body.HandoffProof.validate("body.handoff_proof"); err != nil {
			return SessionStartValues{}, err
		}
	default:
		return SessionStartValues{}, invalid("body.start_authority_kind", "is not a stable session start authority kind")
	}
	if err := validateUTCInstant("body.absolute_expiry", request.Body.AbsoluteExpiry); err != nil {
		return SessionStartValues{}, err
	}
	if !request.Body.AbsoluteExpiry.After(request.Deadline) {
		return SessionStartValues{}, invalid("body.absolute_expiry", "must be after deadline")
	}
	return SessionStartValues{
		Metadata:           request.CommandMetadataDTO,
		WorkspaceID:        request.Body.WorkspaceID,
		PrincipalID:        request.Body.PrincipalID,
		ActorSessionID:     request.Body.ActorSessionID,
		ActorID:            request.Body.ActorID,
		Membership:         membership,
		Delegation:         delegation,
		Device:             device,
		DeviceTrust:        request.ExpectedVersions.DeviceTrust,
		Grants:             grants,
		ClientInstance:     request.Body.Client.InstanceID,
		ClientName:         request.Body.Client.Name,
		ClientVersion:      request.Body.Client.Version,
		Capabilities:       capabilities,
		StartAuthorityKind: request.Body.StartAuthorityKind,
		HandoffProof:       request.Body.HandoffProof,
		AbsoluteExpiry:     request.Body.AbsoluteExpiry,
	}, nil
}

// CeremonyReferenceDTO identifies a pre-authorized, one-use ceremony without
// carrying its challenge response or any channel authentication material.
type CeremonyReferenceDTO struct {
	CeremonyID domain.CeremonyID `json:"ceremony_id"`
	ExpiresAt  time.Time         `json:"expires_at"`
	ProofHash  string            `json:"proof_hash"`
}

func (reference CeremonyReferenceDTO) validate(field string) error {
	if err := validateRequiredID(field+".ceremony_id", reference.CeremonyID); err != nil {
		return err
	}
	if err := validateUTCInstant(field+".expires_at", reference.ExpiresAt); err != nil {
		return err
	}
	return validateSHA256Hex(field+".proof_hash", reference.ProofHash)
}

type PrincipalRegisterRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID              `json:"client_instance_id"`
	ExpectedVersions PrincipalRegisterExpectedVersionsDTO `json:"expected_versions"`
	Body             PrincipalRegisterBodyDTO             `json:"body"`
}

type PrincipalRegisterExpectedVersionsDTO struct {
	Registrar domain.Version `json:"registrar"`
}

type PrincipalRegisterBodyDTO struct {
	InstallationID     domain.InstallationID `json:"installation_id"`
	RegistrarID        domain.PrincipalID    `json:"registrar_id"`
	PrincipalID        domain.PrincipalID    `json:"principal_id"`
	Kind               string                `json:"kind"`
	DisplayName        string                `json:"display_name"`
	PublicKeyReference string                `json:"public_key_reference,omitempty"`
}

func DecodePrincipalRegisterRequest(data []byte) (PrincipalRegisterRequestDTO, error) {
	var request PrincipalRegisterRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return PrincipalRegisterRequestDTO{}, err
	}
	if err := request.Validate(); err != nil {
		return PrincipalRegisterRequestDTO{}, err
	}
	return request, nil
}

func (request PrincipalRegisterRequestDTO) Validate() error {
	if err := request.validate(SchemaPrincipalRegisterCommand, OperationPrincipalRegister); err != nil {
		return err
	}
	if err := validateRequiredID("client_instance_id", request.ClientInstanceID); err != nil {
		return err
	}
	if err := validateVersion("expected_versions.registrar", request.ExpectedVersions.Registrar); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{
		"body.installation_id": request.Body.InstallationID, "body.registrar_id": request.Body.RegistrarID,
		"body.principal_id": request.Body.PrincipalID,
	} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if !validPrincipalKind(request.Body.Kind) {
		return invalid("body.kind", "is not a stable principal kind")
	}
	if err := validateText("body.display_name", request.Body.DisplayName, maxDisplayNameBytes, true); err != nil {
		return err
	}
	if request.Body.Kind != PrincipalKindHuman && request.Body.PublicKeyReference == "" {
		return invalid("body.public_key_reference", "is required for non-human principals")
	}
	return validateText("body.public_key_reference", request.Body.PublicKeyReference, 512, false)
}

type DevicePairingBeginRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID               `json:"client_instance_id"`
	ExpectedVersions DevicePairingBeginExpectedVersionsDTO `json:"expected_versions"`
	Body             DevicePairingBeginBodyDTO             `json:"body"`
}

type DevicePairingBeginExpectedVersionsDTO struct {
	Principal domain.Version `json:"principal"`
}
type DevicePairingBeginBodyDTO struct {
	InstallationID     domain.InstallationID `json:"installation_id"`
	PrincipalID        domain.PrincipalID    `json:"principal_id"`
	DeviceID           domain.DeviceID       `json:"device_id"`
	DisplayName        string                `json:"display_name"`
	PublicKeyReference string                `json:"public_key_reference"`
	Challenge          CeremonyReferenceDTO  `json:"challenge"`
}

func DecodeDevicePairingBeginRequest(data []byte) (DevicePairingBeginRequestDTO, error) {
	var request DevicePairingBeginRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return DevicePairingBeginRequestDTO{}, err
	}
	if err := request.Validate(); err != nil {
		return DevicePairingBeginRequestDTO{}, err
	}
	return request, nil
}
func (request DevicePairingBeginRequestDTO) Validate() error {
	if err := request.validate(SchemaDevicePairingBeginCommand, OperationDevicePairingBegin); err != nil {
		return err
	}
	if err := validateRequiredID("client_instance_id", request.ClientInstanceID); err != nil {
		return err
	}
	if err := validateVersion("expected_versions.principal", request.ExpectedVersions.Principal); err != nil {
		return err
	}
	for field, id := range map[string]interface{ IsZero() bool }{"body.installation_id": request.Body.InstallationID, "body.principal_id": request.Body.PrincipalID, "body.device_id": request.Body.DeviceID} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	if err := validateText("body.display_name", request.Body.DisplayName, maxDisplayNameBytes, true); err != nil {
		return err
	}
	if err := validateText("body.public_key_reference", request.Body.PublicKeyReference, 512, true); err != nil {
		return err
	}
	return request.Body.Challenge.validate("body.challenge")
}

type DevicePairRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID       `json:"client_instance_id"`
	ExpectedVersions DevicePairExpectedVersionsDTO `json:"expected_versions"`
	Body             DevicePairBodyDTO             `json:"body"`
}
type DevicePairExpectedVersionsDTO struct {
	Principal   domain.Version `json:"principal"`
	Device      domain.Version `json:"device"`
	DeviceTrust domain.Version `json:"device_trust"`
}
type DevicePairBodyDTO struct {
	InstallationID domain.InstallationID `json:"installation_id"`
	PrincipalID    domain.PrincipalID    `json:"principal_id"`
	DeviceID       domain.DeviceID       `json:"device_id"`
	Proof          CeremonyReferenceDTO  `json:"proof"`
}

func DecodeDevicePairRequest(data []byte) (DevicePairRequestDTO, error) {
	var request DevicePairRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return DevicePairRequestDTO{}, err
	}
	if err := request.Validate(); err != nil {
		return DevicePairRequestDTO{}, err
	}
	return request, nil
}
func (request DevicePairRequestDTO) Validate() error {
	if err := request.validate(SchemaDevicePairCommand, OperationDevicePair); err != nil {
		return err
	}
	if err := validateRequiredID("client_instance_id", request.ClientInstanceID); err != nil {
		return err
	}
	for field, version := range map[string]domain.Version{"expected_versions.principal": request.ExpectedVersions.Principal, "expected_versions.device": request.ExpectedVersions.Device, "expected_versions.device_trust": request.ExpectedVersions.DeviceTrust} {
		if err := validateVersion(field, version); err != nil {
			return err
		}
	}
	for field, id := range map[string]interface{ IsZero() bool }{"body.installation_id": request.Body.InstallationID, "body.principal_id": request.Body.PrincipalID, "body.device_id": request.Body.DeviceID} {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	return request.Body.Proof.validate("body.proof")
}

type WorkspaceMemberInviteRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID                  `json:"client_instance_id"`
	ExpectedVersions WorkspaceMemberInviteExpectedVersionsDTO `json:"expected_versions"`
	Body             WorkspaceMemberInviteBodyDTO             `json:"body"`
}
type WorkspaceMemberInviteExpectedVersionsDTO struct {
	Administrator domain.Version `json:"administrator"`
	Workspace     domain.Version `json:"workspace"`
	Principal     domain.Version `json:"principal"`
}
type WorkspaceMemberInviteBodyDTO struct {
	WorkspaceID     domain.WorkspaceID   `json:"workspace_id"`
	AdministratorID domain.PrincipalID   `json:"administrator_id"`
	PrincipalID     domain.PrincipalID   `json:"principal_id"`
	MembershipID    domain.MembershipID  `json:"membership_id"`
	Capabilities    []string             `json:"capabilities"`
	Challenge       CeremonyReferenceDTO `json:"challenge"`
}

type WorkspaceMembershipAcceptRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID                      `json:"client_instance_id"`
	ExpectedVersions WorkspaceMembershipAcceptExpectedVersionsDTO `json:"expected_versions"`
	Body             WorkspaceMembershipAcceptBodyDTO             `json:"body"`
}
type WorkspaceMembershipAcceptExpectedVersionsDTO struct {
	Workspace  domain.Version `json:"workspace"`
	Principal  domain.Version `json:"principal"`
	Membership domain.Version `json:"membership"`
}
type WorkspaceMembershipAcceptBodyDTO struct {
	WorkspaceID  domain.WorkspaceID   `json:"workspace_id"`
	PrincipalID  domain.PrincipalID   `json:"principal_id"`
	MembershipID domain.MembershipID  `json:"membership_id"`
	Proof        CeremonyReferenceDTO `json:"proof"`
}

type ActorCreateRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID        `json:"client_instance_id"`
	ExpectedVersions ActorCreateExpectedVersionsDTO `json:"expected_versions"`
	Body             ActorCreateBodyDTO             `json:"body"`
}
type ActorCreateExpectedVersionsDTO struct {
	Administrator domain.Version `json:"administrator"`
	Workspace     domain.Version `json:"workspace"`
}
type ActorCreateBodyDTO struct {
	WorkspaceID     domain.WorkspaceID `json:"workspace_id"`
	AdministratorID domain.PrincipalID `json:"administrator_id"`
	ActorID         domain.ActorID     `json:"actor_id"`
	Kind            string             `json:"kind"`
	DisplayName     string             `json:"display_name"`
}

type ActorDelegationProposeRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID                   `json:"client_instance_id"`
	ExpectedVersions ActorDelegationProposeExpectedVersionsDTO `json:"expected_versions"`
	Body             ActorDelegationProposeBodyDTO             `json:"body"`
}
type ActorDelegationProposeExpectedVersionsDTO struct {
	Administrator domain.Version `json:"administrator"`
	Workspace     domain.Version `json:"workspace"`
	Principal     domain.Version `json:"principal"`
	Actor         domain.Version `json:"actor"`
	Membership    domain.Version `json:"membership"`
}
type ActorDelegationProposeBodyDTO struct {
	WorkspaceID     domain.WorkspaceID       `json:"workspace_id"`
	AdministratorID domain.PrincipalID       `json:"administrator_id"`
	PrincipalID     domain.PrincipalID       `json:"principal_id"`
	ActorID         domain.ActorID           `json:"actor_id"`
	MembershipID    domain.MembershipID      `json:"membership_id"`
	DelegationID    domain.ActorDelegationID `json:"delegation_id"`
	Capabilities    []string                 `json:"capabilities"`
	Challenge       CeremonyReferenceDTO     `json:"challenge"`
}

type ActorDelegationActivateRequestDTO struct {
	CommandMetadataDTO
	ClientInstanceID domain.ClientInstanceID                    `json:"client_instance_id"`
	ExpectedVersions ActorDelegationActivateExpectedVersionsDTO `json:"expected_versions"`
	Body             ActorDelegationActivateBodyDTO             `json:"body"`
}
type ActorDelegationActivateExpectedVersionsDTO struct {
	Workspace  domain.Version `json:"workspace"`
	Principal  domain.Version `json:"principal"`
	Actor      domain.Version `json:"actor"`
	Membership domain.Version `json:"membership"`
	Delegation domain.Version `json:"delegation"`
}
type ActorDelegationActivateBodyDTO struct {
	WorkspaceID           domain.WorkspaceID       `json:"workspace_id"`
	PrincipalID           domain.PrincipalID       `json:"principal_id"`
	ActorID               domain.ActorID           `json:"actor_id"`
	MembershipID          domain.MembershipID      `json:"membership_id"`
	DelegationID          domain.ActorDelegationID `json:"delegation_id"`
	ActivationProof       CeremonyReferenceDTO     `json:"activation_proof"`
	SessionStartChallenge CeremonyReferenceDTO     `json:"session_start_challenge"`
}

func DecodeWorkspaceMemberInviteRequest(data []byte) (WorkspaceMemberInviteRequestDTO, error) {
	var request WorkspaceMemberInviteRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return request, err
	}
	if err := request.Validate(); err != nil {
		return WorkspaceMemberInviteRequestDTO{}, err
	}
	return request, nil
}
func DecodeWorkspaceMembershipAcceptRequest(data []byte) (WorkspaceMembershipAcceptRequestDTO, error) {
	var request WorkspaceMembershipAcceptRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return request, err
	}
	if err := request.Validate(); err != nil {
		return WorkspaceMembershipAcceptRequestDTO{}, err
	}
	return request, nil
}
func DecodeActorCreateRequest(data []byte) (ActorCreateRequestDTO, error) {
	var request ActorCreateRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return request, err
	}
	if err := request.Validate(); err != nil {
		return ActorCreateRequestDTO{}, err
	}
	return request, nil
}
func DecodeActorDelegationProposeRequest(data []byte) (ActorDelegationProposeRequestDTO, error) {
	var request ActorDelegationProposeRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return request, err
	}
	if err := request.Validate(); err != nil {
		return ActorDelegationProposeRequestDTO{}, err
	}
	return request, nil
}
func DecodeActorDelegationActivateRequest(data []byte) (ActorDelegationActivateRequestDTO, error) {
	var request ActorDelegationActivateRequestDTO
	if err := decodeCommandInput(data, &request); err != nil {
		return request, err
	}
	if err := request.Validate(); err != nil {
		return ActorDelegationActivateRequestDTO{}, err
	}
	return request, nil
}

func validateOrdinaryRequest(metadata CommandMetadataDTO, client domain.ClientInstanceID, schema, operation string, versions map[string]domain.Version, ids map[string]interface{ IsZero() bool }) error {
	if err := metadata.validate(schema, operation); err != nil {
		return err
	}
	if err := validateRequiredID("client_instance_id", client); err != nil {
		return err
	}
	for field, version := range versions {
		if err := validateVersion(field, version); err != nil {
			return err
		}
	}
	for field, id := range ids {
		if err := validateRequiredID(field, id); err != nil {
			return err
		}
	}
	return nil
}

func (request WorkspaceMemberInviteRequestDTO) Validate() error {
	if err := validateOrdinaryRequest(request.CommandMetadataDTO, request.ClientInstanceID, SchemaWorkspaceMemberInviteCommand, OperationWorkspaceMemberInvite,
		map[string]domain.Version{"expected_versions.administrator": request.ExpectedVersions.Administrator, "expected_versions.workspace": request.ExpectedVersions.Workspace, "expected_versions.principal": request.ExpectedVersions.Principal},
		map[string]interface{ IsZero() bool }{"body.workspace_id": request.Body.WorkspaceID, "body.administrator_id": request.Body.AdministratorID, "body.principal_id": request.Body.PrincipalID, "body.membership_id": request.Body.MembershipID}); err != nil {
		return err
	}
	if _, err := normalizeCapabilities("body.capabilities", request.Body.Capabilities); err != nil {
		return err
	}
	return request.Body.Challenge.validate("body.challenge")
}
func (request WorkspaceMembershipAcceptRequestDTO) Validate() error {
	if err := validateOrdinaryRequest(request.CommandMetadataDTO, request.ClientInstanceID, SchemaWorkspaceMembershipAcceptCommand, OperationWorkspaceMembershipAccept,
		map[string]domain.Version{"expected_versions.workspace": request.ExpectedVersions.Workspace, "expected_versions.principal": request.ExpectedVersions.Principal, "expected_versions.membership": request.ExpectedVersions.Membership},
		map[string]interface{ IsZero() bool }{"body.workspace_id": request.Body.WorkspaceID, "body.principal_id": request.Body.PrincipalID, "body.membership_id": request.Body.MembershipID}); err != nil {
		return err
	}
	return request.Body.Proof.validate("body.proof")
}
func (request ActorCreateRequestDTO) Validate() error {
	if err := validateOrdinaryRequest(request.CommandMetadataDTO, request.ClientInstanceID, SchemaActorCreateCommand, OperationActorCreate,
		map[string]domain.Version{"expected_versions.administrator": request.ExpectedVersions.Administrator, "expected_versions.workspace": request.ExpectedVersions.Workspace},
		map[string]interface{ IsZero() bool }{"body.workspace_id": request.Body.WorkspaceID, "body.administrator_id": request.Body.AdministratorID, "body.actor_id": request.Body.ActorID}); err != nil {
		return err
	}
	if !validActorKind(request.Body.Kind) {
		return invalid("body.kind", "is not a stable actor kind")
	}
	return validateText("body.display_name", request.Body.DisplayName, maxDisplayNameBytes, true)
}
func (request ActorDelegationProposeRequestDTO) Validate() error {
	if err := validateOrdinaryRequest(request.CommandMetadataDTO, request.ClientInstanceID, SchemaActorDelegationProposeCommand, OperationActorDelegationPropose,
		map[string]domain.Version{"expected_versions.administrator": request.ExpectedVersions.Administrator, "expected_versions.workspace": request.ExpectedVersions.Workspace, "expected_versions.principal": request.ExpectedVersions.Principal, "expected_versions.actor": request.ExpectedVersions.Actor, "expected_versions.membership": request.ExpectedVersions.Membership},
		map[string]interface{ IsZero() bool }{"body.workspace_id": request.Body.WorkspaceID, "body.administrator_id": request.Body.AdministratorID, "body.principal_id": request.Body.PrincipalID, "body.actor_id": request.Body.ActorID, "body.membership_id": request.Body.MembershipID, "body.delegation_id": request.Body.DelegationID}); err != nil {
		return err
	}
	if _, err := normalizeCapabilities("body.capabilities", request.Body.Capabilities); err != nil {
		return err
	}
	return request.Body.Challenge.validate("body.challenge")
}
func (request ActorDelegationActivateRequestDTO) Validate() error {
	if err := validateOrdinaryRequest(request.CommandMetadataDTO, request.ClientInstanceID, SchemaActorDelegationActivateCommand, OperationActorDelegationActivate,
		map[string]domain.Version{"expected_versions.workspace": request.ExpectedVersions.Workspace, "expected_versions.principal": request.ExpectedVersions.Principal, "expected_versions.actor": request.ExpectedVersions.Actor, "expected_versions.membership": request.ExpectedVersions.Membership, "expected_versions.delegation": request.ExpectedVersions.Delegation},
		map[string]interface{ IsZero() bool }{"body.workspace_id": request.Body.WorkspaceID, "body.principal_id": request.Body.PrincipalID, "body.actor_id": request.Body.ActorID, "body.membership_id": request.Body.MembershipID, "body.delegation_id": request.Body.DelegationID}); err != nil {
		return err
	}
	if err := request.Body.ActivationProof.validate("body.activation_proof"); err != nil {
		return err
	}
	return request.Body.SessionStartChallenge.validate("body.session_start_challenge")
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
