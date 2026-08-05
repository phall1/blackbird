package domain

import (
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxIdentityCapabilities     = 64
	MaxSessionGrantRevisions    = 64
	MaxActorSessionLifetime     = 24 * time.Hour
	MaxDeviceCredentialOverlap  = 15 * time.Minute
	MaxBootstrapFailedAttempts  = 5
	BootstrapInvitationLifetime = 5 * time.Minute
)

var (
	ErrInvalidCapability        = errors.New("invalid capability")
	ErrInvalidCapabilitySet     = errors.New("invalid capability set")
	ErrInvalidCeremonyChallenge = errors.New("invalid ceremony challenge")
	ErrInvalidCeremonyProof     = errors.New("invalid ceremony proof")
	ErrInvalidIdentityState     = errors.New("invalid identity state")
	ErrInvalidAuthorization     = errors.New("invalid identity authorization")
	ErrInvalidIdentityMetadata  = errors.New("invalid identity metadata")
)

func validBoundedText(value string, maximum int) bool {
	if strings.TrimSpace(value) != value || value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

type DisplayName struct{ value string }

func NewDisplayName(value string) (DisplayName, error) {
	if !validBoundedText(value, 256) {
		return DisplayName{}, ErrInvalidIdentityMetadata
	}
	return DisplayName{value: value}, nil
}

func (name DisplayName) String() string { return name.value }

type PublicKeyReference struct{ value string }

func NewPublicKeyReference(value string) (PublicKeyReference, error) {
	if !validBoundedText(value, 256) {
		return PublicKeyReference{}, ErrInvalidIdentityMetadata
	}
	return PublicKeyReference{value: value}, nil
}

func (reference PublicKeyReference) String() string { return reference.value }

// CredentialDigest is an already-derived, non-secret SHA-256 value. The
// application credential preparer owns salting/canonicalization; the domain
// stores only the fixed-width result and never reusable credential material.
type CredentialDigest [sha256.Size]byte

func NewCredentialDigest(value [sha256.Size]byte) (CredentialDigest, error) {
	digest := CredentialDigest(value)
	if digest.IsZero() {
		return CredentialDigest{}, ErrInvalidIdentityMetadata
	}
	return digest, nil
}

func (digest CredentialDigest) IsZero() bool { return digest == CredentialDigest{} }

func (digest CredentialDigest) Bytes() [sha256.Size]byte { return [sha256.Size]byte(digest) }

// DeviceCredentialBinding is the finalized, secret-free identity of a paired
// Ed25519 credential. Pending devices carry only their candidate public-key
// reference; every trusted or historical paired device carries this binding.
type DeviceCredentialBinding struct {
	publicKeyReference PublicKeyReference
	spkiFingerprint    CredentialDigest
	transcript         CommandFingerprint
}

const DeviceCredentialAlgorithm = "ed25519-spki-sha256-v1"

func NewDeviceCredentialBinding(
	publicKeyReference PublicKeyReference,
	spkiFingerprint CredentialDigest,
	transcript CommandFingerprint,
) (DeviceCredentialBinding, error) {
	if !validPublicKeyReferenceValue(publicKeyReference) || spkiFingerprint.IsZero() || transcript.IsZero() {
		return DeviceCredentialBinding{}, ErrInvalidIdentityMetadata
	}
	return DeviceCredentialBinding{
		publicKeyReference: publicKeyReference,
		spkiFingerprint:    spkiFingerprint,
		transcript:         transcript,
	}, nil
}

func (binding DeviceCredentialBinding) IsZero() bool {
	return binding.publicKeyReference.valueIsZero() && binding.spkiFingerprint.IsZero() && binding.transcript.IsZero()
}

func (binding DeviceCredentialBinding) Algorithm() string { return DeviceCredentialAlgorithm }
func (binding DeviceCredentialBinding) PublicKeyReference() PublicKeyReference {
	return binding.publicKeyReference
}
func (binding DeviceCredentialBinding) SPKIFingerprint() CredentialDigest {
	return binding.spkiFingerprint
}
func (binding DeviceCredentialBinding) TranscriptFingerprint() CommandFingerprint {
	return binding.transcript
}

type CredentialReference struct{ value string }

func NewCredentialReference(value string) (CredentialReference, error) {
	if !validBoundedText(value, 256) {
		return CredentialReference{}, ErrInvalidIdentityMetadata
	}
	return CredentialReference{value: value}, nil
}

func (reference CredentialReference) String() string { return reference.value }

type CredentialAudience struct{ value string }

func NewCredentialAudience(value string) (CredentialAudience, error) {
	if !validBoundedText(value, 256) {
		return CredentialAudience{}, ErrInvalidIdentityMetadata
	}
	return CredentialAudience{value: value}, nil
}

func (audience CredentialAudience) String() string { return audience.value }

// PresentationCredentialBinding is the durable, non-reusable reference to the
// sender-constrained credential issued for one ActorSession. The bearer value
// and private key never enter domain state.
type PresentationCredentialBinding struct {
	digest    CredentialDigest
	reference CredentialReference
	audience  CredentialAudience
	version   uint16
}

const PresentationCredentialVersion uint16 = 1

func NewPresentationCredentialBinding(
	digest CredentialDigest,
	reference CredentialReference,
	audience CredentialAudience,
	version uint16,
) (PresentationCredentialBinding, error) {
	if digest.IsZero() || !validBoundedText(reference.String(), 256) ||
		!validBoundedText(audience.String(), 256) ||
		version != PresentationCredentialVersion {
		return PresentationCredentialBinding{}, ErrInvalidIdentityMetadata
	}
	return PresentationCredentialBinding{
		digest: digest, reference: reference, audience: audience, version: version,
	}, nil
}

func (binding PresentationCredentialBinding) IsZero() bool {
	return binding.digest.IsZero() && binding.reference.String() == "" &&
		binding.audience.String() == "" && binding.version == 0
}

func (binding PresentationCredentialBinding) Digest() CredentialDigest { return binding.digest }
func (binding PresentationCredentialBinding) Reference() CredentialReference {
	return binding.reference
}
func (binding PresentationCredentialBinding) Audience() CredentialAudience { return binding.audience }
func (binding PresentationCredentialBinding) Version() uint16              { return binding.version }

type WorkspaceAlias struct{ value string }

func NewWorkspaceAlias(value string) (WorkspaceAlias, error) {
	if !validBoundedText(value, 256) {
		return WorkspaceAlias{}, ErrInvalidIdentityMetadata
	}
	return WorkspaceAlias{value: value}, nil
}

func (alias WorkspaceAlias) String() string { return alias.value }

type DiscoveryLocator struct{ value string }

func NewDiscoveryLocator(value string) (DiscoveryLocator, error) {
	if !validBoundedText(value, 4096) {
		return DiscoveryLocator{}, ErrInvalidIdentityMetadata
	}
	return DiscoveryLocator{value: value}, nil
}

func (locator DiscoveryLocator) String() string { return locator.value }

type ActorProfile struct{ displayName DisplayName }

func NewActorProfile(displayName DisplayName) (ActorProfile, error) {
	if displayName.String() == "" {
		return ActorProfile{}, ErrInvalidIdentityMetadata
	}
	return ActorProfile{displayName: displayName}, nil
}

func (profile ActorProfile) DisplayName() DisplayName { return profile.displayName }

type ClientMetadata struct {
	name    string
	version string
}

func NewClientMetadata(name string, version string) (ClientMetadata, error) {
	if !validBoundedText(name, 128) || !validBoundedText(version, 128) {
		return ClientMetadata{}, ErrInvalidIdentityMetadata
	}
	return ClientMetadata{name: name, version: version}, nil
}

func (metadata ClientMetadata) Name() string    { return metadata.name }
func (metadata ClientMetadata) Version() string { return metadata.version }

type Capability struct{ value string }

func NewCapability(value string) (Capability, error) {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return Capability{}, ErrInvalidCapability
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != ':' && character != '_' && character != '-' && character != '.' {
			return Capability{}, ErrInvalidCapability
		}
	}
	return Capability{value: value}, nil
}

func (capability Capability) String() string { return capability.value }

var (
	capabilityInstallationOwner = mustCapability("installation:owner")
	capabilityIdentityAdmin     = mustCapability("identity:admin")
	capabilityWorkspaceCreate   = mustCapability("workspace:create")
	capabilityMembershipAdmin   = mustCapability("membership:admin")
	capabilityActorAdmin        = mustCapability("actor:admin")
	capabilityDelegationAdmin   = mustCapability("delegation:admin")
	capabilityDevicePair        = mustCapability("device:pair")
	capabilityWorkspaceOwner    = mustCapability("workspace:owner")
)

func InstallationOwnerCapability() Capability { return capabilityInstallationOwner }
func IdentityAdminCapability() Capability     { return capabilityIdentityAdmin }
func WorkspaceCreateCapability() Capability   { return capabilityWorkspaceCreate }
func MembershipAdminCapability() Capability   { return capabilityMembershipAdmin }
func ActorAdminCapability() Capability        { return capabilityActorAdmin }
func DelegationAdminCapability() Capability   { return capabilityDelegationAdmin }
func DevicePairCapability() Capability        { return capabilityDevicePair }
func WorkspaceOwnerCapability() Capability    { return capabilityWorkspaceOwner }

func mustCapability(value string) Capability {
	capability, err := NewCapability(value)
	if err != nil {
		panic(err)
	}
	return capability
}

type CapabilitySet struct{ values []Capability }

func NewCapabilitySet(capabilities ...Capability) (CapabilitySet, error) {
	if len(capabilities) == 0 || len(capabilities) > MaxIdentityCapabilities {
		return CapabilitySet{}, ErrInvalidCapabilitySet
	}
	values := append([]Capability(nil), capabilities...)
	for _, capability := range values {
		validated, err := NewCapability(capability.String())
		if err != nil || validated != capability {
			return CapabilitySet{}, ErrInvalidCapabilitySet
		}
	}
	sort.Slice(values, func(left, right int) bool { return values[left].String() < values[right].String() })
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return CapabilitySet{}, ErrInvalidCapabilitySet
		}
	}
	return CapabilitySet{values: values}, nil
}

func (set CapabilitySet) IsZero() bool { return len(set.values) == 0 }

func (set CapabilitySet) Values() []Capability { return append([]Capability(nil), set.values...) }

func (set CapabilitySet) Contains(capability Capability) bool {
	index := sort.Search(len(set.values), func(index int) bool {
		return set.values[index].String() >= capability.String()
	})
	return index < len(set.values) && set.values[index] == capability
}

func (set CapabilitySet) ContainsAll(required CapabilitySet) bool {
	if set.IsZero() || required.IsZero() {
		return false
	}
	for _, capability := range required.values {
		if !set.Contains(capability) {
			return false
		}
	}
	return true
}

func (set CapabilitySet) Equal(other CapabilitySet) bool {
	if len(set.values) != len(other.values) {
		return false
	}
	for index := range set.values {
		if set.values[index] != other.values[index] {
			return false
		}
	}
	return true
}

type CeremonyPurpose string

const (
	CeremonyPurposeMembershipAcceptance CeremonyPurpose = "membership_acceptance"
	CeremonyPurposeDelegationActivation CeremonyPurpose = "delegation_activation"
	CeremonyPurposeDevicePairing        CeremonyPurpose = "device_pairing"
	CeremonyPurposeActorSessionStart    CeremonyPurpose = "actor_session_start"
)

func (purpose CeremonyPurpose) Valid() bool {
	switch purpose {
	case CeremonyPurposeMembershipAcceptance,
		CeremonyPurposeDelegationActivation,
		CeremonyPurposeDevicePairing,
		CeremonyPurposeActorSessionStart:
		return true
	default:
		return false
	}
}

type CeremonyStatus string

const (
	CeremonyPending  CeremonyStatus = "pending"
	CeremonyConsumed CeremonyStatus = "consumed"
)

func (status CeremonyStatus) Valid() bool {
	return status == CeremonyPending || status == CeremonyConsumed
}

// CeremonyChallenge retains only bounded proof metadata. Secret handoff bytes
// and cryptographic verification remain outside the pure domain transition.
type CeremonyChallenge struct {
	id             CeremonyID
	purpose        CeremonyPurpose
	proofDigest    CommandFingerprint
	expiresAt      time.Time
	status         CeremonyStatus
	installationID InstallationID
	workspaceID    WorkspaceID
	principalID    PrincipalID
	membershipID   MembershipID
	actorID        ActorID
	delegationID   ActorDelegationID
	deviceID       DeviceID
}

func newCeremonyChallenge(
	id CeremonyID,
	purpose CeremonyPurpose,
	proofDigest CommandFingerprint,
	expiresAt time.Time,
	installationID InstallationID,
	workspaceID WorkspaceID,
	principalID PrincipalID,
	membershipID MembershipID,
	actorID ActorID,
	delegationID ActorDelegationID,
	deviceID DeviceID,
) (CeremonyChallenge, error) {
	if id.IsZero() || !purpose.Valid() || proofDigest.IsZero() || expiresAt.IsZero() {
		return CeremonyChallenge{}, ErrInvalidCeremonyChallenge
	}
	return CeremonyChallenge{
		id:             id,
		purpose:        purpose,
		proofDigest:    proofDigest,
		expiresAt:      expiresAt.UTC(),
		status:         CeremonyPending,
		installationID: installationID,
		workspaceID:    workspaceID,
		principalID:    principalID,
		membershipID:   membershipID,
		actorID:        actorID,
		delegationID:   delegationID,
		deviceID:       deviceID,
	}, nil
}

func NewMembershipAcceptanceChallenge(
	id CeremonyID,
	proofDigest CommandFingerprint,
	expiresAt time.Time,
	workspaceID WorkspaceID,
	membershipID MembershipID,
	principalID PrincipalID,
) (CeremonyChallenge, error) {
	if workspaceID.IsZero() || membershipID.IsZero() || principalID.IsZero() {
		return CeremonyChallenge{}, ErrInvalidCeremonyChallenge
	}
	return newCeremonyChallenge(id, CeremonyPurposeMembershipAcceptance, proofDigest, expiresAt,
		InstallationID{}, workspaceID, principalID, membershipID, ActorID{}, ActorDelegationID{}, DeviceID{})
}

func NewDelegationActivationChallenge(
	id CeremonyID,
	proofDigest CommandFingerprint,
	expiresAt time.Time,
	workspaceID WorkspaceID,
	delegationID ActorDelegationID,
	principalID PrincipalID,
	actorID ActorID,
) (CeremonyChallenge, error) {
	if workspaceID.IsZero() || delegationID.IsZero() || principalID.IsZero() || actorID.IsZero() {
		return CeremonyChallenge{}, ErrInvalidCeremonyChallenge
	}
	return newCeremonyChallenge(id, CeremonyPurposeDelegationActivation, proofDigest, expiresAt,
		InstallationID{}, workspaceID, principalID, MembershipID{}, actorID, delegationID, DeviceID{})
}

func NewDevicePairingChallenge(
	id CeremonyID,
	proofDigest CommandFingerprint,
	expiresAt time.Time,
	installationID InstallationID,
	principalID PrincipalID,
	deviceID DeviceID,
) (CeremonyChallenge, error) {
	if installationID.IsZero() || principalID.IsZero() || deviceID.IsZero() {
		return CeremonyChallenge{}, ErrInvalidCeremonyChallenge
	}
	return newCeremonyChallenge(id, CeremonyPurposeDevicePairing, proofDigest, expiresAt,
		installationID, WorkspaceID{}, principalID, MembershipID{}, ActorID{}, ActorDelegationID{}, deviceID)
}

func NewSessionStartChallenge(
	id CeremonyID,
	proofDigest CommandFingerprint,
	expiresAt time.Time,
	workspaceID WorkspaceID,
	delegationID ActorDelegationID,
	principalID PrincipalID,
	actorID ActorID,
) (CeremonyChallenge, error) {
	if workspaceID.IsZero() || delegationID.IsZero() || principalID.IsZero() || actorID.IsZero() {
		return CeremonyChallenge{}, ErrInvalidCeremonyChallenge
	}
	return newCeremonyChallenge(id, CeremonyPurposeActorSessionStart, proofDigest, expiresAt,
		InstallationID{}, workspaceID, principalID, MembershipID{}, actorID, delegationID, DeviceID{})
}

func (challenge CeremonyChallenge) ID() CeremonyID                  { return challenge.id }
func (challenge CeremonyChallenge) Purpose() CeremonyPurpose        { return challenge.purpose }
func (challenge CeremonyChallenge) ProofDigest() CommandFingerprint { return challenge.proofDigest }
func (challenge CeremonyChallenge) ExpiresAt() time.Time            { return challenge.expiresAt }
func (challenge CeremonyChallenge) Status() CeremonyStatus          { return challenge.status }
func (challenge CeremonyChallenge) IsZero() bool                    { return challenge.id.IsZero() }
func (challenge CeremonyChallenge) InstallationID() InstallationID  { return challenge.installationID }
func (challenge CeremonyChallenge) WorkspaceID() WorkspaceID        { return challenge.workspaceID }
func (challenge CeremonyChallenge) PrincipalID() PrincipalID        { return challenge.principalID }
func (challenge CeremonyChallenge) MembershipID() MembershipID      { return challenge.membershipID }
func (challenge CeremonyChallenge) ActorID() ActorID                { return challenge.actorID }
func (challenge CeremonyChallenge) DelegationID() ActorDelegationID { return challenge.delegationID }
func (challenge CeremonyChallenge) DeviceID() DeviceID              { return challenge.deviceID }

func (challenge CeremonyChallenge) consume() CeremonyChallenge {
	challenge.status = CeremonyConsumed
	return challenge
}

// CeremonyChallengeRehydrationParams is the complete persisted representation of a
// ceremony challenge. RehydrateCeremonyChallenge is the only persistence
// entrypoint: callers cannot bypass purpose-specific reference validation.
type CeremonyChallengeRehydrationParams struct {
	ID             CeremonyID
	Purpose        CeremonyPurpose
	ProofDigest    CommandFingerprint
	ExpiresAt      time.Time
	Status         CeremonyStatus
	InstallationID InstallationID
	WorkspaceID    WorkspaceID
	PrincipalID    PrincipalID
	MembershipID   MembershipID
	ActorID        ActorID
	DelegationID   ActorDelegationID
	DeviceID       DeviceID
}

func RehydrateCeremonyChallenge(params CeremonyChallengeRehydrationParams) (CeremonyChallenge, error) {
	if params.ID.IsZero() || !params.Purpose.Valid() || params.ProofDigest.IsZero() ||
		params.ExpiresAt.IsZero() || !params.Status.Valid() {
		return CeremonyChallenge{}, ErrInvalidCeremonyChallenge
	}
	validReferences := false
	switch params.Purpose {
	case CeremonyPurposeMembershipAcceptance:
		validReferences = params.InstallationID.IsZero() && !params.WorkspaceID.IsZero() &&
			!params.PrincipalID.IsZero() && !params.MembershipID.IsZero() && params.ActorID.IsZero() &&
			params.DelegationID.IsZero() && params.DeviceID.IsZero()
	case CeremonyPurposeDelegationActivation, CeremonyPurposeActorSessionStart:
		validReferences = params.InstallationID.IsZero() && !params.WorkspaceID.IsZero() &&
			!params.PrincipalID.IsZero() && params.MembershipID.IsZero() && !params.ActorID.IsZero() &&
			!params.DelegationID.IsZero() && params.DeviceID.IsZero()
	case CeremonyPurposeDevicePairing:
		validReferences = !params.InstallationID.IsZero() && params.WorkspaceID.IsZero() &&
			!params.PrincipalID.IsZero() && params.MembershipID.IsZero() && params.ActorID.IsZero() &&
			params.DelegationID.IsZero() && !params.DeviceID.IsZero()
	}
	if !validReferences {
		return CeremonyChallenge{}, ErrInvalidCeremonyChallenge
	}
	return CeremonyChallenge{
		id: params.ID, purpose: params.Purpose, proofDigest: params.ProofDigest,
		expiresAt: params.ExpiresAt.UTC(), status: params.Status,
		installationID: params.InstallationID, workspaceID: params.WorkspaceID,
		principalID: params.PrincipalID, membershipID: params.MembershipID,
		actorID: params.ActorID, delegationID: params.DelegationID, deviceID: params.DeviceID,
	}, nil
}

// CeremonyCreationExpectation makes global CeremonyID uniqueness an explicit
// unit-of-work precondition. The persistence boundary must atomically verify
// that this ID is absent when it stores the transition result.
type CeremonyCreationExpectation struct{ id CeremonyID }

func ExpectCeremonyAbsent(id CeremonyID) (CeremonyCreationExpectation, error) {
	if id.IsZero() {
		return CeremonyCreationExpectation{}, ErrInvalidCeremonyChallenge
	}
	return CeremonyCreationExpectation{id: id}, nil
}

func (expectation CeremonyCreationExpectation) matches(challenge CeremonyChallenge) bool {
	return expectation.id == challenge.ID()
}

// CeremonyProof is immutable proof metadata accepted from the authentication
// boundary. Its digest is compared to canonical retained metadata; this value
// never contains the secret proof itself.
type CeremonyProof struct {
	challengeID CeremonyID
	purpose     CeremonyPurpose
	proofDigest CommandFingerprint
	principalID PrincipalID
	deviceID    DeviceID
}

func NewCeremonyProof(
	challengeID CeremonyID,
	purpose CeremonyPurpose,
	proofDigest CommandFingerprint,
	principalID PrincipalID,
	deviceID DeviceID,
) (CeremonyProof, error) {
	if challengeID.IsZero() || !purpose.Valid() || proofDigest.IsZero() {
		return CeremonyProof{}, ErrInvalidCeremonyProof
	}
	return CeremonyProof{
		challengeID: challengeID,
		purpose:     purpose,
		proofDigest: proofDigest,
		principalID: principalID,
		deviceID:    deviceID,
	}, nil
}

func (proof CeremonyProof) ChallengeID() CeremonyID         { return proof.challengeID }
func (proof CeremonyProof) Purpose() CeremonyPurpose        { return proof.purpose }
func (proof CeremonyProof) ProofDigest() CommandFingerprint { return proof.proofDigest }
func (proof CeremonyProof) PrincipalID() PrincipalID        { return proof.principalID }
func (proof CeremonyProof) DeviceID() DeviceID              { return proof.deviceID }

type InstallationInvitationStatus string

const (
	InstallationInvitationPending   InstallationInvitationStatus = "pending"
	InstallationInvitationConsumed  InstallationInvitationStatus = "consumed"
	InstallationInvitationExhausted InstallationInvitationStatus = "exhausted"
)

type PairingProtocol string

const PairingProtocolV1 PairingProtocol = "blackbird.pair/v1"

func (protocol PairingProtocol) Valid() bool { return protocol == PairingProtocolV1 }

type BootstrapRole string

const BootstrapRoleInstallationOwner BootstrapRole = "installation_owner"

func (role BootstrapRole) Valid() bool { return role == BootstrapRoleInstallationOwner }

type InstallationInvitationState struct {
	id                    InvitationID
	installationID        InstallationID
	installationPublicKey PublicKeyReference
	invitationVerifier    CommandFingerprint
	bootstrapGeneration   BootstrapGenerationID
	expiresAt             time.Time
	failedAttempts        uint8
	status                InstallationInvitationStatus
	version               Version
}

type InstallationInvitationRehydrationParams struct {
	ID                    InvitationID
	InstallationID        InstallationID
	InstallationPublicKey PublicKeyReference
	InvitationVerifier    CommandFingerprint
	BootstrapGenerationID BootstrapGenerationID
	ExpiresAt             time.Time
	FailedAttempts        uint8
	Status                InstallationInvitationStatus
	Version               Version
}

func RehydrateInstallationInvitation(
	params InstallationInvitationRehydrationParams,
) (InstallationInvitationState, error) {
	if params.ID.IsZero() || params.InstallationID.IsZero() || !validPublicKeyReferenceValue(params.InstallationPublicKey) ||
		params.InvitationVerifier.IsZero() || params.BootstrapGenerationID.IsZero() || params.ExpiresAt.IsZero() ||
		!params.Version.Valid() || params.FailedAttempts > MaxBootstrapFailedAttempts {
		return InstallationInvitationState{}, ErrInvalidIdentityState
	}
	var expectedVersion uint64
	switch params.Status {
	case InstallationInvitationPending:
		if params.FailedAttempts == MaxBootstrapFailedAttempts {
			return InstallationInvitationState{}, ErrInvalidIdentityState
		}
		expectedVersion = uint64(params.FailedAttempts) + 1
	case InstallationInvitationConsumed:
		if params.FailedAttempts == MaxBootstrapFailedAttempts {
			return InstallationInvitationState{}, ErrInvalidIdentityState
		}
		expectedVersion = uint64(params.FailedAttempts) + 2
	case InstallationInvitationExhausted:
		if params.FailedAttempts != MaxBootstrapFailedAttempts {
			return InstallationInvitationState{}, ErrInvalidIdentityState
		}
		expectedVersion = uint64(MaxBootstrapFailedAttempts) + 1
	default:
		return InstallationInvitationState{}, ErrInvalidIdentityState
	}
	if params.Version.Uint64() != expectedVersion {
		return InstallationInvitationState{}, ErrInvalidIdentityState
	}
	return InstallationInvitationState{
		id: params.ID, installationID: params.InstallationID,
		installationPublicKey: params.InstallationPublicKey, invitationVerifier: params.InvitationVerifier,
		bootstrapGeneration: params.BootstrapGenerationID, expiresAt: params.ExpiresAt.UTC(),
		failedAttempts: params.FailedAttempts, status: params.Status, version: params.Version,
	}, nil
}

func NewInstallationInvitation(
	id InvitationID,
	installationID InstallationID,
	installationPublicKey PublicKeyReference,
	invitationVerifier CommandFingerprint,
	issuedAt time.Time,
	bootstrapGeneration BootstrapGenerationID,
) (InstallationInvitationState, error) {
	if id.IsZero() || installationID.IsZero() || installationPublicKey.String() == "" ||
		invitationVerifier.IsZero() || issuedAt.IsZero() || bootstrapGeneration.IsZero() {
		return InstallationInvitationState{}, ErrInvalidIdentityState
	}
	return InstallationInvitationState{
		id:                    id,
		installationID:        installationID,
		installationPublicKey: installationPublicKey,
		invitationVerifier:    invitationVerifier,
		bootstrapGeneration:   bootstrapGeneration,
		expiresAt:             issuedAt.UTC().Add(BootstrapInvitationLifetime),
		status:                InstallationInvitationPending,
		version:               InitialVersion(),
	}, nil
}

func (state InstallationInvitationState) IsZero() bool                   { return state.id.IsZero() }
func (state InstallationInvitationState) ID() InvitationID               { return state.id }
func (state InstallationInvitationState) InstallationID() InstallationID { return state.installationID }
func (state InstallationInvitationState) InstallationPublicKey() PublicKeyReference {
	return state.installationPublicKey
}
func (state InstallationInvitationState) InvitationVerifier() CommandFingerprint {
	return state.invitationVerifier
}
func (state InstallationInvitationState) BootstrapGenerationID() BootstrapGenerationID {
	return state.bootstrapGeneration
}
func (state InstallationInvitationState) ExpiresAt() time.Time                 { return state.expiresAt }
func (state InstallationInvitationState) FailedAttempts() uint8                { return state.failedAttempts }
func (state InstallationInvitationState) Status() InstallationInvitationStatus { return state.status }
func (state InstallationInvitationState) Version() Version                     { return state.version }

type BootstrapProof struct {
	invitationID          InvitationID
	installationID        InstallationID
	installationKey       PublicKeyReference
	invitationEvidence    CommandFingerprint
	transcript            CommandFingerprint
	clientNonceDigest     CommandFingerprint
	serverNonceDigest     CommandFingerprint
	protocol              PairingProtocol
	role                  BootstrapRole
	principalID           PrincipalID
	principalDisplayName  DisplayName
	deviceID              DeviceID
	deviceDisplayName     DisplayName
	devicePublicKey       PublicKeyReference
	deviceSPKIFingerprint CredentialDigest
	ownerGrantID          GrantID
	ownerCapabilities     CapabilitySet
}

type BootstrapProofParams struct {
	InvitationID          InvitationID
	InstallationID        InstallationID
	InstallationKey       PublicKeyReference
	InvitationEvidence    CommandFingerprint
	TranscriptFingerprint CommandFingerprint
	ClientNonceDigest     CommandFingerprint
	ServerNonceDigest     CommandFingerprint
	Protocol              PairingProtocol
	Role                  BootstrapRole
	PrincipalID           PrincipalID
	PrincipalDisplayName  DisplayName
	DeviceID              DeviceID
	DeviceDisplayName     DisplayName
	DevicePublicKey       PublicKeyReference
	DeviceSPKIFingerprint CredentialDigest
	OwnerGrantID          GrantID
	OwnerCapabilities     CapabilitySet
}

func NewBootstrapProof(params BootstrapProofParams) (BootstrapProof, error) {
	if params.InvitationID.IsZero() || params.InstallationID.IsZero() || params.InstallationKey.String() == "" ||
		params.InvitationEvidence.IsZero() || params.TranscriptFingerprint.IsZero() ||
		params.ClientNonceDigest.IsZero() || params.ServerNonceDigest.IsZero() ||
		!params.Protocol.Valid() || !params.Role.Valid() || params.PrincipalID.IsZero() ||
		params.PrincipalDisplayName.String() == "" || params.DeviceID.IsZero() ||
		params.DeviceDisplayName.String() == "" || params.DevicePublicKey.String() == "" ||
		params.DeviceSPKIFingerprint.IsZero() ||
		params.OwnerGrantID.IsZero() || params.OwnerCapabilities.IsZero() {
		return BootstrapProof{}, ErrInvalidCeremonyProof
	}
	return BootstrapProof{
		invitationID:          params.InvitationID,
		installationID:        params.InstallationID,
		installationKey:       params.InstallationKey,
		invitationEvidence:    params.InvitationEvidence,
		transcript:            params.TranscriptFingerprint,
		clientNonceDigest:     params.ClientNonceDigest,
		serverNonceDigest:     params.ServerNonceDigest,
		protocol:              params.Protocol,
		role:                  params.Role,
		principalID:           params.PrincipalID,
		principalDisplayName:  params.PrincipalDisplayName,
		deviceID:              params.DeviceID,
		deviceDisplayName:     params.DeviceDisplayName,
		devicePublicKey:       params.DevicePublicKey,
		deviceSPKIFingerprint: params.DeviceSPKIFingerprint,
		ownerGrantID:          params.OwnerGrantID,
		ownerCapabilities:     cloneCapabilitySet(params.OwnerCapabilities),
	}, nil
}

func (proof BootstrapProof) InvitationID() InvitationID                { return proof.invitationID }
func (proof BootstrapProof) InstallationID() InstallationID            { return proof.installationID }
func (proof BootstrapProof) InstallationKey() PublicKeyReference       { return proof.installationKey }
func (proof BootstrapProof) InvitationEvidence() CommandFingerprint    { return proof.invitationEvidence }
func (proof BootstrapProof) TranscriptFingerprint() CommandFingerprint { return proof.transcript }
func (proof BootstrapProof) ClientNonceDigest() CommandFingerprint     { return proof.clientNonceDigest }
func (proof BootstrapProof) ServerNonceDigest() CommandFingerprint     { return proof.serverNonceDigest }
func (proof BootstrapProof) Protocol() PairingProtocol                 { return proof.protocol }
func (proof BootstrapProof) Role() BootstrapRole                       { return proof.role }
func (proof BootstrapProof) PrincipalID() PrincipalID                  { return proof.principalID }
func (proof BootstrapProof) PrincipalDisplayName() DisplayName         { return proof.principalDisplayName }
func (proof BootstrapProof) DeviceID() DeviceID                        { return proof.deviceID }
func (proof BootstrapProof) DeviceDisplayName() DisplayName            { return proof.deviceDisplayName }
func (proof BootstrapProof) DevicePublicKey() PublicKeyReference       { return proof.devicePublicKey }
func (proof BootstrapProof) DeviceSPKIFingerprint() CredentialDigest {
	return proof.deviceSPKIFingerprint
}
func (proof BootstrapProof) OwnerGrantID() GrantID { return proof.ownerGrantID }
func (proof BootstrapProof) OwnerCapabilities() CapabilitySet {
	return cloneCapabilitySet(proof.ownerCapabilities)
}

type BootstrapGenerationAuthorization struct {
	currentGeneration BootstrapGenerationID
	resumeApproval    VerifiedBootstrapResumeApproval
	resumed           bool
}

// VerifiedBootstrapResumeApproval is authority-bound proof metadata accepted
// from the authentication boundary after verifying the approval signature.
// Its fingerprint binds the invitation, installation, and both generations.
type VerifiedBootstrapResumeApproval struct {
	invitationID       InvitationID
	installationID     InstallationID
	previousGeneration BootstrapGenerationID
	currentGeneration  BootstrapGenerationID
	fingerprint        CommandFingerprint
}

func NewVerifiedBootstrapResumeApproval(
	invitationID InvitationID,
	installationID InstallationID,
	previous BootstrapGenerationID,
	current BootstrapGenerationID,
	fingerprint CommandFingerprint,
) (VerifiedBootstrapResumeApproval, error) {
	if invitationID.IsZero() || installationID.IsZero() || previous.IsZero() || current.IsZero() ||
		previous == current || fingerprint.IsZero() {
		return VerifiedBootstrapResumeApproval{}, ErrInvalidAuthorization
	}
	return VerifiedBootstrapResumeApproval{
		invitationID: invitationID, installationID: installationID,
		previousGeneration: previous, currentGeneration: current, fingerprint: fingerprint,
	}, nil
}

func SameBootstrapGeneration(current BootstrapGenerationID) (BootstrapGenerationAuthorization, error) {
	if current.IsZero() {
		return BootstrapGenerationAuthorization{}, ErrInvalidAuthorization
	}
	return BootstrapGenerationAuthorization{currentGeneration: current}, nil
}

func ResumeBootstrapInvitation(
	approval VerifiedBootstrapResumeApproval,
) (BootstrapGenerationAuthorization, error) {
	if approval.invitationID.IsZero() || approval.installationID.IsZero() ||
		approval.previousGeneration.IsZero() || approval.currentGeneration.IsZero() || approval.fingerprint.IsZero() {
		return BootstrapGenerationAuthorization{}, ErrInvalidAuthorization
	}
	return BootstrapGenerationAuthorization{
		currentGeneration: approval.currentGeneration,
		resumeApproval:    approval,
		resumed:           true,
	}, nil
}

func (authorization BootstrapGenerationAuthorization) CurrentGeneration() BootstrapGenerationID {
	return authorization.currentGeneration
}

func (authorization BootstrapGenerationAuthorization) permits(
	invitation InstallationInvitationState,
	currentGeneration BootstrapGenerationID,
) bool {
	if currentGeneration.IsZero() || authorization.currentGeneration != currentGeneration {
		return false
	}
	if !authorization.resumed {
		return currentGeneration == invitation.BootstrapGenerationID()
	}
	approval := authorization.resumeApproval
	return approval.invitationID == invitation.ID() && approval.installationID == invitation.InstallationID() &&
		approval.previousGeneration == invitation.BootstrapGenerationID() &&
		approval.currentGeneration == currentGeneration && !approval.fingerprint.IsZero()
}

// PairingRedemptionAuthorization is trusted output from the pairing verifier
// and policy boundary. It is single-purpose and binds the exact authority,
// challenge, transcript, candidate device, and finalized credential that must
// be rechecked while the Device and ceremony rows are locked.
type PairingRedemptionAuthorization struct {
	authorityID    AuthorityID
	epoch          AuthorityEpoch
	installationID InstallationID
	principalID    PrincipalID
	deviceID       DeviceID
	policy         PolicyRevision
	assurance      AssuranceClass
	evaluatedAt    time.Time
	challengeID    CeremonyID
	transcript     CommandFingerprint
	credential     DeviceCredentialBinding
}

func NewPairingRedemptionAuthorization(
	authorityID AuthorityID,
	epoch AuthorityEpoch,
	installationID InstallationID,
	principalID PrincipalID,
	deviceID DeviceID,
	policy PolicyRevision,
	assurance AssuranceClass,
	evaluatedAt time.Time,
	challengeID CeremonyID,
	transcript CommandFingerprint,
	credential DeviceCredentialBinding,
) (PairingRedemptionAuthorization, error) {
	if authorityID.IsZero() || epoch.IsZero() || installationID.IsZero() || principalID.IsZero() ||
		deviceID.IsZero() || !validPolicyRevisionValue(policy) || !validAssuranceClassValue(assurance) || evaluatedAt.IsZero() ||
		challengeID.IsZero() || transcript.IsZero() || !validDeviceCredentialBinding(credential) ||
		credential.TranscriptFingerprint() != transcript {
		return PairingRedemptionAuthorization{}, ErrInvalidAuthorization
	}
	return PairingRedemptionAuthorization{
		authorityID: authorityID, epoch: epoch, installationID: installationID,
		principalID: principalID, deviceID: deviceID, policy: policy, assurance: assurance,
		evaluatedAt: evaluatedAt.UTC(), challengeID: challengeID, transcript: transcript,
		credential: credential,
	}, nil
}

func (authorization PairingRedemptionAuthorization) AuthorityID() AuthorityID {
	return authorization.authorityID
}
func (authorization PairingRedemptionAuthorization) AuthorityEpoch() AuthorityEpoch {
	return authorization.epoch
}
func (authorization PairingRedemptionAuthorization) InstallationID() InstallationID {
	return authorization.installationID
}
func (authorization PairingRedemptionAuthorization) PrincipalID() PrincipalID {
	return authorization.principalID
}
func (authorization PairingRedemptionAuthorization) DeviceID() DeviceID {
	return authorization.deviceID
}
func (authorization PairingRedemptionAuthorization) PolicyRevision() PolicyRevision {
	return authorization.policy
}
func (authorization PairingRedemptionAuthorization) AssuranceClass() AssuranceClass {
	return authorization.assurance
}
func (authorization PairingRedemptionAuthorization) EvaluatedAt() time.Time {
	return authorization.evaluatedAt
}
func (authorization PairingRedemptionAuthorization) ChallengeID() CeremonyID {
	return authorization.challengeID
}
func (authorization PairingRedemptionAuthorization) TranscriptFingerprint() CommandFingerprint {
	return authorization.transcript
}
func (authorization PairingRedemptionAuthorization) Credential() DeviceCredentialBinding {
	return authorization.credential
}

func validPairingRedemptionAuthorization(value PairingRedemptionAuthorization) bool {
	validated, err := NewPairingRedemptionAuthorization(
		value.AuthorityID(), value.AuthorityEpoch(), value.InstallationID(), value.PrincipalID(), value.DeviceID(),
		value.PolicyRevision(), value.AssuranceClass(), value.EvaluatedAt(), value.ChallengeID(),
		value.TranscriptFingerprint(), value.Credential(),
	)
	return err == nil && validated == value
}

type IdentityAuthorization struct {
	authorityID            AuthorityID
	epoch                  AuthorityEpoch
	installationID         InstallationID
	workspaceID            WorkspaceID
	principalID            PrincipalID
	capabilities           CapabilitySet
	policy                 PolicyRevision
	assurance              AssuranceClass
	evaluatedAt            time.Time
	maxSessionLifetime     time.Duration
	authenticatedDevice    DeviceID
	deviceTrustRevision    Version
	hasAuthenticatedDevice bool
}

func NewIdentityAuthorization(
	authorityID AuthorityID,
	epoch AuthorityEpoch,
	installationID InstallationID,
	principalID PrincipalID,
	capabilities CapabilitySet,
	policy PolicyRevision,
	assurance AssuranceClass,
	evaluatedAt time.Time,
	maxSessionLifetime time.Duration,
) (IdentityAuthorization, error) {
	return newIdentityAuthorization(
		authorityID, epoch, installationID, WorkspaceID{}, principalID, capabilities,
		policy, assurance, evaluatedAt, maxSessionLifetime, DeviceID{}, Version{}, false,
	)
}

func NewWorkspaceIdentityAuthorization(
	authorityID AuthorityID,
	epoch AuthorityEpoch,
	installationID InstallationID,
	workspaceID WorkspaceID,
	principalID PrincipalID,
	capabilities CapabilitySet,
	policy PolicyRevision,
	assurance AssuranceClass,
	evaluatedAt time.Time,
	maxSessionLifetime time.Duration,
) (IdentityAuthorization, error) {
	return newIdentityAuthorization(
		authorityID, epoch, installationID, workspaceID, principalID, capabilities,
		policy, assurance, evaluatedAt, maxSessionLifetime, DeviceID{}, Version{}, false,
	)
}

func NewDeviceBoundWorkspaceIdentityAuthorization(
	authorityID AuthorityID,
	epoch AuthorityEpoch,
	installationID InstallationID,
	workspaceID WorkspaceID,
	principalID PrincipalID,
	capabilities CapabilitySet,
	policy PolicyRevision,
	assurance AssuranceClass,
	evaluatedAt time.Time,
	maxSessionLifetime time.Duration,
	authenticatedDevice DeviceID,
	deviceTrustRevision Version,
) (IdentityAuthorization, error) {
	return newIdentityAuthorization(
		authorityID, epoch, installationID, workspaceID, principalID, capabilities,
		policy, assurance, evaluatedAt, maxSessionLifetime,
		authenticatedDevice, deviceTrustRevision, true,
	)
}

func newIdentityAuthorization(
	authorityID AuthorityID,
	epoch AuthorityEpoch,
	installationID InstallationID,
	workspaceID WorkspaceID,
	principalID PrincipalID,
	capabilities CapabilitySet,
	policy PolicyRevision,
	assurance AssuranceClass,
	evaluatedAt time.Time,
	maxSessionLifetime time.Duration,
	authenticatedDevice DeviceID,
	deviceTrustRevision Version,
	hasAuthenticatedDevice bool,
) (IdentityAuthorization, error) {
	if authorityID.IsZero() || epoch.IsZero() || installationID.IsZero() || principalID.IsZero() ||
		capabilities.IsZero() || policy.String() == "" || assurance.String() == "" || evaluatedAt.IsZero() ||
		maxSessionLifetime <= 0 || maxSessionLifetime > MaxActorSessionLifetime ||
		(hasAuthenticatedDevice && (workspaceID.IsZero() || authenticatedDevice.IsZero() || !deviceTrustRevision.Valid())) ||
		(!hasAuthenticatedDevice && (!authenticatedDevice.IsZero() || !deviceTrustRevision.IsZero())) {
		return IdentityAuthorization{}, ErrInvalidAuthorization
	}
	return IdentityAuthorization{
		authorityID:            authorityID,
		epoch:                  epoch,
		installationID:         installationID,
		workspaceID:            workspaceID,
		principalID:            principalID,
		capabilities:           capabilities,
		policy:                 policy,
		assurance:              assurance,
		evaluatedAt:            evaluatedAt.UTC(),
		maxSessionLifetime:     maxSessionLifetime,
		authenticatedDevice:    authenticatedDevice,
		deviceTrustRevision:    deviceTrustRevision,
		hasAuthenticatedDevice: hasAuthenticatedDevice,
	}, nil
}

func (authorization IdentityAuthorization) AuthorityID() AuthorityID {
	return authorization.authorityID
}
func (authorization IdentityAuthorization) AuthorityEpoch() AuthorityEpoch {
	return authorization.epoch
}
func (authorization IdentityAuthorization) InstallationID() InstallationID {
	return authorization.installationID
}
func (authorization IdentityAuthorization) WorkspaceID() WorkspaceID {
	return authorization.workspaceID
}
func (authorization IdentityAuthorization) PrincipalID() PrincipalID {
	return authorization.principalID
}
func (authorization IdentityAuthorization) Capabilities() CapabilitySet {
	capabilities, _ := NewCapabilitySet(authorization.capabilities.Values()...)
	return capabilities
}
func (authorization IdentityAuthorization) PolicyRevision() PolicyRevision {
	return authorization.policy
}
func (authorization IdentityAuthorization) AssuranceClass() AssuranceClass {
	return authorization.assurance
}
func (authorization IdentityAuthorization) EvaluatedAt() time.Time { return authorization.evaluatedAt }
func (authorization IdentityAuthorization) MaxSessionLifetime() time.Duration {
	return authorization.maxSessionLifetime
}
func (authorization IdentityAuthorization) AuthenticatedDevice() (DeviceID, Version, bool) {
	return authorization.authenticatedDevice, authorization.deviceTrustRevision, authorization.hasAuthenticatedDevice
}

type PrincipalKind string

const (
	PrincipalKindHuman    PrincipalKind = "human"
	PrincipalKindWorkload PrincipalKind = "workload"
	PrincipalKindService  PrincipalKind = "service"
)

func (kind PrincipalKind) Valid() bool {
	return kind == PrincipalKindHuman || kind == PrincipalKindWorkload || kind == PrincipalKindService
}

type PrincipalStatus string

const (
	PrincipalActive    PrincipalStatus = "active"
	PrincipalSuspended PrincipalStatus = "suspended"
	PrincipalDisabled  PrincipalStatus = "disabled"
)

func (status PrincipalStatus) Valid() bool {
	return status == PrincipalActive || status == PrincipalSuspended || status == PrincipalDisabled
}

type PrincipalState struct {
	id             PrincipalID
	installationID InstallationID
	kind           PrincipalKind
	displayName    DisplayName
	publicKey      PublicKeyReference
	status         PrincipalStatus
	version        Version
}

func (state PrincipalState) IsZero() bool                           { return state.id.IsZero() }
func (state PrincipalState) ID() PrincipalID                        { return state.id }
func (state PrincipalState) InstallationID() InstallationID         { return state.installationID }
func (state PrincipalState) Kind() PrincipalKind                    { return state.kind }
func (state PrincipalState) DisplayName() DisplayName               { return state.displayName }
func (state PrincipalState) PublicKeyReference() PublicKeyReference { return state.publicKey }
func (state PrincipalState) Status() PrincipalStatus                { return state.status }
func (state PrincipalState) Version() Version                       { return state.version }

type DeviceStatus string

const (
	DevicePending   DeviceStatus = "pending"
	DeviceTrusted   DeviceStatus = "trusted"
	DeviceSuspended DeviceStatus = "suspended"
	DeviceRevoked   DeviceStatus = "revoked"
)

func (status DeviceStatus) Valid() bool {
	return status == DevicePending || status == DeviceTrusted || status == DeviceSuspended || status == DeviceRevoked
}

type DeviceState struct {
	id                          DeviceID
	installationID              InstallationID
	principalID                 PrincipalID
	displayName                 DisplayName
	publicKey                   PublicKeyReference
	status                      DeviceStatus
	version                     Version
	trustRevision               Version
	revocationRevision          Version
	pairing                     CeremonyChallenge
	credential                  DeviceCredentialBinding
	credentialActivatedAt       time.Time
	retiringCredential          DeviceCredentialBinding
	retiringCredentialExpiresAt time.Time
	lastRotationTranscript      CommandFingerprint
	rotatedAt                   time.Time
	revokedAt                   time.Time
}

func (state DeviceState) IsZero() bool                               { return state.id.IsZero() }
func (state DeviceState) ID() DeviceID                               { return state.id }
func (state DeviceState) InstallationID() InstallationID             { return state.installationID }
func (state DeviceState) PrincipalID() PrincipalID                   { return state.principalID }
func (state DeviceState) DisplayName() DisplayName                   { return state.displayName }
func (state DeviceState) PublicKeyReference() PublicKeyReference     { return state.publicKey }
func (state DeviceState) Status() DeviceStatus                       { return state.status }
func (state DeviceState) Version() Version                           { return state.version }
func (state DeviceState) TrustRevision() Version                     { return state.trustRevision }
func (state DeviceState) RevocationRevision() Version                { return state.revocationRevision }
func (state DeviceState) PairingChallenge() CeremonyChallenge        { return state.pairing }
func (state DeviceState) CredentialBinding() DeviceCredentialBinding { return state.credential }
func (state DeviceState) ActiveCredential() DeviceCredentialBinding  { return state.credential }
func (state DeviceState) CredentialActivatedAt() time.Time           { return state.credentialActivatedAt }
func (state DeviceState) RotationTranscriptFingerprint() CommandFingerprint {
	return state.lastRotationTranscript
}
func (state DeviceState) RotatedAt() time.Time { return state.rotatedAt }
func (state DeviceState) RevokedAt() time.Time { return state.revokedAt }
func (state DeviceState) RetiringCredential() (DeviceCredentialBinding, time.Time, bool) {
	return state.retiringCredential, state.retiringCredentialExpiresAt, !state.retiringCredential.IsZero()
}

func (state DeviceState) AcceptsCredential(fingerprint CredentialDigest, evaluatedAt time.Time) bool {
	if state.status != DeviceTrusted || fingerprint.IsZero() || evaluatedAt.IsZero() {
		return false
	}
	if state.credential.SPKIFingerprint() == fingerprint {
		return true
	}
	return !state.retiringCredential.IsZero() &&
		state.retiringCredential.SPKIFingerprint() == fingerprint &&
		evaluatedAt.Before(state.retiringCredentialExpiresAt)
}

type GrantStatus string

const (
	GrantActive  GrantStatus = "active"
	GrantRevoked GrantStatus = "revoked"
)

func (status GrantStatus) Valid() bool { return status == GrantActive || status == GrantRevoked }

type GrantState struct {
	id             GrantID
	installationID InstallationID
	workspaceID    WorkspaceID
	principalID    PrincipalID
	status         GrantStatus
	version        Version
	capabilities   CapabilitySet
}

func (state GrantState) IsZero() bool                   { return state.id.IsZero() }
func (state GrantState) ID() GrantID                    { return state.id }
func (state GrantState) InstallationID() InstallationID { return state.installationID }
func (state GrantState) WorkspaceID() WorkspaceID       { return state.workspaceID }
func (state GrantState) PrincipalID() PrincipalID       { return state.principalID }
func (state GrantState) Status() GrantStatus            { return state.status }
func (state GrantState) Version() Version               { return state.version }
func (state GrantState) Capabilities() CapabilitySet    { return cloneCapabilitySet(state.capabilities) }

type WorkspaceStatus string

const (
	WorkspaceActive    WorkspaceStatus = "active"
	WorkspaceSuspended WorkspaceStatus = "suspended"
	WorkspaceArchived  WorkspaceStatus = "archived"
)

func (status WorkspaceStatus) Valid() bool {
	return status == WorkspaceActive || status == WorkspaceSuspended || status == WorkspaceArchived
}

type WorkspaceState struct {
	id             WorkspaceID
	installationID InstallationID
	authorityID    AuthorityID
	epoch          AuthorityEpoch
	alias          WorkspaceAlias
	discovery      DiscoveryLocator
	policy         PolicyRevision
	status         WorkspaceStatus
	version        Version
}

func (state WorkspaceState) IsZero() bool                       { return state.id.IsZero() }
func (state WorkspaceState) ID() WorkspaceID                    { return state.id }
func (state WorkspaceState) InstallationID() InstallationID     { return state.installationID }
func (state WorkspaceState) AuthorityID() AuthorityID           { return state.authorityID }
func (state WorkspaceState) AuthorityEpoch() AuthorityEpoch     { return state.epoch }
func (state WorkspaceState) Alias() WorkspaceAlias              { return state.alias }
func (state WorkspaceState) DiscoveryLocator() DiscoveryLocator { return state.discovery }
func (state WorkspaceState) PolicyRevision() PolicyRevision     { return state.policy }
func (state WorkspaceState) Status() WorkspaceStatus            { return state.status }
func (state WorkspaceState) Version() Version                   { return state.version }

type MembershipStatus string

const (
	MembershipInvited   MembershipStatus = "invited"
	MembershipActive    MembershipStatus = "active"
	MembershipSuspended MembershipStatus = "suspended"
	MembershipRevoked   MembershipStatus = "revoked"
)

func (status MembershipStatus) Valid() bool {
	return status == MembershipInvited || status == MembershipActive ||
		status == MembershipSuspended || status == MembershipRevoked
}

type MembershipState struct {
	id           MembershipID
	workspaceID  WorkspaceID
	principalID  PrincipalID
	status       MembershipStatus
	version      Version
	capabilities CapabilitySet
	acceptance   CeremonyChallenge
}

func (state MembershipState) IsZero() bool             { return state.id.IsZero() }
func (state MembershipState) ID() MembershipID         { return state.id }
func (state MembershipState) WorkspaceID() WorkspaceID { return state.workspaceID }
func (state MembershipState) PrincipalID() PrincipalID { return state.principalID }
func (state MembershipState) Status() MembershipStatus { return state.status }
func (state MembershipState) Version() Version         { return state.version }
func (state MembershipState) Capabilities() CapabilitySet {
	return cloneCapabilitySet(state.capabilities)
}
func (state MembershipState) AcceptanceChallenge() CeremonyChallenge { return state.acceptance }

type ActorKind string

const (
	ActorKindHuman      ActorKind = "human"
	ActorKindAgent      ActorKind = "agent"
	ActorKindAutomation ActorKind = "automation"
	ActorKindService    ActorKind = "service"
)

func (kind ActorKind) Valid() bool {
	return kind == ActorKindHuman || kind == ActorKindAgent || kind == ActorKindAutomation || kind == ActorKindService
}

type ActorStatus string

const (
	ActorActive    ActorStatus = "active"
	ActorSuspended ActorStatus = "suspended"
	ActorRetired   ActorStatus = "retired"
)

func (status ActorStatus) Valid() bool {
	return status == ActorActive || status == ActorSuspended || status == ActorRetired
}

type ActorState struct {
	id          ActorID
	workspaceID WorkspaceID
	kind        ActorKind
	profile     ActorProfile
	status      ActorStatus
	version     Version
}

func (state ActorState) IsZero() bool             { return state.id.IsZero() }
func (state ActorState) ID() ActorID              { return state.id }
func (state ActorState) WorkspaceID() WorkspaceID { return state.workspaceID }
func (state ActorState) Kind() ActorKind          { return state.kind }
func (state ActorState) Profile() ActorProfile    { return state.profile }
func (state ActorState) Status() ActorStatus      { return state.status }
func (state ActorState) Version() Version         { return state.version }

type DelegationStatus string

const (
	DelegationProposed  DelegationStatus = "proposed"
	DelegationActive    DelegationStatus = "active"
	DelegationSuspended DelegationStatus = "suspended"
	DelegationRevoked   DelegationStatus = "revoked"
)

func (status DelegationStatus) Valid() bool {
	return status == DelegationProposed || status == DelegationActive ||
		status == DelegationSuspended || status == DelegationRevoked
}

type ActorDelegationState struct {
	id           ActorDelegationID
	workspaceID  WorkspaceID
	principalID  PrincipalID
	actorID      ActorID
	membershipID MembershipID
	status       DelegationStatus
	version      Version
	capabilities CapabilitySet
	activation   CeremonyChallenge
}

func (state ActorDelegationState) IsZero() bool               { return state.id.IsZero() }
func (state ActorDelegationState) ID() ActorDelegationID      { return state.id }
func (state ActorDelegationState) WorkspaceID() WorkspaceID   { return state.workspaceID }
func (state ActorDelegationState) PrincipalID() PrincipalID   { return state.principalID }
func (state ActorDelegationState) ActorID() ActorID           { return state.actorID }
func (state ActorDelegationState) MembershipID() MembershipID { return state.membershipID }
func (state ActorDelegationState) Status() DelegationStatus   { return state.status }
func (state ActorDelegationState) Version() Version           { return state.version }
func (state ActorDelegationState) Capabilities() CapabilitySet {
	return cloneCapabilitySet(state.capabilities)
}
func (state ActorDelegationState) ActivationChallenge() CeremonyChallenge { return state.activation }

type ActorSessionStatus string

const (
	ActorSessionActive  ActorSessionStatus = "active"
	ActorSessionEnded   ActorSessionStatus = "ended"
	ActorSessionRevoked ActorSessionStatus = "revoked"
	ActorSessionExpired ActorSessionStatus = "expired"
)

func (status ActorSessionStatus) Valid() bool {
	return status == ActorSessionActive || status == ActorSessionEnded ||
		status == ActorSessionRevoked || status == ActorSessionExpired
}

type ActorSessionState struct {
	id             ActorSessionID
	clientInstance ClientInstanceID
	clientMetadata ClientMetadata
	status         ActorSessionStatus
	version        Version
	binding        SessionBinding
	capabilities   CapabilitySet
	presentation   PresentationCredentialBinding
}

func (state ActorSessionState) IsZero() bool                       { return state.id.IsZero() }
func (state ActorSessionState) ID() ActorSessionID                 { return state.id }
func (state ActorSessionState) ClientInstanceID() ClientInstanceID { return state.clientInstance }
func (state ActorSessionState) ClientMetadata() ClientMetadata     { return state.clientMetadata }
func (state ActorSessionState) Status() ActorSessionStatus         { return state.status }
func (state ActorSessionState) Version() Version                   { return state.version }
func (state ActorSessionState) Binding() SessionBinding            { return state.binding }
func (state ActorSessionState) Capabilities() CapabilitySet {
	return cloneCapabilitySet(state.capabilities)
}
func (state ActorSessionState) PresentationCredential() PresentationCredentialBinding {
	return state.presentation
}

// The rehydration parameter types below are deliberately separate from
// transition inputs. They describe only durable state and force every adapter
// to pass back through the same invariant checks after decoding storage.

type PrincipalRehydrationParams struct {
	ID                 PrincipalID
	InstallationID     InstallationID
	Kind               PrincipalKind
	DisplayName        DisplayName
	PublicKeyReference PublicKeyReference
	Status             PrincipalStatus
	Version            Version
}

func RehydratePrincipal(params PrincipalRehydrationParams) (PrincipalState, error) {
	if params.ID.IsZero() || params.InstallationID.IsZero() || !params.Kind.Valid() ||
		!params.Status.Valid() || !params.Version.Valid() || !validDisplayNameValue(params.DisplayName) ||
		(!params.PublicKeyReference.valueIsZero() && !validPublicKeyReferenceValue(params.PublicKeyReference)) ||
		(params.Kind != PrincipalKindHuman && params.PublicKeyReference.valueIsZero()) ||
		(params.Status != PrincipalActive && !versionRecordsMutation(params.Version)) {
		return PrincipalState{}, ErrInvalidIdentityState
	}
	return PrincipalState{
		id: params.ID, installationID: params.InstallationID, kind: params.Kind,
		displayName: params.DisplayName, publicKey: params.PublicKeyReference,
		status: params.Status, version: params.Version,
	}, nil
}

type DeviceRehydrationParams struct {
	ID                            DeviceID
	InstallationID                InstallationID
	PrincipalID                   PrincipalID
	DisplayName                   DisplayName
	PublicKeyReference            PublicKeyReference
	Status                        DeviceStatus
	Version                       Version
	TrustRevision                 Version
	RevocationRevision            Version
	PairingChallenge              CeremonyChallenge
	CredentialBinding             DeviceCredentialBinding
	CredentialActivatedAt         time.Time
	RetiringCredential            DeviceCredentialBinding
	RetiringCredentialExpiresAt   time.Time
	RotationTranscriptFingerprint CommandFingerprint
	RotatedAt                     time.Time
	RevokedAt                     time.Time
}

func RehydrateDevice(params DeviceRehydrationParams) (DeviceState, error) {
	if params.ID.IsZero() || params.InstallationID.IsZero() || params.PrincipalID.IsZero() ||
		!validDisplayNameValue(params.DisplayName) || !validPublicKeyReferenceValue(params.PublicKeyReference) ||
		!params.Status.Valid() || !params.Version.Valid() || !params.TrustRevision.Valid() || !params.RevocationRevision.Valid() ||
		params.TrustRevision.Uint64() > params.Version.Uint64() ||
		params.RevocationRevision.Uint64() > params.Version.Uint64() {
		return DeviceState{}, ErrInvalidIdentityState
	}
	hasPairing := !params.PairingChallenge.IsZero()
	hasCredential := !params.CredentialBinding.IsZero()
	hasRetiringCredential := !params.RetiringCredential.IsZero()
	if hasCredential && !validDeviceCredentialBinding(params.CredentialBinding) {
		return DeviceState{}, ErrInvalidIdentityState
	}
	if hasRetiringCredential {
		if params.Status != DeviceTrusted || !hasCredential ||
			!validDeviceCredentialBinding(params.RetiringCredential) ||
			params.RetiringCredential.SPKIFingerprint() == params.CredentialBinding.SPKIFingerprint() ||
			params.RetiringCredentialExpiresAt.IsZero() || params.RotatedAt.IsZero() ||
			params.CredentialActivatedAt.IsZero() || params.RotationTranscriptFingerprint.IsZero() ||
			params.CredentialBinding.TranscriptFingerprint() != params.RotationTranscriptFingerprint ||
			!params.RetiringCredentialExpiresAt.After(params.RotatedAt) ||
			params.RetiringCredentialExpiresAt.After(params.RotatedAt.Add(MaxDeviceCredentialOverlap)) ||
			!params.CredentialActivatedAt.Equal(params.RotatedAt) {
			return DeviceState{}, ErrInvalidIdentityState
		}
	} else if !params.RetiringCredentialExpiresAt.IsZero() {
		return DeviceState{}, ErrInvalidIdentityState
	}
	if params.Status == DeviceRevoked {
		if params.RevokedAt.IsZero() || hasRetiringCredential || params.RevocationRevision.Uint64() <= InitialVersion().Uint64() {
			return DeviceState{}, ErrInvalidIdentityState
		}
	} else if !params.RevokedAt.IsZero() {
		return DeviceState{}, ErrInvalidIdentityState
	}
	if (params.Status == DeviceSuspended || params.Status == DeviceRevoked) && !versionRecordsMutation(params.Version) {
		return DeviceState{}, ErrInvalidIdentityState
	}
	if params.Status == DevicePending {
		if !hasPairing || params.PairingChallenge.Status() != CeremonyPending || hasCredential ||
			!params.CredentialActivatedAt.IsZero() {
			return DeviceState{}, ErrInvalidIdentityState
		}
	} else {
		if !hasCredential || params.CredentialActivatedAt.IsZero() ||
			params.CredentialBinding.PublicKeyReference() != params.PublicKeyReference {
			return DeviceState{}, ErrInvalidIdentityState
		}
	}
	if params.Status != DevicePending && hasPairing {
		if params.PairingChallenge.Status() != CeremonyConsumed || !versionRecordsMutation(params.Version) ||
			!versionRecordsMutation(params.TrustRevision) {
			return DeviceState{}, ErrInvalidIdentityState
		}
	}
	if hasPairing && (!validCeremonyChallenge(params.PairingChallenge) ||
		params.PairingChallenge.Purpose() != CeremonyPurposeDevicePairing ||
		params.PairingChallenge.InstallationID() != params.InstallationID ||
		params.PairingChallenge.PrincipalID() != params.PrincipalID ||
		params.PairingChallenge.DeviceID() != params.ID ||
		(hasCredential && params.CredentialBinding.TranscriptFingerprint() != params.PairingChallenge.ProofDigest())) {
		return DeviceState{}, ErrInvalidIdentityState
	}
	return DeviceState{
		id: params.ID, installationID: params.InstallationID, principalID: params.PrincipalID,
		displayName: params.DisplayName, publicKey: params.PublicKeyReference, status: params.Status,
		version: params.Version, trustRevision: params.TrustRevision, revocationRevision: params.RevocationRevision,
		pairing: params.PairingChallenge, credential: params.CredentialBinding,
		credentialActivatedAt: params.CredentialActivatedAt.UTC(), retiringCredential: params.RetiringCredential,
		retiringCredentialExpiresAt: params.RetiringCredentialExpiresAt.UTC(),
		lastRotationTranscript:      params.RotationTranscriptFingerprint, rotatedAt: params.RotatedAt.UTC(),
		revokedAt: params.RevokedAt.UTC(),
	}, nil
}

type GrantRehydrationParams struct {
	ID             GrantID
	InstallationID InstallationID
	WorkspaceID    WorkspaceID
	PrincipalID    PrincipalID
	Status         GrantStatus
	Version        Version
	Capabilities   CapabilitySet
}

func RehydrateGrant(params GrantRehydrationParams) (GrantState, error) {
	capabilities, valid := validatedCapabilitySet(params.Capabilities)
	if params.ID.IsZero() || params.InstallationID.IsZero() || params.PrincipalID.IsZero() ||
		!params.Status.Valid() || !params.Version.Valid() || !valid ||
		(params.Status == GrantRevoked && !versionRecordsMutation(params.Version)) {
		return GrantState{}, ErrInvalidIdentityState
	}
	return GrantState{
		id: params.ID, installationID: params.InstallationID, workspaceID: params.WorkspaceID,
		principalID: params.PrincipalID, status: params.Status, version: params.Version,
		capabilities: capabilities,
	}, nil
}

type WorkspaceRehydrationParams struct {
	ID               WorkspaceID
	InstallationID   InstallationID
	AuthorityID      AuthorityID
	AuthorityEpoch   AuthorityEpoch
	Alias            WorkspaceAlias
	DiscoveryLocator DiscoveryLocator
	PolicyRevision   PolicyRevision
	Status           WorkspaceStatus
	Version          Version
}

func RehydrateWorkspace(params WorkspaceRehydrationParams) (WorkspaceState, error) {
	if params.ID.IsZero() || params.InstallationID.IsZero() || params.AuthorityID.IsZero() ||
		params.AuthorityEpoch.IsZero() || !validWorkspaceAliasValue(params.Alias) ||
		(!params.DiscoveryLocator.valueIsZero() && !validDiscoveryLocatorValue(params.DiscoveryLocator)) ||
		!validPolicyRevisionValue(params.PolicyRevision) || !params.Status.Valid() || !params.Version.Valid() ||
		(params.Status != WorkspaceActive && !versionRecordsMutation(params.Version)) {
		return WorkspaceState{}, ErrInvalidIdentityState
	}
	return WorkspaceState{
		id: params.ID, installationID: params.InstallationID, authorityID: params.AuthorityID,
		epoch: params.AuthorityEpoch, alias: params.Alias, discovery: params.DiscoveryLocator,
		policy: params.PolicyRevision, status: params.Status, version: params.Version,
	}, nil
}

type MembershipRehydrationParams struct {
	ID                  MembershipID
	WorkspaceID         WorkspaceID
	PrincipalID         PrincipalID
	Status              MembershipStatus
	Version             Version
	Capabilities        CapabilitySet
	AcceptanceChallenge CeremonyChallenge
}

func RehydrateMembership(params MembershipRehydrationParams) (MembershipState, error) {
	capabilities, valid := validatedCapabilitySet(params.Capabilities)
	if params.ID.IsZero() || params.WorkspaceID.IsZero() || params.PrincipalID.IsZero() ||
		!params.Status.Valid() || !params.Version.Valid() || !valid {
		return MembershipState{}, ErrInvalidIdentityState
	}
	hasAcceptance := !params.AcceptanceChallenge.IsZero()
	if (params.Status == MembershipSuspended || params.Status == MembershipRevoked) &&
		!versionRecordsMutation(params.Version) {
		return MembershipState{}, ErrInvalidIdentityState
	}
	if params.Status == MembershipInvited {
		if !hasAcceptance || params.AcceptanceChallenge.Status() != CeremonyPending {
			return MembershipState{}, ErrInvalidIdentityState
		}
	} else if hasAcceptance {
		if params.AcceptanceChallenge.Status() != CeremonyConsumed || !versionRecordsMutation(params.Version) {
			return MembershipState{}, ErrInvalidIdentityState
		}
	}
	if hasAcceptance && (!validCeremonyChallenge(params.AcceptanceChallenge) ||
		params.AcceptanceChallenge.Purpose() != CeremonyPurposeMembershipAcceptance ||
		params.AcceptanceChallenge.WorkspaceID() != params.WorkspaceID ||
		params.AcceptanceChallenge.MembershipID() != params.ID ||
		params.AcceptanceChallenge.PrincipalID() != params.PrincipalID) {
		return MembershipState{}, ErrInvalidIdentityState
	}
	return MembershipState{
		id: params.ID, workspaceID: params.WorkspaceID, principalID: params.PrincipalID,
		status: params.Status, version: params.Version, capabilities: capabilities,
		acceptance: params.AcceptanceChallenge,
	}, nil
}

type ActorRehydrationParams struct {
	ID          ActorID
	WorkspaceID WorkspaceID
	Kind        ActorKind
	Profile     ActorProfile
	Status      ActorStatus
	Version     Version
}

func RehydrateActor(params ActorRehydrationParams) (ActorState, error) {
	if params.ID.IsZero() || params.WorkspaceID.IsZero() || !params.Kind.Valid() ||
		!validActorProfileValue(params.Profile) || !params.Status.Valid() || !params.Version.Valid() ||
		(params.Status != ActorActive && !versionRecordsMutation(params.Version)) {
		return ActorState{}, ErrInvalidIdentityState
	}
	return ActorState{
		id: params.ID, workspaceID: params.WorkspaceID, kind: params.Kind,
		profile: params.Profile, status: params.Status, version: params.Version,
	}, nil
}

type ActorDelegationRehydrationParams struct {
	ID                  ActorDelegationID
	WorkspaceID         WorkspaceID
	PrincipalID         PrincipalID
	ActorID             ActorID
	MembershipID        MembershipID
	Status              DelegationStatus
	Version             Version
	Capabilities        CapabilitySet
	ActivationChallenge CeremonyChallenge
}

func RehydrateActorDelegation(
	params ActorDelegationRehydrationParams,
) (ActorDelegationState, error) {
	capabilities, valid := validatedCapabilitySet(params.Capabilities)
	if params.ID.IsZero() || params.WorkspaceID.IsZero() || params.PrincipalID.IsZero() ||
		params.ActorID.IsZero() || params.MembershipID.IsZero() || !params.Status.Valid() ||
		!params.Version.Valid() || !valid || params.ActivationChallenge.IsZero() ||
		!validCeremonyChallenge(params.ActivationChallenge) ||
		params.ActivationChallenge.Purpose() != CeremonyPurposeDelegationActivation ||
		params.ActivationChallenge.WorkspaceID() != params.WorkspaceID ||
		params.ActivationChallenge.PrincipalID() != params.PrincipalID ||
		params.ActivationChallenge.ActorID() != params.ActorID ||
		params.ActivationChallenge.DelegationID() != params.ID {
		return ActorDelegationState{}, ErrInvalidIdentityState
	}
	if (params.Status == DelegationProposed) != (params.ActivationChallenge.Status() == CeremonyPending) {
		return ActorDelegationState{}, ErrInvalidIdentityState
	}
	if params.Status != DelegationProposed && !versionRecordsMutation(params.Version) {
		return ActorDelegationState{}, ErrInvalidIdentityState
	}
	return ActorDelegationState{
		id: params.ID, workspaceID: params.WorkspaceID, principalID: params.PrincipalID,
		actorID: params.ActorID, membershipID: params.MembershipID, status: params.Status,
		version: params.Version, capabilities: capabilities, activation: params.ActivationChallenge,
	}, nil
}

type ActorSessionRehydrationParams struct {
	ID                     ActorSessionID
	ClientInstanceID       ClientInstanceID
	ClientMetadata         ClientMetadata
	Status                 ActorSessionStatus
	Version                Version
	Binding                SessionBinding
	Capabilities           CapabilitySet
	PresentationCredential PresentationCredentialBinding
}

func RehydrateActorSession(params ActorSessionRehydrationParams) (ActorSessionState, error) {
	capabilities, capabilitiesValid := validatedCapabilitySet(params.Capabilities)
	binding, bindingValid := validatedSessionBinding(params.Binding)
	if params.ID.IsZero() || params.ClientInstanceID.IsZero() ||
		!validClientMetadataValue(params.ClientMetadata) || !params.Status.Valid() ||
		!params.Version.Valid() || !capabilitiesValid || !bindingValid ||
		!validPresentationCredentialBinding(params.PresentationCredential) ||
		(params.Status != ActorSessionActive && !versionRecordsMutation(params.Version)) {
		return ActorSessionState{}, ErrInvalidIdentityState
	}
	return ActorSessionState{
		id: params.ID, clientInstance: params.ClientInstanceID, clientMetadata: params.ClientMetadata,
		status: params.Status, version: params.Version, binding: binding, capabilities: capabilities,
		presentation: params.PresentationCredential,
	}, nil
}

func validDisplayNameValue(value DisplayName) bool {
	validated, err := NewDisplayName(value.String())
	return err == nil && validated == value
}

func versionRecordsMutation(version Version) bool {
	return version.Valid() && version.Uint64() > InitialVersion().Uint64()
}

func (reference PublicKeyReference) valueIsZero() bool { return reference.String() == "" }

func validPublicKeyReferenceValue(value PublicKeyReference) bool {
	validated, err := NewPublicKeyReference(value.String())
	return err == nil && validated == value
}

func validDeviceCredentialBinding(value DeviceCredentialBinding) bool {
	validated, err := NewDeviceCredentialBinding(
		value.PublicKeyReference(), value.SPKIFingerprint(), value.TranscriptFingerprint(),
	)
	return err == nil && validated == value
}

func validPresentationCredentialBinding(value PresentationCredentialBinding) bool {
	validated, err := NewPresentationCredentialBinding(
		value.Digest(), value.Reference(), value.Audience(), value.Version(),
	)
	return err == nil && validated == value
}

func validWorkspaceAliasValue(value WorkspaceAlias) bool {
	validated, err := NewWorkspaceAlias(value.String())
	return err == nil && validated == value
}

func (locator DiscoveryLocator) valueIsZero() bool { return locator.String() == "" }

func validDiscoveryLocatorValue(value DiscoveryLocator) bool {
	validated, err := NewDiscoveryLocator(value.String())
	return err == nil && validated == value
}

func validPolicyRevisionValue(value PolicyRevision) bool {
	validated, err := NewPolicyRevision(value.String())
	return err == nil && validated == value
}

func validAssuranceClassValue(value AssuranceClass) bool {
	validated, err := NewAssuranceClass(value.String())
	return err == nil && validated == value
}

func validActorProfileValue(value ActorProfile) bool {
	validated, err := NewActorProfile(value.DisplayName())
	return err == nil && validated == value && validDisplayNameValue(value.DisplayName())
}

func validClientMetadataValue(value ClientMetadata) bool {
	validated, err := NewClientMetadata(value.Name(), value.Version())
	return err == nil && validated == value
}

func validatedCapabilitySet(value CapabilitySet) (CapabilitySet, bool) {
	validated, err := NewCapabilitySet(value.Values()...)
	return validated, err == nil && validated.Equal(value)
}

func equalSessionBindings(left SessionBinding, right SessionBinding) bool {
	if left.AuthorityID() != right.AuthorityID() || left.AuthorityEpoch() != right.AuthorityEpoch() ||
		left.WorkspaceID() != right.WorkspaceID() || left.PrincipalID() != right.PrincipalID() ||
		left.ActorID() != right.ActorID() || left.MembershipRevision() != right.MembershipRevision() ||
		left.DelegationRevision() != right.DelegationRevision() || left.PolicyRevision() != right.PolicyRevision() ||
		left.AssuranceClass() != right.AssuranceClass() || !left.IssuedAt().Equal(right.IssuedAt()) ||
		!left.AbsoluteExpiry().Equal(right.AbsoluteExpiry()) {
		return false
	}
	leftDevice, leftHasDevice := left.DeviceRevision()
	rightDevice, rightHasDevice := right.DeviceRevision()
	leftTrust, leftHasTrust := left.DeviceTrustRevision()
	rightTrust, rightHasTrust := right.DeviceTrustRevision()
	if leftHasDevice != rightHasDevice || leftDevice != rightDevice || leftHasTrust != rightHasTrust || leftTrust != rightTrust {
		return false
	}
	leftGrants := left.GrantRevisions()
	rightGrants := right.GrantRevisions()
	if len(leftGrants) != len(rightGrants) {
		return false
	}
	for index := range leftGrants {
		if leftGrants[index] != rightGrants[index] {
			return false
		}
	}
	return true
}

func validCeremonyChallenge(challenge CeremonyChallenge) bool {
	validated, err := RehydrateCeremonyChallenge(CeremonyChallengeRehydrationParams{
		ID: challenge.ID(), Purpose: challenge.Purpose(), ProofDigest: challenge.ProofDigest(),
		ExpiresAt: challenge.ExpiresAt(), Status: challenge.Status(),
		InstallationID: challenge.InstallationID(), WorkspaceID: challenge.WorkspaceID(),
		PrincipalID: challenge.PrincipalID(), MembershipID: challenge.MembershipID(),
		ActorID: challenge.ActorID(), DelegationID: challenge.DelegationID(), DeviceID: challenge.DeviceID(),
	})
	return err == nil && validated == challenge
}

func validatedSessionBinding(value SessionBinding) (SessionBinding, bool) {
	if !validPolicyRevisionValue(value.PolicyRevision()) || !validAssuranceClassValue(value.AssuranceClass()) {
		return SessionBinding{}, false
	}
	device, hasDevice := value.DeviceRevision()
	deviceTrust, hasDeviceTrust := value.DeviceTrustRevision()
	if hasDevice != hasDeviceTrust {
		return SessionBinding{}, false
	}
	var devicePointer *AggregateRef
	if hasDevice {
		deviceCopy := device
		devicePointer = &deviceCopy
	}
	validated, err := NewSessionBinding(
		value.AuthorityID(), value.AuthorityEpoch(), value.WorkspaceID(), value.PrincipalID(), value.ActorID(),
		value.MembershipRevision(), value.DelegationRevision(), devicePointer, deviceTrust,
		value.GrantRevisions(), value.PolicyRevision(), value.AssuranceClass(), value.IssuedAt(), value.AbsoluteExpiry(),
	)
	return validated, err == nil && equalSessionBindings(validated, value)
}

func cloneCapabilitySet(set CapabilitySet) CapabilitySet {
	if set.IsZero() {
		return CapabilitySet{}
	}
	cloned, _ := NewCapabilitySet(set.Values()...)
	return cloned
}
