package domain

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

var ErrInvalidIdentityTransition = errors.New("invalid identity transition")

type IdentityFact interface {
	Type() EventType
	Origin() AggregateRef
	identityFact()
}

type InstallationBootstrappedFact struct {
	origin         AggregateRef
	installationID InstallationID
	invitationID   InvitationID
	principalID    PrincipalID
	deviceID       DeviceID
	grantID        GrantID
	transcript     CommandFingerprint
}

func (InstallationBootstrappedFact) Type() EventType                     { return EventTypeInstallationBootstrapped }
func (InstallationBootstrappedFact) identityFact()                       {}
func (fact InstallationBootstrappedFact) Origin() AggregateRef           { return fact.origin }
func (fact InstallationBootstrappedFact) InstallationID() InstallationID { return fact.installationID }
func (fact InstallationBootstrappedFact) InvitationID() InvitationID     { return fact.invitationID }
func (fact InstallationBootstrappedFact) PrincipalID() PrincipalID       { return fact.principalID }
func (fact InstallationBootstrappedFact) DeviceID() DeviceID             { return fact.deviceID }
func (fact InstallationBootstrappedFact) GrantID() GrantID               { return fact.grantID }
func (fact InstallationBootstrappedFact) TranscriptFingerprint() CommandFingerprint {
	return fact.transcript
}

type PrincipalRegisteredFact struct {
	origin         AggregateRef
	installationID InstallationID
	principalID    PrincipalID
	kind           PrincipalKind
	displayName    DisplayName
	publicKey      PublicKeyReference
}

func (PrincipalRegisteredFact) Type() EventType                             { return EventTypePrincipalRegistered }
func (PrincipalRegisteredFact) identityFact()                               {}
func (fact PrincipalRegisteredFact) Origin() AggregateRef                   { return fact.origin }
func (fact PrincipalRegisteredFact) InstallationID() InstallationID         { return fact.installationID }
func (fact PrincipalRegisteredFact) PrincipalID() PrincipalID               { return fact.principalID }
func (fact PrincipalRegisteredFact) PrincipalKind() PrincipalKind           { return fact.kind }
func (fact PrincipalRegisteredFact) DisplayName() DisplayName               { return fact.displayName }
func (fact PrincipalRegisteredFact) PublicKeyReference() PublicKeyReference { return fact.publicKey }

type DevicePairingBeganFact struct {
	origin         AggregateRef
	installationID InstallationID
	deviceID       DeviceID
	principalID    PrincipalID
	ceremonyID     CeremonyID
	displayName    DisplayName
	publicKey      PublicKeyReference
}

func (DevicePairingBeganFact) Type() EventType                             { return EventTypeDevicePairingBegan }
func (DevicePairingBeganFact) identityFact()                               {}
func (fact DevicePairingBeganFact) Origin() AggregateRef                   { return fact.origin }
func (fact DevicePairingBeganFact) InstallationID() InstallationID         { return fact.installationID }
func (fact DevicePairingBeganFact) DeviceID() DeviceID                     { return fact.deviceID }
func (fact DevicePairingBeganFact) PrincipalID() PrincipalID               { return fact.principalID }
func (fact DevicePairingBeganFact) CeremonyID() CeremonyID                 { return fact.ceremonyID }
func (fact DevicePairingBeganFact) DisplayName() DisplayName               { return fact.displayName }
func (fact DevicePairingBeganFact) PublicKeyReference() PublicKeyReference { return fact.publicKey }

type DevicePairedFact struct {
	origin             AggregateRef
	installationID     InstallationID
	deviceID           DeviceID
	principalID        PrincipalID
	displayName        DisplayName
	transcript         CommandFingerprint
	trustRevision      Version
	revocationRevision Version
	credential         DeviceCredentialBinding
	activatedAt        time.Time
}

func (DevicePairedFact) Type() EventType                                 { return EventTypeDevicePaired }
func (DevicePairedFact) identityFact()                                   {}
func (fact DevicePairedFact) Origin() AggregateRef                       { return fact.origin }
func (fact DevicePairedFact) InstallationID() InstallationID             { return fact.installationID }
func (fact DevicePairedFact) DeviceID() DeviceID                         { return fact.deviceID }
func (fact DevicePairedFact) PrincipalID() PrincipalID                   { return fact.principalID }
func (fact DevicePairedFact) DisplayName() DisplayName                   { return fact.displayName }
func (fact DevicePairedFact) TranscriptFingerprint() CommandFingerprint  { return fact.transcript }
func (fact DevicePairedFact) TrustRevision() Version                     { return fact.trustRevision }
func (fact DevicePairedFact) RevocationRevision() Version                { return fact.revocationRevision }
func (fact DevicePairedFact) CredentialBinding() DeviceCredentialBinding { return fact.credential }
func (fact DevicePairedFact) CredentialActivatedAt() time.Time           { return fact.activatedAt }

type DeviceCredentialRotatedFact struct {
	origin             AggregateRef
	deviceID           DeviceID
	previousCredential DeviceCredentialBinding
	activeCredential   DeviceCredentialBinding
	trustRevision      Version
	revocationRevision Version
	transcript         CommandFingerprint
	rotatedAt          time.Time
	retiringExpiresAt  time.Time
}

func (DeviceCredentialRotatedFact) Type() EventType           { return EventTypeDeviceCredentialRotated }
func (DeviceCredentialRotatedFact) identityFact()             {}
func (fact DeviceCredentialRotatedFact) Origin() AggregateRef { return fact.origin }
func (fact DeviceCredentialRotatedFact) DeviceID() DeviceID   { return fact.deviceID }
func (fact DeviceCredentialRotatedFact) PreviousCredential() DeviceCredentialBinding {
	return fact.previousCredential
}
func (fact DeviceCredentialRotatedFact) ActiveCredential() DeviceCredentialBinding {
	return fact.activeCredential
}
func (fact DeviceCredentialRotatedFact) TrustRevision() Version      { return fact.trustRevision }
func (fact DeviceCredentialRotatedFact) RevocationRevision() Version { return fact.revocationRevision }
func (fact DeviceCredentialRotatedFact) TranscriptFingerprint() CommandFingerprint {
	return fact.transcript
}
func (fact DeviceCredentialRotatedFact) RotatedAt() time.Time { return fact.rotatedAt }
func (fact DeviceCredentialRotatedFact) RetiringCredentialExpiresAt() time.Time {
	return fact.retiringExpiresAt
}

type DeviceRevokedFact struct {
	origin                AggregateRef
	deviceID              DeviceID
	credential            DeviceCredentialBinding
	trustRevision         Version
	revocationRevision    Version
	revocationFingerprint CommandFingerprint
	revokedAt             time.Time
}

func (DeviceRevokedFact) Type() EventType                                 { return EventTypeDeviceRevoked }
func (DeviceRevokedFact) identityFact()                                   {}
func (fact DeviceRevokedFact) Origin() AggregateRef                       { return fact.origin }
func (fact DeviceRevokedFact) DeviceID() DeviceID                         { return fact.deviceID }
func (fact DeviceRevokedFact) CredentialBinding() DeviceCredentialBinding { return fact.credential }
func (fact DeviceRevokedFact) TrustRevision() Version                     { return fact.trustRevision }
func (fact DeviceRevokedFact) RevocationRevision() Version                { return fact.revocationRevision }
func (fact DeviceRevokedFact) RevocationFingerprint() CommandFingerprint {
	return fact.revocationFingerprint
}
func (fact DeviceRevokedFact) RevokedAt() time.Time { return fact.revokedAt }

type WorkspaceCreatedFact struct {
	origin      AggregateRef
	workspaceID WorkspaceID
	authorityID AuthorityID
	epoch       AuthorityEpoch
	alias       WorkspaceAlias
	discovery   DiscoveryLocator
	policy      PolicyRevision
}

func (WorkspaceCreatedFact) Type() EventType                         { return EventTypeWorkspaceCreated }
func (WorkspaceCreatedFact) identityFact()                           {}
func (fact WorkspaceCreatedFact) Origin() AggregateRef               { return fact.origin }
func (fact WorkspaceCreatedFact) WorkspaceID() WorkspaceID           { return fact.workspaceID }
func (fact WorkspaceCreatedFact) AuthorityID() AuthorityID           { return fact.authorityID }
func (fact WorkspaceCreatedFact) AuthorityEpoch() AuthorityEpoch     { return fact.epoch }
func (fact WorkspaceCreatedFact) Alias() WorkspaceAlias              { return fact.alias }
func (fact WorkspaceCreatedFact) DiscoveryLocator() DiscoveryLocator { return fact.discovery }
func (fact WorkspaceCreatedFact) PolicyRevision() PolicyRevision     { return fact.policy }

type WorkspaceMemberInvitedFact struct {
	origin       AggregateRef
	membershipID MembershipID
	workspaceID  WorkspaceID
	principalID  PrincipalID
	ceremonyID   CeremonyID
	capabilities CapabilitySet
}

func (WorkspaceMemberInvitedFact) Type() EventType                 { return EventTypeWorkspaceMemberInvited }
func (WorkspaceMemberInvitedFact) identityFact()                   {}
func (fact WorkspaceMemberInvitedFact) Origin() AggregateRef       { return fact.origin }
func (fact WorkspaceMemberInvitedFact) MembershipID() MembershipID { return fact.membershipID }
func (fact WorkspaceMemberInvitedFact) WorkspaceID() WorkspaceID   { return fact.workspaceID }
func (fact WorkspaceMemberInvitedFact) PrincipalID() PrincipalID   { return fact.principalID }
func (fact WorkspaceMemberInvitedFact) CeremonyID() CeremonyID     { return fact.ceremonyID }
func (fact WorkspaceMemberInvitedFact) Capabilities() CapabilitySet {
	return cloneCapabilitySet(fact.capabilities)
}

type WorkspaceMembershipAcceptedFact struct {
	origin       AggregateRef
	membershipID MembershipID
	workspaceID  WorkspaceID
	principalID  PrincipalID
}

func (WorkspaceMembershipAcceptedFact) Type() EventType                 { return EventTypeWorkspaceMembershipAccepted }
func (WorkspaceMembershipAcceptedFact) identityFact()                   {}
func (fact WorkspaceMembershipAcceptedFact) Origin() AggregateRef       { return fact.origin }
func (fact WorkspaceMembershipAcceptedFact) MembershipID() MembershipID { return fact.membershipID }
func (fact WorkspaceMembershipAcceptedFact) WorkspaceID() WorkspaceID   { return fact.workspaceID }
func (fact WorkspaceMembershipAcceptedFact) PrincipalID() PrincipalID   { return fact.principalID }

type ActorCreatedFact struct {
	origin      AggregateRef
	actorID     ActorID
	workspaceID WorkspaceID
	kind        ActorKind
	profile     ActorProfile
}

func (ActorCreatedFact) Type() EventType               { return EventTypeActorCreated }
func (ActorCreatedFact) identityFact()                 {}
func (fact ActorCreatedFact) Origin() AggregateRef     { return fact.origin }
func (fact ActorCreatedFact) ActorID() ActorID         { return fact.actorID }
func (fact ActorCreatedFact) WorkspaceID() WorkspaceID { return fact.workspaceID }
func (fact ActorCreatedFact) ActorKind() ActorKind     { return fact.kind }
func (fact ActorCreatedFact) Profile() ActorProfile    { return fact.profile }

type ActorDelegationProposedFact struct {
	origin       AggregateRef
	delegationID ActorDelegationID
	workspaceID  WorkspaceID
	principalID  PrincipalID
	actorID      ActorID
	ceremonyID   CeremonyID
}

func (ActorDelegationProposedFact) Type() EventType                      { return EventTypeActorDelegationProposed }
func (ActorDelegationProposedFact) identityFact()                        {}
func (fact ActorDelegationProposedFact) Origin() AggregateRef            { return fact.origin }
func (fact ActorDelegationProposedFact) DelegationID() ActorDelegationID { return fact.delegationID }
func (fact ActorDelegationProposedFact) WorkspaceID() WorkspaceID        { return fact.workspaceID }
func (fact ActorDelegationProposedFact) PrincipalID() PrincipalID        { return fact.principalID }
func (fact ActorDelegationProposedFact) ActorID() ActorID                { return fact.actorID }
func (fact ActorDelegationProposedFact) CeremonyID() CeremonyID          { return fact.ceremonyID }

type ActorDelegationActivatedFact struct {
	origin       AggregateRef
	delegationID ActorDelegationID
	workspaceID  WorkspaceID
	principalID  PrincipalID
	actorID      ActorID
	sessionStart CeremonyID
}

func (ActorDelegationActivatedFact) Type() EventType                      { return EventTypeActorDelegationActivated }
func (ActorDelegationActivatedFact) identityFact()                        {}
func (fact ActorDelegationActivatedFact) Origin() AggregateRef            { return fact.origin }
func (fact ActorDelegationActivatedFact) DelegationID() ActorDelegationID { return fact.delegationID }
func (fact ActorDelegationActivatedFact) WorkspaceID() WorkspaceID        { return fact.workspaceID }
func (fact ActorDelegationActivatedFact) PrincipalID() PrincipalID        { return fact.principalID }
func (fact ActorDelegationActivatedFact) ActorID() ActorID                { return fact.actorID }
func (fact ActorDelegationActivatedFact) SessionStartCeremonyID() CeremonyID {
	return fact.sessionStart
}

type ActorSessionStartedFact struct {
	origin         AggregateRef
	sessionID      ActorSessionID
	workspaceID    WorkspaceID
	clientInstance ClientInstanceID
	clientMetadata ClientMetadata
	binding        SessionBinding
	capabilities   CapabilitySet
	presentation   PresentationCredentialBinding
}

type WorkRefObservedFact struct {
	origin      AggregateRef
	workspaceID WorkspaceID
	observation ProviderObservation
}

func (WorkRefObservedFact) Type() EventType                       { return EventTypeWorkRefObserved }
func (WorkRefObservedFact) identityFact()                         {}
func (fact WorkRefObservedFact) Origin() AggregateRef             { return fact.origin }
func (fact WorkRefObservedFact) WorkspaceID() WorkspaceID         { return fact.workspaceID }
func (fact WorkRefObservedFact) Observation() ProviderObservation { return fact.observation }

type ObjectiveCreatedFact struct {
	origin             AggregateRef
	workspaceID        WorkspaceID
	title              string
	acceptanceCriteria string
}

func (ObjectiveCreatedFact) Type() EventType                 { return EventTypeObjectiveCreated }
func (ObjectiveCreatedFact) identityFact()                   {}
func (fact ObjectiveCreatedFact) Origin() AggregateRef       { return fact.origin }
func (fact ObjectiveCreatedFact) WorkspaceID() WorkspaceID   { return fact.workspaceID }
func (fact ObjectiveCreatedFact) Title() string              { return fact.title }
func (fact ObjectiveCreatedFact) AcceptanceCriteria() string { return fact.acceptanceCriteria }

type WorkUnitCreatedFact struct {
	origin          AggregateRef
	workspaceID     WorkspaceID
	objectiveID     ObjectiveID
	workReferenceID WorkReferenceID
	title           string
}

func (WorkUnitCreatedFact) Type() EventType                       { return EventTypeWorkUnitCreated }
func (WorkUnitCreatedFact) identityFact()                         {}
func (fact WorkUnitCreatedFact) Origin() AggregateRef             { return fact.origin }
func (fact WorkUnitCreatedFact) WorkspaceID() WorkspaceID         { return fact.workspaceID }
func (fact WorkUnitCreatedFact) ObjectiveID() ObjectiveID         { return fact.objectiveID }
func (fact WorkUnitCreatedFact) WorkReferenceID() WorkReferenceID { return fact.workReferenceID }
func (fact WorkUnitCreatedFact) Title() string                    { return fact.title }

type ObjectiveActivatedFact struct {
	origin      AggregateRef
	objectiveID ObjectiveID
}

func (ObjectiveActivatedFact) Type() EventType               { return EventTypeObjectiveActivated }
func (ObjectiveActivatedFact) identityFact()                 {}
func (fact ObjectiveActivatedFact) Origin() AggregateRef     { return fact.origin }
func (fact ObjectiveActivatedFact) ObjectiveID() ObjectiveID { return fact.objectiveID }

type RunPlannedFact struct {
	origin      AggregateRef
	objectiveID ObjectiveID
	workUnitID  WorkUnitID
	operatorID  ActorID
}

func (RunPlannedFact) Type() EventType               { return EventTypeRunPlanned }
func (RunPlannedFact) identityFact()                 {}
func (fact RunPlannedFact) Origin() AggregateRef     { return fact.origin }
func (fact RunPlannedFact) ObjectiveID() ObjectiveID { return fact.objectiveID }
func (fact RunPlannedFact) WorkUnitID() WorkUnitID   { return fact.workUnitID }
func (fact RunPlannedFact) OperatorID() ActorID      { return fact.operatorID }

type RunParticipantInvitedFact struct {
	origin  AggregateRef
	runID   RunID
	actorID ActorID
	role    string
}

func (RunParticipantInvitedFact) Type() EventType           { return EventTypeRunParticipantInvited }
func (RunParticipantInvitedFact) identityFact()             {}
func (fact RunParticipantInvitedFact) Origin() AggregateRef { return fact.origin }
func (fact RunParticipantInvitedFact) RunID() RunID         { return fact.runID }
func (fact RunParticipantInvitedFact) ActorID() ActorID     { return fact.actorID }
func (fact RunParticipantInvitedFact) Role() string         { return fact.role }

type RuntimeBindingRequestedFact struct {
	origin          AggregateRef
	runID           RunID
	participationID RunParticipationID
	sessionID       ActorSessionID
	endpointID      RuntimeEndpointID
}

func (RuntimeBindingRequestedFact) Type() EventType           { return EventTypeRuntimeBindingRequested }
func (RuntimeBindingRequestedFact) identityFact()             {}
func (fact RuntimeBindingRequestedFact) Origin() AggregateRef { return fact.origin }
func (fact RuntimeBindingRequestedFact) RunID() RunID         { return fact.runID }
func (fact RuntimeBindingRequestedFact) ParticipationID() RunParticipationID {
	return fact.participationID
}
func (fact RuntimeBindingRequestedFact) ActorSessionID() ActorSessionID       { return fact.sessionID }
func (fact RuntimeBindingRequestedFact) RuntimeEndpointID() RuntimeEndpointID { return fact.endpointID }

type RunParticipantJoinedFact struct {
	origin    AggregateRef
	runID     RunID
	actorID   ActorID
	sessionID ActorSessionID
}

func (RunParticipantJoinedFact) Type() EventType                     { return EventTypeRunParticipantJoined }
func (RunParticipantJoinedFact) identityFact()                       {}
func (fact RunParticipantJoinedFact) Origin() AggregateRef           { return fact.origin }
func (fact RunParticipantJoinedFact) RunID() RunID                   { return fact.runID }
func (fact RunParticipantJoinedFact) ActorID() ActorID               { return fact.actorID }
func (fact RunParticipantJoinedFact) ActorSessionID() ActorSessionID { return fact.sessionID }

type RunStartedFact struct {
	origin         AggregateRef
	runID          RunID
	participations []AggregateRef
}

func (RunStartedFact) Type() EventType           { return EventTypeRunStarted }
func (RunStartedFact) identityFact()             {}
func (fact RunStartedFact) Origin() AggregateRef { return fact.origin }
func (fact RunStartedFact) RunID() RunID         { return fact.runID }
func (fact RunStartedFact) ParticipationRevisions() []AggregateRef {
	return append([]AggregateRef(nil), fact.participations...)
}

func (ActorSessionStartedFact) Type() EventType                         { return EventTypeActorSessionStarted }
func (ActorSessionStartedFact) identityFact()                           {}
func (fact ActorSessionStartedFact) Origin() AggregateRef               { return fact.origin }
func (fact ActorSessionStartedFact) SessionID() ActorSessionID          { return fact.sessionID }
func (fact ActorSessionStartedFact) WorkspaceID() WorkspaceID           { return fact.workspaceID }
func (fact ActorSessionStartedFact) ClientInstanceID() ClientInstanceID { return fact.clientInstance }
func (fact ActorSessionStartedFact) ClientMetadata() ClientMetadata     { return fact.clientMetadata }
func (fact ActorSessionStartedFact) Binding() SessionBinding            { return fact.binding }
func (fact ActorSessionStartedFact) Capabilities() CapabilitySet {
	return cloneCapabilitySet(fact.capabilities)
}
func (fact ActorSessionStartedFact) PresentationCredential() PresentationCredentialBinding {
	return fact.presentation
}

func cloneIdentityFacts(facts []IdentityFact) []IdentityFact {
	return append([]IdentityFact(nil), facts...)
}

func identityOrigin[ID aggregateIdentifier](id ID, version Version) (AggregateRef, error) {
	ref, err := NewAggregateRef(id, version)
	if err != nil {
		return AggregateRef{}, fmt.Errorf("%w: invalid fact origin: %w", ErrInvalidIdentityTransition, err)
	}
	return ref, nil
}

func nextTransitionVersion(version Version) (Version, error) {
	next, err := version.Next()
	if err != nil {
		return Version{}, fmt.Errorf("%w: %w", ErrInvalidIdentityTransition, err)
	}
	return next, nil
}

func transitionConflict(kind ConflictKind, message string) error {
	commandError, err := NewConflictError(kind.errorCode(), kind, message, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIdentityTransition, err)
	}
	return commandError
}

func transitionError(code ErrorCode, message string) error {
	commandError, err := NewCommandError(code, message, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIdentityTransition, err)
	}
	return commandError
}

func checkExpectedVersion(actual Version, expected Version) error {
	if !actual.Valid() || !expected.Valid() || actual != expected {
		return transitionConflict(ConflictVersion, "aggregate version is stale")
	}
	return nil
}

func checkActivePrincipal(
	authorization IdentityAuthorization,
	principal PrincipalState,
	expected Version,
	required Capability,
) error {
	if principal.IsZero() || authorization.PrincipalID() != principal.ID() {
		return transitionError(ErrorCodeForbidden, "authenticated principal does not match")
	}
	if err := checkExpectedVersion(principal.Version(), expected); err != nil {
		return err
	}
	if principal.Status() != PrincipalActive {
		return transitionError(ErrorCodeForbidden, "principal is not active")
	}
	if principal.InstallationID() != authorization.InstallationID() {
		return transitionConflict(ConflictReference, "principal installation does not match")
	}
	if required.String() != "" && !authorization.capabilities.Contains(required) {
		return transitionError(ErrorCodeForbidden, "required identity capability is absent")
	}
	return nil
}

func checkWorkspaceAuthority(authorization IdentityAuthorization, workspace WorkspaceState, expected Version) error {
	if workspace.IsZero() || workspace.Status() != WorkspaceActive ||
		workspace.InstallationID() != authorization.InstallationID() || authorization.WorkspaceID() != workspace.ID() {
		return transitionConflict(ConflictReference, "workspace is not an active installation workspace")
	}
	if workspace.AuthorityID() != authorization.AuthorityID() ||
		!workspace.AuthorityEpoch().Equal(authorization.AuthorityEpoch()) {
		return transitionConflict(ConflictAuthorityMismatch, "workspace authority does not match")
	}
	if workspace.PolicyRevision() != authorization.PolicyRevision() {
		return transitionConflict(ConflictReference, "workspace policy revision is stale")
	}
	return checkExpectedVersion(workspace.Version(), expected)
}

func checkInstallationAuthorization(authorization IdentityAuthorization) error {
	if !authorization.WorkspaceID().IsZero() {
		return transitionConflict(ConflictReference, "workspace-scoped authorization cannot mutate installation identity")
	}
	return nil
}

func checkCeremony(
	challenge CeremonyChallenge,
	proof CeremonyProof,
	purpose CeremonyPurpose,
	evaluatedAt time.Time,
) error {
	if challenge.IsZero() || proof.ChallengeID() != challenge.ID() || challenge.Purpose() != purpose ||
		proof.Purpose() != purpose || proof.ProofDigest() != challenge.ProofDigest() {
		return transitionConflict(ConflictState, "ceremony proof does not match its purpose and challenge")
	}
	if challenge.Status() != CeremonyPending {
		return transitionConflict(ConflictState, "ceremony challenge is already consumed")
	}
	if evaluatedAt.IsZero() || !evaluatedAt.Before(challenge.ExpiresAt()) {
		return transitionConflict(ConflictState, "ceremony challenge is expired")
	}
	return nil
}

// BootstrapInstallationInput carries a canonical server-derived attempt
// fingerprint. The application must durably deduplicate (invitation ID,
// fingerprint) before invoking this transition; retransmission never counts
// as a new failed attempt. A distinct fingerprint enters the version CAS.
type BootstrapInstallationInput struct {
	Invitation                InstallationInvitationState
	ExpectedInvitationVersion Version
	CurrentGeneration         BootstrapGenerationID
	GenerationAuthorization   BootstrapGenerationAuthorization
	Principal                 PrincipalState
	PrincipalID               PrincipalID
	PrincipalDisplayName      DisplayName
	Device                    DeviceState
	DeviceID                  DeviceID
	DeviceDisplayName         DisplayName
	DevicePublicKey           PublicKeyReference
	OwnerGrant                GrantState
	OwnerGrantID              GrantID
	OwnerGrantCapabilities    CapabilitySet
	Proof                     BootstrapProof
	AttemptFingerprint        CommandFingerprint
	EvaluatedAt               time.Time
}

type BootstrapInstallationResult struct {
	invitation InstallationInvitationState
	principal  PrincipalState
	device     DeviceState
	ownerGrant GrantState
	facts      []IdentityFact
	outcome    BootstrapInstallationOutcome
	rejection  BootstrapProofRejection
}

type BootstrapProofRejection struct {
	invitationID       InvitationID
	invitationVersion  Version
	attemptFingerprint CommandFingerprint
}

func (rejection BootstrapProofRejection) InvitationID() InvitationID { return rejection.invitationID }
func (rejection BootstrapProofRejection) InvitationVersion() Version {
	return rejection.invitationVersion
}
func (rejection BootstrapProofRejection) AttemptFingerprint() CommandFingerprint {
	return rejection.attemptFingerprint
}

type BootstrapInstallationOutcome string

const (
	BootstrapInstallationCompleted     BootstrapInstallationOutcome = "completed"
	BootstrapInstallationProofRejected BootstrapInstallationOutcome = "proof_rejected"
)

func BootstrapInstallation(input BootstrapInstallationInput) (BootstrapInstallationResult, error) {
	if input.Invitation.IsZero() || input.PrincipalID.IsZero() || input.PrincipalDisplayName.String() == "" ||
		input.DeviceID.IsZero() || input.DeviceDisplayName.String() == "" ||
		input.DevicePublicKey.String() == "" || input.OwnerGrantID.IsZero() || input.OwnerGrantCapabilities.IsZero() ||
		input.CurrentGeneration.IsZero() || input.AttemptFingerprint.IsZero() ||
		!input.Principal.IsZero() || !input.Device.IsZero() ||
		!input.OwnerGrant.IsZero() || input.EvaluatedAt.IsZero() {
		return BootstrapInstallationResult{}, transitionError(ErrorCodeInvalidArgument, "bootstrap input is invalid")
	}
	if err := checkExpectedVersion(input.Invitation.Version(), input.ExpectedInvitationVersion); err != nil {
		return BootstrapInstallationResult{}, err
	}
	if input.Invitation.Status() != InstallationInvitationPending {
		return BootstrapInstallationResult{}, transitionConflict(ConflictState, "installation invitation is consumed or exhausted")
	}
	if !input.EvaluatedAt.Before(input.Invitation.ExpiresAt()) {
		return BootstrapInstallationResult{}, transitionConflict(ConflictState, "installation invitation is expired")
	}
	if !input.GenerationAuthorization.permits(input.Invitation, input.CurrentGeneration) {
		return BootstrapInstallationResult{}, transitionConflict(ConflictState, "bootstrap process generation changed without an authorized resume")
	}
	if !bootstrapProofMatches(input) {
		return RejectBootstrapProof(RejectBootstrapProofInput{
			Invitation:                input.Invitation,
			ExpectedInvitationVersion: input.ExpectedInvitationVersion,
			CurrentGeneration:         input.CurrentGeneration,
			GenerationAuthorization:   input.GenerationAuthorization,
			AttemptFingerprint:        input.AttemptFingerprint,
			EvaluatedAt:               input.EvaluatedAt,
		})
	}
	requiredOwnerCapabilities, _ := NewCapabilitySet(
		capabilityInstallationOwner,
		capabilityIdentityAdmin,
		capabilityWorkspaceCreate,
		capabilityMembershipAdmin,
		capabilityActorAdmin,
		capabilityDelegationAdmin,
		capabilityDevicePair,
		capabilityWorkspaceOwner,
	)
	if !input.OwnerGrantCapabilities.ContainsAll(requiredOwnerCapabilities) {
		return BootstrapInstallationResult{}, transitionError(ErrorCodeInvalidArgument, "installation-owner grant lacks required capabilities")
	}
	nextInvitationVersion, err := nextTransitionVersion(input.Invitation.Version())
	if err != nil {
		return BootstrapInstallationResult{}, err
	}
	invitation := input.Invitation
	invitation.status = InstallationInvitationConsumed
	invitation.version = nextInvitationVersion
	principal := PrincipalState{
		id:             input.PrincipalID,
		installationID: input.Invitation.InstallationID(),
		kind:           PrincipalKindHuman,
		displayName:    input.PrincipalDisplayName,
		status:         PrincipalActive,
		version:        InitialVersion(),
	}
	device := DeviceState{
		id:                 input.DeviceID,
		installationID:     input.Invitation.InstallationID(),
		principalID:        input.PrincipalID,
		displayName:        input.DeviceDisplayName,
		publicKey:          input.DevicePublicKey,
		status:             DeviceTrusted,
		version:            InitialVersion(),
		trustRevision:      InitialVersion(),
		revocationRevision: InitialVersion(),
	}
	credential, err := NewDeviceCredentialBinding(
		input.Proof.DevicePublicKey(), input.Proof.DeviceSPKIFingerprint(), input.Proof.TranscriptFingerprint(),
	)
	if err != nil {
		return BootstrapInstallationResult{}, transitionError(ErrorCodeInvalidArgument, "bootstrap credential binding is invalid")
	}
	device.credential = credential
	device.credentialActivatedAt = input.EvaluatedAt.UTC()
	grant := GrantState{
		id:             input.OwnerGrantID,
		installationID: input.Invitation.InstallationID(),
		principalID:    input.PrincipalID,
		status:         GrantActive,
		version:        InitialVersion(),
		capabilities:   cloneCapabilitySet(input.OwnerGrantCapabilities),
	}
	invitationOrigin, err := identityOrigin(invitation.ID(), invitation.Version())
	if err != nil {
		return BootstrapInstallationResult{}, err
	}
	principalOrigin, err := identityOrigin(principal.ID(), principal.Version())
	if err != nil {
		return BootstrapInstallationResult{}, err
	}
	deviceOrigin, err := identityOrigin(device.ID(), device.Version())
	if err != nil {
		return BootstrapInstallationResult{}, err
	}
	facts := []IdentityFact{
		InstallationBootstrappedFact{
			origin:         invitationOrigin,
			installationID: input.Invitation.InstallationID(),
			invitationID:   invitation.ID(),
			principalID:    input.PrincipalID,
			deviceID:       input.DeviceID,
			grantID:        input.OwnerGrantID,
			transcript:     input.Proof.TranscriptFingerprint(),
		},
		PrincipalRegisteredFact{
			origin: principalOrigin, installationID: input.Invitation.InstallationID(), principalID: input.PrincipalID,
			kind: PrincipalKindHuman, displayName: principal.DisplayName(), publicKey: principal.PublicKeyReference(),
		},
		DevicePairedFact{
			origin:             deviceOrigin,
			installationID:     input.Invitation.InstallationID(),
			deviceID:           input.DeviceID,
			principalID:        input.PrincipalID,
			displayName:        device.DisplayName(),
			transcript:         input.Proof.TranscriptFingerprint(),
			trustRevision:      device.TrustRevision(),
			revocationRevision: device.RevocationRevision(),
			credential:         device.CredentialBinding(),
			activatedAt:        device.CredentialActivatedAt(),
		},
	}
	return BootstrapInstallationResult{
		invitation: invitation,
		principal:  principal,
		device:     device,
		ownerGrant: grant,
		facts:      facts,
		outcome:    BootstrapInstallationCompleted,
	}, nil
}

func bootstrapProofMatches(input BootstrapInstallationInput) bool {
	proof := input.Proof
	return proof.InvitationID() == input.Invitation.ID() &&
		proof.InstallationID() == input.Invitation.InstallationID() &&
		proof.InstallationKey() == input.Invitation.InstallationPublicKey() &&
		proof.InvitationEvidence() == input.Invitation.InvitationVerifier() &&
		!proof.TranscriptFingerprint().IsZero() && !proof.ClientNonceDigest().IsZero() &&
		!proof.ServerNonceDigest().IsZero() && proof.Protocol() == PairingProtocolV1 &&
		proof.Role() == BootstrapRoleInstallationOwner && proof.PrincipalID() == input.PrincipalID &&
		proof.PrincipalDisplayName() == input.PrincipalDisplayName && proof.DeviceID() == input.DeviceID &&
		proof.DeviceDisplayName() == input.DeviceDisplayName && proof.DevicePublicKey() == input.DevicePublicKey &&
		!proof.DeviceSPKIFingerprint().IsZero() &&
		proof.OwnerGrantID() == input.OwnerGrantID && proof.OwnerCapabilities().Equal(input.OwnerGrantCapabilities)
}

type RejectBootstrapProofInput struct {
	Invitation                InstallationInvitationState
	ExpectedInvitationVersion Version
	CurrentGeneration         BootstrapGenerationID
	GenerationAuthorization   BootstrapGenerationAuthorization
	AttemptFingerprint        CommandFingerprint
	EvaluatedAt               time.Time
}

// RejectBootstrapProof is the security-only transition for a proof verifier's
// cryptographically_rejected decision. It cannot create bootstrap authority.
func RejectBootstrapProof(input RejectBootstrapProofInput) (BootstrapInstallationResult, error) {
	if input.Invitation.IsZero() || input.CurrentGeneration.IsZero() ||
		input.AttemptFingerprint.IsZero() || input.EvaluatedAt.IsZero() {
		return BootstrapInstallationResult{}, transitionError(ErrorCodeInvalidArgument, "bootstrap rejection input is invalid")
	}
	if err := checkExpectedVersion(input.Invitation.Version(), input.ExpectedInvitationVersion); err != nil {
		return BootstrapInstallationResult{}, err
	}
	if input.Invitation.Status() != InstallationInvitationPending {
		return BootstrapInstallationResult{}, transitionConflict(ConflictState, "installation invitation is consumed or exhausted")
	}
	if !input.EvaluatedAt.Before(input.Invitation.ExpiresAt()) {
		return BootstrapInstallationResult{}, transitionConflict(ConflictState, "installation invitation is expired")
	}
	if !input.GenerationAuthorization.permits(input.Invitation, input.CurrentGeneration) {
		return BootstrapInstallationResult{}, transitionConflict(ConflictState, "bootstrap process generation changed without an authorized resume")
	}
	nextVersion, err := nextTransitionVersion(input.Invitation.Version())
	if err != nil {
		return BootstrapInstallationResult{}, err
	}
	attempted := input.Invitation
	attempted.failedAttempts++
	attempted.version = nextVersion
	if attempted.failedAttempts >= MaxBootstrapFailedAttempts {
		attempted.status = InstallationInvitationExhausted
	}
	return BootstrapInstallationResult{
		invitation: attempted,
		outcome:    BootstrapInstallationProofRejected,
		rejection: BootstrapProofRejection{
			invitationID: input.Invitation.ID(), invitationVersion: attempted.Version(),
			attemptFingerprint: input.AttemptFingerprint,
		},
	}, nil
}

func (result BootstrapInstallationResult) Invitation() InstallationInvitationState {
	return result.invitation
}
func (result BootstrapInstallationResult) Principal() PrincipalState { return result.principal }
func (result BootstrapInstallationResult) Device() DeviceState       { return result.device }
func (result BootstrapInstallationResult) OwnerGrant() GrantState    { return result.ownerGrant }
func (result BootstrapInstallationResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}
func (result BootstrapInstallationResult) Outcome() BootstrapInstallationOutcome {
	return result.outcome
}
func (result BootstrapInstallationResult) Rejection() (BootstrapProofRejection, bool) {
	return result.rejection, result.outcome == BootstrapInstallationProofRejected
}

type RegisterPrincipalInput struct {
	Authorization            IdentityAuthorization
	Registrar                PrincipalState
	ExpectedRegistrarVersion Version
	Principal                PrincipalState
	PrincipalID              PrincipalID
	Kind                     PrincipalKind
	DisplayName              DisplayName
	PublicKeyReference       PublicKeyReference
}

type RegisterPrincipalResult struct {
	principal PrincipalState
	facts     []IdentityFact
}

func RegisterPrincipal(input RegisterPrincipalInput) (RegisterPrincipalResult, error) {
	if !input.Principal.IsZero() {
		return RegisterPrincipalResult{}, transitionConflict(ConflictState, "principal already exists")
	}
	if input.PrincipalID.IsZero() || !input.Kind.Valid() || input.DisplayName.String() == "" ||
		(input.Kind != PrincipalKindHuman && input.PublicKeyReference.String() == "") {
		return RegisterPrincipalResult{}, transitionError(ErrorCodeInvalidArgument, "principal registration input is invalid")
	}
	if err := checkActivePrincipal(input.Authorization, input.Registrar, input.ExpectedRegistrarVersion, capabilityIdentityAdmin); err != nil {
		return RegisterPrincipalResult{}, err
	}
	if err := checkInstallationAuthorization(input.Authorization); err != nil {
		return RegisterPrincipalResult{}, err
	}
	principal := PrincipalState{
		id:             input.PrincipalID,
		installationID: input.Authorization.InstallationID(),
		kind:           input.Kind,
		displayName:    input.DisplayName,
		publicKey:      input.PublicKeyReference,
		status:         PrincipalActive,
		version:        InitialVersion(),
	}
	origin, err := identityOrigin(principal.ID(), principal.Version())
	if err != nil {
		return RegisterPrincipalResult{}, err
	}
	return RegisterPrincipalResult{
		principal: principal,
		facts: []IdentityFact{PrincipalRegisteredFact{
			origin: origin, installationID: principal.InstallationID(), principalID: principal.ID(), kind: principal.Kind(),
			displayName: principal.DisplayName(), publicKey: principal.PublicKeyReference(),
		}},
	}, nil
}

func (result RegisterPrincipalResult) Principal() PrincipalState { return result.principal }
func (result RegisterPrincipalResult) Facts() []IdentityFact     { return cloneIdentityFacts(result.facts) }

type CreateWorkspaceInput struct {
	Authorization        IdentityAuthorization
	Owner                PrincipalState
	ExpectedOwnerVersion Version
	InstallationGrant    GrantState
	ExpectedGrantVersion Version
	Workspace            WorkspaceState
	WorkspaceID          WorkspaceID
	Alias                WorkspaceAlias
	DiscoveryLocator     DiscoveryLocator
	OwnerMembership      MembershipState
	OwnerMembershipID    MembershipID
	OwnerCapabilities    CapabilitySet
}

type CreateWorkspaceResult struct {
	workspace  WorkspaceState
	membership MembershipState
	facts      []IdentityFact
}

func CreateWorkspace(input CreateWorkspaceInput) (CreateWorkspaceResult, error) {
	if !input.Workspace.IsZero() || !input.OwnerMembership.IsZero() {
		return CreateWorkspaceResult{}, transitionConflict(ConflictState, "workspace or owner membership already exists")
	}
	if input.WorkspaceID.IsZero() || input.OwnerCapabilities.IsZero() ||
		input.Alias.String() == "" || input.OwnerMembershipID.IsZero() {
		return CreateWorkspaceResult{}, transitionError(ErrorCodeInvalidArgument, "workspace creation input is invalid")
	}
	if err := checkActivePrincipal(input.Authorization, input.Owner, input.ExpectedOwnerVersion, capabilityWorkspaceCreate); err != nil {
		return CreateWorkspaceResult{}, err
	}
	if err := checkInstallationAuthorization(input.Authorization); err != nil {
		return CreateWorkspaceResult{}, err
	}
	if input.InstallationGrant.IsZero() || input.InstallationGrant.Status() != GrantActive ||
		input.InstallationGrant.InstallationID() != input.Authorization.InstallationID() ||
		input.InstallationGrant.PrincipalID() != input.Owner.ID() ||
		!input.InstallationGrant.Capabilities().Contains(capabilityInstallationOwner) {
		return CreateWorkspaceResult{}, transitionError(ErrorCodeForbidden, "active installation-owner grant is required")
	}
	if err := checkExpectedVersion(input.InstallationGrant.Version(), input.ExpectedGrantVersion); err != nil {
		return CreateWorkspaceResult{}, err
	}
	if !input.Authorization.capabilities.ContainsAll(input.OwnerCapabilities) ||
		!input.InstallationGrant.Capabilities().ContainsAll(input.OwnerCapabilities) {
		return CreateWorkspaceResult{}, transitionError(ErrorCodeForbidden, "owner capabilities exceed evaluated installation grant")
	}
	workspace := WorkspaceState{
		id:             input.WorkspaceID,
		installationID: input.Authorization.InstallationID(),
		authorityID:    input.Authorization.AuthorityID(),
		epoch:          input.Authorization.AuthorityEpoch(),
		alias:          input.Alias,
		discovery:      input.DiscoveryLocator,
		policy:         input.Authorization.PolicyRevision(),
		status:         WorkspaceActive,
		version:        InitialVersion(),
	}
	requiredOwnerCapabilities, _ := NewCapabilitySet(
		capabilityWorkspaceOwner,
		capabilityMembershipAdmin,
		capabilityActorAdmin,
		capabilityDelegationAdmin,
		capabilityDevicePair,
	)
	if !input.OwnerCapabilities.ContainsAll(requiredOwnerCapabilities) {
		return CreateWorkspaceResult{}, transitionError(ErrorCodeForbidden, "owner membership lacks required administration capabilities")
	}
	if input.OwnerCapabilities.Contains(capabilityInstallationOwner) ||
		input.OwnerCapabilities.Contains(capabilityIdentityAdmin) ||
		input.OwnerCapabilities.Contains(capabilityWorkspaceCreate) {
		return CreateWorkspaceResult{}, transitionError(ErrorCodeForbidden, "installation capabilities cannot enter a workspace membership")
	}
	ownerCapabilities := cloneCapabilitySet(input.OwnerCapabilities)
	membership := MembershipState{
		id:           input.OwnerMembershipID,
		workspaceID:  input.WorkspaceID,
		principalID:  input.Owner.ID(),
		status:       MembershipActive,
		version:      InitialVersion(),
		capabilities: ownerCapabilities,
	}
	workspaceOrigin, err := identityOrigin(workspace.ID(), workspace.Version())
	if err != nil {
		return CreateWorkspaceResult{}, err
	}
	membershipOrigin, err := identityOrigin(membership.ID(), membership.Version())
	if err != nil {
		return CreateWorkspaceResult{}, err
	}
	facts := []IdentityFact{
		WorkspaceCreatedFact{
			origin: workspaceOrigin, workspaceID: workspace.ID(),
			authorityID: workspace.AuthorityID(), epoch: workspace.AuthorityEpoch(), alias: workspace.Alias(),
			discovery: workspace.DiscoveryLocator(), policy: workspace.PolicyRevision(),
		},
		WorkspaceMemberInvitedFact{
			origin:       membershipOrigin,
			membershipID: membership.ID(), workspaceID: workspace.ID(), principalID: input.Owner.ID(),
			capabilities: ownerCapabilities,
		},
		WorkspaceMembershipAcceptedFact{
			origin:       membershipOrigin,
			membershipID: membership.ID(), workspaceID: workspace.ID(), principalID: input.Owner.ID(),
		},
	}
	return CreateWorkspaceResult{workspace: workspace, membership: membership, facts: facts}, nil
}

func (result CreateWorkspaceResult) Workspace() WorkspaceState        { return result.workspace }
func (result CreateWorkspaceResult) OwnerMembership() MembershipState { return result.membership }
func (result CreateWorkspaceResult) Facts() []IdentityFact            { return cloneIdentityFacts(result.facts) }

type InviteWorkspaceMemberInput struct {
	Authorization                IdentityAuthorization
	Administrator                PrincipalState
	ExpectedAdministratorVersion Version
	Workspace                    WorkspaceState
	ExpectedWorkspaceVersion     Version
	Principal                    PrincipalState
	ExpectedPrincipalVersion     Version
	Membership                   MembershipState
	MembershipID                 MembershipID
	Capabilities                 CapabilitySet
	Challenge                    CeremonyChallenge
	ChallengeCreation            CeremonyCreationExpectation
}

type InviteWorkspaceMemberResult struct {
	membership MembershipState
	facts      []IdentityFact
}

func InviteWorkspaceMember(input InviteWorkspaceMemberInput) (InviteWorkspaceMemberResult, error) {
	if !input.Membership.IsZero() {
		return InviteWorkspaceMemberResult{}, transitionConflict(ConflictState, "workspace membership already exists")
	}
	if input.MembershipID.IsZero() || input.Capabilities.IsZero() || input.Challenge.IsZero() ||
		!input.ChallengeCreation.matches(input.Challenge) {
		return InviteWorkspaceMemberResult{}, transitionError(ErrorCodeInvalidArgument, "membership invitation input is invalid")
	}
	if err := checkActivePrincipal(input.Authorization, input.Administrator, input.ExpectedAdministratorVersion, capabilityMembershipAdmin); err != nil {
		return InviteWorkspaceMemberResult{}, err
	}
	if err := checkWorkspaceAuthority(input.Authorization, input.Workspace, input.ExpectedWorkspaceVersion); err != nil {
		return InviteWorkspaceMemberResult{}, err
	}
	if !input.Authorization.capabilities.ContainsAll(input.Capabilities) {
		return InviteWorkspaceMemberResult{}, transitionError(ErrorCodeForbidden, "membership capabilities exceed delegator ceiling")
	}
	if err := checkExpectedVersion(input.Principal.Version(), input.ExpectedPrincipalVersion); err != nil {
		return InviteWorkspaceMemberResult{}, err
	}
	if input.Principal.Status() != PrincipalActive ||
		input.Principal.InstallationID() != input.Workspace.InstallationID() ||
		input.Challenge.Purpose() != CeremonyPurposeMembershipAcceptance ||
		input.Challenge.Status() != CeremonyPending ||
		input.Challenge.WorkspaceID() != input.Workspace.ID() ||
		input.Challenge.MembershipID() != input.MembershipID ||
		input.Challenge.PrincipalID() != input.Principal.ID() {
		return InviteWorkspaceMemberResult{}, transitionConflict(ConflictReference, "membership references do not match")
	}
	if !input.Challenge.ExpiresAt().After(input.Authorization.EvaluatedAt()) {
		return InviteWorkspaceMemberResult{}, transitionConflict(ConflictState, "membership challenge is expired")
	}
	membership := MembershipState{
		id:           input.MembershipID,
		workspaceID:  input.Workspace.ID(),
		principalID:  input.Principal.ID(),
		status:       MembershipInvited,
		version:      InitialVersion(),
		capabilities: cloneCapabilitySet(input.Capabilities),
		acceptance:   input.Challenge,
	}
	origin, err := identityOrigin(membership.ID(), membership.Version())
	if err != nil {
		return InviteWorkspaceMemberResult{}, err
	}
	fact := WorkspaceMemberInvitedFact{
		origin:       origin,
		membershipID: membership.ID(), workspaceID: membership.WorkspaceID(), principalID: membership.PrincipalID(),
		ceremonyID: input.Challenge.ID(), capabilities: membership.Capabilities(),
	}
	return InviteWorkspaceMemberResult{membership: membership, facts: []IdentityFact{fact}}, nil
}

func (result InviteWorkspaceMemberResult) Membership() MembershipState { return result.membership }
func (result InviteWorkspaceMemberResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}

type AcceptWorkspaceMembershipInput struct {
	Authorization             IdentityAuthorization
	Workspace                 WorkspaceState
	ExpectedWorkspaceVersion  Version
	Principal                 PrincipalState
	ExpectedPrincipalVersion  Version
	Membership                MembershipState
	ExpectedMembershipVersion Version
	Proof                     CeremonyProof
}

type AcceptWorkspaceMembershipResult struct {
	membership MembershipState
	facts      []IdentityFact
}

func AcceptWorkspaceMembership(input AcceptWorkspaceMembershipInput) (AcceptWorkspaceMembershipResult, error) {
	if err := checkActivePrincipal(input.Authorization, input.Principal, input.ExpectedPrincipalVersion, Capability{}); err != nil {
		return AcceptWorkspaceMembershipResult{}, err
	}
	if err := checkWorkspaceAuthority(input.Authorization, input.Workspace, input.ExpectedWorkspaceVersion); err != nil {
		return AcceptWorkspaceMembershipResult{}, err
	}
	if err := checkExpectedVersion(input.Membership.Version(), input.ExpectedMembershipVersion); err != nil {
		return AcceptWorkspaceMembershipResult{}, err
	}
	if input.Membership.Status() != MembershipInvited {
		return AcceptWorkspaceMembershipResult{}, transitionConflict(ConflictState, "membership is not invited")
	}
	if input.Membership.WorkspaceID() != input.Workspace.ID() ||
		input.Membership.PrincipalID() != input.Principal.ID() || input.Proof.PrincipalID() != input.Principal.ID() {
		return AcceptWorkspaceMembershipResult{}, transitionError(ErrorCodeForbidden, "membership belongs to another principal")
	}
	acceptance := input.Membership.AcceptanceChallenge()
	if acceptance.WorkspaceID() != input.Membership.WorkspaceID() ||
		acceptance.MembershipID() != input.Membership.ID() ||
		acceptance.PrincipalID() != input.Membership.PrincipalID() {
		return AcceptWorkspaceMembershipResult{}, transitionConflict(ConflictReference, "membership challenge binding is stale or malformed")
	}
	if err := checkCeremony(acceptance, input.Proof,
		CeremonyPurposeMembershipAcceptance, input.Authorization.EvaluatedAt()); err != nil {
		return AcceptWorkspaceMembershipResult{}, err
	}
	nextVersion, err := nextTransitionVersion(input.Membership.Version())
	if err != nil {
		return AcceptWorkspaceMembershipResult{}, err
	}
	membership := input.Membership
	membership.status = MembershipActive
	membership.version = nextVersion
	membership.acceptance = membership.acceptance.consume()
	origin, err := identityOrigin(membership.ID(), membership.Version())
	if err != nil {
		return AcceptWorkspaceMembershipResult{}, err
	}
	fact := WorkspaceMembershipAcceptedFact{
		origin:       origin,
		membershipID: membership.ID(), workspaceID: membership.WorkspaceID(), principalID: membership.PrincipalID(),
	}
	return AcceptWorkspaceMembershipResult{membership: membership, facts: []IdentityFact{fact}}, nil
}

func (result AcceptWorkspaceMembershipResult) Membership() MembershipState { return result.membership }
func (result AcceptWorkspaceMembershipResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}

type CreateActorInput struct {
	Authorization                IdentityAuthorization
	Administrator                PrincipalState
	ExpectedAdministratorVersion Version
	Workspace                    WorkspaceState
	ExpectedWorkspaceVersion     Version
	Actor                        ActorState
	ActorID                      ActorID
	Kind                         ActorKind
	Profile                      ActorProfile
}

type CreateActorResult struct {
	actor ActorState
	facts []IdentityFact
}

func CreateActor(input CreateActorInput) (CreateActorResult, error) {
	if !input.Actor.IsZero() {
		return CreateActorResult{}, transitionConflict(ConflictState, "actor already exists")
	}
	if input.ActorID.IsZero() || !input.Kind.Valid() || input.Profile.DisplayName().String() == "" {
		return CreateActorResult{}, transitionError(ErrorCodeInvalidArgument, "actor creation input is invalid")
	}
	if err := checkActivePrincipal(input.Authorization, input.Administrator, input.ExpectedAdministratorVersion, capabilityActorAdmin); err != nil {
		return CreateActorResult{}, err
	}
	if err := checkWorkspaceAuthority(input.Authorization, input.Workspace, input.ExpectedWorkspaceVersion); err != nil {
		return CreateActorResult{}, err
	}
	actor := ActorState{
		id:          input.ActorID,
		workspaceID: input.Workspace.ID(),
		kind:        input.Kind,
		profile:     input.Profile,
		status:      ActorActive,
		version:     InitialVersion(),
	}
	origin, err := identityOrigin(actor.ID(), actor.Version())
	if err != nil {
		return CreateActorResult{}, err
	}
	return CreateActorResult{
		actor: actor,
		facts: []IdentityFact{ActorCreatedFact{
			origin: origin, actorID: actor.ID(), workspaceID: actor.WorkspaceID(),
			kind: actor.Kind(), profile: actor.Profile(),
		}},
	}, nil
}

func (result CreateActorResult) Actor() ActorState     { return result.actor }
func (result CreateActorResult) Facts() []IdentityFact { return cloneIdentityFacts(result.facts) }

type ProposeActorDelegationInput struct {
	Authorization                IdentityAuthorization
	Administrator                PrincipalState
	ExpectedAdministratorVersion Version
	Workspace                    WorkspaceState
	ExpectedWorkspaceVersion     Version
	Principal                    PrincipalState
	ExpectedPrincipalVersion     Version
	Actor                        ActorState
	ExpectedActorVersion         Version
	Membership                   MembershipState
	ExpectedMembershipVersion    Version
	Delegation                   ActorDelegationState
	DelegationID                 ActorDelegationID
	Capabilities                 CapabilitySet
	Challenge                    CeremonyChallenge
	ChallengeCreation            CeremonyCreationExpectation
}

type ProposeActorDelegationResult struct {
	delegation ActorDelegationState
	facts      []IdentityFact
}

func ProposeActorDelegation(input ProposeActorDelegationInput) (ProposeActorDelegationResult, error) {
	if !input.Delegation.IsZero() {
		return ProposeActorDelegationResult{}, transitionConflict(ConflictState, "actor delegation already exists")
	}
	if input.DelegationID.IsZero() || input.Capabilities.IsZero() || input.Challenge.IsZero() ||
		!input.ChallengeCreation.matches(input.Challenge) {
		return ProposeActorDelegationResult{}, transitionError(ErrorCodeInvalidArgument, "delegation proposal input is invalid")
	}
	if err := checkActivePrincipal(input.Authorization, input.Administrator, input.ExpectedAdministratorVersion, capabilityDelegationAdmin); err != nil {
		return ProposeActorDelegationResult{}, err
	}
	if err := checkWorkspaceAuthority(input.Authorization, input.Workspace, input.ExpectedWorkspaceVersion); err != nil {
		return ProposeActorDelegationResult{}, err
	}
	if err := checkExpectedVersion(input.Principal.Version(), input.ExpectedPrincipalVersion); err != nil {
		return ProposeActorDelegationResult{}, err
	}
	if err := checkExpectedVersion(input.Actor.Version(), input.ExpectedActorVersion); err != nil {
		return ProposeActorDelegationResult{}, err
	}
	if err := checkExpectedVersion(input.Membership.Version(), input.ExpectedMembershipVersion); err != nil {
		return ProposeActorDelegationResult{}, err
	}
	if input.Principal.Status() != PrincipalActive || input.Actor.Status() != ActorActive ||
		input.Membership.Status() != MembershipActive || input.Actor.WorkspaceID() != input.Workspace.ID() ||
		input.Membership.WorkspaceID() != input.Workspace.ID() || input.Membership.PrincipalID() != input.Principal.ID() ||
		!input.Membership.Capabilities().ContainsAll(input.Capabilities) {
		return ProposeActorDelegationResult{}, transitionConflict(ConflictReference, "delegation references or capability ceiling do not match")
	}
	if input.Principal.Kind() == PrincipalKindService {
		return ProposeActorDelegationResult{}, transitionError(ErrorCodeForbidden, "service principals cannot receive actor delegations")
	}
	if input.Challenge.Purpose() != CeremonyPurposeDelegationActivation ||
		input.Challenge.Status() != CeremonyPending ||
		input.Challenge.WorkspaceID() != input.Workspace.ID() || input.Challenge.DelegationID() != input.DelegationID ||
		input.Challenge.PrincipalID() != input.Principal.ID() || input.Challenge.ActorID() != input.Actor.ID() ||
		!input.Challenge.ExpiresAt().After(input.Authorization.EvaluatedAt()) {
		return ProposeActorDelegationResult{}, transitionConflict(ConflictReference, "delegation challenge binding does not match")
	}
	delegation := ActorDelegationState{
		id:           input.DelegationID,
		workspaceID:  input.Workspace.ID(),
		principalID:  input.Principal.ID(),
		actorID:      input.Actor.ID(),
		membershipID: input.Membership.ID(),
		status:       DelegationProposed,
		version:      InitialVersion(),
		capabilities: cloneCapabilitySet(input.Capabilities),
		activation:   input.Challenge,
	}
	origin, err := identityOrigin(delegation.ID(), delegation.Version())
	if err != nil {
		return ProposeActorDelegationResult{}, err
	}
	fact := ActorDelegationProposedFact{
		origin:       origin,
		delegationID: delegation.ID(), workspaceID: delegation.WorkspaceID(), principalID: delegation.PrincipalID(),
		actorID: delegation.ActorID(), ceremonyID: input.Challenge.ID(),
	}
	return ProposeActorDelegationResult{delegation: delegation, facts: []IdentityFact{fact}}, nil
}

func (result ProposeActorDelegationResult) Delegation() ActorDelegationState {
	return result.delegation
}
func (result ProposeActorDelegationResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}

type ActivateActorDelegationInput struct {
	Authorization             IdentityAuthorization
	Workspace                 WorkspaceState
	ExpectedWorkspaceVersion  Version
	Principal                 PrincipalState
	ExpectedPrincipalVersion  Version
	Actor                     ActorState
	ExpectedActorVersion      Version
	Membership                MembershipState
	ExpectedMembershipVersion Version
	Delegation                ActorDelegationState
	ExpectedDelegationVersion Version
	Proof                     CeremonyProof
	SessionStartChallenge     CeremonyChallenge
	SessionChallengeCreation  CeremonyCreationExpectation
}

type ActivateActorDelegationResult struct {
	delegation            ActorDelegationState
	sessionStartChallenge CeremonyChallenge
	facts                 []IdentityFact
}

func ActivateActorDelegation(input ActivateActorDelegationInput) (ActivateActorDelegationResult, error) {
	if !input.SessionChallengeCreation.matches(input.SessionStartChallenge) {
		return ActivateActorDelegationResult{}, transitionError(ErrorCodeInvalidArgument, "session ceremony creation expectation is absent or mismatched")
	}
	if err := checkActivePrincipal(input.Authorization, input.Principal, input.ExpectedPrincipalVersion, Capability{}); err != nil {
		return ActivateActorDelegationResult{}, err
	}
	if err := checkWorkspaceAuthority(input.Authorization, input.Workspace, input.ExpectedWorkspaceVersion); err != nil {
		return ActivateActorDelegationResult{}, err
	}
	if err := checkExpectedVersion(input.Actor.Version(), input.ExpectedActorVersion); err != nil {
		return ActivateActorDelegationResult{}, err
	}
	if err := checkExpectedVersion(input.Membership.Version(), input.ExpectedMembershipVersion); err != nil {
		return ActivateActorDelegationResult{}, err
	}
	if err := checkExpectedVersion(input.Delegation.Version(), input.ExpectedDelegationVersion); err != nil {
		return ActivateActorDelegationResult{}, err
	}
	if input.Membership.Status() != MembershipActive || input.Delegation.Status() != DelegationProposed ||
		input.Actor.Status() != ActorActive || input.Actor.ID() != input.Delegation.ActorID() ||
		input.Actor.WorkspaceID() != input.Workspace.ID() || input.Delegation.WorkspaceID() != input.Workspace.ID() ||
		input.Membership.ID() != input.Delegation.MembershipID() ||
		input.Membership.WorkspaceID() != input.Delegation.WorkspaceID() ||
		input.Membership.PrincipalID() != input.Principal.ID() || input.Delegation.PrincipalID() != input.Principal.ID() {
		return ActivateActorDelegationResult{}, transitionConflict(ConflictReference, "delegation activation references do not match")
	}
	if !input.Membership.Capabilities().ContainsAll(input.Delegation.Capabilities()) {
		return ActivateActorDelegationResult{}, transitionError(ErrorCodeForbidden, "delegation exceeds the current membership capability ceiling")
	}
	if input.Proof.PrincipalID() != input.Principal.ID() {
		return ActivateActorDelegationResult{}, transitionError(ErrorCodeForbidden, "delegation proof belongs to another principal")
	}
	activation := input.Delegation.ActivationChallenge()
	if activation.WorkspaceID() != input.Delegation.WorkspaceID() ||
		activation.DelegationID() != input.Delegation.ID() ||
		activation.PrincipalID() != input.Delegation.PrincipalID() ||
		activation.ActorID() != input.Delegation.ActorID() {
		return ActivateActorDelegationResult{}, transitionConflict(ConflictReference, "delegation challenge binding is stale or malformed")
	}
	if err := checkCeremony(activation, input.Proof,
		CeremonyPurposeDelegationActivation, input.Authorization.EvaluatedAt()); err != nil {
		return ActivateActorDelegationResult{}, err
	}
	if input.SessionStartChallenge.Purpose() != CeremonyPurposeActorSessionStart ||
		input.SessionStartChallenge.Status() != CeremonyPending ||
		input.SessionStartChallenge.WorkspaceID() != input.Delegation.WorkspaceID() ||
		input.SessionStartChallenge.DelegationID() != input.Delegation.ID() ||
		input.SessionStartChallenge.PrincipalID() != input.Principal.ID() ||
		input.SessionStartChallenge.ActorID() != input.Delegation.ActorID() ||
		!input.SessionStartChallenge.ExpiresAt().After(input.Authorization.EvaluatedAt()) {
		return ActivateActorDelegationResult{}, transitionConflict(ConflictReference, "session-start challenge binding does not match")
	}
	nextVersion, err := nextTransitionVersion(input.Delegation.Version())
	if err != nil {
		return ActivateActorDelegationResult{}, err
	}
	delegation := input.Delegation
	delegation.status = DelegationActive
	delegation.version = nextVersion
	delegation.activation = delegation.activation.consume()
	origin, err := identityOrigin(delegation.ID(), delegation.Version())
	if err != nil {
		return ActivateActorDelegationResult{}, err
	}
	fact := ActorDelegationActivatedFact{
		origin:       origin,
		delegationID: delegation.ID(), workspaceID: delegation.WorkspaceID(),
		principalID: delegation.PrincipalID(), actorID: delegation.ActorID(),
		sessionStart: input.SessionStartChallenge.ID(),
	}
	return ActivateActorDelegationResult{
		delegation:            delegation,
		sessionStartChallenge: input.SessionStartChallenge,
		facts:                 []IdentityFact{fact},
	}, nil
}

func (result ActivateActorDelegationResult) Delegation() ActorDelegationState {
	return result.delegation
}
func (result ActivateActorDelegationResult) SessionStartChallenge() CeremonyChallenge {
	return result.sessionStartChallenge
}
func (result ActivateActorDelegationResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}

type BeginDevicePairingInput struct {
	Authorization            IdentityAuthorization
	Principal                PrincipalState
	ExpectedPrincipalVersion Version
	Device                   DeviceState
	DeviceID                 DeviceID
	DisplayName              DisplayName
	PublicKeyReference       PublicKeyReference
	Challenge                CeremonyChallenge
	ChallengeCreation        CeremonyCreationExpectation
}

type BeginDevicePairingResult struct {
	device DeviceState
	facts  []IdentityFact
}

func BeginDevicePairing(input BeginDevicePairingInput) (BeginDevicePairingResult, error) {
	if !input.Device.IsZero() {
		return BeginDevicePairingResult{}, transitionConflict(ConflictState, "device registration already exists")
	}
	if input.DeviceID.IsZero() || input.DisplayName.String() == "" ||
		input.PublicKeyReference.String() == "" || input.Challenge.IsZero() ||
		!input.ChallengeCreation.matches(input.Challenge) {
		return BeginDevicePairingResult{}, transitionError(ErrorCodeInvalidArgument, "device pairing input is invalid")
	}
	if err := checkActivePrincipal(input.Authorization, input.Principal, input.ExpectedPrincipalVersion, capabilityDevicePair); err != nil {
		return BeginDevicePairingResult{}, err
	}
	if err := checkInstallationAuthorization(input.Authorization); err != nil {
		return BeginDevicePairingResult{}, err
	}
	if input.Challenge.Purpose() != CeremonyPurposeDevicePairing ||
		input.Challenge.Status() != CeremonyPending ||
		input.Challenge.InstallationID() != input.Authorization.InstallationID() ||
		input.Challenge.PrincipalID() != input.Principal.ID() || input.Challenge.DeviceID() != input.DeviceID ||
		!input.Challenge.ExpiresAt().After(input.Authorization.EvaluatedAt()) {
		return BeginDevicePairingResult{}, transitionConflict(ConflictReference, "device challenge binding does not match")
	}
	device := DeviceState{
		id:                 input.DeviceID,
		installationID:     input.Authorization.InstallationID(),
		principalID:        input.Principal.ID(),
		displayName:        input.DisplayName,
		publicKey:          input.PublicKeyReference,
		status:             DevicePending,
		version:            InitialVersion(),
		trustRevision:      InitialVersion(),
		revocationRevision: InitialVersion(),
		pairing:            input.Challenge,
	}
	origin, err := identityOrigin(device.ID(), device.Version())
	if err != nil {
		return BeginDevicePairingResult{}, err
	}
	fact := DevicePairingBeganFact{
		origin: origin, installationID: device.InstallationID(), deviceID: device.ID(), principalID: device.PrincipalID(),
		ceremonyID: input.Challenge.ID(), displayName: device.DisplayName(), publicKey: device.PublicKeyReference(),
	}
	return BeginDevicePairingResult{device: device, facts: []IdentityFact{fact}}, nil
}

func (result BeginDevicePairingResult) Device() DeviceState { return result.device }
func (result BeginDevicePairingResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}

type PairDeviceInput struct {
	Authorization            PairingRedemptionAuthorization
	CurrentAuthorization     IdentityAuthorization
	AuthorityTime            time.Time
	Principal                PrincipalState
	ExpectedPrincipalVersion Version
	Device                   DeviceState
	ExpectedDeviceVersion    Version
	ExpectedTrustRevision    Version
	Proof                    CeremonyProof
}

type PairDeviceResult struct {
	device DeviceState
	facts  []IdentityFact
}

func PairDevice(input PairDeviceInput) (PairDeviceResult, error) {
	if err := checkExpectedVersion(input.Principal.Version(), input.ExpectedPrincipalVersion); err != nil {
		return PairDeviceResult{}, err
	}
	if err := checkExpectedVersion(input.Device.Version(), input.ExpectedDeviceVersion); err != nil {
		return PairDeviceResult{}, err
	}
	if err := checkExpectedVersion(input.Device.TrustRevision(), input.ExpectedTrustRevision); err != nil {
		return PairDeviceResult{}, err
	}
	if input.Device.Status() != DevicePending {
		return PairDeviceResult{}, transitionConflict(ConflictState, "device is not pending pairing")
	}
	if !validPairingRedemptionAuthorization(input.Authorization) ||
		input.CurrentAuthorization.AuthorityID() != input.Authorization.AuthorityID() ||
		input.CurrentAuthorization.AuthorityEpoch() != input.Authorization.AuthorityEpoch() ||
		input.CurrentAuthorization.InstallationID() != input.Authorization.InstallationID() ||
		input.CurrentAuthorization.PrincipalID() != input.Authorization.PrincipalID() ||
		input.CurrentAuthorization.PolicyRevision() != input.Authorization.PolicyRevision() ||
		input.CurrentAuthorization.AssuranceClass() != input.Authorization.AssuranceClass() ||
		input.AuthorityTime.IsZero() || !input.CurrentAuthorization.EvaluatedAt().Equal(input.AuthorityTime) ||
		!input.CurrentAuthorization.Capabilities().Contains(DevicePairCapability()) ||
		input.Authorization.InstallationID() != input.Principal.InstallationID() ||
		input.Authorization.PrincipalID() != input.Principal.ID() ||
		input.Authorization.DeviceID() != input.Device.ID() ||
		input.Authorization.PolicyRevision().String() == "" || input.Authorization.AssuranceClass().String() == "" ||
		input.Authorization.EvaluatedAt().IsZero() ||
		input.Principal.Status() != PrincipalActive || input.Device.InstallationID() != input.Principal.InstallationID() ||
		input.Device.PrincipalID() != input.Principal.ID() || input.Proof.PrincipalID() != input.Principal.ID() ||
		input.Proof.DeviceID() != input.Device.ID() {
		return PairDeviceResult{}, transitionError(ErrorCodeForbidden, "device pairing principal does not match")
	}
	pairing := input.Device.PairingChallenge()
	if input.Authorization.ChallengeID() != pairing.ID() ||
		input.Authorization.TranscriptFingerprint() != input.Proof.ProofDigest() ||
		input.Authorization.Credential().TranscriptFingerprint() != input.Proof.ProofDigest() ||
		input.Authorization.Credential().PublicKeyReference() != input.Device.PublicKeyReference() ||
		pairing.InstallationID() != input.Device.InstallationID() ||
		pairing.PrincipalID() != input.Device.PrincipalID() || pairing.DeviceID() != input.Device.ID() {
		return PairDeviceResult{}, transitionConflict(ConflictReference, "device challenge binding is stale or malformed")
	}
	if err := checkCeremony(pairing, input.Proof,
		CeremonyPurposeDevicePairing, input.AuthorityTime); err != nil {
		return PairDeviceResult{}, err
	}
	nextVersion, err := nextTransitionVersion(input.Device.Version())
	if err != nil {
		return PairDeviceResult{}, err
	}
	nextTrustRevision, err := nextTransitionVersion(input.Device.TrustRevision())
	if err != nil {
		return PairDeviceResult{}, err
	}
	device := input.Device
	device.status = DeviceTrusted
	device.version = nextVersion
	device.trustRevision = nextTrustRevision
	device.pairing = device.pairing.consume()
	device.credential = input.Authorization.Credential()
	device.credentialActivatedAt = input.AuthorityTime.UTC()
	origin, err := identityOrigin(device.ID(), device.Version())
	if err != nil {
		return PairDeviceResult{}, err
	}
	fact := DevicePairedFact{
		origin: origin, installationID: device.InstallationID(),
		deviceID: device.ID(), principalID: device.PrincipalID(), displayName: device.DisplayName(),
		transcript:         input.Proof.ProofDigest(),
		trustRevision:      device.TrustRevision(),
		revocationRevision: device.RevocationRevision(),
		credential:         device.CredentialBinding(),
		activatedAt:        device.CredentialActivatedAt(),
	}
	return PairDeviceResult{device: device, facts: []IdentityFact{fact}}, nil
}

func (result PairDeviceResult) Device() DeviceState   { return result.device }
func (result PairDeviceResult) Facts() []IdentityFact { return cloneIdentityFacts(result.facts) }

// VerifiedDeviceCredentialPossession is verifier output for one side of a
// rotation. It carries only public binding metadata; signature bytes and key
// material remain at the authentication boundary.
type VerifiedDeviceCredentialPossession struct {
	deviceID   DeviceID
	credential CredentialDigest
	transcript CommandFingerprint
	verifiedAt time.Time
}

func NewVerifiedDeviceCredentialPossession(
	deviceID DeviceID,
	credential CredentialDigest,
	transcript CommandFingerprint,
	verifiedAt time.Time,
) (VerifiedDeviceCredentialPossession, error) {
	if deviceID.IsZero() || credential.IsZero() || transcript.IsZero() || verifiedAt.IsZero() {
		return VerifiedDeviceCredentialPossession{}, ErrInvalidAuthorization
	}
	return VerifiedDeviceCredentialPossession{
		deviceID: deviceID, credential: credential, transcript: transcript, verifiedAt: verifiedAt.UTC(),
	}, nil
}

type DeviceCredentialRotationCommand struct {
	device                DeviceState
	expectedVersion       Version
	expectedTrustRevision Version
	newCredential         DeviceCredentialBinding
	oldPossession         VerifiedDeviceCredentialPossession
	newPossession         VerifiedDeviceCredentialPossession
	overlap               time.Duration
	rotatedAt             time.Time
}

func NewDeviceCredentialRotationCommand(
	device DeviceState,
	expectedVersion Version,
	expectedTrustRevision Version,
	newCredential DeviceCredentialBinding,
	oldPossession VerifiedDeviceCredentialPossession,
	newPossession VerifiedDeviceCredentialPossession,
	overlap time.Duration,
	rotatedAt time.Time,
) (DeviceCredentialRotationCommand, error) {
	active := device.CredentialBinding()
	if device.IsZero() || device.Status() != DeviceTrusted || !expectedVersion.Valid() ||
		!expectedTrustRevision.Valid() || !validDeviceCredentialBinding(active) ||
		!validDeviceCredentialBinding(newCredential) ||
		newCredential.SPKIFingerprint() == active.SPKIFingerprint() ||
		newCredential.PublicKeyReference() == active.PublicKeyReference() ||
		overlap <= 0 || overlap > MaxDeviceCredentialOverlap || rotatedAt.IsZero() ||
		oldPossession.deviceID != device.ID() || newPossession.deviceID != device.ID() ||
		oldPossession.credential != active.SPKIFingerprint() ||
		newPossession.credential != newCredential.SPKIFingerprint() ||
		oldPossession.transcript.IsZero() || oldPossession.transcript != newPossession.transcript ||
		newCredential.TranscriptFingerprint() != oldPossession.transcript ||
		oldPossession.verifiedAt.IsZero() || !oldPossession.verifiedAt.Equal(rotatedAt) ||
		newPossession.verifiedAt.IsZero() || !newPossession.verifiedAt.Equal(rotatedAt) {
		return DeviceCredentialRotationCommand{}, ErrInvalidAuthorization
	}
	return DeviceCredentialRotationCommand{
		device: device, expectedVersion: expectedVersion, expectedTrustRevision: expectedTrustRevision,
		newCredential: newCredential, oldPossession: oldPossession, newPossession: newPossession,
		overlap: overlap, rotatedAt: rotatedAt.UTC(),
	}, nil
}

type DeviceCredentialRotationResult struct {
	device DeviceState
	facts  []IdentityFact
}

func RotateDeviceCredential(command DeviceCredentialRotationCommand) (DeviceCredentialRotationResult, error) {
	if command.device.IsZero() || command.oldPossession.deviceID.IsZero() || command.newPossession.deviceID.IsZero() {
		return DeviceCredentialRotationResult{}, transitionError(ErrorCodeInvalidArgument, "credential rotation command is invalid")
	}
	if err := checkExpectedVersion(command.device.Version(), command.expectedVersion); err != nil {
		return DeviceCredentialRotationResult{}, err
	}
	if err := checkExpectedVersion(command.device.TrustRevision(), command.expectedTrustRevision); err != nil {
		return DeviceCredentialRotationResult{}, err
	}
	if command.device.Status() != DeviceTrusted {
		return DeviceCredentialRotationResult{}, transitionConflict(ConflictState, "device is not trusted")
	}
	nextVersion, err := nextTransitionVersion(command.device.Version())
	if err != nil {
		return DeviceCredentialRotationResult{}, err
	}
	nextTrustRevision, err := nextTransitionVersion(command.device.TrustRevision())
	if err != nil {
		return DeviceCredentialRotationResult{}, err
	}
	device := command.device
	previous := device.credential
	device.publicKey = command.newCredential.PublicKeyReference()
	device.credential = command.newCredential
	device.credentialActivatedAt = command.rotatedAt
	device.retiringCredential = previous
	device.retiringCredentialExpiresAt = command.rotatedAt.Add(command.overlap)
	device.lastRotationTranscript = command.newCredential.TranscriptFingerprint()
	device.rotatedAt = command.rotatedAt
	device.version = nextVersion
	device.trustRevision = nextTrustRevision
	if device.revocationRevision.IsZero() {
		device.revocationRevision = InitialVersion()
	}
	origin, err := identityOrigin(device.ID(), device.Version())
	if err != nil {
		return DeviceCredentialRotationResult{}, err
	}
	fact := DeviceCredentialRotatedFact{
		origin: origin, deviceID: device.ID(), previousCredential: previous,
		activeCredential: device.CredentialBinding(), trustRevision: device.TrustRevision(),
		revocationRevision: device.RevocationRevision(), transcript: device.RotationTranscriptFingerprint(),
		rotatedAt: device.RotatedAt(), retiringExpiresAt: device.retiringCredentialExpiresAt,
	}
	return DeviceCredentialRotationResult{device: device, facts: []IdentityFact{fact}}, nil
}

func (result DeviceCredentialRotationResult) Device() DeviceState { return result.device }
func (result DeviceCredentialRotationResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}

type DeviceRevocationCommand struct {
	device                     DeviceState
	expectedVersion            Version
	expectedTrustRevision      Version
	expectedRevocationRevision Version
	revocationFingerprint      CommandFingerprint
	revokedAt                  time.Time
}

func NewDeviceRevocationCommand(
	device DeviceState,
	expectedVersion Version,
	expectedTrustRevision Version,
	expectedRevocationRevision Version,
	revocationFingerprint CommandFingerprint,
	revokedAt time.Time,
) (DeviceRevocationCommand, error) {
	if device.IsZero() || !expectedVersion.Valid() || !expectedTrustRevision.Valid() ||
		!expectedRevocationRevision.Valid() || revocationFingerprint.IsZero() || revokedAt.IsZero() ||
		device.Status() == DevicePending || device.Status() == DeviceRevoked ||
		!validDeviceCredentialBinding(device.CredentialBinding()) {
		return DeviceRevocationCommand{}, ErrInvalidAuthorization
	}
	return DeviceRevocationCommand{
		device: device, expectedVersion: expectedVersion, expectedTrustRevision: expectedTrustRevision,
		expectedRevocationRevision: expectedRevocationRevision,
		revocationFingerprint:      revocationFingerprint, revokedAt: revokedAt.UTC(),
	}, nil
}

type DeviceRevocationResult struct {
	device DeviceState
	facts  []IdentityFact
}

func RevokeDevice(command DeviceRevocationCommand) (DeviceRevocationResult, error) {
	if command.device.IsZero() || command.revocationFingerprint.IsZero() {
		return DeviceRevocationResult{}, transitionError(ErrorCodeInvalidArgument, "device revocation command is invalid")
	}
	if err := checkExpectedVersion(command.device.Version(), command.expectedVersion); err != nil {
		return DeviceRevocationResult{}, err
	}
	if err := checkExpectedVersion(command.device.TrustRevision(), command.expectedTrustRevision); err != nil {
		return DeviceRevocationResult{}, err
	}
	if err := checkExpectedVersion(command.device.RevocationRevision(), command.expectedRevocationRevision); err != nil {
		return DeviceRevocationResult{}, err
	}
	if command.device.Status() == DeviceRevoked {
		return DeviceRevocationResult{}, transitionConflict(ConflictState, "device revocation is terminal")
	}
	nextVersion, err := nextTransitionVersion(command.device.Version())
	if err != nil {
		return DeviceRevocationResult{}, err
	}
	nextTrustRevision, err := nextTransitionVersion(command.device.TrustRevision())
	if err != nil {
		return DeviceRevocationResult{}, err
	}
	nextRevocationRevision, err := nextTransitionVersion(command.device.RevocationRevision())
	if err != nil {
		return DeviceRevocationResult{}, err
	}
	device := command.device
	device.status = DeviceRevoked
	device.version = nextVersion
	device.trustRevision = nextTrustRevision
	device.revocationRevision = nextRevocationRevision
	device.retiringCredential = DeviceCredentialBinding{}
	device.retiringCredentialExpiresAt = time.Time{}
	device.revokedAt = command.revokedAt
	origin, err := identityOrigin(device.ID(), device.Version())
	if err != nil {
		return DeviceRevocationResult{}, err
	}
	fact := DeviceRevokedFact{
		origin: origin, deviceID: device.ID(), credential: device.CredentialBinding(),
		trustRevision: device.TrustRevision(), revocationRevision: device.RevocationRevision(),
		revocationFingerprint: command.revocationFingerprint, revokedAt: device.RevokedAt(),
	}
	return DeviceRevocationResult{device: device, facts: []IdentityFact{fact}}, nil
}

func (result DeviceRevocationResult) Device() DeviceState   { return result.device }
func (result DeviceRevocationResult) Facts() []IdentityFact { return cloneIdentityFacts(result.facts) }

type ObserveWorkRefInput struct {
	Authorization                IdentityAuthorization
	Adapter                      PrincipalState
	ExpectedAdapterVersion       Version
	Workspace                    WorkspaceState
	ExpectedWorkspaceVersion     Version
	WorkReference                WorkReferenceState
	ExpectedWorkReferenceVersion Version
	WorkReferenceID              WorkReferenceID
	Observation                  ProviderObservation
	PreviousProviderVersion      OpaqueProviderValue
}

type ObserveWorkRefResult struct {
	workReference WorkReferenceState
	facts         []IdentityFact
}

func ObserveWorkRef(input ObserveWorkRefInput) (ObserveWorkRefResult, error) {
	if input.WorkReferenceID.IsZero() || !validProviderObservation(input.Observation) ||
		input.Observation.AdapterPrincipalID() != input.Authorization.PrincipalID() ||
		input.Observation.ObservedAt().After(input.Authorization.EvaluatedAt()) {
		return ObserveWorkRefResult{}, transitionError(ErrorCodeInvalidArgument, "provider observation is invalid")
	}
	if err := checkWorkspaceAuthority(input.Authorization, input.Workspace, input.ExpectedWorkspaceVersion); err != nil {
		return ObserveWorkRefResult{}, err
	}
	if err := checkActivePrincipal(input.Authorization, input.Adapter, input.ExpectedAdapterVersion, Capability{}); err != nil {
		return ObserveWorkRefResult{}, err
	}
	if input.Adapter.Kind() != PrincipalKindService {
		return ObserveWorkRefResult{}, transitionConflict(ConflictProviderAuthority, "provider adapter is not a service principal")
	}
	version := InitialVersion()
	if !input.WorkReference.IsZero() {
		if err := checkExpectedVersion(input.WorkReference.Version(), input.ExpectedWorkReferenceVersion); err != nil {
			return ObserveWorkRefResult{}, err
		}
		current := input.WorkReference.Observation()
		if input.WorkReference.ID() != input.WorkReferenceID || input.WorkReference.WorkspaceID() != input.Workspace.ID() ||
			current.Namespace() != input.Observation.Namespace() || current.ObjectID() != input.Observation.ObjectID() ||
			current.AdapterPrincipalID() != input.Observation.AdapterPrincipalID() {
			return ObserveWorkRefResult{}, transitionConflict(ConflictProviderAuthority, "provider observation authority changed")
		}
		if input.PreviousProviderVersion != current.ProviderVersion() ||
			input.Observation.ProviderVersion() == current.ProviderVersion() ||
			!input.Observation.ObservedAt().After(current.ObservedAt()) {
			return ObserveWorkRefResult{}, transitionConflict(ConflictProviderObservation, "provider observation is stale or regressed")
		}
		var err error
		version, err = nextTransitionVersion(input.WorkReference.Version())
		if err != nil {
			return ObserveWorkRefResult{}, err
		}
	} else if !workReferenceStateIsEmpty(input.WorkReference) || !input.ExpectedWorkReferenceVersion.IsZero() ||
		input.PreviousProviderVersion.String() != "" {
		return ObserveWorkRefResult{}, transitionConflict(ConflictProviderObservation, "new provider observation has stale predecessor")
	}
	state := WorkReferenceState{id: input.WorkReferenceID, workspaceID: input.Workspace.ID(),
		observation: input.Observation, version: version}
	origin, err := identityOrigin(state.ID(), state.Version())
	if err != nil {
		return ObserveWorkRefResult{}, err
	}
	return ObserveWorkRefResult{workReference: state, facts: []IdentityFact{
		WorkRefObservedFact{origin: origin, workspaceID: state.WorkspaceID(), observation: state.Observation()},
	}}, nil
}

func workReferenceStateIsEmpty(state WorkReferenceState) bool {
	return state.id.IsZero() && state.workspaceID.IsZero() && state.observation.namespace.String() == "" &&
		state.observation.objectID.String() == "" && state.observation.locator.String() == "" &&
		state.observation.providerVersion.String() == "" && state.observation.fields.IsZero() &&
		state.observation.adapter.IsZero() && state.observation.observedAt.IsZero() && state.version.IsZero()
}

func (result ObserveWorkRefResult) WorkReference() WorkReferenceState { return result.workReference }
func (result ObserveWorkRefResult) Facts() []IdentityFact             { return cloneIdentityFacts(result.facts) }

type CreateObjectiveAndWorkInput struct {
	Session                      ActorSessionState
	ExpectedSessionVersion       Version
	Objective                    ObjectiveState
	ObjectiveID                  ObjectiveID
	ObjectiveTitle               string
	AcceptanceCriteria           string
	WorkUnit                     WorkUnitState
	WorkUnitID                   WorkUnitID
	WorkUnitTitle                string
	WorkReference                WorkReferenceState
	ExpectedWorkReferenceVersion Version
}

type CreateObjectiveAndWorkResult struct {
	objective ObjectiveState
	workUnit  WorkUnitState
	facts     []IdentityFact
}

func CreateObjectiveAndWork(input CreateObjectiveAndWorkInput) (CreateObjectiveAndWorkResult, error) {
	if !input.Objective.IsZero() || !input.WorkUnit.IsZero() {
		return CreateObjectiveAndWorkResult{}, transitionConflict(ConflictState, "objective or work unit already exists")
	}
	if input.ObjectiveID.IsZero() || input.WorkUnitID.IsZero() ||
		!validBoundedText(input.ObjectiveTitle, 512) || !validBoundedText(input.AcceptanceCriteria, 8192) ||
		!validBoundedText(input.WorkUnitTitle, 512) {
		return CreateObjectiveAndWorkResult{}, transitionError(ErrorCodeInvalidArgument, "objective and work input is invalid")
	}
	if err := checkWorkSession(input.Session, input.ExpectedSessionVersion); err != nil {
		return CreateObjectiveAndWorkResult{}, err
	}
	workspaceID := input.Session.Binding().WorkspaceID()
	workReferenceID := WorkReferenceID{}
	if !input.WorkReference.IsZero() {
		if input.WorkReference.WorkspaceID() != workspaceID {
			return CreateObjectiveAndWorkResult{}, transitionConflict(ConflictProviderAuthority, "work reference belongs to another workspace")
		}
		if err := checkExpectedVersion(input.WorkReference.Version(), input.ExpectedWorkReferenceVersion); err != nil {
			return CreateObjectiveAndWorkResult{}, err
		}
		workReferenceID = input.WorkReference.ID()
	} else if !workReferenceStateIsEmpty(input.WorkReference) || !input.ExpectedWorkReferenceVersion.IsZero() {
		return CreateObjectiveAndWorkResult{}, transitionError(ErrorCodeInvalidArgument, "work reference shape is invalid")
	}
	objective := ObjectiveState{id: input.ObjectiveID, workspaceID: workspaceID,
		title: input.ObjectiveTitle, acceptanceCriteria: input.AcceptanceCriteria,
		status: ObjectiveDraft, version: InitialVersion()}
	workUnit := WorkUnitState{id: input.WorkUnitID, workspaceID: objective.WorkspaceID(), objectiveID: objective.ID(),
		workReferenceID: workReferenceID, title: input.WorkUnitTitle,
		status: WorkUnitProposed, version: InitialVersion()}
	objectiveOrigin, _ := identityOrigin(objective.ID(), objective.Version())
	workOrigin, _ := identityOrigin(workUnit.ID(), workUnit.Version())
	return CreateObjectiveAndWorkResult{objective: objective, workUnit: workUnit, facts: []IdentityFact{
		ObjectiveCreatedFact{origin: objectiveOrigin, workspaceID: objective.WorkspaceID(), title: objective.Title(), acceptanceCriteria: objective.AcceptanceCriteria()},
		WorkUnitCreatedFact{origin: workOrigin, workspaceID: workUnit.WorkspaceID(), objectiveID: workUnit.ObjectiveID(), workReferenceID: workUnit.WorkReferenceID(), title: workUnit.Title()},
	}}, nil
}

func (result CreateObjectiveAndWorkResult) Objective() ObjectiveState { return result.objective }
func (result CreateObjectiveAndWorkResult) WorkUnit() WorkUnitState   { return result.workUnit }
func (result CreateObjectiveAndWorkResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}

type ActivateObjectiveInput struct {
	Session                  ActorSessionState
	ExpectedSessionVersion   Version
	Objective                ObjectiveState
	ExpectedObjectiveVersion Version
}

type ActivateObjectiveResult struct {
	objective ObjectiveState
	facts     []IdentityFact
}

func ActivateObjective(input ActivateObjectiveInput) (ActivateObjectiveResult, error) {
	if err := checkWorkSession(input.Session, input.ExpectedSessionVersion); err != nil {
		return ActivateObjectiveResult{}, err
	}
	if err := checkExpectedVersion(input.Objective.Version(), input.ExpectedObjectiveVersion); err != nil {
		return ActivateObjectiveResult{}, err
	}
	if input.Objective.WorkspaceID() != input.Session.Binding().WorkspaceID() {
		return ActivateObjectiveResult{}, transitionConflict(ConflictReference, "objective belongs to another workspace")
	}
	if input.Objective.Status() != ObjectiveDraft {
		return ActivateObjectiveResult{}, transitionConflict(ConflictState, "objective is not draft")
	}
	next, err := nextTransitionVersion(input.Objective.Version())
	if err != nil {
		return ActivateObjectiveResult{}, err
	}
	objective := input.Objective
	objective.status, objective.version = ObjectiveActive, next
	origin, _ := identityOrigin(objective.ID(), objective.Version())
	return ActivateObjectiveResult{objective: objective, facts: []IdentityFact{
		ObjectiveActivatedFact{origin: origin, objectiveID: objective.ID()},
	}}, nil
}

func (result ActivateObjectiveResult) Objective() ObjectiveState { return result.objective }
func (result ActivateObjectiveResult) Facts() []IdentityFact     { return cloneIdentityFacts(result.facts) }

type RunParticipantPlan struct {
	ParticipationID        RunParticipationID
	Actor                  ActorState
	ExpectedActorVersion   Version
	Session                ActorSessionState
	ExpectedSessionVersion Version
	Role                   string
}

type RuntimeBindingPlan struct {
	BindingID       RuntimeBindingID
	ParticipationID RunParticipationID
	SessionID       ActorSessionID
	Endpoint        AggregateRef
}

type PlanRunWithBindingsInput struct {
	OperatorSession                ActorSessionState
	ExpectedOperatorSessionVersion Version
	Run                            RunState
	RunID                          RunID
	Objective                      ObjectiveState
	ExpectedObjectiveVersion       Version
	WorkUnit                       WorkUnitState
	ExpectedWorkUnitVersion        Version
	Participants                   []RunParticipantPlan
	Bindings                       []RuntimeBindingPlan
}

type PlanRunWithBindingsResult struct {
	run            RunState
	participations []RunParticipationState
	bindings       []RuntimeBindingState
	facts          []IdentityFact
}

func PlanRunWithBindings(input PlanRunWithBindingsInput) (PlanRunWithBindingsResult, error) {
	if !input.Run.IsZero() {
		return PlanRunWithBindingsResult{}, transitionConflict(ConflictState, "run already exists")
	}
	if input.RunID.IsZero() || len(input.Participants) == 0 ||
		len(input.Participants) > MaxRunParticipants || len(input.Bindings) == 0 || len(input.Bindings) > MaxRunBindings {
		return PlanRunWithBindingsResult{}, transitionError(ErrorCodeInvalidArgument, "run plan exceeds its bounded shape")
	}
	if err := checkWorkSession(input.OperatorSession, input.ExpectedOperatorSessionVersion); err != nil {
		return PlanRunWithBindingsResult{}, err
	}
	if err := checkExpectedVersion(input.Objective.Version(), input.ExpectedObjectiveVersion); err != nil {
		return PlanRunWithBindingsResult{}, err
	}
	if err := checkExpectedVersion(input.WorkUnit.Version(), input.ExpectedWorkUnitVersion); err != nil {
		return PlanRunWithBindingsResult{}, err
	}
	workspace := input.OperatorSession.Binding().WorkspaceID()
	if input.Objective.Status() != ObjectiveActive || input.Objective.WorkspaceID() != workspace ||
		input.WorkUnit.WorkspaceID() != workspace || input.WorkUnit.ObjectiveID() != input.Objective.ID() {
		return PlanRunWithBindingsResult{}, transitionConflict(ConflictReference, "run objective and work references do not match")
	}
	participants := append([]RunParticipantPlan(nil), input.Participants...)
	sort.Slice(participants, func(i, j int) bool {
		return participants[i].ParticipationID.String() < participants[j].ParticipationID.String()
	})
	participations := make([]RunParticipationState, len(participants))
	byID := make(map[RunParticipationID]RunParticipationState, len(participants))
	seenActors := make(map[ActorID]struct{}, len(participants))
	for index, plan := range participants {
		if plan.ParticipationID.IsZero() || !validBoundedText(plan.Role, 128) || plan.Actor.IsZero() ||
			plan.Actor.WorkspaceID() != workspace || plan.Actor.Status() != ActorActive ||
			plan.Session.Binding().ActorID() != plan.Actor.ID() || plan.Session.Binding().WorkspaceID() != workspace {
			return PlanRunWithBindingsResult{}, transitionConflict(ConflictParticipant, "run participant plan is invalid")
		}
		if err := checkExpectedVersion(plan.Actor.Version(), plan.ExpectedActorVersion); err != nil {
			return PlanRunWithBindingsResult{}, err
		}
		if err := checkWorkSession(plan.Session, plan.ExpectedSessionVersion); err != nil {
			return PlanRunWithBindingsResult{}, err
		}
		if _, duplicate := seenActors[plan.Actor.ID()]; duplicate {
			return PlanRunWithBindingsResult{}, transitionConflict(ConflictParticipant, "actor is invited more than once")
		}
		if _, duplicate := byID[plan.ParticipationID]; duplicate {
			return PlanRunWithBindingsResult{}, transitionConflict(ConflictParticipant, "participation identity is duplicated")
		}
		seenActors[plan.Actor.ID()] = struct{}{}
		state := RunParticipationState{id: plan.ParticipationID, runID: input.RunID, actorID: plan.Actor.ID(),
			role: plan.Role, status: RunParticipationInvited, version: InitialVersion()}
		participations[index], byID[state.ID()] = state, state
	}
	bindingPlans := append([]RuntimeBindingPlan(nil), input.Bindings...)
	sort.Slice(bindingPlans, func(i, j int) bool { return bindingPlans[i].BindingID.String() < bindingPlans[j].BindingID.String() })
	bindings := make([]RuntimeBindingState, len(bindingPlans))
	seenBindings := make(map[RuntimeBindingID]struct{}, len(bindingPlans))
	for index, plan := range bindingPlans {
		participant, exists := byID[plan.ParticipationID]
		if plan.BindingID.IsZero() || !exists || plan.SessionID.IsZero() || plan.Endpoint.Kind() != AggregateKindRuntimeEndpoint || plan.Endpoint.IsZero() {
			return PlanRunWithBindingsResult{}, transitionConflict(ConflictReference, "runtime binding plan is invalid")
		}
		if _, duplicate := seenBindings[plan.BindingID]; duplicate {
			return PlanRunWithBindingsResult{}, transitionConflict(ConflictReference, "runtime binding is duplicated")
		}
		seenBindings[plan.BindingID] = struct{}{}
		matched := false
		for _, declared := range participants {
			matched = matched || declared.ParticipationID == participant.ID() && declared.Session.ID() == plan.SessionID
		}
		if !matched {
			return PlanRunWithBindingsResult{}, transitionConflict(ConflictParticipant, "binding session does not match participant")
		}
		endpoint, err := ParseRuntimeEndpointID(plan.Endpoint.ID())
		if err != nil {
			return PlanRunWithBindingsResult{}, transitionConflict(ConflictReference, "runtime endpoint identity is invalid")
		}
		bindings[index] = RuntimeBindingState{id: plan.BindingID, runID: input.RunID, participationID: participant.ID(),
			sessionID: plan.SessionID, endpointID: endpoint, status: RuntimeBindingRequested, version: InitialVersion()}
	}
	requiredParticipationIDs := make([]RunParticipationID, len(participations))
	for index, participation := range participations {
		requiredParticipationIDs[index] = participation.ID()
	}
	run := RunState{id: input.RunID, workspaceID: workspace, objectiveID: input.Objective.ID(),
		workUnitID: input.WorkUnit.ID(), operatorID: input.OperatorSession.Binding().ActorID(),
		requiredParticipationIDs: requiredParticipationIDs, status: RunPlanned, version: InitialVersion()}
	runOrigin, _ := identityOrigin(run.ID(), run.Version())
	facts := []IdentityFact{RunPlannedFact{origin: runOrigin, objectiveID: run.ObjectiveID(), workUnitID: run.WorkUnitID(), operatorID: run.OperatorID()}}
	for _, state := range participations {
		origin, _ := identityOrigin(state.ID(), state.Version())
		facts = append(facts, RunParticipantInvitedFact{origin: origin, runID: state.RunID(), actorID: state.ActorID(), role: state.Role()})
	}
	for _, state := range bindings {
		origin, _ := identityOrigin(state.ID(), state.Version())
		facts = append(facts, RuntimeBindingRequestedFact{origin: origin, runID: state.RunID(), participationID: state.ParticipationID(), sessionID: state.ActorSessionID(), endpointID: state.RuntimeEndpointID()})
	}
	return PlanRunWithBindingsResult{run: run, participations: participations, bindings: bindings, facts: facts}, nil
}

func (result PlanRunWithBindingsResult) Run() RunState { return result.run }
func (result PlanRunWithBindingsResult) Participations() []RunParticipationState {
	return append([]RunParticipationState(nil), result.participations...)
}
func (result PlanRunWithBindingsResult) Bindings() []RuntimeBindingState {
	return append([]RuntimeBindingState(nil), result.bindings...)
}
func (result PlanRunWithBindingsResult) Facts() []IdentityFact {
	return cloneIdentityFacts(result.facts)
}

type JoinRunInput struct {
	Session                      ActorSessionState
	ExpectedSessionVersion       Version
	Run                          RunState
	ExpectedRunVersion           Version
	Participation                RunParticipationState
	ExpectedParticipationVersion Version
}

type JoinRunResult struct {
	participation RunParticipationState
	facts         []IdentityFact
}

func JoinRun(input JoinRunInput) (JoinRunResult, error) {
	if err := checkWorkSession(input.Session, input.ExpectedSessionVersion); err != nil {
		return JoinRunResult{}, err
	}
	if err := checkExpectedVersion(input.Run.Version(), input.ExpectedRunVersion); err != nil {
		return JoinRunResult{}, err
	}
	if err := checkExpectedVersion(input.Participation.Version(), input.ExpectedParticipationVersion); err != nil {
		return JoinRunResult{}, err
	}
	if input.Run.Status() != RunPlanned || input.Participation.Status() != RunParticipationInvited ||
		input.Participation.RunID() != input.Run.ID() || input.Participation.ActorID() != input.Session.Binding().ActorID() ||
		input.Run.WorkspaceID() != input.Session.Binding().WorkspaceID() {
		return JoinRunResult{}, transitionConflict(ConflictParticipant, "actor session is not the invited run participant")
	}
	next, err := nextTransitionVersion(input.Participation.Version())
	if err != nil {
		return JoinRunResult{}, err
	}
	participation := input.Participation
	participation.status, participation.sessionID, participation.version = RunParticipationActive, input.Session.ID(), next
	origin, _ := identityOrigin(participation.ID(), participation.Version())
	return JoinRunResult{participation: participation, facts: []IdentityFact{RunParticipantJoinedFact{
		origin: origin, runID: participation.RunID(), actorID: participation.ActorID(), sessionID: participation.ActorSessionID(),
	}}}, nil
}

func (result JoinRunResult) Participation() RunParticipationState { return result.participation }
func (result JoinRunResult) Facts() []IdentityFact                { return cloneIdentityFacts(result.facts) }

type StartRunInput struct {
	OperatorSession                ActorSessionState
	ExpectedOperatorSessionVersion Version
	Run                            RunState
	ExpectedRunVersion             Version
	Participations                 []RunParticipationSnapshot
}

type RunParticipationSnapshot struct {
	Participation   RunParticipationState
	ExpectedVersion Version
}

type StartRunResult struct {
	run   RunState
	facts []IdentityFact
}

func StartRun(input StartRunInput) (StartRunResult, error) {
	if err := checkWorkSession(input.OperatorSession, input.ExpectedOperatorSessionVersion); err != nil {
		return StartRunResult{}, err
	}
	if err := checkExpectedVersion(input.Run.Version(), input.ExpectedRunVersion); err != nil {
		return StartRunResult{}, err
	}
	if input.Run.Status() != RunPlanned || input.Run.OperatorID() != input.OperatorSession.Binding().ActorID() || len(input.Participations) == 0 || len(input.Participations) > MaxRunParticipants {
		return StartRunResult{}, transitionConflict(ConflictParticipant, "run start policy is not satisfied")
	}
	required := input.Run.RequiredParticipationIDs()
	if len(input.Participations) != len(required) {
		return StartRunResult{}, transitionConflict(ConflictParticipant, "all declared participants must be joined")
	}
	seen := make(map[RunParticipationID]struct{}, len(input.Participations))
	participationRefs := make([]AggregateRef, 0, len(input.Participations))
	for _, snapshot := range input.Participations {
		participant := snapshot.Participation
		if err := checkExpectedVersion(participant.Version(), snapshot.ExpectedVersion); err != nil {
			return StartRunResult{}, err
		}
		if participant.RunID() != input.Run.ID() || participant.Status() != RunParticipationActive || participant.ActorSessionID().IsZero() {
			return StartRunResult{}, transitionConflict(ConflictParticipant, "all declared participants must be joined")
		}
		if _, duplicate := seen[participant.ID()]; duplicate {
			return StartRunResult{}, transitionConflict(ConflictParticipant, "participation is cited more than once")
		}
		seen[participant.ID()] = struct{}{}
		ref, err := NewAggregateRef(participant.ID(), participant.Version())
		if err != nil {
			return StartRunResult{}, transitionConflict(ConflictParticipant, "participation revision is invalid")
		}
		participationRefs = append(participationRefs, ref)
	}
	for _, participationID := range required {
		if _, present := seen[participationID]; !present {
			return StartRunResult{}, transitionConflict(ConflictParticipant, "run start roster does not match its declared policy")
		}
	}
	sort.Slice(participationRefs, func(left, right int) bool {
		return participationRefs[left].Target().String() < participationRefs[right].Target().String()
	})
	next, err := nextTransitionVersion(input.Run.Version())
	if err != nil {
		return StartRunResult{}, err
	}
	run := input.Run
	run.status, run.version = RunStarting, next
	origin, _ := identityOrigin(run.ID(), run.Version())
	return StartRunResult{run: run, facts: []IdentityFact{
		RunStartedFact{origin: origin, runID: run.ID(), participations: participationRefs},
	}}, nil
}

func (result StartRunResult) Run() RunState         { return result.run }
func (result StartRunResult) Facts() []IdentityFact { return cloneIdentityFacts(result.facts) }

func checkWorkSession(session ActorSessionState, expected Version) error {
	if session.IsZero() || session.Status() != ActorSessionActive {
		return transitionConflict(ConflictSessionTerminal, "actor session is not active")
	}
	return checkExpectedVersion(session.Version(), expected)
}

type SessionStartAuthorityKind string

const (
	SessionStartByTrustedDevice SessionStartAuthorityKind = "trusted_device"
	SessionStartByHandoff       SessionStartAuthorityKind = "one_use_handoff"
)

type SessionStartAuthority struct {
	kind           SessionStartAuthorityKind
	device         DeviceState
	expectedDevice Version
	expectedTrust  Version
	challenge      CeremonyChallenge
	proof          CeremonyProof
}

func TrustedDeviceSessionStart(
	device DeviceState,
	expectedVersion Version,
	expectedTrustRevision Version,
) (SessionStartAuthority, error) {
	if device.IsZero() || !expectedVersion.Valid() || !expectedTrustRevision.Valid() ||
		device.Status() != DeviceTrusted || !validDeviceCredentialBinding(device.CredentialBinding()) {
		return SessionStartAuthority{}, ErrInvalidAuthorization
	}
	return SessionStartAuthority{
		kind: SessionStartByTrustedDevice, device: device,
		expectedDevice: expectedVersion, expectedTrust: expectedTrustRevision,
	}, nil
}

func HandoffSessionStart(challenge CeremonyChallenge, proof CeremonyProof) (SessionStartAuthority, error) {
	if challenge.IsZero() || proof.ChallengeID().IsZero() {
		return SessionStartAuthority{}, ErrInvalidAuthorization
	}
	return SessionStartAuthority{kind: SessionStartByHandoff, challenge: challenge, proof: proof}, nil
}

func (authority SessionStartAuthority) Kind() SessionStartAuthorityKind { return authority.kind }

type GrantRevision struct {
	grant    GrantState
	expected Version
}

func NewGrantRevision(grant GrantState, expected Version) (GrantRevision, error) {
	if grant.IsZero() || !expected.Valid() {
		return GrantRevision{}, ErrInvalidIdentityState
	}
	return GrantRevision{grant: grant, expected: expected}, nil
}

func (revision GrantRevision) Grant() GrantState        { return revision.grant }
func (revision GrantRevision) ExpectedVersion() Version { return revision.expected }

type StartActorSessionInput struct {
	Authorization             IdentityAuthorization
	Session                   ActorSessionState
	SessionID                 ActorSessionID
	ClientInstanceID          ClientInstanceID
	ClientMetadata            ClientMetadata
	Workspace                 WorkspaceState
	ExpectedWorkspaceVersion  Version
	Principal                 PrincipalState
	ExpectedPrincipalVersion  Version
	Membership                MembershipState
	ExpectedMembershipVersion Version
	Actor                     ActorState
	ExpectedActorVersion      Version
	Delegation                ActorDelegationState
	ExpectedDelegationVersion Version
	Grants                    []GrantRevision
	StartAuthority            SessionStartAuthority
	AbsoluteExpiry            time.Time
	PresentationCredential    PresentationCredentialBinding
}

type StartActorSessionResult struct {
	session            ActorSessionState
	consumedHandoff    CeremonyChallenge
	hasConsumedHandoff bool
	facts              []IdentityFact
}

func StartActorSession(input StartActorSessionInput) (StartActorSessionResult, error) {
	if !input.Session.IsZero() {
		switch input.Session.Status() {
		case ActorSessionEnded, ActorSessionRevoked, ActorSessionExpired:
			return StartActorSessionResult{}, transitionConflict(ConflictSessionTerminal, "actor session identity is terminal")
		default:
			return StartActorSessionResult{}, transitionConflict(ConflictState, "actor session identity already exists")
		}
	}
	if input.SessionID.IsZero() || input.ClientInstanceID.IsZero() ||
		input.ClientMetadata.Name() == "" || input.AbsoluteExpiry.IsZero() ||
		!validPresentationCredentialBinding(input.PresentationCredential) ||
		!input.AbsoluteExpiry.After(input.Authorization.EvaluatedAt()) ||
		input.AbsoluteExpiry.After(input.Authorization.EvaluatedAt().Add(input.Authorization.MaxSessionLifetime())) ||
		len(input.Grants) > MaxSessionGrantRevisions {
		return StartActorSessionResult{}, transitionError(ErrorCodeInvalidArgument, "session start input is invalid")
	}
	if err := checkActivePrincipal(input.Authorization, input.Principal, input.ExpectedPrincipalVersion, Capability{}); err != nil {
		return StartActorSessionResult{}, err
	}
	if err := checkWorkspaceAuthority(input.Authorization, input.Workspace, input.ExpectedWorkspaceVersion); err != nil {
		return StartActorSessionResult{}, err
	}
	if err := checkExpectedVersion(input.Membership.Version(), input.ExpectedMembershipVersion); err != nil {
		return StartActorSessionResult{}, err
	}
	if err := checkExpectedVersion(input.Actor.Version(), input.ExpectedActorVersion); err != nil {
		return StartActorSessionResult{}, err
	}
	if err := checkExpectedVersion(input.Delegation.Version(), input.ExpectedDelegationVersion); err != nil {
		return StartActorSessionResult{}, err
	}
	if input.Membership.Status() != MembershipActive || input.Actor.Status() != ActorActive ||
		input.Delegation.Status() != DelegationActive || input.Membership.WorkspaceID() != input.Workspace.ID() ||
		input.Actor.WorkspaceID() != input.Workspace.ID() || input.Delegation.WorkspaceID() != input.Workspace.ID() ||
		input.Membership.PrincipalID() != input.Principal.ID() || input.Delegation.PrincipalID() != input.Principal.ID() ||
		input.Delegation.ActorID() != input.Actor.ID() || input.Delegation.MembershipID() != input.Membership.ID() {
		return StartActorSessionResult{}, transitionConflict(ConflictReference, "session identity references do not match")
	}
	if input.Principal.Kind() == PrincipalKindService {
		return StartActorSessionResult{}, transitionError(ErrorCodeForbidden, "service principals cannot start actor sessions")
	}
	if !input.Membership.Capabilities().ContainsAll(input.Delegation.Capabilities()) {
		return StartActorSessionResult{}, transitionError(ErrorCodeForbidden, "delegation exceeds membership capability ceiling")
	}

	grantRefs := make([]AggregateRef, 0, len(input.Grants))
	grantSets := make([]CapabilitySet, 0, len(input.Grants))
	seenGrants := make(map[GrantID]struct{}, len(input.Grants))
	for _, cited := range input.Grants {
		grant := cited.Grant()
		if _, duplicate := seenGrants[grant.ID()]; duplicate {
			return StartActorSessionResult{}, transitionConflict(ConflictReference, "grant is cited more than once")
		}
		seenGrants[grant.ID()] = struct{}{}
		if err := checkExpectedVersion(grant.Version(), cited.ExpectedVersion()); err != nil {
			return StartActorSessionResult{}, err
		}
		if grant.Status() != GrantActive || grant.PrincipalID() != input.Principal.ID() ||
			(grant.WorkspaceID().IsZero() && grant.InstallationID() != input.Authorization.InstallationID()) ||
			(!grant.WorkspaceID().IsZero() && grant.WorkspaceID() != input.Workspace.ID()) {
			return StartActorSessionResult{}, transitionError(ErrorCodeForbidden, "grant is revoked or outside the session scope")
		}
		ref, err := NewAggregateRef(grant.ID(), grant.Version())
		if err != nil {
			return StartActorSessionResult{}, fmt.Errorf("%w: invalid grant revision: %w", ErrInvalidIdentityTransition, err)
		}
		grantRefs = append(grantRefs, ref)
		grantSets = append(grantSets, grant.Capabilities())
	}
	sort.Slice(grantRefs, func(left, right int) bool { return grantRefs[left].ID() < grantRefs[right].ID() })
	effective := intersectCapabilitySets(input.Membership.Capabilities(), input.Delegation.Capabilities())
	effective = intersectCapabilitySets(effective, input.Authorization.capabilities)
	if len(grantSets) > 0 {
		effective = intersectCapabilitySets(effective, unionCapabilitySets(grantSets...))
	}
	if effective.IsZero() {
		return StartActorSessionResult{}, transitionError(ErrorCodeForbidden, "session capability intersection is empty")
	}

	var deviceRef *AggregateRef
	var deviceTrust Version
	var consumed CeremonyChallenge
	hasConsumed := false
	switch input.StartAuthority.Kind() {
	case SessionStartByTrustedDevice:
		device := input.StartAuthority.device
		authenticatedDevice, authenticatedTrust, authenticated := input.Authorization.AuthenticatedDevice()
		if !authenticated || authenticatedDevice != device.ID() || authenticatedTrust != device.TrustRevision() {
			return StartActorSessionResult{}, transitionError(ErrorCodeUnauthenticated, "trusted device is not the device authenticated on this channel")
		}
		if err := checkExpectedVersion(device.Version(), input.StartAuthority.expectedDevice); err != nil {
			return StartActorSessionResult{}, err
		}
		if err := checkExpectedVersion(device.TrustRevision(), input.StartAuthority.expectedTrust); err != nil {
			return StartActorSessionResult{}, err
		}
		if device.Status() != DeviceTrusted || !validDeviceCredentialBinding(device.CredentialBinding()) ||
			device.PrincipalID() != input.Principal.ID() ||
			device.InstallationID() != input.Authorization.InstallationID() {
			return StartActorSessionResult{}, transitionError(ErrorCodeUnauthenticated, "trusted device binding is invalid")
		}
		ref, err := NewAggregateRef(device.ID(), device.Version())
		if err != nil {
			return StartActorSessionResult{}, fmt.Errorf("%w: invalid device revision: %w", ErrInvalidIdentityTransition, err)
		}
		deviceRef = &ref
		deviceTrust = device.TrustRevision()
	case SessionStartByHandoff:
		challenge := input.StartAuthority.challenge
		proof := input.StartAuthority.proof
		if proof.PrincipalID() != input.Principal.ID() || challenge.WorkspaceID() != input.Workspace.ID() ||
			challenge.PrincipalID() != input.Principal.ID() || challenge.ActorID() != input.Actor.ID() ||
			challenge.DelegationID() != input.Delegation.ID() {
			return StartActorSessionResult{}, transitionError(ErrorCodeUnauthenticated, "session handoff binding is invalid")
		}
		if err := checkCeremony(challenge, proof, CeremonyPurposeActorSessionStart, input.Authorization.EvaluatedAt()); err != nil {
			return StartActorSessionResult{}, transitionError(ErrorCodeUnauthenticated, "session handoff is expired, consumed, or invalid")
		}
		consumed = challenge.consume()
		hasConsumed = true
	default:
		return StartActorSessionResult{}, transitionError(ErrorCodeUnauthenticated, "session start authority is absent")
	}

	membershipRef, err := NewAggregateRef(input.Membership.ID(), input.Membership.Version())
	if err != nil {
		return StartActorSessionResult{}, fmt.Errorf("%w: invalid membership revision: %w", ErrInvalidIdentityTransition, err)
	}
	delegationRef, err := NewAggregateRef(input.Delegation.ID(), input.Delegation.Version())
	if err != nil {
		return StartActorSessionResult{}, fmt.Errorf("%w: invalid delegation revision: %w", ErrInvalidIdentityTransition, err)
	}
	binding, err := NewSessionBinding(
		input.Authorization.AuthorityID(), input.Authorization.AuthorityEpoch(), input.Workspace.ID(),
		input.Principal.ID(), input.Actor.ID(), membershipRef, delegationRef, deviceRef, deviceTrust, grantRefs,
		input.Authorization.PolicyRevision(), input.Authorization.AssuranceClass(),
		input.Authorization.EvaluatedAt(), input.AbsoluteExpiry,
	)
	if err != nil {
		return StartActorSessionResult{}, fmt.Errorf("%w: %v", ErrInvalidIdentityTransition, err)
	}
	session := ActorSessionState{
		id:             input.SessionID,
		clientInstance: input.ClientInstanceID,
		clientMetadata: input.ClientMetadata,
		status:         ActorSessionActive,
		version:        InitialVersion(),
		binding:        binding,
		capabilities:   effective,
		presentation:   input.PresentationCredential,
	}
	origin, err := identityOrigin(session.ID(), session.Version())
	if err != nil {
		return StartActorSessionResult{}, err
	}
	fact := ActorSessionStartedFact{
		origin: origin, sessionID: session.ID(), workspaceID: binding.WorkspaceID(),
		clientInstance: session.ClientInstanceID(), clientMetadata: session.ClientMetadata(),
		binding: binding, capabilities: session.Capabilities(), presentation: session.PresentationCredential(),
	}
	return StartActorSessionResult{
		session:            session,
		consumedHandoff:    consumed,
		hasConsumedHandoff: hasConsumed,
		facts:              []IdentityFact{fact},
	}, nil
}

func (result StartActorSessionResult) Session() ActorSessionState { return result.session }
func (result StartActorSessionResult) ConsumedHandoff() (CeremonyChallenge, bool) {
	return result.consumedHandoff, result.hasConsumedHandoff
}
func (result StartActorSessionResult) Facts() []IdentityFact { return cloneIdentityFacts(result.facts) }

func intersectCapabilitySets(left CapabilitySet, right CapabilitySet) CapabilitySet {
	if left.IsZero() || right.IsZero() {
		return CapabilitySet{}
	}
	values := make([]Capability, 0)
	for _, capability := range left.values {
		if right.Contains(capability) {
			values = append(values, capability)
		}
	}
	if len(values) == 0 {
		return CapabilitySet{}
	}
	set, _ := NewCapabilitySet(values...)
	return set
}

func unionCapabilitySets(sets ...CapabilitySet) CapabilitySet {
	unique := make(map[Capability]struct{})
	for _, set := range sets {
		for _, capability := range set.values {
			unique[capability] = struct{}{}
		}
	}
	values := make([]Capability, 0, len(unique))
	for capability := range unique {
		values = append(values, capability)
	}
	if len(values) == 0 {
		return CapabilitySet{}
	}
	result, _ := NewCapabilitySet(values...)
	return result
}
