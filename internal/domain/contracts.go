package domain

import (
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidAggregateKind  = errors.New("invalid aggregate kind")
	ErrInvalidExpectation    = errors.New("invalid aggregate expectation")
	ErrDuplicateAggregate    = errors.New("duplicate aggregate target")
	ErrInvalidScope          = errors.New("invalid authority scope")
	ErrInvalidOperation      = errors.New("invalid operation name")
	ErrInvalidIdempotencyKey = errors.New("invalid idempotency key")
	ErrInvalidCommitSet      = errors.New("invalid atomic commit set")
	ErrInvalidSessionBinding = errors.New("invalid actor session binding")
	ErrInvalidPolicyRevision = errors.New("invalid policy revision")
	ErrInvalidAssuranceClass = errors.New("invalid assurance class")
)

type AggregateKind string

const (
	AggregateKindInstallation     AggregateKind = "installation"
	AggregateKindWorkspace        AggregateKind = "workspace"
	AggregateKindPrincipal        AggregateKind = "principal"
	AggregateKindDevice           AggregateKind = "device_registration"
	AggregateKindMembership       AggregateKind = "workspace_membership"
	AggregateKindActor            AggregateKind = "actor"
	AggregateKindActorDelegation  AggregateKind = "actor_delegation"
	AggregateKindActorSession     AggregateKind = "actor_session"
	AggregateKindGrant            AggregateKind = "grant"
	AggregateKindInvitation       AggregateKind = "invitation"
	AggregateKindWorkReference    AggregateKind = "work_reference"
	AggregateKindObjective        AggregateKind = "objective"
	AggregateKindWorkUnit         AggregateKind = "work_unit"
	AggregateKindRun              AggregateKind = "run"
	AggregateKindRunParticipation AggregateKind = "run_participation"
	AggregateKindRuntimeBinding   AggregateKind = "runtime_binding"
	AggregateKindRuntimeEndpoint  AggregateKind = "runtime_endpoint_registration"
)

func (kind AggregateKind) Valid() bool {
	switch kind {
	case AggregateKindInstallation,
		AggregateKindWorkspace,
		AggregateKindPrincipal,
		AggregateKindDevice,
		AggregateKindMembership,
		AggregateKindActor,
		AggregateKindActorDelegation,
		AggregateKindActorSession,
		AggregateKindGrant,
		AggregateKindInvitation,
		AggregateKindWorkReference,
		AggregateKindObjective,
		AggregateKindWorkUnit,
		AggregateKindRun,
		AggregateKindRunParticipation,
		AggregateKindRuntimeBinding,
		AggregateKindRuntimeEndpoint:
		return true
	default:
		return false
	}
}

type aggregateIdentifier interface {
	String() string
	IsZero() bool
	aggregateKind() AggregateKind
}

func (InstallationID) aggregateKind() AggregateKind     { return AggregateKindInstallation }
func (WorkspaceID) aggregateKind() AggregateKind        { return AggregateKindWorkspace }
func (PrincipalID) aggregateKind() AggregateKind        { return AggregateKindPrincipal }
func (DeviceID) aggregateKind() AggregateKind           { return AggregateKindDevice }
func (MembershipID) aggregateKind() AggregateKind       { return AggregateKindMembership }
func (ActorID) aggregateKind() AggregateKind            { return AggregateKindActor }
func (ActorDelegationID) aggregateKind() AggregateKind  { return AggregateKindActorDelegation }
func (ActorSessionID) aggregateKind() AggregateKind     { return AggregateKindActorSession }
func (GrantID) aggregateKind() AggregateKind            { return AggregateKindGrant }
func (InvitationID) aggregateKind() AggregateKind       { return AggregateKindInvitation }
func (WorkReferenceID) aggregateKind() AggregateKind    { return AggregateKindWorkReference }
func (ObjectiveID) aggregateKind() AggregateKind        { return AggregateKindObjective }
func (WorkUnitID) aggregateKind() AggregateKind         { return AggregateKindWorkUnit }
func (RunID) aggregateKind() AggregateKind              { return AggregateKindRun }
func (RunParticipationID) aggregateKind() AggregateKind { return AggregateKindRunParticipation }
func (RuntimeBindingID) aggregateKind() AggregateKind   { return AggregateKindRuntimeBinding }
func (RuntimeEndpointID) aggregateKind() AggregateKind  { return AggregateKindRuntimeEndpoint }

// AggregateTarget is an immutable typed aggregate identity without a version.
type AggregateTarget struct {
	kind AggregateKind
	id   string
}

func NewAggregateTarget[ID aggregateIdentifier](id ID) (AggregateTarget, error) {
	if id.IsZero() {
		return AggregateTarget{}, ErrZeroIdentifier
	}
	return AggregateTarget{kind: id.aggregateKind(), id: id.String()}, nil
}

func (target AggregateTarget) IsZero() bool { return target.kind == "" || target.id == "" }

func (target AggregateTarget) Kind() AggregateKind { return target.kind }

func (target AggregateTarget) ID() string { return target.id }

func (target AggregateTarget) String() string {
	if target.IsZero() {
		return ""
	}
	return string(target.kind) + ":" + target.id
}

// AggregateRef pins an aggregate identity to the exact revision on which a
// command decision or event depends.
type AggregateRef struct {
	target  AggregateTarget
	version Version
}

func NewAggregateRef[ID aggregateIdentifier](id ID, version Version) (AggregateRef, error) {
	target, err := NewAggregateTarget(id)
	if err != nil {
		return AggregateRef{}, err
	}
	if !version.Valid() {
		return AggregateRef{}, ErrInvalidVersion
	}
	return AggregateRef{target: target, version: version}, nil
}

func (ref AggregateRef) IsZero() bool { return ref.target.IsZero() || !ref.version.Valid() }

func (ref AggregateRef) Target() AggregateTarget { return ref.target }

func (ref AggregateRef) Kind() AggregateKind { return ref.target.Kind() }

func (ref AggregateRef) ID() string { return ref.target.ID() }

func (ref AggregateRef) Version() Version { return ref.version }

type ExpectationKind string

const (
	ExpectationMustNotExist    ExpectationKind = "must_not_exist"
	ExpectationExpectedVersion ExpectationKind = "expected_version"
)

// AggregateExpectation makes create-nonexistence and optimistic-version
// guards disjoint at the type/value boundary.
type AggregateExpectation struct {
	kind    ExpectationKind
	target  AggregateTarget
	version Version
}

func ExpectAggregateAbsent[ID aggregateIdentifier](id ID) (AggregateExpectation, error) {
	target, err := NewAggregateTarget(id)
	if err != nil {
		return AggregateExpectation{}, err
	}
	return AggregateExpectation{kind: ExpectationMustNotExist, target: target}, nil
}

func ExpectAggregateVersion[ID aggregateIdentifier](id ID, version Version) (AggregateExpectation, error) {
	ref, err := NewAggregateRef(id, version)
	if err != nil {
		return AggregateExpectation{}, err
	}
	return AggregateExpectation{kind: ExpectationExpectedVersion, target: ref.Target(), version: version}, nil
}

func (expectation AggregateExpectation) Kind() ExpectationKind { return expectation.kind }

func (expectation AggregateExpectation) Target() AggregateTarget { return expectation.target }

func (expectation AggregateExpectation) Version() (Version, bool) {
	return expectation.version, expectation.kind == ExpectationExpectedVersion
}

type ScopeKind string

const (
	ScopeKindInstallation ScopeKind = "installation"
	ScopeKindWorkspace    ScopeKind = "workspace"
)

// AuthorityScope is the installation or workspace stream on which an
// authoritative command/event lives. It is independent from AuthorityID.
type AuthorityScope struct {
	kind ScopeKind
	id   string
}

func InstallationScope(id InstallationID) (AuthorityScope, error) {
	if id.IsZero() {
		return AuthorityScope{}, ErrZeroIdentifier
	}
	return AuthorityScope{kind: ScopeKindInstallation, id: id.String()}, nil
}

func WorkspaceScope(id WorkspaceID) (AuthorityScope, error) {
	if id.IsZero() {
		return AuthorityScope{}, ErrZeroIdentifier
	}
	return AuthorityScope{kind: ScopeKindWorkspace, id: id.String()}, nil
}

func (scope AuthorityScope) IsZero() bool { return scope.kind == "" || scope.id == "" }

func (scope AuthorityScope) Kind() ScopeKind { return scope.kind }

func (scope AuthorityScope) ID() string { return scope.id }

type OperationName struct{ value string }

func NewOperationName(value string) (OperationName, error) {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return OperationName{}, ErrInvalidOperation
	}
	lastDot := false
	for _, character := range value {
		valid := (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '.'
		if !valid || (character == '.' && lastDot) {
			return OperationName{}, ErrInvalidOperation
		}
		lastDot = character == '.'
	}
	if lastDot {
		return OperationName{}, ErrInvalidOperation
	}
	return OperationName{value: value}, nil
}

func (operation OperationName) String() string { return operation.value }

type IdempotencyKey struct{ value string }

func NewIdempotencyKey(value string) (IdempotencyKey, error) {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return IdempotencyKey{}, ErrInvalidIdempotencyKey
	}
	return IdempotencyKey{value: value}, nil
}

func (key IdempotencyKey) String() string { return key.value }

// IdempotencyScope is the canonical uniqueness identity for an ordinary
// workspace write. AuthorityID and AuthorityEpoch are deliberately absent:
// receipts transfer with a workspace and survive restore and failover.
type IdempotencyScope struct {
	workspace      WorkspaceID
	principal      PrincipalID
	clientInstance ClientInstanceID
	operation      OperationName
	key            IdempotencyKey
}

func NewIdempotencyScope(
	workspace WorkspaceID,
	principal PrincipalID,
	clientInstance ClientInstanceID,
	operation OperationName,
	key IdempotencyKey,
) (IdempotencyScope, error) {
	if workspace.IsZero() || principal.IsZero() || clientInstance.IsZero() || operation.String() == "" || key.String() == "" {
		return IdempotencyScope{}, ErrInvalidScope
	}
	return IdempotencyScope{
		workspace:      workspace,
		principal:      principal,
		clientInstance: clientInstance,
		operation:      operation,
		key:            key,
	}, nil
}

func (scope IdempotencyScope) WorkspaceID() WorkspaceID { return scope.workspace }

func (scope IdempotencyScope) PrincipalID() PrincipalID { return scope.principal }

func (scope IdempotencyScope) ClientInstanceID() ClientInstanceID { return scope.clientInstance }

func (scope IdempotencyScope) Operation() OperationName { return scope.operation }

func (scope IdempotencyScope) Key() IdempotencyKey { return scope.key }

// ProvisioningIdempotencyScope is intentionally separate from the ordinary
// workspace uniqueness identity. It covers a purpose-bound pre-membership
// ceremony, such as installation bootstrap, without weakening the normal
// principal/client-instance contract.
type ProvisioningIdempotencyScope struct {
	scope      AuthorityScope
	transcript CommandFingerprint
	operation  OperationName
	key        IdempotencyKey
}

func NewProvisioningIdempotencyScope(
	scope AuthorityScope,
	transcript CommandFingerprint,
	operation OperationName,
	key IdempotencyKey,
) (ProvisioningIdempotencyScope, error) {
	if scope.IsZero() || scope.Kind() != ScopeKindInstallation || transcript.IsZero() ||
		operation.String() != "installation.bootstrap.v1" || key.String() == "" {
		return ProvisioningIdempotencyScope{}, ErrInvalidScope
	}
	return ProvisioningIdempotencyScope{
		scope: scope, transcript: transcript, operation: operation, key: key,
	}, nil
}

type CommandFingerprint [sha256.Size]byte

func FingerprintCommand(canonicalSemanticBytes []byte) CommandFingerprint {
	return sha256.Sum256(canonicalSemanticBytes)
}

func (fingerprint CommandFingerprint) IsZero() bool { return fingerprint == CommandFingerprint{} }

func (scope ProvisioningIdempotencyScope) AuthorityScope() AuthorityScope { return scope.scope }
func (scope ProvisioningIdempotencyScope) TranscriptFingerprint() CommandFingerprint {
	return scope.transcript
}
func (scope ProvisioningIdempotencyScope) Operation() OperationName { return scope.operation }
func (scope ProvisioningIdempotencyScope) Key() IdempotencyKey      { return scope.key }

type CommitSetKind string

const (
	CommitSetBootstrapInstallation CommitSetKind = "bootstrap_installation"
	CommitSetCreateWorkspaceOwner  CommitSetKind = "create_workspace_owner"
)

// AtomicCommitSet is the immutable aggregate guard set for a cataloged W0
// semantic commit. It describes atomicity without exposing storage locks.
type AtomicCommitSet struct {
	kind         CommitSetKind
	expectations []AggregateExpectation
}

func newAtomicCommitSet(kind CommitSetKind, expectations ...AggregateExpectation) (AtomicCommitSet, error) {
	if len(expectations) == 0 {
		return AtomicCommitSet{}, ErrInvalidCommitSet
	}
	cloned := append([]AggregateExpectation(nil), expectations...)
	sort.Slice(cloned, func(left, right int) bool {
		return cloned[left].Target().String() < cloned[right].Target().String()
	})
	for index, expectation := range cloned {
		if expectation.Target().IsZero() {
			return AtomicCommitSet{}, ErrInvalidExpectation
		}
		switch expectation.kind {
		case ExpectationMustNotExist:
			if !expectation.version.IsZero() {
				return AtomicCommitSet{}, ErrInvalidExpectation
			}
		case ExpectationExpectedVersion:
			if !expectation.version.Valid() {
				return AtomicCommitSet{}, ErrInvalidExpectation
			}
		default:
			return AtomicCommitSet{}, ErrInvalidExpectation
		}
		if index > 0 && cloned[index-1].Target() == expectation.Target() {
			return AtomicCommitSet{}, ErrDuplicateAggregate
		}
	}
	return AtomicCommitSet{kind: kind, expectations: cloned}, nil
}

func BootstrapInstallationCommitSet(
	principal PrincipalID,
	device DeviceID,
	grant GrantID,
	invitation InvitationID,
	invitationVersion Version,
) (AtomicCommitSet, error) {
	principalAbsent, err := ExpectAggregateAbsent(principal)
	if err != nil {
		return AtomicCommitSet{}, err
	}
	deviceAbsent, err := ExpectAggregateAbsent(device)
	if err != nil {
		return AtomicCommitSet{}, err
	}
	grantAbsent, err := ExpectAggregateAbsent(grant)
	if err != nil {
		return AtomicCommitSet{}, err
	}
	invitationExpected, err := ExpectAggregateVersion(invitation, invitationVersion)
	if err != nil {
		return AtomicCommitSet{}, err
	}
	return newAtomicCommitSet(
		CommitSetBootstrapInstallation,
		principalAbsent,
		deviceAbsent,
		grantAbsent,
		invitationExpected,
	)
}

func CreateWorkspaceOwnerCommitSet(
	workspace WorkspaceID,
	membership MembershipID,
	owner PrincipalID,
	ownerVersion Version,
) (AtomicCommitSet, error) {
	workspaceAbsent, err := ExpectAggregateAbsent(workspace)
	if err != nil {
		return AtomicCommitSet{}, err
	}
	membershipAbsent, err := ExpectAggregateAbsent(membership)
	if err != nil {
		return AtomicCommitSet{}, err
	}
	ownerExpected, err := ExpectAggregateVersion(owner, ownerVersion)
	if err != nil {
		return AtomicCommitSet{}, err
	}
	return newAtomicCommitSet(
		CommitSetCreateWorkspaceOwner,
		workspaceAbsent,
		membershipAbsent,
		ownerExpected,
	)
}

func (set AtomicCommitSet) Kind() CommitSetKind { return set.kind }

func (set AtomicCommitSet) Expectations() []AggregateExpectation {
	return append([]AggregateExpectation(nil), set.expectations...)
}

// PolicyRevision is an opaque, bounded identifier for the exact policy input
// evaluated at session issuance. It has equality semantics only.
type PolicyRevision struct{ value string }

func NewPolicyRevision(value string) (PolicyRevision, error) {
	if strings.TrimSpace(value) != value || value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return PolicyRevision{}, ErrInvalidPolicyRevision
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return PolicyRevision{}, ErrInvalidPolicyRevision
		}
	}
	return PolicyRevision{value: value}, nil
}

func (revision PolicyRevision) String() string { return revision.value }

// AssuranceClass is a stable policy vocabulary token, not a transport
// authentication mechanism. Lowercase tokens allow new policy classes without
// coupling the domain layer to a particular identity provider.
type AssuranceClass struct{ value string }

func NewAssuranceClass(value string) (AssuranceClass, error) {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return AssuranceClass{}, ErrInvalidAssuranceClass
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return AssuranceClass{}, ErrInvalidAssuranceClass
		}
	}
	return AssuranceClass{value: value}, nil
}

func (assurance AssuranceClass) String() string { return assurance.value }

// SessionBinding snapshots the exact identities, revisions, policy decision,
// and lifetime used to issue an actor session. Current authorization still
// re-evaluates revocation and narrowing; the snapshot exists for attribution
// and stale-reference rejection.
type SessionBinding struct {
	authority      AuthorityID
	epoch          AuthorityEpoch
	workspace      WorkspaceID
	principal      PrincipalID
	actor          ActorID
	membership     AggregateRef
	delegation     AggregateRef
	device         AggregateRef
	hasDevice      bool
	deviceTrust    Version
	grants         []AggregateRef
	policy         PolicyRevision
	assurance      AssuranceClass
	issuedAt       time.Time
	absoluteExpiry time.Time
}

func NewSessionBinding(
	authority AuthorityID,
	epoch AuthorityEpoch,
	workspace WorkspaceID,
	principal PrincipalID,
	actor ActorID,
	membership AggregateRef,
	delegation AggregateRef,
	device *AggregateRef,
	deviceTrust Version,
	grants []AggregateRef,
	policy PolicyRevision,
	assurance AssuranceClass,
	issuedAt time.Time,
	absoluteExpiry time.Time,
) (SessionBinding, error) {
	if authority.IsZero() || epoch.IsZero() || workspace.IsZero() || principal.IsZero() || actor.IsZero() ||
		membership.IsZero() || membership.Kind() != AggregateKindMembership ||
		delegation.IsZero() || delegation.Kind() != AggregateKindActorDelegation ||
		policy.String() == "" || assurance.String() == "" || issuedAt.IsZero() ||
		absoluteExpiry.IsZero() || !absoluteExpiry.After(issuedAt) ||
		absoluteExpiry.Sub(issuedAt) > MaxActorSessionLifetime || len(grants) > MaxSessionGrantRevisions {
		return SessionBinding{}, ErrInvalidSessionBinding
	}
	binding := SessionBinding{
		authority:      authority,
		epoch:          epoch,
		workspace:      workspace,
		principal:      principal,
		actor:          actor,
		membership:     membership,
		delegation:     delegation,
		policy:         policy,
		assurance:      assurance,
		issuedAt:       issuedAt.UTC(),
		absoluteExpiry: absoluteExpiry.UTC(),
	}
	if device != nil {
		if device.Kind() != AggregateKindDevice || device.IsZero() || !deviceTrust.Valid() {
			return SessionBinding{}, ErrInvalidSessionBinding
		}
		binding.device = *device
		binding.hasDevice = true
		binding.deviceTrust = deviceTrust
	} else if !deviceTrust.IsZero() {
		return SessionBinding{}, ErrInvalidSessionBinding
	}
	binding.grants = append([]AggregateRef(nil), grants...)
	sort.Slice(binding.grants, func(left, right int) bool {
		return binding.grants[left].Target().String() < binding.grants[right].Target().String()
	})
	seenGrants := make(map[AggregateTarget]struct{}, len(binding.grants))
	for _, grant := range binding.grants {
		if grant.Kind() != AggregateKindGrant || grant.IsZero() {
			return SessionBinding{}, ErrInvalidSessionBinding
		}
		if _, duplicate := seenGrants[grant.Target()]; duplicate {
			return SessionBinding{}, ErrInvalidSessionBinding
		}
		seenGrants[grant.Target()] = struct{}{}
	}
	return binding, nil
}

func (binding SessionBinding) AuthorityID() AuthorityID         { return binding.authority }
func (binding SessionBinding) AuthorityEpoch() AuthorityEpoch   { return binding.epoch }
func (binding SessionBinding) WorkspaceID() WorkspaceID         { return binding.workspace }
func (binding SessionBinding) PrincipalID() PrincipalID         { return binding.principal }
func (binding SessionBinding) ActorID() ActorID                 { return binding.actor }
func (binding SessionBinding) MembershipRevision() AggregateRef { return binding.membership }
func (binding SessionBinding) DelegationRevision() AggregateRef { return binding.delegation }
func (binding SessionBinding) PolicyRevision() PolicyRevision   { return binding.policy }
func (binding SessionBinding) AssuranceClass() AssuranceClass   { return binding.assurance }
func (binding SessionBinding) IssuedAt() time.Time              { return binding.issuedAt }
func (binding SessionBinding) AbsoluteExpiry() time.Time        { return binding.absoluteExpiry }

func (binding SessionBinding) DeviceRevision() (AggregateRef, bool) {
	return binding.device, binding.hasDevice
}

func (binding SessionBinding) DeviceTrustRevision() (Version, bool) {
	return binding.deviceTrust, binding.hasDevice
}

func (binding SessionBinding) GrantRevisions() []AggregateRef {
	return append([]AggregateRef(nil), binding.grants...)
}
