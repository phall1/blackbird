// Package application defines Blackbird's transport-neutral command boundary.
//
// The package deliberately models a database transaction as one higher-order
// operation. Application services declare the complete lock/guard/fact shape
// up front, and a storage adapter supplies only the state observed while those
// declarations are locked. There is no repository facade that permits a
// handler to perform undeclared reads, writes, or external I/O mid-transaction.
package application

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	// MaxCanonicalInteger is the largest integer that remains exact in every
	// I-JSON consumer. Versions and persisted generations crossing this seam
	// must never exceed it.
	MaxCanonicalInteger uint64 = domain.MaxCanonicalInteger

	MaxCommandGuards    = 64
	MaxCommandMutations = 64
	MaxCommandFacts     = 64
	MaxCommandEffects   = 64

	MaxReceiptResultBytes   = 2 * 1024
	MaxAuditMetadataBytes   = 8 * 1024
	MaxAuditEntryBytes      = 32 * 1024
	MaxEffectMetadataBytes  = 8 * 1024
	MaxRecoveryCapsuleBytes = 32 * 1024
	Ed25519SignatureBytes   = 64
)

var (
	ErrInvalidApplicationContract = errors.New("invalid application contract")
	ErrInvalidReceiptIdentity     = errors.New("invalid receipt identity")
	ErrInvalidGuardPlan           = errors.New("invalid command guard plan")
	ErrInvalidCommandSpec         = errors.New("invalid command specification")
	ErrInvalidCommandContext      = errors.New("invalid command context")
	ErrInvalidCommandDecision     = errors.New("invalid command decision")
	ErrInvalidCommandExecution    = errors.New("invalid command execution")
	ErrInvalidSecuritySpec        = errors.New("invalid security specification")
	ErrInvalidSecurityContext     = errors.New("invalid security context")
	ErrInvalidSecurityDecision    = errors.New("invalid security decision")
	ErrInvalidSecurityExecution   = errors.New("invalid security execution")
	ErrApplicationLimitExceeded   = errors.New("application contract limit exceeded")
)

// Digest is a non-zero SHA-256 digest used for bounded result, capsule, audit,
// and effect content. Command semantic fingerprints continue to use the
// domain's distinct CommandFingerprint type.
type Digest [sha256.Size]byte

func DigestBytes(content []byte) Digest { return sha256.Sum256(content) }
func (digest Digest) IsZero() bool      { return digest == Digest{} }

// GuardGeneration is a positive, I-JSON-safe persisted generation. It is not
// an aggregate Version and is never compared across guard identities.
type GuardGeneration struct{ value uint64 }

func NewGuardGeneration(value uint64) (GuardGeneration, error) {
	if value == 0 || value > MaxCanonicalInteger {
		return GuardGeneration{}, fmt.Errorf("%w: guard generation", ErrInvalidApplicationContract)
	}
	return GuardGeneration{value: value}, nil
}

func (generation GuardGeneration) Uint64() uint64 { return generation.value }
func (generation GuardGeneration) IsZero() bool   { return generation.value == 0 }

// OperationMajor is recorded separately from an operation token so receipt
// uniqueness cannot accidentally collapse incompatible protocol majors.
type OperationMajor struct{ value uint16 }

func NewOperationMajor(value uint16) (OperationMajor, error) {
	if value == 0 {
		return OperationMajor{}, fmt.Errorf("%w: operation major", ErrInvalidApplicationContract)
	}
	return OperationMajor{value: value}, nil
}

func (major OperationMajor) Uint16() uint16 { return major.value }
func (major OperationMajor) IsZero() bool   { return major.value == 0 }

func operationHasMajor(operation domain.OperationName, major OperationMajor) bool {
	if operation.String() == "" || major.IsZero() {
		return false
	}
	suffix := ".v" + strconv.FormatUint(uint64(major.Uint16()), 10)
	return strings.HasSuffix(operation.String(), suffix) && len(operation.String()) > len(suffix)
}

type ReceiptIdentityKind string

const (
	ReceiptIdentityOrdinary          ReceiptIdentityKind = "ordinary_workspace"
	ReceiptIdentityProvisioning      ReceiptIdentityKind = "installation_provisioning"
	ReceiptIdentityInstallationAdmin ReceiptIdentityKind = "installation_admin"
)

// ReceiptIdentity is the closed secondary uniqueness key. Authority identity
// and epoch are intentionally absent from every variant; they are provenance,
// not retry identity.
type ReceiptIdentity struct {
	kind           ReceiptIdentityKind
	scope          domain.AuthorityScope
	workspace      domain.WorkspaceID
	installation   domain.InstallationID
	principal      domain.PrincipalID
	clientInstance domain.ClientInstanceID
	transcript     domain.CommandFingerprint
	operation      domain.OperationName
	key            domain.IdempotencyKey
}

func OrdinaryReceiptIdentity(scope domain.IdempotencyScope) (ReceiptIdentity, error) {
	authorityScope, err := domain.WorkspaceScope(scope.WorkspaceID())
	if err != nil || scope.PrincipalID().IsZero() || scope.ClientInstanceID().IsZero() ||
		scope.Operation().String() == "" || scope.Key().String() == "" {
		return ReceiptIdentity{}, ErrInvalidReceiptIdentity
	}
	return ReceiptIdentity{
		kind: ReceiptIdentityOrdinary, scope: authorityScope, workspace: scope.WorkspaceID(),
		principal: scope.PrincipalID(), clientInstance: scope.ClientInstanceID(),
		operation: scope.Operation(), key: scope.Key(),
	}, nil
}

func ProvisioningReceiptIdentity(scope domain.ProvisioningIdempotencyScope) (ReceiptIdentity, error) {
	if scope.AuthorityScope().IsZero() || scope.AuthorityScope().Kind() != domain.ScopeKindInstallation ||
		scope.TranscriptFingerprint().IsZero() || scope.Operation().String() == "" || scope.Key().String() == "" {
		return ReceiptIdentity{}, ErrInvalidReceiptIdentity
	}
	installation, err := domain.ParseInstallationID(scope.AuthorityScope().ID())
	if err != nil {
		return ReceiptIdentity{}, ErrInvalidReceiptIdentity
	}
	return ReceiptIdentity{
		kind: ReceiptIdentityProvisioning, scope: scope.AuthorityScope(), installation: installation,
		transcript: scope.TranscriptFingerprint(), operation: scope.Operation(), key: scope.Key(),
	}, nil
}

func InstallationAdminReceiptIdentity(
	installation domain.InstallationID,
	principal domain.PrincipalID,
	clientInstance domain.ClientInstanceID,
	operation domain.OperationName,
	key domain.IdempotencyKey,
) (ReceiptIdentity, error) {
	scope, err := domain.InstallationScope(installation)
	if err != nil || principal.IsZero() || clientInstance.IsZero() || operation.String() == "" || key.String() == "" {
		return ReceiptIdentity{}, ErrInvalidReceiptIdentity
	}
	return ReceiptIdentity{
		kind: ReceiptIdentityInstallationAdmin, scope: scope, installation: installation,
		principal: principal, clientInstance: clientInstance, operation: operation, key: key,
	}, nil
}

func (identity ReceiptIdentity) Kind() ReceiptIdentityKind       { return identity.kind }
func (identity ReceiptIdentity) Scope() domain.AuthorityScope    { return identity.scope }
func (identity ReceiptIdentity) WorkspaceID() domain.WorkspaceID { return identity.workspace }
func (identity ReceiptIdentity) InstallationID() domain.InstallationID {
	return identity.installation
}
func (identity ReceiptIdentity) PrincipalID() domain.PrincipalID { return identity.principal }
func (identity ReceiptIdentity) ClientInstanceID() domain.ClientInstanceID {
	return identity.clientInstance
}
func (identity ReceiptIdentity) TranscriptFingerprint() domain.CommandFingerprint {
	return identity.transcript
}
func (identity ReceiptIdentity) Operation() domain.OperationName { return identity.operation }
func (identity ReceiptIdentity) Key() domain.IdempotencyKey      { return identity.key }

type AuthorshipClass string

const (
	AuthorshipProvisioning   AuthorshipClass = "provisioning"
	AuthorshipAuthority      AuthorshipClass = "authority"
	AuthorshipWorkspaceAdmin AuthorshipClass = "workspace_admin"
	AuthorshipWork           AuthorshipClass = "work"
)

// CommandAuthorship keeps the security subject distinct from optional or
// required work-persona attribution.
type CommandAuthorship struct {
	class        AuthorshipClass
	principal    domain.PrincipalID
	actor        domain.ActorID
	actorSession domain.ActorSessionID
	hasActor     bool
}

// ActorAttribution is an indivisible actor/session pair. There is no public
// constructor for a partial attribution, so semantic fingerprints and events
// can never acquire an actor without the session that authorized it (or vice
// versa).
type ActorAttribution struct {
	actor   domain.ActorID
	session domain.ActorSessionID
}

func NewActorAttribution(
	actor domain.ActorID,
	session domain.ActorSessionID,
) (ActorAttribution, error) {
	if actor.IsZero() || session.IsZero() {
		return ActorAttribution{}, ErrInvalidCommandSpec
	}
	return ActorAttribution{actor: actor, session: session}, nil
}

func (attribution ActorAttribution) ActorID() domain.ActorID { return attribution.actor }
func (attribution ActorAttribution) ActorSessionID() domain.ActorSessionID {
	return attribution.session
}

func ProvisioningAuthorship(prospectivePrincipal domain.PrincipalID) (CommandAuthorship, error) {
	if prospectivePrincipal.IsZero() {
		return CommandAuthorship{}, ErrInvalidCommandSpec
	}
	return CommandAuthorship{class: AuthorshipProvisioning, principal: prospectivePrincipal}, nil
}

func AuthorityAuthorship(principal domain.PrincipalID) (CommandAuthorship, error) {
	if principal.IsZero() {
		return CommandAuthorship{}, ErrInvalidCommandSpec
	}
	return CommandAuthorship{class: AuthorshipAuthority, principal: principal}, nil
}

func WorkspaceAdminAuthorship(
	principal domain.PrincipalID,
	attribution *ActorAttribution,
) (CommandAuthorship, error) {
	if principal.IsZero() {
		return CommandAuthorship{}, ErrInvalidCommandSpec
	}
	authorship := CommandAuthorship{class: AuthorshipWorkspaceAdmin, principal: principal}
	if attribution != nil {
		if attribution.actor.IsZero() || attribution.session.IsZero() {
			return CommandAuthorship{}, ErrInvalidCommandSpec
		}
		authorship.actor = attribution.actor
		authorship.actorSession = attribution.session
		authorship.hasActor = true
	}
	return authorship, nil
}

func WorkAuthorship(
	principal domain.PrincipalID,
	attribution ActorAttribution,
) (CommandAuthorship, error) {
	if principal.IsZero() || attribution.actor.IsZero() || attribution.session.IsZero() {
		return CommandAuthorship{}, ErrInvalidCommandSpec
	}
	return CommandAuthorship{
		class: AuthorshipWork, principal: principal, actor: attribution.actor,
		actorSession: attribution.session, hasActor: true,
	}, nil
}

func (authorship CommandAuthorship) Class() AuthorshipClass          { return authorship.class }
func (authorship CommandAuthorship) PrincipalID() domain.PrincipalID { return authorship.principal }
func (authorship CommandAuthorship) ActorAttribution() (ActorAttribution, bool) {
	return ActorAttribution{actor: authorship.actor, session: authorship.actorSession}, authorship.hasActor
}

type CeremonyClaimKind string

const (
	CeremonyReserveAbsent     CeremonyClaimKind = "reserve_absent"
	CeremonyConsumeEmbedded   CeremonyClaimKind = "consume_embedded"
	CeremonyConsumeStandalone CeremonyClaimKind = "consume_standalone"
)

// CeremonyClaim declares global CeremonyID uniqueness and, for redemption,
// the exact pending-to-consumed compare-and-swap. Embedded claims must name
// their owning aggregate revision; standalone handoffs are consumed directly
// with the session creation and receipt transaction.
type CeremonyClaim struct {
	kind        CeremonyClaimKind
	id          domain.CeremonyID
	purpose     domain.CeremonyPurpose
	proof       domain.CommandFingerprint
	expiresAt   time.Time
	ownerTarget domain.AggregateTarget
	ownerRef    domain.AggregateRef
	challenge   domain.CeremonyChallenge
}

func ReserveCeremony(
	challenge domain.CeremonyChallenge,
	owner domain.AggregateTarget,
) (CeremonyClaim, error) {
	if challenge.IsZero() || challenge.Status() != domain.CeremonyPending || owner.IsZero() ||
		!ceremonyOwnerMatchesTarget(challenge, owner) {
		return CeremonyClaim{}, ErrInvalidGuardPlan
	}
	return CeremonyClaim{
		kind: CeremonyReserveAbsent, id: challenge.ID(), purpose: challenge.Purpose(),
		proof: challenge.ProofDigest(), expiresAt: challenge.ExpiresAt(), ownerTarget: owner,
		challenge: challenge,
	}, nil
}

func ConsumeEmbeddedCeremony(
	id domain.CeremonyID,
	purpose domain.CeremonyPurpose,
	proof domain.CommandFingerprint,
	owner domain.AggregateRef,
) (CeremonyClaim, error) {
	if id.IsZero() || !purpose.Valid() || proof.IsZero() || owner.IsZero() {
		return CeremonyClaim{}, ErrInvalidGuardPlan
	}
	return CeremonyClaim{
		kind: CeremonyConsumeEmbedded, id: id, purpose: purpose, proof: proof, ownerRef: owner,
	}, nil
}

func ConsumeStandaloneCeremony(
	id domain.CeremonyID,
	purpose domain.CeremonyPurpose,
	proof domain.CommandFingerprint,
) (CeremonyClaim, error) {
	if id.IsZero() || !purpose.Valid() || proof.IsZero() {
		return CeremonyClaim{}, ErrInvalidGuardPlan
	}
	return CeremonyClaim{
		kind: CeremonyConsumeStandalone, id: id, purpose: purpose, proof: proof,
	}, nil
}

func (claim CeremonyClaim) Kind() CeremonyClaimKind                     { return claim.kind }
func (claim CeremonyClaim) ID() domain.CeremonyID                       { return claim.id }
func (claim CeremonyClaim) Purpose() domain.CeremonyPurpose             { return claim.purpose }
func (claim CeremonyClaim) ProofFingerprint() domain.CommandFingerprint { return claim.proof }
func (claim CeremonyClaim) ExpiresAt() time.Time                        { return claim.expiresAt }
func (claim CeremonyClaim) OwnerTarget() (domain.AggregateTarget, bool) {
	return claim.ownerTarget, !claim.ownerTarget.IsZero()
}
func (claim CeremonyClaim) OwnerRevision() (domain.AggregateRef, bool) {
	return claim.ownerRef, !claim.ownerRef.IsZero()
}

type CommandGuardPlanParams struct {
	AdmissionScope      domain.AuthorityScope
	AdmissionGeneration GuardGeneration
	Evidence            []EvidenceGuard
	Authorization       []domain.AggregateRef
	References          []domain.AggregateRef
	Disclosure          []domain.AggregateTarget
	Mutations           []domain.AggregateExpectation
	Ceremonies          []CeremonyClaim
	Genesis             *ScopeGenesisAbsence
}

type EvidenceGuardKind string

const (
	EvidenceCurrentAuthorityEpoch EvidenceGuardKind = "current_authority_epoch"
	EvidencePolicyRevision        EvidenceGuardKind = "policy_revision"
	EvidenceLifecycleStatus       EvidenceGuardKind = "lifecycle_status"
	EvidenceDeviceTrustRevision   EvidenceGuardKind = "device_trust_revision"
	EvidenceCapabilityCeiling     EvidenceGuardKind = "capability_ceiling"
	EvidenceResourceConstraint    EvidenceGuardKind = "resource_constraint"
	EvidenceBootstrapGeneration   EvidenceGuardKind = "bootstrap_generation"
)

// EvidenceGuard is the closed typed vocabulary for non-aggregate-version
// authorization predicates. Each constructor fills exactly the value slot
// owned by its kind; callers cannot create an ambiguous multi-slot record.
type EvidenceGuard struct {
	kind                EvidenceGuardKind
	targetKind          string
	targetID            string
	authorityID         domain.AuthorityID
	authorityEpoch      domain.AuthorityEpoch
	policyRevision      domain.PolicyRevision
	status              string
	revision            domain.Version
	digest              Digest
	bootstrapGeneration domain.BootstrapGenerationID
}

func CurrentAuthorityEpochGuard(
	scope domain.AuthorityScope,
	authorityID domain.AuthorityID,
	epoch domain.AuthorityEpoch,
) (EvidenceGuard, error) {
	if scope.IsZero() || authorityID.IsZero() || epoch.IsZero() {
		return EvidenceGuard{}, ErrInvalidGuardPlan
	}
	return EvidenceGuard{
		kind: EvidenceCurrentAuthorityEpoch, targetKind: string(scope.Kind()), targetID: scope.ID(),
		authorityID: authorityID, authorityEpoch: epoch,
	}, nil
}

func PolicyRevisionGuard(
	scope domain.AuthorityScope,
	revision domain.PolicyRevision,
) (EvidenceGuard, error) {
	if scope.IsZero() || revision.String() == "" {
		return EvidenceGuard{}, ErrInvalidGuardPlan
	}
	return EvidenceGuard{
		kind: EvidencePolicyRevision, targetKind: string(scope.Kind()), targetID: scope.ID(), policyRevision: revision,
	}, nil
}

func LifecycleStatusGuard(target domain.AggregateTarget, status string) (EvidenceGuard, error) {
	if target.IsZero() || !validToken(status, 64) {
		return EvidenceGuard{}, ErrInvalidGuardPlan
	}
	return EvidenceGuard{
		kind: EvidenceLifecycleStatus, targetKind: string(target.Kind()), targetID: target.ID(), status: status,
	}, nil
}

func DeviceTrustRevisionGuard(device domain.DeviceID, revision domain.Version) (EvidenceGuard, error) {
	target, err := domain.NewAggregateTarget(device)
	if err != nil || !revision.Valid() || revision.Uint64() > MaxCanonicalInteger {
		return EvidenceGuard{}, ErrInvalidGuardPlan
	}
	return EvidenceGuard{
		kind: EvidenceDeviceTrustRevision, targetKind: string(target.Kind()), targetID: target.ID(), revision: revision,
	}, nil
}

func CapabilityCeilingGuard(target domain.AggregateTarget, digest Digest) (EvidenceGuard, error) {
	return digestEvidenceGuard(EvidenceCapabilityCeiling, target, digest)
}

func ResourceConstraintGuard(target domain.AggregateTarget, digest Digest) (EvidenceGuard, error) {
	return digestEvidenceGuard(EvidenceResourceConstraint, target, digest)
}

func digestEvidenceGuard(kind EvidenceGuardKind, target domain.AggregateTarget, digest Digest) (EvidenceGuard, error) {
	if target.IsZero() || digest.IsZero() {
		return EvidenceGuard{}, ErrInvalidGuardPlan
	}
	return EvidenceGuard{kind: kind, targetKind: string(target.Kind()), targetID: target.ID(), digest: digest}, nil
}

func BootstrapGenerationGuard(
	scope domain.AuthorityScope,
	generation domain.BootstrapGenerationID,
) (EvidenceGuard, error) {
	if scope.IsZero() || scope.Kind() != domain.ScopeKindInstallation || generation.IsZero() {
		return EvidenceGuard{}, ErrInvalidGuardPlan
	}
	return EvidenceGuard{
		kind: EvidenceBootstrapGeneration, targetKind: string(scope.Kind()), targetID: scope.ID(),
		bootstrapGeneration: generation,
	}, nil
}

func (guard EvidenceGuard) Kind() EvidenceGuardKind { return guard.kind }
func (guard EvidenceGuard) TargetKind() string      { return guard.targetKind }
func (guard EvidenceGuard) TargetID() string        { return guard.targetID }
func (guard EvidenceGuard) Authority() (domain.AuthorityID, domain.AuthorityEpoch, bool) {
	return guard.authorityID, guard.authorityEpoch, guard.kind == EvidenceCurrentAuthorityEpoch
}
func (guard EvidenceGuard) PolicyRevision() (domain.PolicyRevision, bool) {
	return guard.policyRevision, guard.kind == EvidencePolicyRevision
}
func (guard EvidenceGuard) Status() (string, bool) {
	return guard.status, guard.kind == EvidenceLifecycleStatus
}
func (guard EvidenceGuard) Revision() (domain.Version, bool) {
	return guard.revision, guard.kind == EvidenceDeviceTrustRevision
}
func (guard EvidenceGuard) Digest() (Digest, bool) {
	return guard.digest, guard.kind == EvidenceCapabilityCeiling || guard.kind == EvidenceResourceConstraint
}
func (guard EvidenceGuard) BootstrapGeneration() (domain.BootstrapGenerationID, bool) {
	return guard.bootstrapGeneration, guard.kind == EvidenceBootstrapGeneration
}

// ScopeGenesisAbsence declares the three infrastructure rows whose absence is
// required when workspace.create.v1 establishes a new authority scope.
type ScopeGenesisAbsence struct {
	scope       domain.AuthorityScope
	authorityID domain.AuthorityID
	epoch       domain.AuthorityEpoch
}

func AbsentScopeGenesis(
	scope domain.AuthorityScope,
	authorityID domain.AuthorityID,
	epoch domain.AuthorityEpoch,
) (ScopeGenesisAbsence, error) {
	if scope.IsZero() || scope.Kind() != domain.ScopeKindWorkspace || authorityID.IsZero() || epoch.IsZero() {
		return ScopeGenesisAbsence{}, ErrInvalidGuardPlan
	}
	return ScopeGenesisAbsence{scope: scope, authorityID: authorityID, epoch: epoch}, nil
}

func (absence ScopeGenesisAbsence) Scope() domain.AuthorityScope          { return absence.scope }
func (absence ScopeGenesisAbsence) AuthorityID() domain.AuthorityID       { return absence.authorityID }
func (absence ScopeGenesisAbsence) AuthorityEpoch() domain.AuthorityEpoch { return absence.epoch }

// CommandGuardPlan is the complete bounded lock/CAS vocabulary for one
// command. Storage must not load or mutate an undeclared authoritative row.
type CommandGuardPlan struct {
	admissionScope      domain.AuthorityScope
	admissionGeneration GuardGeneration
	evidence            []EvidenceGuard
	authorization       []domain.AggregateRef
	references          []domain.AggregateRef
	disclosure          []domain.AggregateTarget
	mutations           []domain.AggregateExpectation
	ceremonies          []CeremonyClaim
	genesis             *ScopeGenesisAbsence
}

func NewCommandGuardPlan(params CommandGuardPlanParams) (CommandGuardPlan, error) {
	if params.AdmissionScope.IsZero() || params.AdmissionGeneration.IsZero() || len(params.Mutations) == 0 ||
		len(params.Evidence) > MaxCommandGuards ||
		len(params.Authorization) > MaxCommandGuards || len(params.References) > MaxCommandGuards ||
		len(params.Disclosure) == 0 || len(params.Disclosure) > MaxCommandGuards ||
		len(params.Mutations) > MaxCommandMutations || len(params.Ceremonies) > MaxCommandGuards {
		return CommandGuardPlan{}, ErrInvalidGuardPlan
	}
	evidence, err := normalizeEvidenceGuards(params.Evidence)
	if err != nil {
		return CommandGuardPlan{}, err
	}

	authorization, err := normalizeRefs(params.Authorization)
	if err != nil {
		return CommandGuardPlan{}, err
	}
	references, err := normalizeRefs(params.References)
	if err != nil {
		return CommandGuardPlan{}, err
	}
	disclosure, err := normalizeTargets(params.Disclosure)
	if err != nil {
		return CommandGuardPlan{}, err
	}
	mutations, err := normalizeExpectations(params.Mutations)
	if err != nil {
		return CommandGuardPlan{}, err
	}
	ceremonies, err := normalizeCeremonies(params.Ceremonies, mutations)
	if err != nil {
		return CommandGuardPlan{}, err
	}

	if err := consistentReferenceVersions(authorization, references, mutations); err != nil {
		return CommandGuardPlan{}, err
	}
	var genesis *ScopeGenesisAbsence
	if params.Genesis != nil {
		if params.Genesis.scope.IsZero() || params.Genesis.authorityID.IsZero() || params.Genesis.epoch.IsZero() {
			return CommandGuardPlan{}, ErrInvalidGuardPlan
		}
		copy := *params.Genesis
		genesis = &copy
	}
	return CommandGuardPlan{
		admissionScope: params.AdmissionScope, admissionGeneration: params.AdmissionGeneration,
		evidence:      evidence,
		authorization: authorization, references: references, disclosure: disclosure,
		mutations: mutations, ceremonies: ceremonies,
		genesis: genesis,
	}, nil
}

func normalizeTargets(targets []domain.AggregateTarget) ([]domain.AggregateTarget, error) {
	cloned := append([]domain.AggregateTarget(nil), targets...)
	sort.Slice(cloned, func(left, right int) bool { return cloned[left].String() < cloned[right].String() })
	for index, target := range cloned {
		if target.IsZero() || (index > 0 && cloned[index-1] == target) {
			return nil, ErrInvalidGuardPlan
		}
	}
	return cloned, nil
}

func normalizeEvidenceGuards(guards []EvidenceGuard) ([]EvidenceGuard, error) {
	cloned := append([]EvidenceGuard(nil), guards...)
	sort.Slice(cloned, func(left, right int) bool {
		if cloned[left].kind != cloned[right].kind {
			return evidenceGuardRank(cloned[left].kind) < evidenceGuardRank(cloned[right].kind)
		}
		if cloned[left].targetKind != cloned[right].targetKind {
			return cloned[left].targetKind < cloned[right].targetKind
		}
		return cloned[left].targetID < cloned[right].targetID
	})
	for index, guard := range cloned {
		if !validEvidenceGuard(guard) ||
			(index > 0 && guard.kind == cloned[index-1].kind &&
				guard.targetKind == cloned[index-1].targetKind && guard.targetID == cloned[index-1].targetID) {
			return nil, ErrInvalidGuardPlan
		}
	}
	return cloned, nil
}

func evidenceGuardRank(kind EvidenceGuardKind) int {
	switch kind {
	case EvidenceCurrentAuthorityEpoch:
		return 1
	case EvidencePolicyRevision:
		return 2
	case EvidenceLifecycleStatus:
		return 3
	case EvidenceDeviceTrustRevision:
		return 4
	case EvidenceCapabilityCeiling:
		return 5
	case EvidenceResourceConstraint:
		return 6
	case EvidenceBootstrapGeneration:
		return 7
	default:
		return 0
	}
}

func validEvidenceGuard(guard EvidenceGuard) bool {
	if evidenceGuardRank(guard.kind) == 0 || guard.targetKind == "" || guard.targetID == "" {
		return false
	}
	switch guard.kind {
	case EvidenceCurrentAuthorityEpoch:
		return !guard.authorityID.IsZero() && !guard.authorityEpoch.IsZero()
	case EvidencePolicyRevision:
		return guard.policyRevision.String() != ""
	case EvidenceLifecycleStatus:
		return validToken(guard.status, 64)
	case EvidenceDeviceTrustRevision:
		return guard.revision.Valid() && guard.revision.Uint64() <= MaxCanonicalInteger
	case EvidenceCapabilityCeiling, EvidenceResourceConstraint:
		return !guard.digest.IsZero()
	case EvidenceBootstrapGeneration:
		return !guard.bootstrapGeneration.IsZero()
	default:
		return false
	}
}

func normalizeRefs(refs []domain.AggregateRef) ([]domain.AggregateRef, error) {
	cloned := append([]domain.AggregateRef(nil), refs...)
	sort.Slice(cloned, func(left, right int) bool {
		return cloned[left].Target().String() < cloned[right].Target().String()
	})
	for index, ref := range cloned {
		if ref.IsZero() || ref.Version().Uint64() > MaxCanonicalInteger {
			return nil, ErrInvalidGuardPlan
		}
		if index > 0 && cloned[index-1].Target() == ref.Target() {
			return nil, ErrInvalidGuardPlan
		}
	}
	return cloned, nil
}

func normalizeExpectations(
	expectations []domain.AggregateExpectation,
) ([]domain.AggregateExpectation, error) {
	cloned := append([]domain.AggregateExpectation(nil), expectations...)
	sort.Slice(cloned, func(left, right int) bool {
		return cloned[left].Target().String() < cloned[right].Target().String()
	})
	for index, expectation := range cloned {
		if expectation.Target().IsZero() {
			return nil, ErrInvalidGuardPlan
		}
		switch expectation.Kind() {
		case domain.ExpectationMustNotExist:
			if version, hasVersion := expectation.Version(); hasVersion || !version.IsZero() {
				return nil, ErrInvalidGuardPlan
			}
		case domain.ExpectationExpectedVersion:
			version, hasVersion := expectation.Version()
			if !hasVersion || version.IsZero() || version.Uint64() >= MaxCanonicalInteger {
				return nil, ErrInvalidGuardPlan
			}
		default:
			return nil, ErrInvalidGuardPlan
		}
		if index > 0 && cloned[index-1].Target() == expectation.Target() {
			return nil, ErrInvalidGuardPlan
		}
	}
	return cloned, nil
}

func normalizeCeremonies(
	claims []CeremonyClaim,
	mutations []domain.AggregateExpectation,
) ([]CeremonyClaim, error) {
	cloned := append([]CeremonyClaim(nil), claims...)
	sort.Slice(cloned, func(left, right int) bool { return cloned[left].ID().String() < cloned[right].ID().String() })
	mutationByTarget := make(map[domain.AggregateTarget]domain.AggregateExpectation, len(mutations))
	for _, mutation := range mutations {
		mutationByTarget[mutation.Target()] = mutation
	}
	for index, claim := range cloned {
		if claim.id.IsZero() || !claim.purpose.Valid() || claim.proof.IsZero() {
			return nil, ErrInvalidGuardPlan
		}
		switch claim.kind {
		case CeremonyReserveAbsent:
			if claim.expiresAt.IsZero() || claim.ownerTarget.IsZero() || !claim.ownerRef.IsZero() ||
				claim.challenge.IsZero() || claim.challenge.Status() != domain.CeremonyPending ||
				!challengeMatchesClaim(claim.challenge, claim) ||
				!claim.challenge.ExpiresAt().Equal(claim.expiresAt) ||
				!ceremonyOwnerMatchesTarget(claim.challenge, claim.ownerTarget) {
				return nil, ErrInvalidGuardPlan
			}
			if _, declared := mutationByTarget[claim.ownerTarget]; !declared {
				return nil, ErrInvalidGuardPlan
			}
		case CeremonyConsumeEmbedded:
			if claim.ownerRef.IsZero() || !claim.ownerTarget.IsZero() || !claim.expiresAt.IsZero() {
				return nil, ErrInvalidGuardPlan
			}
			mutation, declared := mutationByTarget[claim.ownerRef.Target()]
			version, hasVersion := mutation.Version()
			if !declared || !hasVersion || version != claim.ownerRef.Version() {
				return nil, ErrInvalidGuardPlan
			}
		case CeremonyConsumeStandalone:
			if !claim.ownerRef.IsZero() || !claim.ownerTarget.IsZero() || !claim.expiresAt.IsZero() {
				return nil, ErrInvalidGuardPlan
			}
		default:
			return nil, ErrInvalidGuardPlan
		}
		if index > 0 && cloned[index-1].ID() == claim.ID() {
			return nil, ErrInvalidGuardPlan
		}
	}
	return cloned, nil
}

func consistentReferenceVersions(
	authorization []domain.AggregateRef,
	references []domain.AggregateRef,
	mutations []domain.AggregateExpectation,
) error {
	versions := make(map[domain.AggregateTarget]domain.Version)
	for _, group := range [][]domain.AggregateRef{authorization, references} {
		for _, ref := range group {
			if prior, exists := versions[ref.Target()]; exists && prior != ref.Version() {
				return ErrInvalidGuardPlan
			}
			versions[ref.Target()] = ref.Version()
		}
	}
	for _, expectation := range mutations {
		version, hasVersion := expectation.Version()
		if !hasVersion {
			continue
		}
		if prior, exists := versions[expectation.Target()]; exists && prior != version {
			return ErrInvalidGuardPlan
		}
	}
	return nil
}

func (plan CommandGuardPlan) AdmissionGeneration() GuardGeneration {
	return plan.admissionGeneration
}
func (plan CommandGuardPlan) AdmissionScope() domain.AuthorityScope { return plan.admissionScope }
func (plan CommandGuardPlan) Evidence() []EvidenceGuard {
	return append([]EvidenceGuard(nil), plan.evidence...)
}
func (plan CommandGuardPlan) Authorization() []domain.AggregateRef {
	return append([]domain.AggregateRef(nil), plan.authorization...)
}
func (plan CommandGuardPlan) References() []domain.AggregateRef {
	return append([]domain.AggregateRef(nil), plan.references...)
}
func (plan CommandGuardPlan) DisclosureTargets() []domain.AggregateTarget {
	return append([]domain.AggregateTarget(nil), plan.disclosure...)
}
func (plan CommandGuardPlan) Mutations() []domain.AggregateExpectation {
	return append([]domain.AggregateExpectation(nil), plan.mutations...)
}
func (plan CommandGuardPlan) Ceremonies() []CeremonyClaim {
	return append([]CeremonyClaim(nil), plan.ceremonies...)
}
func (plan CommandGuardPlan) GenesisAbsence() (ScopeGenesisAbsence, bool) {
	if plan.genesis == nil {
		return ScopeGenesisAbsence{}, false
	}
	return *plan.genesis, true
}
func (plan CommandGuardPlan) CreateAbsences() []domain.AggregateTarget {
	targets := make([]domain.AggregateTarget, 0, len(plan.mutations))
	for _, mutation := range plan.mutations {
		if mutation.Kind() == domain.ExpectationMustNotExist {
			targets = append(targets, mutation.Target())
		}
	}
	return targets
}

type FactExpectation struct {
	eventID   domain.EventID
	eventType domain.EventType
	origin    domain.AggregateRef
	ordinal   uint16
}

type PreparedRecoveryCapsuleSigner interface {
	KeyID() string
	Ed25519PublicKey() ed25519.PublicKey
	SignRecoveryCapsule(context.Context, []byte) ([]byte, error)
}

func RecoveryCapsuleSigningMessage(digest Digest) ([]byte, error) {
	if digest.IsZero() {
		return nil, ErrInvalidApplicationContract
	}
	message := make([]byte, 0, len("blackbird-recovery-capsule-signature/v1\x00")+sha256.Size)
	message = append(message, "blackbird-recovery-capsule-signature/v1\x00"...)
	message = append(message, digest[:]...)
	return message, nil
}

type RecoveryCapsuleRequirement string

const (
	RecoveryCapsuleRequired      RecoveryCapsuleRequirement = "required"
	RecoveryCapsuleNotApplicable RecoveryCapsuleRequirement = "not_applicable"
)

type RecoveryCapsulePlan struct {
	requirement RecoveryCapsuleRequirement
	keyID       string
	publicKey   ed25519.PublicKey
}

// PrepareRecoveryCapsulePlan is called only after signer preflight has
// completed outside the transaction. SignRecoveryCapsule is post-commit only.
func PrepareRecoveryCapsulePlan(signer PreparedRecoveryCapsuleSigner) (RecoveryCapsulePlan, error) {
	if isNilInterface(signer) {
		return RecoveryCapsulePlan{}, ErrInvalidCommandSpec
	}
	keyID := signer.KeyID()
	publicKey := signer.Ed25519PublicKey()
	if !validOpaqueText(keyID, 256) || len(publicKey) != ed25519.PublicKeySize {
		return RecoveryCapsulePlan{}, ErrInvalidCommandSpec
	}
	// Deliberately retain only the immutable key identity. The caller keeps the
	// prepared signer outside CommandSpec and its transaction callback.
	return RecoveryCapsulePlan{
		requirement: RecoveryCapsuleRequired,
		keyID:       keyID,
		publicKey:   append(ed25519.PublicKey(nil), publicKey...),
	}, nil
}

func NotApplicableRecoveryCapsulePlan() RecoveryCapsulePlan {
	return RecoveryCapsulePlan{requirement: RecoveryCapsuleNotApplicable}
}

func (plan RecoveryCapsulePlan) Requirement() RecoveryCapsuleRequirement { return plan.requirement }
func (plan RecoveryCapsulePlan) KeyID() string                           { return plan.keyID }

func cloneRecoveryCapsulePlan(plan RecoveryCapsulePlan) RecoveryCapsulePlan {
	plan.publicKey = append(ed25519.PublicKey(nil), plan.publicKey...)
	return plan
}

type RecoveryCapsuleDraft struct {
	canonical    []byte
	digest       Digest
	resultDigest Digest
	keyID        string
}

func NewRecoveryCapsuleDraft(
	result ResultEnvelope,
	document RecoveryCapsuleDocument,
	keyID string,
) (RecoveryCapsuleDraft, error) {
	if result.IsZero() || document.IsZero() || !validOpaqueText(keyID, 256) ||
		result.capsulePlan.requirement != RecoveryCapsuleRequired || result.capsulePlan.keyID != keyID ||
		document.SigningKeyID() != keyID || !document.MatchesResult(result.document) {
		return RecoveryCapsuleDraft{}, ErrInvalidApplicationContract
	}
	canonical := document.CanonicalBytes()
	if len(canonical) == 0 || len(canonical) > MaxRecoveryCapsuleBytes {
		return RecoveryCapsuleDraft{}, ErrInvalidApplicationContract
	}
	return RecoveryCapsuleDraft{
		canonical: canonical, digest: document.Digest(), resultDigest: document.ResultDigest(), keyID: keyID,
	}, nil
}

func (draft RecoveryCapsuleDraft) CanonicalBytes() []byte {
	return append([]byte(nil), draft.canonical...)
}
func (draft RecoveryCapsuleDraft) Digest() Digest       { return draft.digest }
func (draft RecoveryCapsuleDraft) ResultDigest() Digest { return draft.resultDigest }
func (draft RecoveryCapsuleDraft) KeyID() string        { return draft.keyID }

type RecoveryCapsuleEnvelope struct {
	draft     RecoveryCapsuleDraft
	signature []byte
}

const (
	RecoveryCapsuleEnvelopeSchema     = "blackbird.recovery_capsule/v1"
	RecoveryCapsuleSignatureAlgorithm = "Ed25519"
)

func newRecoveryCapsuleEnvelope(
	draft RecoveryCapsuleDraft,
	signature []byte,
) (RecoveryCapsuleEnvelope, error) {
	if draft.digest.IsZero() || len(signature) != Ed25519SignatureBytes {
		return RecoveryCapsuleEnvelope{}, ErrInvalidApplicationContract
	}
	return RecoveryCapsuleEnvelope{draft: draft, signature: append([]byte(nil), signature...)}, nil
}

// SignRecoveryCapsule is a post-commit helper. It must never be called by a
// UnitOfWork callback or storage transaction.
func SignRecoveryCapsule(
	ctx context.Context,
	plan RecoveryCapsulePlan,
	signer PreparedRecoveryCapsuleSigner,
	draft RecoveryCapsuleDraft,
) (RecoveryCapsuleEnvelope, error) {
	if isNilInterface(signer) {
		return RecoveryCapsuleEnvelope{}, ErrInvalidApplicationContract
	}
	keyID := signer.KeyID()
	publicKey := signer.Ed25519PublicKey()
	if plan.requirement != RecoveryCapsuleRequired ||
		plan.keyID != draft.keyID || keyID != plan.keyID || draft.digest.IsZero() ||
		len(plan.publicKey) != ed25519.PublicKeySize ||
		!ed25519.PublicKey(publicKey).Equal(plan.publicKey) {
		return RecoveryCapsuleEnvelope{}, ErrInvalidApplicationContract
	}
	message, err := RecoveryCapsuleSigningMessage(draft.digest)
	if err != nil {
		return RecoveryCapsuleEnvelope{}, err
	}
	signature, err := signer.SignRecoveryCapsule(ctx, message)
	if err != nil {
		return RecoveryCapsuleEnvelope{}, fmt.Errorf("sign recovery capsule: %w", err)
	}
	if !ed25519.Verify(plan.publicKey, message, signature) {
		return RecoveryCapsuleEnvelope{}, fmt.Errorf("%w: recovery capsule signature verification", ErrInvalidApplicationContract)
	}
	return newRecoveryCapsuleEnvelope(draft, signature)
}

func (envelope RecoveryCapsuleEnvelope) Draft() RecoveryCapsuleDraft { return envelope.draft }
func (envelope RecoveryCapsuleEnvelope) Schema() string              { return RecoveryCapsuleEnvelopeSchema }
func (envelope RecoveryCapsuleEnvelope) DigestHex() string {
	return hex.EncodeToString(envelope.draft.digest[:])
}
func (envelope RecoveryCapsuleEnvelope) Algorithm() string    { return RecoveryCapsuleSignatureAlgorithm }
func (envelope RecoveryCapsuleEnvelope) SigningKeyID() string { return envelope.draft.keyID }
func (envelope RecoveryCapsuleEnvelope) Signature() []byte {
	return append([]byte(nil), envelope.signature...)
}
func (envelope RecoveryCapsuleEnvelope) SignatureBase64URL() string {
	return base64.RawURLEncoding.EncodeToString(envelope.signature)
}

func NewFactExpectation(
	eventID domain.EventID,
	eventType domain.EventType,
	origin domain.AggregateRef,
) (FactExpectation, error) {
	if eventID.IsZero() || !identityEventType(eventType) || origin.IsZero() ||
		origin.Version().Uint64() > MaxCanonicalInteger {
		return FactExpectation{}, ErrInvalidCommandSpec
	}
	return FactExpectation{eventID: eventID, eventType: eventType, origin: origin}, nil
}

func identityEventType(eventType domain.EventType) bool {
	switch eventType {
	case domain.EventTypeInstallationBootstrapped,
		domain.EventTypePrincipalRegistered,
		domain.EventTypeDevicePairingBegan,
		domain.EventTypeDevicePaired,
		domain.EventTypeWorkspaceCreated,
		domain.EventTypeWorkspaceMemberInvited,
		domain.EventTypeWorkspaceMembershipAccepted,
		domain.EventTypeActorCreated,
		domain.EventTypeActorDelegationProposed,
		domain.EventTypeActorDelegationActivated,
		domain.EventTypeActorSessionStarted:
		return true
	default:
		return false
	}
}

func (expectation FactExpectation) EventID() domain.EventID     { return expectation.eventID }
func (expectation FactExpectation) EventType() domain.EventType { return expectation.eventType }
func (expectation FactExpectation) Origin() domain.AggregateRef { return expectation.origin }
func (expectation FactExpectation) Ordinal() uint16             { return expectation.ordinal }

type AuthorityTimeClass string

const (
	AuthorityTimeOrdinary                AuthorityTimeClass = "ordinary"
	AuthorityTimeIssuesExpiringAuthority AuthorityTimeClass = "issues_expiring_authority"
	AuthorityTimeRenewsExpiringAuthority AuthorityTimeClass = "renews_expiring_authority"
)

func (classification AuthorityTimeClass) Valid() bool {
	return classification == AuthorityTimeOrdinary ||
		classification == AuthorityTimeIssuesExpiringAuthority ||
		classification == AuthorityTimeRenewsExpiringAuthority
}

type CommandOperation string

const (
	CommandBootstrapInstallation     CommandOperation = "installation.bootstrap.v1"
	CommandRegisterPrincipal         CommandOperation = "principal.register.v1"
	CommandCreateWorkspace           CommandOperation = "workspace.create.v1"
	CommandInviteWorkspaceMember     CommandOperation = "workspace_member.invite.v1"
	CommandAcceptWorkspaceMembership CommandOperation = "workspace_membership.accept.v1"
	CommandCreateActor               CommandOperation = "actor.create.v1"
	CommandProposeActorDelegation    CommandOperation = "actor_delegation.propose.v1"
	CommandActivateActorDelegation   CommandOperation = "actor_delegation.activate.v1"
	CommandBeginDevicePairing        CommandOperation = "pairing.challenge.issue.v1"
	CommandPairDevice                CommandOperation = "pairing.challenge.redeem.v1"
	CommandStartActorSession         CommandOperation = "session.start.v1"
)

type operationContract struct {
	operation        CommandOperation
	receipt          ReceiptIdentityKind
	scope            domain.ScopeKind
	authorship       AuthorshipClass
	attribution      attributionPolicy
	recovery         RecoveryCapsuleRequirement
	timeClass        AuthorityTimeClass
	facts            []domain.EventType
	mutations        map[domain.AggregateKind]domain.ExpectationKind
	reads            map[domain.AggregateKind]int
	variableReads    map[domain.AggregateKind]bool
	referenceReads   map[domain.AggregateKind]int
	disclosure       map[domain.AggregateKind]int
	ceremonies       []ceremonyContract
	evidenceMinimums map[EvidenceGuardKind]int
	genesis          bool
}

type attributionPolicy uint8

const (
	attributionForbidden attributionPolicy = iota + 1
	attributionOptional
)

type ceremonyContract struct {
	kind    CeremonyClaimKind
	purpose domain.CeremonyPurpose
}

var operationContracts = map[CommandOperation]operationContract{
	CommandBootstrapInstallation: {
		operation: CommandBootstrapInstallation, receipt: ReceiptIdentityProvisioning,
		scope: domain.ScopeKindInstallation, authorship: AuthorshipProvisioning,
		attribution: attributionForbidden, recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeOrdinary,
		facts: []domain.EventType{domain.EventTypeInstallationBootstrapped, domain.EventTypePrincipalRegistered, domain.EventTypeDevicePaired},
		mutations: map[domain.AggregateKind]domain.ExpectationKind{
			domain.AggregateKindInvitation: domain.ExpectationExpectedVersion,
			domain.AggregateKindPrincipal:  domain.ExpectationMustNotExist,
			domain.AggregateKindDevice:     domain.ExpectationMustNotExist,
			domain.AggregateKindGrant:      domain.ExpectationMustNotExist,
		},
		evidenceMinimums: map[EvidenceGuardKind]int{
			EvidenceCurrentAuthorityEpoch: 1, EvidenceBootstrapGeneration: 1, EvidenceLifecycleStatus: 1,
		},
		disclosure: map[domain.AggregateKind]int{domain.AggregateKindInvitation: 1},
	},
	CommandRegisterPrincipal: singleCreateContract(
		CommandRegisterPrincipal, ReceiptIdentityInstallationAdmin, domain.ScopeKindInstallation,
		AuthorshipAuthority, attributionForbidden, AuthorityTimeOrdinary,
		domain.AggregateKindPrincipal, domain.EventTypePrincipalRegistered, 2, 1,
	),
	CommandCreateWorkspace: {
		operation: CommandCreateWorkspace, receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
		authorship: AuthorshipAuthority, attribution: attributionForbidden,
		recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeOrdinary,
		facts: []domain.EventType{domain.EventTypeWorkspaceCreated, domain.EventTypeWorkspaceMemberInvited, domain.EventTypeWorkspaceMembershipAccepted},
		mutations: map[domain.AggregateKind]domain.ExpectationKind{
			domain.AggregateKindWorkspace:  domain.ExpectationMustNotExist,
			domain.AggregateKindMembership: domain.ExpectationMustNotExist,
		},
		evidenceMinimums: standardEvidenceMinimums(2, 1), genesis: true,
		reads:      map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindGrant: 1},
		disclosure: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1},
	},
	CommandInviteWorkspaceMember: ceremonyCreateContract(
		CommandInviteWorkspaceMember, domain.AggregateKindMembership, domain.EventTypeWorkspaceMemberInvited,
		domain.CeremonyPurposeMembershipAcceptance, 3,
	),
	CommandAcceptWorkspaceMembership: ceremonyAdvanceContract(
		CommandAcceptWorkspaceMembership, AuthorshipAuthority, domain.AggregateKindMembership,
		domain.EventTypeWorkspaceMembershipAccepted, domain.CeremonyPurposeMembershipAcceptance, 3,
	),
	CommandCreateActor: singleCreateContract(
		CommandCreateActor, ReceiptIdentityOrdinary, domain.ScopeKindWorkspace,
		AuthorshipWorkspaceAdmin, attributionOptional, AuthorityTimeOrdinary,
		domain.AggregateKindActor, domain.EventTypeActorCreated, 2, 0,
	),
	CommandProposeActorDelegation: withOptionalAttribution(ceremonyCreateContract(
		CommandProposeActorDelegation, domain.AggregateKindActorDelegation, domain.EventTypeActorDelegationProposed,
		domain.CeremonyPurposeDelegationActivation, 5,
	)),
	CommandActivateActorDelegation: {
		operation: CommandActivateActorDelegation, receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
		authorship: AuthorshipAuthority, attribution: attributionForbidden,
		recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeIssuesExpiringAuthority,
		facts:     []domain.EventType{domain.EventTypeActorDelegationActivated},
		mutations: map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindActorDelegation: domain.ExpectationExpectedVersion},
		ceremonies: []ceremonyContract{
			{kind: CeremonyConsumeEmbedded, purpose: domain.CeremonyPurposeDelegationActivation},
			{kind: CeremonyReserveAbsent, purpose: domain.CeremonyPurposeActorSessionStart},
		},
		evidenceMinimums: standardEvidenceMinimums(5, 1),
		reads: map[domain.AggregateKind]int{
			domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 1,
			domain.AggregateKindActor: 1, domain.AggregateKindMembership: 1,
		},
		referenceReads: map[domain.AggregateKind]int{
			domain.AggregateKindWorkspace: 1, domain.AggregateKindActor: 1, domain.AggregateKindMembership: 1,
		},
		disclosure: map[domain.AggregateKind]int{
			domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1,
			domain.AggregateKindActorDelegation: 1,
		},
	},
	CommandBeginDevicePairing: ceremonyCreateContract(
		CommandBeginDevicePairing, domain.AggregateKindDevice, domain.EventTypeDevicePairingBegan,
		domain.CeremonyPurposeDevicePairing, 2,
	),
	CommandPairDevice: {
		operation: CommandPairDevice, receipt: ReceiptIdentityInstallationAdmin, scope: domain.ScopeKindInstallation,
		authorship: AuthorshipAuthority, attribution: attributionForbidden,
		recovery: RecoveryCapsuleNotApplicable, timeClass: AuthorityTimeOrdinary,
		facts:      []domain.EventType{domain.EventTypeDevicePaired},
		mutations:  map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindDevice: domain.ExpectationExpectedVersion},
		ceremonies: []ceremonyContract{{kind: CeremonyConsumeEmbedded, purpose: domain.CeremonyPurposeDevicePairing}},
		evidenceMinimums: map[EvidenceGuardKind]int{
			EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1,
			EvidenceLifecycleStatus: 2, EvidenceDeviceTrustRevision: 1,
		},
		reads:      map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1},
		disclosure: map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindDevice: 1},
	},
	CommandStartActorSession: {
		operation: CommandStartActorSession, receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
		authorship: AuthorshipAuthority, attribution: attributionForbidden,
		recovery: RecoveryCapsuleRequired, timeClass: AuthorityTimeIssuesExpiringAuthority,
		facts:     []domain.EventType{domain.EventTypeActorSessionStarted},
		mutations: map[domain.AggregateKind]domain.ExpectationKind{domain.AggregateKindActorSession: domain.ExpectationMustNotExist},
		evidenceMinimums: map[EvidenceGuardKind]int{
			EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1,
			EvidenceLifecycleStatus: 5, EvidenceCapabilityCeiling: 2, EvidenceResourceConstraint: 1,
		},
		reads: map[domain.AggregateKind]int{
			domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1,
			domain.AggregateKindMembership: 1, domain.AggregateKindActor: 1,
			domain.AggregateKindActorDelegation: 1,
		},
		variableReads:  map[domain.AggregateKind]bool{domain.AggregateKindGrant: true, domain.AggregateKindDevice: true},
		referenceReads: map[domain.AggregateKind]int{},
		disclosure: map[domain.AggregateKind]int{
			domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1,
			domain.AggregateKindActorSession: 1,
		},
	},
}

func standardEvidenceMinimums(lifecycle, ceilings int) map[EvidenceGuardKind]int {
	minimums := map[EvidenceGuardKind]int{
		EvidenceCurrentAuthorityEpoch: 1, EvidencePolicyRevision: 1,
		EvidenceLifecycleStatus: lifecycle,
	}
	if ceilings > 0 {
		minimums[EvidenceCapabilityCeiling] = ceilings
	}
	return minimums
}

func singleCreateContract(
	operation CommandOperation,
	receipt ReceiptIdentityKind,
	scope domain.ScopeKind,
	authorship AuthorshipClass,
	attribution attributionPolicy,
	timeClass AuthorityTimeClass,
	target domain.AggregateKind,
	fact domain.EventType,
	lifecycle int,
	ceilings int,
) operationContract {
	contract := operationContract{
		operation: operation, receipt: receipt, scope: scope, authorship: authorship, attribution: attribution,
		recovery: RecoveryCapsuleRequired, timeClass: timeClass, facts: []domain.EventType{fact},
		mutations:        map[domain.AggregateKind]domain.ExpectationKind{target: domain.ExpectationMustNotExist},
		evidenceMinimums: standardEvidenceMinimums(lifecycle, ceilings),
	}
	switch operation {
	case CommandRegisterPrincipal:
		contract.reads = map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindGrant: 1}
		contract.disclosure = map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 2}
	case CommandCreateActor:
		contract.reads = map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 1}
		contract.disclosure = map[domain.AggregateKind]int{
			domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindActor: 1,
		}
	}
	return contract
}

func ceremonyCreateContract(
	operation CommandOperation,
	target domain.AggregateKind,
	fact domain.EventType,
	purpose domain.CeremonyPurpose,
	lifecycle int,
) operationContract {
	contract := singleCreateContract(
		operation, ReceiptIdentityOrdinary, domain.ScopeKindWorkspace,
		AuthorshipWorkspaceAdmin, attributionForbidden, AuthorityTimeIssuesExpiringAuthority,
		target, fact, lifecycle, 1,
	)
	if operation == CommandBeginDevicePairing {
		contract.receipt = ReceiptIdentityInstallationAdmin
		contract.scope = domain.ScopeKindInstallation
		contract.authorship = AuthorshipAuthority
	}
	contract.ceremonies = []ceremonyContract{{kind: CeremonyReserveAbsent, purpose: purpose}}
	switch operation {
	case CommandInviteWorkspaceMember:
		contract.reads = map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 2}
		contract.disclosure = map[domain.AggregateKind]int{
			domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1, domain.AggregateKindMembership: 1,
		}
		contract.referenceReads = map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1}
	case CommandProposeActorDelegation:
		contract.reads = map[domain.AggregateKind]int{
			domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 2,
			domain.AggregateKindActor: 1, domain.AggregateKindMembership: 1,
		}
		contract.disclosure = map[domain.AggregateKind]int{
			domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1,
			domain.AggregateKindActorDelegation: 1,
		}
		contract.referenceReads = map[domain.AggregateKind]int{
			domain.AggregateKindPrincipal: 1, domain.AggregateKindActor: 1, domain.AggregateKindMembership: 1,
		}
	case CommandBeginDevicePairing:
		contract.reads = map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindGrant: 1}
		contract.disclosure = map[domain.AggregateKind]int{domain.AggregateKindPrincipal: 1, domain.AggregateKindDevice: 1}
	}
	return contract
}

func withOptionalAttribution(contract operationContract) operationContract {
	contract.attribution = attributionOptional
	return contract
}

func ceremonyAdvanceContract(
	operation CommandOperation,
	authorship AuthorshipClass,
	target domain.AggregateKind,
	fact domain.EventType,
	purpose domain.CeremonyPurpose,
	lifecycle int,
) operationContract {
	return operationContract{
		operation: operation, receipt: ReceiptIdentityOrdinary, scope: domain.ScopeKindWorkspace,
		authorship: authorship, attribution: attributionForbidden,
		recovery: RecoveryCapsuleNotApplicable, timeClass: AuthorityTimeOrdinary,
		facts:            []domain.EventType{fact},
		mutations:        map[domain.AggregateKind]domain.ExpectationKind{target: domain.ExpectationExpectedVersion},
		ceremonies:       []ceremonyContract{{kind: CeremonyConsumeEmbedded, purpose: purpose}},
		evidenceMinimums: standardEvidenceMinimums(lifecycle, 0),
		reads: map[domain.AggregateKind]int{
			domain.AggregateKindWorkspace: 1, domain.AggregateKindPrincipal: 1,
		},
		referenceReads: map[domain.AggregateKind]int{domain.AggregateKindWorkspace: 1},
		disclosure: map[domain.AggregateKind]int{
			domain.AggregateKindPrincipal: 1, domain.AggregateKindWorkspace: 1,
			domain.AggregateKindMembership: 1,
		},
	}
}

type CommandSpecParams struct {
	Scope              domain.AuthorityScope
	AuthorityID        domain.AuthorityID
	RequestedEpoch     domain.AuthorityEpoch
	CommandID          domain.CommandID
	ReceiptID          domain.ReceiptID
	Operation          domain.OperationName
	OperationMajor     OperationMajor
	ReceiptIdentity    ReceiptIdentity
	RequestFingerprint domain.CommandFingerprint
	Authorship         CommandAuthorship
	CorrelationID      domain.CorrelationID
	CausationEventID   *domain.EventID
	AuthorityTimeClass AuthorityTimeClass
	RecoveryCapsule    RecoveryCapsulePlan
	Guards             CommandGuardPlan
	ExpectedFacts      []FactExpectation
}

type CommandSpec struct {
	commandOperation   CommandOperation
	scope              domain.AuthorityScope
	authorityID        domain.AuthorityID
	requestedEpoch     domain.AuthorityEpoch
	commandID          domain.CommandID
	receiptID          domain.ReceiptID
	operation          domain.OperationName
	operationMajor     OperationMajor
	receiptIdentity    ReceiptIdentity
	requestFingerprint domain.CommandFingerprint
	authorship         CommandAuthorship
	correlationID      domain.CorrelationID
	causationEventID   domain.EventID
	hasCausation       bool
	authorityTimeClass AuthorityTimeClass
	recoveryCapsule    RecoveryCapsulePlan
	guards             CommandGuardPlan
	expectedFacts      []FactExpectation
}

func NewCommandSpec(params CommandSpecParams) (CommandSpec, error) {
	contract, cataloged := operationContracts[CommandOperation(params.Operation.String())]
	if params.Scope.IsZero() || params.AuthorityID.IsZero() || params.RequestedEpoch.IsZero() ||
		params.CommandID.IsZero() || params.ReceiptID.IsZero() || params.Operation.String() == "" ||
		!operationHasMajor(params.Operation, params.OperationMajor) || params.ReceiptIdentity.kind == "" ||
		params.ReceiptIdentity.Scope() != params.Scope || params.ReceiptIdentity.Operation() != params.Operation ||
		params.RequestFingerprint.IsZero() || params.Authorship.principal.IsZero() ||
		params.CorrelationID.IsZero() || !params.AuthorityTimeClass.Valid() || params.Guards.admissionGeneration.IsZero() ||
		len(params.ExpectedFacts) == 0 || len(params.ExpectedFacts) > MaxCommandFacts || !cataloged {
		return CommandSpec{}, ErrInvalidCommandSpec
	}
	if !authorshipMatchesReceipt(params.Authorship, params.ReceiptIdentity) {
		return CommandSpec{}, ErrInvalidCommandSpec
	}
	if params.CausationEventID != nil && params.CausationEventID.IsZero() {
		return CommandSpec{}, ErrInvalidCommandSpec
	}
	switch params.RecoveryCapsule.requirement {
	case RecoveryCapsuleRequired:
		if !validOpaqueText(params.RecoveryCapsule.keyID, 256) ||
			len(params.RecoveryCapsule.publicKey) != ed25519.PublicKeySize {
			return CommandSpec{}, ErrInvalidCommandSpec
		}
	case RecoveryCapsuleNotApplicable:
		if params.RecoveryCapsule.keyID != "" || len(params.RecoveryCapsule.publicKey) != 0 {
			return CommandSpec{}, ErrInvalidCommandSpec
		}
	default:
		return CommandSpec{}, ErrInvalidCommandSpec
	}
	if !matchesOperationContract(params, contract) {
		return CommandSpec{}, ErrInvalidCommandSpec
	}

	expectedFacts := append([]FactExpectation(nil), params.ExpectedFacts...)
	seenEventIDs := make(map[domain.EventID]struct{}, len(expectedFacts))
	postVersions := mutationPostVersions(params.Guards.mutations)
	for index, fact := range expectedFacts {
		if fact.eventID.IsZero() || !identityEventType(fact.eventType) || fact.origin.IsZero() {
			return CommandSpec{}, ErrInvalidCommandSpec
		}
		if _, duplicate := seenEventIDs[fact.eventID]; duplicate {
			return CommandSpec{}, ErrInvalidCommandSpec
		}
		seenEventIDs[fact.eventID] = struct{}{}
		expectedFacts[index].ordinal = uint16(index)
		postVersion, mutated := postVersions[fact.origin.Target()]
		if !mutated || postVersion != fact.origin.Version() {
			return CommandSpec{}, ErrInvalidCommandSpec
		}
	}

	spec := CommandSpec{
		commandOperation: contract.operation,
		scope:            params.Scope, authorityID: params.AuthorityID, requestedEpoch: params.RequestedEpoch,
		commandID: params.CommandID, receiptID: params.ReceiptID, operation: params.Operation,
		operationMajor: params.OperationMajor, receiptIdentity: params.ReceiptIdentity,
		requestFingerprint: params.RequestFingerprint, authorship: params.Authorship,
		correlationID: params.CorrelationID, authorityTimeClass: params.AuthorityTimeClass,
		recoveryCapsule: params.RecoveryCapsule,
		guards:          cloneGuardPlan(params.Guards), expectedFacts: expectedFacts,
	}
	if params.CausationEventID != nil {
		spec.causationEventID = *params.CausationEventID
		spec.hasCausation = true
	}
	return spec, nil
}

func authorshipMatchesReceipt(authorship CommandAuthorship, identity ReceiptIdentity) bool {
	switch identity.Kind() {
	case ReceiptIdentityProvisioning:
		return authorship.Class() == AuthorshipProvisioning
	case ReceiptIdentityOrdinary:
		return authorship.Class() != AuthorshipProvisioning && authorship.PrincipalID() == identity.PrincipalID()
	case ReceiptIdentityInstallationAdmin:
		return authorship.Class() == AuthorshipAuthority && authorship.PrincipalID() == identity.PrincipalID()
	default:
		return false
	}
}

func matchesOperationContract(params CommandSpecParams, contract operationContract) bool {
	if params.ReceiptIdentity.kind != contract.receipt || params.Scope.Kind() != contract.scope ||
		params.Authorship.class != contract.authorship || params.RecoveryCapsule.requirement != contract.recovery ||
		params.AuthorityTimeClass != contract.timeClass || params.Guards.admissionScope.IsZero() {
		return false
	}
	if contract.attribution == attributionForbidden && params.Authorship.hasActor {
		return false
	}
	if params.Authorship.hasActor && (params.Authorship.actor.IsZero() || params.Authorship.actorSession.IsZero()) {
		return false
	}
	if !params.Authorship.hasActor && (!params.Authorship.actor.IsZero() || !params.Authorship.actorSession.IsZero()) {
		return false
	}
	if contract.operation == CommandCreateWorkspace {
		genesis, present := params.Guards.GenesisAbsence()
		if !present || genesis.scope != params.Scope || params.Guards.admissionScope.Kind() != domain.ScopeKindInstallation {
			return false
		}
		if genesis.authorityID != params.AuthorityID || genesis.epoch != params.RequestedEpoch {
			return false
		}
	} else if params.Guards.genesis != nil || params.Guards.admissionScope != params.Scope {
		return false
	}
	if !matchesMutationContract(params.Guards.mutations, contract.mutations) ||
		!matchesReadContract(params, contract) ||
		!matchesDisclosureContract(params.Guards.disclosure, contract.disclosure) ||
		!matchesFactContract(params.ExpectedFacts, contract.facts) ||
		!matchesCeremonyContract(params.Guards.ceremonies, contract) ||
		!matchesEvidenceContract(params, contract) {
		return false
	}
	return true
}

func matchesDisclosureContract(
	targets []domain.AggregateTarget,
	want map[domain.AggregateKind]int,
) bool {
	if len(targets) == 0 || len(want) == 0 {
		return false
	}
	counts := make(map[domain.AggregateKind]int)
	for _, target := range targets {
		counts[target.Kind()]++
	}
	if len(counts) != len(want) {
		return false
	}
	for kind, count := range want {
		if counts[kind] != count {
			return false
		}
	}
	return true
}

func matchesReadContract(params CommandSpecParams, contract operationContract) bool {
	authorizationWant := make(map[domain.AggregateKind]int, len(contract.reads)+2)
	for kind, count := range contract.reads {
		authorizationWant[kind] = count - contract.referenceReads[kind]
	}
	if params.Authorship.hasActor {
		authorizationWant[domain.AggregateKindActor]++
		authorizationWant[domain.AggregateKindActorSession]++
		actorTarget, err := domain.NewAggregateTarget(params.Authorship.actor)
		if err != nil {
			return false
		}
		sessionTarget, err := domain.NewAggregateTarget(params.Authorship.actorSession)
		if err != nil {
			return false
		}
		if !containsRefTarget(params.Guards.authorization, actorTarget) {
			return false
		}
		if !containsRefTarget(params.Guards.authorization, sessionTarget) {
			return false
		}
	}
	if !exactRefKindCounts(params.Guards.authorization, authorizationWant, nil) {
		return false
	}
	if !exactRefKindCounts(params.Guards.references, contract.referenceReads, contract.variableReads) {
		return false
	}
	return true
}

func containsRefTarget(refs []domain.AggregateRef, target domain.AggregateTarget) bool {
	for _, ref := range refs {
		if ref.Target() == target {
			return true
		}
	}
	return false
}

func exactRefKindCounts(
	refs []domain.AggregateRef,
	want map[domain.AggregateKind]int,
	variable map[domain.AggregateKind]bool,
) bool {
	counts := make(map[domain.AggregateKind]int)
	for _, ref := range refs {
		counts[ref.Kind()]++
	}
	for kind, count := range want {
		if counts[kind] != count {
			return false
		}
	}
	for kind, count := range counts {
		if _, fixed := want[kind]; fixed {
			continue
		}
		if !variable[kind] || count == 0 {
			return false
		}
	}
	return true
}

func matchesMutationContract(
	mutations []domain.AggregateExpectation,
	want map[domain.AggregateKind]domain.ExpectationKind,
) bool {
	if len(mutations) != len(want) {
		return false
	}
	seen := make(map[domain.AggregateKind]struct{}, len(mutations))
	for _, mutation := range mutations {
		if mutation.Kind() != want[mutation.Target().Kind()] {
			return false
		}
		if _, duplicate := seen[mutation.Target().Kind()]; duplicate {
			return false
		}
		seen[mutation.Target().Kind()] = struct{}{}
	}
	return len(seen) == len(want)
}

func matchesFactContract(facts []FactExpectation, want []domain.EventType) bool {
	if len(facts) != len(want) {
		return false
	}
	for index := range want {
		if facts[index].eventType != want[index] {
			return false
		}
	}
	return true
}

func matchesCeremonyContract(claims []CeremonyClaim, contract operationContract) bool {
	if contract.operation == CommandStartActorSession {
		if len(claims) == 0 {
			return true
		}
		return len(claims) == 1 && claims[0].kind == CeremonyConsumeStandalone &&
			claims[0].purpose == domain.CeremonyPurposeActorSessionStart
	}
	if len(claims) != len(contract.ceremonies) {
		return false
	}
	remaining := append([]ceremonyContract(nil), contract.ceremonies...)
	for _, claim := range claims {
		matched := -1
		for index, expected := range remaining {
			if claim.kind == expected.kind && claim.purpose == expected.purpose {
				matched = index
				break
			}
		}
		if matched < 0 {
			return false
		}
		remaining = append(remaining[:matched], remaining[matched+1:]...)
	}
	return len(remaining) == 0
}

func matchesEvidenceContract(params CommandSpecParams, contract operationContract) bool {
	counts := make(map[EvidenceGuardKind]int)
	declaredTargets := make(map[string]struct{})
	for _, group := range [][]domain.AggregateRef{params.Guards.authorization, params.Guards.references} {
		for _, ref := range group {
			declaredTargets[ref.Target().String()] = struct{}{}
		}
	}
	for _, mutation := range params.Guards.mutations {
		declaredTargets[mutation.Target().String()] = struct{}{}
	}
	for _, guard := range params.Guards.evidence {
		counts[guard.kind]++
		if guard.kind == EvidenceCurrentAuthorityEpoch {
			if guard.targetKind != string(params.Guards.admissionScope.Kind()) ||
				guard.targetID != params.Guards.admissionScope.ID() ||
				guard.authorityID != params.AuthorityID || guard.authorityEpoch != params.RequestedEpoch {
				return false
			}
		}
		if (guard.kind == EvidencePolicyRevision || guard.kind == EvidenceBootstrapGeneration) &&
			(guard.targetKind != string(params.Guards.admissionScope.Kind()) ||
				guard.targetID != params.Guards.admissionScope.ID()) {
			return false
		}
		if guard.kind == EvidenceLifecycleStatus || guard.kind == EvidenceDeviceTrustRevision ||
			guard.kind == EvidenceCapabilityCeiling || guard.kind == EvidenceResourceConstraint {
			if _, declared := declaredTargets[guard.targetKind+":"+guard.targetID]; !declared {
				return false
			}
		}
	}
	for kind, minimum := range contract.evidenceMinimums {
		if kind == EvidenceLifecycleStatus && params.Authorship.hasActor {
			minimum += 2
		}
		if counts[kind] < minimum || (contract.operation != CommandStartActorSession && counts[kind] != minimum) {
			return false
		}
	}
	for kind := range counts {
		if _, expected := contract.evidenceMinimums[kind]; !expected {
			// Start-session permits an optional trusted-device predicate.
			if contract.operation != CommandStartActorSession || kind != EvidenceDeviceTrustRevision {
				return false
			}
		}
	}
	if contract.operation == CommandStartActorSession {
		if counts[EvidenceCurrentAuthorityEpoch] != 1 || counts[EvidencePolicyRevision] != 1 ||
			counts[EvidenceCapabilityCeiling] != 2 || counts[EvidenceResourceConstraint] != 1 ||
			counts[EvidenceDeviceTrustRevision] > 1 {
			return false
		}
	}
	if contract.operation == CommandBootstrapInstallation {
		for _, guard := range params.Guards.evidence {
			if guard.kind == EvidenceLifecycleStatus && guard.status != string(domain.InstallationInvitationPending) {
				return false
			}
		}
	}
	return true
}

func mutationPostVersions(
	expectations []domain.AggregateExpectation,
) map[domain.AggregateTarget]domain.Version {
	versions := make(map[domain.AggregateTarget]domain.Version, len(expectations))
	for _, expectation := range expectations {
		if expectation.Kind() == domain.ExpectationMustNotExist {
			versions[expectation.Target()] = domain.InitialVersion()
			continue
		}
		version, _ := expectation.Version()
		next, err := version.Next()
		if err == nil {
			versions[expectation.Target()] = next
		}
	}
	return versions
}

func cloneGuardPlan(plan CommandGuardPlan) CommandGuardPlan {
	clone := CommandGuardPlan{
		admissionScope: plan.admissionScope, admissionGeneration: plan.admissionGeneration,
		evidence:      append([]EvidenceGuard(nil), plan.evidence...),
		authorization: append([]domain.AggregateRef(nil), plan.authorization...),
		references:    append([]domain.AggregateRef(nil), plan.references...),
		disclosure:    append([]domain.AggregateTarget(nil), plan.disclosure...),
		mutations:     append([]domain.AggregateExpectation(nil), plan.mutations...),
		ceremonies:    append([]CeremonyClaim(nil), plan.ceremonies...),
	}
	if plan.genesis != nil {
		genesis := *plan.genesis
		clone.genesis = &genesis
	}
	return clone
}

func (spec CommandSpec) Scope() domain.AuthorityScope          { return spec.scope }
func (spec CommandSpec) CommandOperation() CommandOperation    { return spec.commandOperation }
func (spec CommandSpec) AuthorityID() domain.AuthorityID       { return spec.authorityID }
func (spec CommandSpec) RequestedEpoch() domain.AuthorityEpoch { return spec.requestedEpoch }
func (spec CommandSpec) CommandID() domain.CommandID           { return spec.commandID }
func (spec CommandSpec) ReceiptID() domain.ReceiptID           { return spec.receiptID }
func (spec CommandSpec) Operation() domain.OperationName       { return spec.operation }
func (spec CommandSpec) OperationMajor() OperationMajor        { return spec.operationMajor }
func (spec CommandSpec) ReceiptIdentity() ReceiptIdentity      { return spec.receiptIdentity }
func (spec CommandSpec) RequestFingerprint() domain.CommandFingerprint {
	return spec.requestFingerprint
}
func (spec CommandSpec) Authorship() CommandAuthorship          { return spec.authorship }
func (spec CommandSpec) CorrelationID() domain.CorrelationID    { return spec.correlationID }
func (spec CommandSpec) AuthorityTimeClass() AuthorityTimeClass { return spec.authorityTimeClass }
func (spec CommandSpec) RecoveryCapsule() RecoveryCapsulePlan   { return spec.recoveryCapsule }
func (spec CommandSpec) Guards() CommandGuardPlan               { return cloneGuardPlan(spec.guards) }
func (spec CommandSpec) ExpectedFacts() []FactExpectation {
	return append([]FactExpectation(nil), spec.expectedFacts...)
}
func (spec CommandSpec) CausationEventID() (domain.EventID, bool) {
	return spec.causationEventID, spec.hasCausation
}

type StateKind string

const (
	StateInstallationInvitation StateKind = "installation_invitation"
	StatePrincipal              StateKind = "principal"
	StateDevice                 StateKind = "device"
	StateGrant                  StateKind = "grant"
	StateWorkspace              StateKind = "workspace"
	StateMembership             StateKind = "membership"
	StateActor                  StateKind = "actor"
	StateActorDelegation        StateKind = "actor_delegation"
	StateActorSession           StateKind = "actor_session"
)

// IdentityState is the closed W0 state union shared by application and storage.
// Value returns one of the nine domain state value types accepted by
// NewIdentityState; callers must still switch on Kind before asserting it.
type IdentityState struct {
	kind    StateKind
	target  domain.AggregateTarget
	version domain.Version
	value   any
}

func NewIdentityState(value any) (IdentityState, error) {
	var (
		kind    StateKind
		target  domain.AggregateTarget
		version domain.Version
		err     error
	)
	switch state := value.(type) {
	case domain.InstallationInvitationState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StateInstallationInvitation, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	case domain.PrincipalState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StatePrincipal, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	case domain.DeviceState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StateDevice, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	case domain.GrantState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StateGrant, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	case domain.WorkspaceState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StateWorkspace, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	case domain.MembershipState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StateMembership, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	case domain.ActorState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StateActor, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	case domain.ActorDelegationState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StateActorDelegation, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	case domain.ActorSessionState:
		if state.IsZero() {
			return IdentityState{}, ErrInvalidApplicationContract
		}
		kind, version = StateActorSession, state.Version()
		target, err = domain.NewAggregateTarget(state.ID())
	default:
		return IdentityState{}, ErrInvalidApplicationContract
	}
	if err != nil || version.IsZero() || version.Uint64() > MaxCanonicalInteger {
		return IdentityState{}, ErrInvalidApplicationContract
	}
	return IdentityState{kind: kind, target: target, version: version, value: value}, nil
}

func (state IdentityState) Kind() StateKind                { return state.kind }
func (state IdentityState) Target() domain.AggregateTarget { return state.target }
func (state IdentityState) Version() domain.Version        { return state.version }
func (state IdentityState) Value() any                     { return state.value }

type ResultEnvelope struct {
	canonical      []byte
	responseDigest Digest
	operation      CommandOperation
	document       ReceiptResultDocument
	capsulePlan    RecoveryCapsulePlan
}

// NewResultEnvelope accepts only the sealed output of the production receipt
// result codec. Raw JSON cannot cross this digest boundary.
func NewResultEnvelope(document ReceiptResultDocument) (ResultEnvelope, error) {
	if document.IsZero() {
		return ResultEnvelope{}, ErrInvalidApplicationContract
	}
	canonical := document.CanonicalBytes()
	if len(canonical) == 0 || len(canonical) > MaxReceiptResultBytes {
		return ResultEnvelope{}, ErrInvalidApplicationContract
	}
	return ResultEnvelope{
		canonical: canonical, responseDigest: document.Digest(), operation: document.Operation(),
		document: document,
	}, nil
}

func (result ResultEnvelope) IsZero() bool                           { return len(result.canonical) == 0 }
func (result ResultEnvelope) CanonicalBytes() []byte                 { return append([]byte(nil), result.canonical...) }
func (result ResultEnvelope) ResponseDigest() Digest                 { return result.responseDigest }
func (result ResultEnvelope) Operation() CommandOperation            { return result.operation }
func (result ResultEnvelope) ReceiptDocument() ReceiptResultDocument { return result.document }
func (result ResultEnvelope) RecoveryCapsulePlan() RecoveryCapsulePlan {
	return cloneRecoveryCapsulePlan(result.capsulePlan)
}

func bindResultEnvelopePlan(result ResultEnvelope, plan ReceiptResultPlan) (ResultEnvelope, error) {
	if result.IsZero() || result.operation != plan.operation ||
		plan.capsulePlan.requirement == "" ||
		result.document.wire.CapsuleRequired != (plan.capsulePlan.requirement == RecoveryCapsuleRequired) {
		return ResultEnvelope{}, ErrInvalidApplicationContract
	}
	result.capsulePlan = cloneRecoveryCapsulePlan(plan.capsulePlan)
	return result, nil
}

type AuditOutcome string

const (
	AuditCommandApplied   AuditOutcome = "command_applied"
	AuditSecurityMutation AuditOutcome = "security_mutation"
	AuditSecurityDenied   AuditOutcome = "security_denied"
)

type AuditIntent struct {
	operation        domain.OperationName
	outcome          AuditOutcome
	fingerprint      domain.CommandFingerprint
	detail           AuditDetail
	invocation       AuditInvocation
	timing           AuditTiming
	subject          AuditSubject
	provenance       AuditProvenance
	authorization    AuditAuthorization
	resources        []AuditResourceVersion
	approvalEvidence []Digest
	finalized        bool
}

type AuditInvocationKind string

const (
	AuditInvocationCommand  AuditInvocationKind = "command"
	AuditInvocationSecurity AuditInvocationKind = "security"
)

// AuditInvocation is a closed command/security union. Command identifiers and
// receipt identity cannot be supplied independently of the CommandSpec from
// which they are derived. Security-only entries retain their closed operation
// identity without pretending that a command receipt existed.
type AuditInvocation struct {
	kind                  AuditInvocationKind
	commandID             domain.CommandID
	receiptID             domain.ReceiptID
	receiptIdentityDigest Digest
	requestID             *CanonicalIdentifier
	correlationID         *CanonicalIdentifier
	traceID               *CanonicalIdentifier
	securityOperation     SecurityOperation
}

type AuditTiming struct {
	persistedAuthorityTime time.Time
	serverReceivedTime     *time.Time
	clientTime             *time.Time
}

// AuditRequestContext is trusted transport metadata that is excluded from the
// semantic command fingerprint but retained in the required audit entry.
type AuditRequestContext struct {
	requestID      CanonicalIdentifier
	traceID        CanonicalIdentifier
	serverReceived time.Time
	clientTime     time.Time
	hasClientTime  bool
}

func NewAuditRequestContext(
	requestID string,
	traceID string,
	serverReceived time.Time,
	authenticatedClientTime *time.Time,
) (AuditRequestContext, error) {
	request, requestErr := NewCanonicalIdentifier(requestID)
	trace, traceErr := NewCanonicalIdentifier(traceID)
	if requestErr != nil || traceErr != nil || serverReceived.IsZero() {
		return AuditRequestContext{}, ErrInvalidApplicationContract
	}
	if _, err := NewCanonicalInstant(serverReceived); err != nil {
		return AuditRequestContext{}, ErrInvalidApplicationContract
	}
	result := AuditRequestContext{
		requestID: request, traceID: trace, serverReceived: serverReceived.UTC(),
	}
	if authenticatedClientTime != nil {
		if authenticatedClientTime.IsZero() {
			return AuditRequestContext{}, ErrInvalidApplicationContract
		}
		if _, err := NewCanonicalInstant(*authenticatedClientTime); err != nil {
			return AuditRequestContext{}, ErrInvalidApplicationContract
		}
		result.clientTime, result.hasClientTime = authenticatedClientTime.UTC(), true
	}
	return result, nil
}

func (context AuditRequestContext) RequestID() string { return context.requestID.String() }
func (context AuditRequestContext) TraceID() string   { return context.traceID.String() }
func (context AuditRequestContext) ServerReceivedAt() time.Time {
	return context.serverReceived
}
func (context AuditRequestContext) AuthenticatedClientAt() (time.Time, bool) {
	return context.clientTime, context.hasClientTime
}

func validAuditRequestContext(context AuditRequestContext) bool {
	if context.requestID.String() == "" || context.traceID.String() == "" || context.serverReceived.IsZero() {
		return false
	}
	if _, err := NewCanonicalIdentifier(context.requestID.String()); err != nil {
		return false
	}
	if _, err := NewCanonicalIdentifier(context.traceID.String()); err != nil {
		return false
	}
	if _, err := NewCanonicalInstant(context.serverReceived); err != nil {
		return false
	}
	if context.hasClientTime {
		_, err := NewCanonicalInstant(context.clientTime)
		return err == nil
	}
	return context.clientTime.IsZero()
}

type AuditProvenanceEvidence struct {
	sourceAuthority    domain.AuthorityID
	federationEnvelope *CanonicalIdentifier
}

func NewAuditProvenanceEvidence(
	sourceAuthority domain.AuthorityID,
	federationEnvelopeID *string,
) (AuditProvenanceEvidence, error) {
	if sourceAuthority.IsZero() {
		return AuditProvenanceEvidence{}, ErrInvalidApplicationContract
	}
	evidence := AuditProvenanceEvidence{sourceAuthority: sourceAuthority}
	if federationEnvelopeID != nil {
		envelope, err := NewCanonicalIdentifier(*federationEnvelopeID)
		if err != nil {
			return AuditProvenanceEvidence{}, ErrInvalidApplicationContract
		}
		evidence.federationEnvelope = &envelope
	}
	return evidence, nil
}

func (evidence AuditProvenanceEvidence) SourceAuthorityID() domain.AuthorityID {
	return evidence.sourceAuthority
}
func (evidence AuditProvenanceEvidence) FederationEnvelopeID() (string, bool) {
	if evidence.federationEnvelope == nil {
		return "", false
	}
	return evidence.federationEnvelope.String(), true
}

func validAuditProvenanceEvidence(evidence AuditProvenanceEvidence) bool {
	if evidence.sourceAuthority.IsZero() {
		return false
	}
	if evidence.federationEnvelope == nil {
		return true
	}
	_, err := NewCanonicalIdentifier(evidence.federationEnvelope.String())
	return err == nil
}

type AuditSubjectKind string

const (
	AuditSubjectAttributed   AuditSubjectKind = "attributed"
	AuditSubjectUnattributed AuditSubjectKind = "unattributed"
)

// AuditSubject keeps principal/device/workload attribution separate from the
// actor/session/delegation chain. A denial before authentication uses only a
// one-way source digest; raw addresses, channels, and credentials cannot enter.
type AuditSubject struct {
	kind         AuditSubjectKind
	principal    domain.PrincipalID
	device       domain.DeviceID
	hasDevice    bool
	workload     domain.PrincipalID
	hasWorkload  bool
	actor        domain.ActorID
	actorSession domain.ActorSessionID
	hasActor     bool
	delegations  []domain.AggregateRef
	unattributed Digest
}

type AuditProvenance struct {
	sourceAuthority    domain.AuthorityID
	federationEnvelope *CanonicalIdentifier
}

type AuditRevision struct {
	target  domain.AggregateTarget
	version domain.Version
}

type AuditAuthorization struct {
	grants              []AuditRevision
	authorization       []AuditRevision
	revocations         []AuditRevision
	policy              domain.PolicyRevision
	hasPolicy           bool
	deviceTrustRevision domain.Version
	hasDeviceTrust      bool
	guardDigest         domain.AuthorizationDigest
	admissionGeneration GuardGeneration
	oldGeneration       domain.BootstrapGenerationID
	newGeneration       domain.BootstrapGenerationID
	hasGenerationChange bool
}

type AuditResourceVersion struct {
	target    domain.AggregateTarget
	before    domain.Version
	hasBefore bool
	after     domain.Version
	hasAfter  bool
}

type AuditDetailKind string

const (
	AuditDetailCommandApplied   AuditDetailKind = "command_applied"
	AuditDetailSecurityMutation AuditDetailKind = "security_mutation"
	AuditDetailSecurityDenied   AuditDetailKind = "security_denied"
)

// AuditDetail is a safe, closed record. Arbitrary JSON/text, credentials, and
// request bodies cannot enter the audit transaction through this boundary.
type AuditDetail struct {
	kind   AuditDetailKind
	reason string
}

func CommandAppliedAuditDetail() AuditDetail { return AuditDetail{kind: AuditDetailCommandApplied} }
func SecurityMutationAuditDetail(reason string) (AuditDetail, error) {
	return newReasonAuditDetail(AuditDetailSecurityMutation, reason)
}
func SecurityDeniedAuditDetail(reason string) (AuditDetail, error) {
	return newReasonAuditDetail(AuditDetailSecurityDenied, reason)
}
func newReasonAuditDetail(kind AuditDetailKind, reason string) (AuditDetail, error) {
	if !validAuditReason(reason) {
		return AuditDetail{}, ErrInvalidApplicationContract
	}
	return AuditDetail{kind: kind, reason: reason}, nil
}
func (detail AuditDetail) Kind() AuditDetailKind { return detail.kind }
func (detail AuditDetail) SafeReason() string    { return detail.reason }

func NewAuditIntent(
	operation domain.OperationName,
	outcome AuditOutcome,
	fingerprint domain.CommandFingerprint,
	detail AuditDetail,
) (AuditIntent, error) {
	if operation.String() == "" || fingerprint.IsZero() ||
		(outcome == AuditCommandApplied && detail.kind != AuditDetailCommandApplied) ||
		(outcome == AuditSecurityMutation && detail.kind != AuditDetailSecurityMutation) ||
		(outcome == AuditSecurityDenied && detail.kind != AuditDetailSecurityDenied) ||
		(outcome != AuditCommandApplied && outcome != AuditSecurityMutation && outcome != AuditSecurityDenied) {
		return AuditIntent{}, ErrInvalidApplicationContract
	}
	return AuditIntent{
		operation: operation, outcome: outcome, fingerprint: fingerprint, detail: detail,
	}, nil
}

func (intent AuditIntent) Operation() domain.OperationName { return intent.operation }
func (intent AuditIntent) Outcome() AuditOutcome           { return intent.outcome }
func (intent AuditIntent) Fingerprint() domain.CommandFingerprint {
	return intent.fingerprint
}
func (intent AuditIntent) Detail() AuditDetail { return intent.detail }

func validAuditReason(reason string) bool {
	switch reason {
	case "bootstrap_proof_rejected", "proof_rejected", "credential_rejected",
		"policy_denied", "installation_initialized", "bootstrap_generation_rotated", "bootstrap_generation_resumed":
		return true
	default:
		return false
	}
}

func finalizeCommandAudit(
	seed AuditIntent,
	commandContext CommandContext,
	commit OperationCommit,
) (AuditIntent, error) {
	spec := commandContext.spec
	if seed.finalized || seed.outcome != AuditCommandApplied || seed.operation != spec.operation ||
		seed.fingerprint != spec.requestFingerprint || commandContext.timeEvidence.mode != CommandTimePersistedWrite {
		return AuditIntent{}, ErrInvalidCommandDecision
	}
	receiptDigest, err := hashReceiptIdentity(spec.receiptIdentity)
	if err != nil {
		return AuditIntent{}, ErrInvalidCommandDecision
	}
	trace, err := NewCanonicalIdentifier(spec.correlationID.String())
	if err != nil {
		return AuditIntent{}, ErrInvalidCommandDecision
	}
	seed.invocation.kind = AuditInvocationCommand
	seed.invocation.commandID = spec.commandID
	seed.invocation.receiptID = spec.receiptID
	seed.invocation.receiptIdentityDigest = receiptDigest
	seed.invocation.securityOperation = ""
	seed.invocation.correlationID = &trace
	seed.timing.persistedAuthorityTime = commandContext.timeEvidence.value.UTC()
	seed.subject = commandAuditSubject(seed.subject, commandContext)
	seed.authorization = commandAuditAuthorization(commandContext)
	seed.resources = auditResources(spec.guards.mutations)
	for _, ceremony := range spec.guards.ceremonies {
		if ceremony.kind == CeremonyConsumeEmbedded || ceremony.kind == CeremonyConsumeStandalone {
			seed.approvalEvidence = append(seed.approvalEvidence, Digest(ceremony.proof))
		}
	}
	if len(seed.resources) != len(commit.writes) || seed.subject.kind == "" || seed.authorization.guardDigest.IsZero() {
		return AuditIntent{}, ErrInvalidCommandDecision
	}
	seed.finalized = true
	return seed, nil
}

func commandAuditSubject(subject AuditSubject, commandContext CommandContext) AuditSubject {
	spec := commandContext.spec
	if subject.kind == "" {
		subject = AuditSubject{kind: AuditSubjectAttributed, principal: spec.authorship.principal}
	}
	if spec.authorship.hasActor {
		subject.actor, subject.actorSession, subject.hasActor =
			spec.authorship.actor, spec.authorship.actorSession, true
	}
	for _, state := range commandContext.states {
		switch value := state.value.(type) {
		case domain.PrincipalState:
			if value.ID() == spec.authorship.principal &&
				(value.Kind() == domain.PrincipalKindWorkload || value.Kind() == domain.PrincipalKindService) {
				subject.workload, subject.hasWorkload = value.ID(), true
			}
		case domain.DeviceState:
			if spec.commandOperation == CommandStartActorSession && !subject.hasDevice {
				for _, guard := range spec.guards.evidence {
					if guard.kind == EvidenceDeviceTrustRevision && guard.targetID == value.ID().String() {
						subject.device, subject.hasDevice = value.ID(), true
					}
				}
			}
		}
	}
	for _, ref := range append(spec.guards.Authorization(), spec.guards.References()...) {
		if ref.Target().Kind() == domain.AggregateKindActorDelegation {
			subject.delegations = append(subject.delegations, ref)
		}
	}
	return subject
}

func commandAuditAuthorization(commandContext CommandContext) AuditAuthorization {
	authorization := AuditAuthorization{
		guardDigest:         commandContext.guardEvidence.digest,
		admissionGeneration: commandContext.spec.guards.admissionGeneration,
	}
	revisions := make(map[string]AuditRevision)
	revisionKey := func(target domain.AggregateTarget) string {
		return string(target.Kind()) + "\x00" + target.ID()
	}
	for _, ref := range commandContext.spec.guards.authorization {
		revision := AuditRevision{target: ref.Target(), version: ref.Version()}
		authorization.authorization = append(authorization.authorization, revision)
		revisions[revisionKey(ref.Target())] = revision
		if ref.Target().Kind() == domain.AggregateKindGrant {
			authorization.grants = append(authorization.grants, revision)
		}
	}
	for _, ref := range commandContext.spec.guards.references {
		revisions[revisionKey(ref.Target())] = AuditRevision{target: ref.Target(), version: ref.Version()}
	}
	for _, expectation := range commandContext.spec.guards.mutations {
		if version, present := expectation.Version(); present {
			revisions[revisionKey(expectation.Target())] = AuditRevision{target: expectation.Target(), version: version}
		}
	}
	for _, guard := range commandContext.guardEvidence.observed {
		switch guard.kind {
		case EvidencePolicyRevision:
			authorization.policy, authorization.hasPolicy = guard.policyRevision, true
		case EvidenceDeviceTrustRevision:
			authorization.deviceTrustRevision, authorization.hasDeviceTrust = guard.revision, true
		case EvidenceLifecycleStatus:
			revision, present := revisions[guard.targetKind+"\x00"+guard.targetID]
			if present {
				authorization.revocations = append(authorization.revocations, revision)
			}
		}
	}
	return authorization
}

func auditResources(expectations []domain.AggregateExpectation) []AuditResourceVersion {
	resources := make([]AuditResourceVersion, len(expectations))
	for index, expectation := range expectations {
		resources[index].target = expectation.Target()
		if before, present := expectation.Version(); present {
			resources[index].before, resources[index].hasBefore = before, true
			resources[index].after, _ = before.Next()
			resources[index].hasAfter = true
		} else {
			resources[index].after, resources[index].hasAfter = domain.InitialVersion(), true
		}
	}
	return resources
}

type EffectIntent struct {
	causingEvent   domain.EventID
	handler        string
	contractMajor  OperationMajor
	destinationKey string
	ordinal        uint16
	metadata       []byte
	metadataDigest Digest
}

func NewEffectIntent(
	causingEvent domain.EventID,
	handler string,
	contractMajor OperationMajor,
	destinationKey string,
	ordinal uint16,
	metadata []byte,
) (EffectIntent, error) {
	if causingEvent.IsZero() || !validToken(handler, 128) || contractMajor.IsZero() ||
		!validOpaqueText(destinationKey, 512) || len(metadata) == 0 ||
		len(metadata) > MaxEffectMetadataBytes || !utf8.Valid(metadata) {
		return EffectIntent{}, ErrInvalidApplicationContract
	}
	return EffectIntent{
		causingEvent: causingEvent, handler: handler, contractMajor: contractMajor,
		destinationKey: destinationKey, ordinal: ordinal, metadata: append([]byte(nil), metadata...),
		metadataDigest: DigestBytes(metadata),
	}, nil
}

func validToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func validOpaqueText(value string, maximum int) bool {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (intent EffectIntent) CausingEventID() domain.EventID { return intent.causingEvent }
func (intent EffectIntent) Handler() string                { return intent.handler }
func (intent EffectIntent) ContractMajor() OperationMajor  { return intent.contractMajor }
func (intent EffectIntent) DestinationKey() string         { return intent.destinationKey }
func (intent EffectIntent) Ordinal() uint16                { return intent.ordinal }
func (intent EffectIntent) Metadata() []byte               { return append([]byte(nil), intent.metadata...) }
func (intent EffectIntent) MetadataDigest() Digest         { return intent.metadataDigest }

type EffectSet struct{ intents []EffectIntent }

func NewEffectSet(intents ...EffectIntent) (EffectSet, error) {
	if len(intents) > MaxCommandEffects {
		return EffectSet{}, ErrApplicationLimitExceeded
	}
	cloned := append([]EffectIntent(nil), intents...)
	sort.Slice(cloned, func(left, right int) bool {
		if cloned[left].handler != cloned[right].handler {
			return cloned[left].handler < cloned[right].handler
		}
		if cloned[left].contractMajor != cloned[right].contractMajor {
			return cloned[left].contractMajor.Uint16() < cloned[right].contractMajor.Uint16()
		}
		if cloned[left].destinationKey != cloned[right].destinationKey {
			return cloned[left].destinationKey < cloned[right].destinationKey
		}
		if cloned[left].ordinal != cloned[right].ordinal {
			return cloned[left].ordinal < cloned[right].ordinal
		}
		return cloned[left].causingEvent.String() < cloned[right].causingEvent.String()
	})
	for index, intent := range cloned {
		if intent.causingEvent.IsZero() || intent.handler == "" || intent.contractMajor.IsZero() ||
			intent.destinationKey == "" || len(intent.metadata) == 0 {
			return EffectSet{}, ErrInvalidApplicationContract
		}
		if index > 0 && sameLogicalEffect(cloned[index-1], intent) {
			return EffectSet{}, ErrInvalidApplicationContract
		}
	}
	return EffectSet{intents: cloned}, nil
}

func sameLogicalEffect(left, right EffectIntent) bool {
	return left.handler == right.handler &&
		left.contractMajor == right.contractMajor && left.destinationKey == right.destinationKey &&
		left.ordinal == right.ordinal
}

func (set EffectSet) Intents() []EffectIntent { return append([]EffectIntent(nil), set.intents...) }

type EventRange struct {
	first domain.StreamPosition
	last  domain.StreamPosition
	count uint16
}

func NewEventRange(first domain.StreamPosition, last domain.StreamPosition, count uint16) (EventRange, error) {
	if first.IsZero() || last.IsZero() || count == 0 || first.Uint64() > MaxCanonicalInteger ||
		last.Uint64() > MaxCanonicalInteger || last.Uint64() < first.Uint64() ||
		last.Uint64()-first.Uint64()+1 != uint64(count) {
		return EventRange{}, ErrInvalidApplicationContract
	}
	return EventRange{first: first, last: last, count: count}, nil
}

func (eventRange EventRange) First() domain.StreamPosition { return eventRange.first }
func (eventRange EventRange) Last() domain.StreamPosition  { return eventRange.last }
func (eventRange EventRange) Count() uint16                { return eventRange.count }

// ReceiptResultReplayBinding is the complete trusted record needed to verify
// retained canonical result bytes after restart. It combines the original
// receipt header with an exact stored semantic plan, including resources,
// ceremonies, session binding, event identities, and final stream digest.
type ReceiptResultReplayBinding struct {
	originalCommandID  domain.CommandID
	operation          CommandOperation
	operationMajor     OperationMajor
	identity           ReceiptIdentity
	requestFingerprint domain.CommandFingerprint
	authorityID        domain.AuthorityID
	authorityEpoch     domain.AuthorityEpoch
	guardDigest        domain.AuthorizationDigest
	events             EventRange
	finalStreamDigest  domain.StreamDigest
	capsulePlan        RecoveryCapsulePlan
	expectedPlan       ReceiptResultPlan
}

type ReceiptResultReplayBindingParams struct {
	OriginalCommandID      domain.CommandID
	AcceptedAuthorityID    domain.AuthorityID
	AcceptedAuthorityEpoch domain.AuthorityEpoch
	AcceptedAt             time.Time
	GuardDigest            domain.AuthorizationDigest
	Resources              []domain.AggregateRef
	IssuedCeremonies       []domain.CeremonyChallenge
	EventIDs               []domain.EventID
	Events                 EventRange
	FinalStreamDigest      domain.StreamDigest
	SessionBinding         *domain.SessionBinding
	SessionClient          domain.ClientInstanceID
	PresentationCredential domain.PresentationCredentialBinding
	// RecoveryCapsulePlan is the plan reconstructed from the receipt's
	// historical signing-key reference, not the plan prepared for this retry.
	RecoveryCapsulePlan RecoveryCapsulePlan
}

func NewReceiptResultReplayBinding(
	spec CommandSpec,
	params ReceiptResultReplayBindingParams,
) (ReceiptResultReplayBinding, error) {
	contract, cataloged := operationContracts[spec.commandOperation]
	if !cataloged || params.OriginalCommandID.IsZero() || params.AcceptedAuthorityID.IsZero() ||
		params.AcceptedAuthorityEpoch.IsZero() || params.GuardDigest.IsZero() || params.FinalStreamDigest.IsZero() ||
		params.Events.count != uint16(len(spec.expectedFacts)) || params.Events.count != uint16(len(contract.facts)) ||
		spec.receiptIdentity.operation != spec.operation || spec.receiptIdentity.scope != spec.scope ||
		spec.recoveryCapsule.requirement != contract.recovery ||
		!validRecoveryCapsulePlan(params.RecoveryCapsulePlan, contract.recovery) {
		return ReceiptResultReplayBinding{}, ErrInvalidApplicationContract
	}
	storedSpec := spec
	storedSpec.recoveryCapsule = cloneRecoveryCapsulePlan(params.RecoveryCapsulePlan)
	expectedPlan, err := NewStoredReceiptResultPlan(storedSpec, StoredReceiptResultPlanParams{
		OriginalCommandID: params.OriginalCommandID, AcceptedAuthorityID: params.AcceptedAuthorityID,
		AcceptedAuthorityEpoch: params.AcceptedAuthorityEpoch, AcceptedAt: params.AcceptedAt,
		AuthorizationDigest: params.GuardDigest, Resources: params.Resources,
		IssuedCeremonies: params.IssuedCeremonies, EventIDs: params.EventIDs,
		SessionBinding: params.SessionBinding, SessionClient: params.SessionClient,
		PresentationCredential: params.PresentationCredential,
	})
	if err != nil {
		return ReceiptResultReplayBinding{}, err
	}
	return ReceiptResultReplayBinding{
		originalCommandID: params.OriginalCommandID, operation: spec.commandOperation,
		operationMajor: spec.operationMajor, identity: spec.receiptIdentity,
		requestFingerprint: spec.requestFingerprint, authorityID: params.AcceptedAuthorityID,
		authorityEpoch: params.AcceptedAuthorityEpoch, guardDigest: params.GuardDigest,
		events: params.Events, finalStreamDigest: params.FinalStreamDigest,
		capsulePlan:  cloneRecoveryCapsulePlan(params.RecoveryCapsulePlan),
		expectedPlan: cloneReceiptResultPlan(expectedPlan),
	}, nil
}

func validRecoveryCapsulePlan(plan RecoveryCapsulePlan, requirement RecoveryCapsuleRequirement) bool {
	if plan.requirement != requirement {
		return false
	}
	if requirement == RecoveryCapsuleNotApplicable {
		return plan.keyID == "" && len(plan.publicKey) == 0
	}
	return requirement == RecoveryCapsuleRequired && validOpaqueText(plan.keyID, 256) &&
		len(plan.publicKey) == ed25519.PublicKeySize
}

func (binding ReceiptResultReplayBinding) OriginalCommandID() domain.CommandID {
	return binding.originalCommandID
}
func (binding ReceiptResultReplayBinding) Operation() CommandOperation { return binding.operation }
func (binding ReceiptResultReplayBinding) OperationMajor() OperationMajor {
	return binding.operationMajor
}
func (binding ReceiptResultReplayBinding) Identity() ReceiptIdentity { return binding.identity }
func (binding ReceiptResultReplayBinding) RequestFingerprint() domain.CommandFingerprint {
	return binding.requestFingerprint
}
func (binding ReceiptResultReplayBinding) AuthorityID() domain.AuthorityID {
	return binding.authorityID
}
func (binding ReceiptResultReplayBinding) AuthorityEpoch() domain.AuthorityEpoch {
	return binding.authorityEpoch
}
func (binding ReceiptResultReplayBinding) GuardDigest() domain.AuthorizationDigest {
	return binding.guardDigest
}
func (binding ReceiptResultReplayBinding) Events() EventRange { return binding.events }
func (binding ReceiptResultReplayBinding) FinalStreamDigest() domain.StreamDigest {
	return binding.finalStreamDigest
}
func (binding ReceiptResultReplayBinding) RecoveryCapsulePlan() RecoveryCapsulePlan {
	return cloneRecoveryCapsulePlan(binding.capsulePlan)
}
func (binding ReceiptResultReplayBinding) ExpectedPlan() ReceiptResultPlan {
	return cloneReceiptResultPlan(binding.expectedPlan)
}

type ReceiptSnapshotParams struct {
	ReceiptID          domain.ReceiptID
	CommandID          domain.CommandID
	Identity           ReceiptIdentity
	RequestFingerprint domain.CommandFingerprint
	Result             ResultEnvelope
	AuthorityID        domain.AuthorityID
	AuthorityEpoch     domain.AuthorityEpoch
	GuardDigest        domain.AuthorizationDigest
	Events             EventRange
	CapsuleRequirement RecoveryCapsuleRequirement
	RecoveryCapsule    *RecoveryCapsuleDraft
}

type ReceiptSnapshot struct {
	receiptID          domain.ReceiptID
	commandID          domain.CommandID
	identity           ReceiptIdentity
	requestFingerprint domain.CommandFingerprint
	result             ResultEnvelope
	authorityID        domain.AuthorityID
	authorityEpoch     domain.AuthorityEpoch
	guardDigest        domain.AuthorizationDigest
	events             EventRange
	capsuleRequirement RecoveryCapsuleRequirement
	recoveryCapsule    RecoveryCapsuleDraft
	hasRecoveryCapsule bool
}

func NewReceiptSnapshot(params ReceiptSnapshotParams) (ReceiptSnapshot, error) {
	contract, cataloged := operationContracts[CommandOperation(params.Identity.operation.String())]
	if params.ReceiptID.IsZero() || params.CommandID.IsZero() || params.Identity.kind == "" ||
		params.RequestFingerprint.IsZero() || params.Result.IsZero() || params.AuthorityID.IsZero() ||
		params.AuthorityEpoch.IsZero() || params.GuardDigest.IsZero() || params.Events.count == 0 ||
		!cataloged || params.Result.operation != contract.operation || params.CapsuleRequirement != contract.recovery ||
		(params.CapsuleRequirement != RecoveryCapsuleRequired &&
			params.CapsuleRequirement != RecoveryCapsuleNotApplicable) ||
		(params.CapsuleRequirement == RecoveryCapsuleRequired) != (params.RecoveryCapsule != nil) ||
		!resultMatchesReceiptSnapshot(params) {
		return ReceiptSnapshot{}, ErrInvalidApplicationContract
	}
	receipt := ReceiptSnapshot{
		receiptID: params.ReceiptID, commandID: params.CommandID, identity: params.Identity,
		requestFingerprint: params.RequestFingerprint, result: cloneResult(params.Result),
		authorityID: params.AuthorityID, authorityEpoch: params.AuthorityEpoch,
		guardDigest: params.GuardDigest, events: params.Events, capsuleRequirement: params.CapsuleRequirement,
	}
	if params.RecoveryCapsule != nil {
		if params.RecoveryCapsule.digest.IsZero() || params.RecoveryCapsule.resultDigest != params.Result.responseDigest {
			return ReceiptSnapshot{}, ErrInvalidApplicationContract
		}
		if params.Result.capsulePlan.requirement != RecoveryCapsuleRequired ||
			params.RecoveryCapsule.keyID != params.Result.capsulePlan.keyID {
			return ReceiptSnapshot{}, ErrInvalidApplicationContract
		}
		receipt.recoveryCapsule = RecoveryCapsuleDraft{
			canonical: append([]byte(nil), params.RecoveryCapsule.canonical...),
			digest:    params.RecoveryCapsule.digest, resultDigest: params.RecoveryCapsule.resultDigest,
			keyID: params.RecoveryCapsule.keyID,
		}
		receipt.hasRecoveryCapsule = true
	}
	return receipt, nil
}

func resultMatchesReceiptSnapshot(params ReceiptSnapshotParams) bool {
	if params.Result.document.IsZero() {
		return false
	}
	wire := params.Result.document.wire
	return params.Result.capsulePlan.requirement == params.CapsuleRequirement &&
		wire.Operation == string(params.Result.operation) &&
		wire.Operation == params.Identity.operation.String() &&
		wire.AuthorityID.String() == params.AuthorityID.String() &&
		wire.AuthorityEpoch.String() == params.AuthorityEpoch.String() &&
		wire.ScopeKind == string(params.Identity.scope.Kind()) &&
		wire.ScopeID.String() == params.Identity.scope.ID() &&
		wire.CommandFingerprint.String() == hex.EncodeToString(params.RequestFingerprint[:]) &&
		wire.AuthorizationDigest.String() == params.GuardDigest.String() &&
		wire.Events.FirstPosition == params.Events.first.Uint64() &&
		wire.Events.LastPosition == params.Events.last.Uint64() &&
		wire.Events.Count == params.Events.count
}

func cloneResult(result ResultEnvelope) ResultEnvelope {
	return ResultEnvelope{
		canonical: append([]byte(nil), result.canonical...), responseDigest: result.responseDigest,
		operation: result.operation, document: result.document,
		capsulePlan: cloneRecoveryCapsulePlan(result.capsulePlan),
	}
}

func (receipt ReceiptSnapshot) ReceiptID() domain.ReceiptID { return receipt.receiptID }
func (receipt ReceiptSnapshot) CommandID() domain.CommandID { return receipt.commandID }
func (receipt ReceiptSnapshot) Identity() ReceiptIdentity   { return receipt.identity }
func (receipt ReceiptSnapshot) RequestFingerprint() domain.CommandFingerprint {
	return receipt.requestFingerprint
}
func (receipt ReceiptSnapshot) Result() ResultEnvelope                  { return cloneResult(receipt.result) }
func (receipt ReceiptSnapshot) AuthorityID() domain.AuthorityID         { return receipt.authorityID }
func (receipt ReceiptSnapshot) AuthorityEpoch() domain.AuthorityEpoch   { return receipt.authorityEpoch }
func (receipt ReceiptSnapshot) GuardDigest() domain.AuthorizationDigest { return receipt.guardDigest }
func (receipt ReceiptSnapshot) Events() EventRange                      { return receipt.events }
func (receipt ReceiptSnapshot) CapsuleRequirement() RecoveryCapsuleRequirement {
	return receipt.capsuleRequirement
}
func (receipt ReceiptSnapshot) RecoveryCapsule() (RecoveryCapsuleDraft, bool) {
	draft := receipt.recoveryCapsule
	draft.canonical = append([]byte(nil), draft.canonical...)
	return draft, receipt.hasRecoveryCapsule
}

type ReceiptResolutionKind string

const (
	ReceiptAdmitted            ReceiptResolutionKind = "admitted"
	ReceiptExactReplay         ReceiptResolutionKind = "exact_replay"
	ReceiptCommandIDConflict   ReceiptResolutionKind = "command_id_conflict"
	ReceiptIdempotencyConflict ReceiptResolutionKind = "idempotency_conflict"
	ReceiptInProgress          ReceiptResolutionKind = "in_progress"
	ReceiptIntegrityConflict   ReceiptResolutionKind = "integrity_conflict"
)

type ReceiptResolution struct {
	kind      ReceiptResolutionKind
	receipt   ReceiptSnapshot
	conflict  domain.ReceiptID
	hasRecord bool
}

func AdmitReceipt() ReceiptResolution { return ReceiptResolution{kind: ReceiptAdmitted} }

func ReplayReceipt(receipt ReceiptSnapshot) (ReceiptResolution, error) {
	if receipt.receiptID.IsZero() {
		return ReceiptResolution{}, ErrInvalidCommandContext
	}
	return ReceiptResolution{kind: ReceiptExactReplay, receipt: receipt, hasRecord: true}, nil
}

func ConflictReceipt(kind ReceiptResolutionKind, existing domain.ReceiptID) (ReceiptResolution, error) {
	switch kind {
	case ReceiptCommandIDConflict, ReceiptIdempotencyConflict, ReceiptInProgress:
		if existing.IsZero() {
			return ReceiptResolution{}, ErrInvalidCommandContext
		}
		return ReceiptResolution{kind: kind, conflict: existing, hasRecord: true}, nil
	case ReceiptIntegrityConflict:
		return ReceiptResolution{kind: kind}, nil
	default:
		return ReceiptResolution{}, ErrInvalidCommandContext
	}
}

func (resolution ReceiptResolution) Kind() ReceiptResolutionKind { return resolution.kind }
func (resolution ReceiptResolution) Receipt() (ReceiptSnapshot, bool) {
	return resolution.receipt, resolution.kind == ReceiptExactReplay
}
func (resolution ReceiptResolution) ExistingReceiptID() (domain.ReceiptID, bool) {
	return resolution.conflict, resolution.hasRecord && resolution.kind != ReceiptExactReplay
}

// AppliedGuardEvidence is the exact guard set and digest observed under lock.
// The constructor copies the declaration; storage supplies the reviewed
// canonical digest after proving those values remain current at final CAS.
type AppliedGuardEvidence struct {
	plan     CommandGuardPlan
	observed []EvidenceGuard
	digest   domain.AuthorizationDigest
}

func NewAppliedGuardEvidence(
	plan CommandGuardPlan,
	observed []EvidenceGuard,
) (AppliedGuardEvidence, error) {
	normalized, err := normalizeEvidenceGuards(observed)
	if err != nil || plan.admissionGeneration.IsZero() ||
		!equalEvidenceGuards(plan.evidence, normalized) {
		return AppliedGuardEvidence{}, ErrInvalidCommandContext
	}
	digest, err := hashAppliedAuthorizationGuards(plan, normalized)
	if err != nil {
		return AppliedGuardEvidence{}, ErrInvalidCommandContext
	}
	return AppliedGuardEvidence{
		plan: cloneGuardPlan(plan), observed: append([]EvidenceGuard(nil), normalized...), digest: digest,
	}, nil
}

type authorizationGuardHashRecordV1 struct {
	Kind             string               `json:"kind"`
	TargetKind       string               `json:"target_kind"`
	TargetID         CanonicalIdentifier  `json:"target_id"`
	Version          *uint64              `json:"version"`
	GenerationID     *CanonicalIdentifier `json:"generation_id"`
	GenerationNumber *uint64              `json:"generation_number"`
	AuthorityEpoch   *CanonicalIdentifier `json:"authority_epoch"`
	PolicyRevision   *string              `json:"policy_revision"`
	TrustRevision    *uint64              `json:"trust_revision"`
	Status           *string              `json:"status"`
	ConstraintDigest *CanonicalDigest     `json:"constraint_digest"`
}

type authorizationGuardHashViewV1 struct {
	Guards []authorizationGuardHashRecordV1 `json:"guards"`
}

func (authorizationGuardHashViewV1) canonicalView()              {}
func (authorizationGuardHashViewV1) authorizationGuardHashView() {}

func hashAppliedAuthorizationGuards(
	plan CommandGuardPlan,
	observed []EvidenceGuard,
) (domain.AuthorizationDigest, error) {
	records := make([]authorizationGuardHashRecordV1, 0,
		1+len(observed)+len(plan.authorization)+len(plan.references)+len(plan.mutations)+len(plan.ceremonies)+1)
	scopeID, err := NewCanonicalIdentifier(plan.admissionScope.ID())
	if err != nil {
		return domain.AuthorizationDigest{}, err
	}
	generation := plan.admissionGeneration.Uint64()
	records = append(records, authorizationGuardHashRecordV1{
		Kind: "scope_admission", TargetKind: string(plan.admissionScope.Kind()), TargetID: scopeID,
		GenerationNumber: &generation,
	})
	for _, guard := range observed {
		record, recordErr := authorizationGuardHashRecord(guard)
		if recordErr != nil {
			return domain.AuthorizationDigest{}, recordErr
		}
		records = append(records, record)
	}
	for _, ref := range plan.authorization {
		record, recordErr := aggregateGuardHashRecord("authorization_revision", ref.Target(), ref.Version())
		if recordErr != nil {
			return domain.AuthorizationDigest{}, recordErr
		}
		records = append(records, record)
	}
	for _, ref := range plan.references {
		record, recordErr := aggregateGuardHashRecord("reference_revision", ref.Target(), ref.Version())
		if recordErr != nil {
			return domain.AuthorizationDigest{}, recordErr
		}
		records = append(records, record)
	}
	for _, expectation := range plan.mutations {
		kind := "aggregate_absent"
		version := domain.Version{}
		if expected, hasVersion := expectation.Version(); hasVersion {
			kind = "aggregate_revision"
			version = expected
		}
		record, recordErr := aggregateGuardHashRecord(kind, expectation.Target(), version)
		if recordErr != nil {
			return domain.AuthorizationDigest{}, recordErr
		}
		records = append(records, record)
	}
	for _, ceremony := range plan.ceremonies {
		record, recordErr := ceremonyGuardHashRecord(ceremony)
		if recordErr != nil {
			return domain.AuthorizationDigest{}, recordErr
		}
		records = append(records, record)
	}
	if plan.genesis != nil {
		target, targetErr := NewCanonicalIdentifier(plan.genesis.authorityID.String())
		if targetErr != nil {
			return domain.AuthorizationDigest{}, targetErr
		}
		epoch, epochErr := NewCanonicalIdentifier(plan.genesis.epoch.String())
		if epochErr != nil {
			return domain.AuthorizationDigest{}, epochErr
		}
		records = append(records, authorizationGuardHashRecordV1{
			Kind: "scope_genesis_absent", TargetKind: "authority", TargetID: target,
			AuthorityEpoch: &epoch,
		})
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].Kind != records[right].Kind {
			return records[left].Kind < records[right].Kind
		}
		if records[left].TargetKind != records[right].TargetKind {
			return records[left].TargetKind < records[right].TargetKind
		}
		return records[left].TargetID.String() < records[right].TargetID.String()
	})
	return NewProductionCanonicalCodec().HashAuthorizationGuards(authorizationGuardHashViewV1{Guards: records})
}

func aggregateGuardHashRecord(
	kind string,
	target domain.AggregateTarget,
	version domain.Version,
) (authorizationGuardHashRecordV1, error) {
	targetID, err := NewCanonicalIdentifier(target.ID())
	if err != nil {
		return authorizationGuardHashRecordV1{}, err
	}
	record := authorizationGuardHashRecordV1{Kind: kind, TargetKind: string(target.Kind()), TargetID: targetID}
	if !version.IsZero() {
		value := version.Uint64()
		record.Version = &value
	}
	return record, nil
}

func ceremonyGuardHashRecord(claim CeremonyClaim) (authorizationGuardHashRecordV1, error) {
	targetID, err := NewCanonicalIdentifier(claim.id.String())
	if err != nil {
		return authorizationGuardHashRecordV1{}, err
	}
	proof, err := NewCanonicalDigest(hex.EncodeToString(claim.proof[:]))
	if err != nil {
		return authorizationGuardHashRecordV1{}, err
	}
	purpose := string(claim.purpose)
	record := authorizationGuardHashRecordV1{
		Kind: string(claim.kind), TargetKind: "ceremony", TargetID: targetID,
		Status: &purpose, ConstraintDigest: &proof,
	}
	if !claim.ownerRef.IsZero() {
		version := claim.ownerRef.Version().Uint64()
		record.Version = &version
	}
	return record, nil
}

func authorizationGuardHashRecord(guard EvidenceGuard) (authorizationGuardHashRecordV1, error) {
	targetKind := guard.targetKind
	targetID := guard.targetID
	if guard.kind == EvidenceCurrentAuthorityEpoch {
		targetKind = "authority"
		targetID = guard.authorityID.String()
	}
	canonicalTarget, err := NewCanonicalIdentifier(targetID)
	if err != nil {
		return authorizationGuardHashRecordV1{}, err
	}
	record := authorizationGuardHashRecordV1{
		Kind: string(guard.kind), TargetKind: targetKind, TargetID: canonicalTarget,
	}
	switch guard.kind {
	case EvidenceCurrentAuthorityEpoch:
		epoch, epochErr := NewCanonicalIdentifier(guard.authorityEpoch.String())
		if epochErr != nil {
			return authorizationGuardHashRecordV1{}, epochErr
		}
		record.AuthorityEpoch = &epoch
	case EvidencePolicyRevision:
		value := guard.policyRevision.String()
		record.PolicyRevision = &value
	case EvidenceLifecycleStatus:
		value := guard.status
		record.Status = &value
	case EvidenceDeviceTrustRevision:
		value := guard.revision.Uint64()
		record.TrustRevision = &value
	case EvidenceCapabilityCeiling, EvidenceResourceConstraint:
		value, digestErr := CanonicalDigestFromDigest(guard.digest)
		if digestErr != nil {
			return authorizationGuardHashRecordV1{}, digestErr
		}
		record.ConstraintDigest = &value
	case EvidenceBootstrapGeneration:
		value, generationErr := NewCanonicalIdentifier(guard.bootstrapGeneration.String())
		if generationErr != nil {
			return authorizationGuardHashRecordV1{}, generationErr
		}
		record.GenerationID = &value
	default:
		return authorizationGuardHashRecordV1{}, ErrCanonicalProfile
	}
	return record, nil
}

func equalEvidenceGuards(left, right []EvidenceGuard) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (evidence AppliedGuardEvidence) Plan() CommandGuardPlan { return cloneGuardPlan(evidence.plan) }
func (evidence AppliedGuardEvidence) Observed() []EvidenceGuard {
	return append([]EvidenceGuard(nil), evidence.observed...)
}
func (evidence AppliedGuardEvidence) Digest() domain.AuthorizationDigest { return evidence.digest }

type CommandTimeMode string

const (
	CommandTimePersistedWrite     CommandTimeMode = "persisted_write"
	CommandTimeReadOnlyDisclosure CommandTimeMode = "read_only_disclosure"
)

type CommandTimeEvidence struct {
	mode  CommandTimeMode
	value time.Time
}

func PersistedCommandAuthorityTime(value time.Time) (CommandTimeEvidence, error) {
	if value.IsZero() {
		return CommandTimeEvidence{}, ErrInvalidCommandContext
	}
	return CommandTimeEvidence{mode: CommandTimePersistedWrite, value: value.UTC()}, nil
}

func ReadOnlyDisclosureTime(databaseWallTime, persistedFloor time.Time) (CommandTimeEvidence, error) {
	if databaseWallTime.IsZero() || persistedFloor.IsZero() {
		return CommandTimeEvidence{}, ErrInvalidCommandContext
	}
	value := databaseWallTime
	if persistedFloor.After(value) {
		value = persistedFloor
	}
	return CommandTimeEvidence{mode: CommandTimeReadOnlyDisclosure, value: value.UTC()}, nil
}

func (evidence CommandTimeEvidence) Mode() CommandTimeMode { return evidence.mode }
func (evidence CommandTimeEvidence) Value() time.Time      { return evidence.value }

type CommandContext struct {
	spec                 CommandSpec
	timeEvidence         CommandTimeEvidence
	states               []IdentityState
	standaloneCeremonies []domain.CeremonyChallenge
	resolution           ReceiptResolution
	guardEvidence        AppliedGuardEvidence
}

func NewCommandContext(
	spec CommandSpec,
	timeEvidence CommandTimeEvidence,
	states []IdentityState,
	resolution ReceiptResolution,
	guardEvidence AppliedGuardEvidence,
) (CommandContext, error) {
	return NewCommandContextWithStandaloneCeremonies(
		spec, timeEvidence, states, nil, resolution, guardEvidence,
	)
}

func NewCommandContextWithStandaloneCeremonies(
	spec CommandSpec,
	timeEvidence CommandTimeEvidence,
	states []IdentityState,
	standaloneCeremonies []domain.CeremonyChallenge,
	resolution ReceiptResolution,
	guardEvidence AppliedGuardEvidence,
) (CommandContext, error) {
	if spec.commandID.IsZero() || timeEvidence.value.IsZero() || guardEvidence.digest.IsZero() ||
		!sameGuardPlan(spec.guards, guardEvidence.plan) || !validReceiptResolution(spec, resolution) {
		return CommandContext{}, ErrInvalidCommandContext
	}
	if (resolution.kind == ReceiptAdmitted && timeEvidence.mode != CommandTimePersistedWrite) ||
		(resolution.kind != ReceiptAdmitted && timeEvidence.mode != CommandTimeReadOnlyDisclosure) {
		return CommandContext{}, ErrInvalidCommandContext
	}
	clonedStates := append([]IdentityState(nil), states...)
	sort.Slice(clonedStates, func(left, right int) bool {
		return clonedStates[left].Target().String() < clonedStates[right].Target().String()
	})
	for index, state := range clonedStates {
		if state.target.IsZero() || state.version.IsZero() || state.version.Uint64() > MaxCanonicalInteger {
			return CommandContext{}, ErrInvalidCommandContext
		}
		if index > 0 && clonedStates[index-1].Target() == state.Target() {
			return CommandContext{}, ErrInvalidCommandContext
		}
	}
	statesValid := false
	switch resolution.kind {
	case ReceiptAdmitted:
		statesValid = statesSatisfyReadPlan(spec.guards, clonedStates, true)
	case ReceiptExactReplay:
		statesValid = statesSatisfyReadPlan(spec.guards, clonedStates, false)
	case ReceiptCommandIDConflict, ReceiptIdempotencyConflict, ReceiptInProgress, ReceiptIntegrityConflict:
		statesValid = len(clonedStates) == 0
	}
	if !statesValid {
		return CommandContext{}, ErrInvalidCommandContext
	}
	if resolution.kind == ReceiptAdmitted && !evidenceMatchesLockedStates(spec.guards.evidence, clonedStates) {
		return CommandContext{}, ErrInvalidCommandContext
	}
	var ceremonies []domain.CeremonyChallenge
	if resolution.kind == ReceiptAdmitted {
		var err error
		ceremonies, err = validateStandaloneCeremonies(spec.guards, standaloneCeremonies)
		if err != nil {
			return CommandContext{}, err
		}
	} else if len(standaloneCeremonies) != 0 {
		return CommandContext{}, ErrInvalidCommandContext
	}
	return CommandContext{
		spec: spec, timeEvidence: timeEvidence, states: clonedStates, standaloneCeremonies: ceremonies,
		resolution: resolution, guardEvidence: guardEvidence,
	}, nil
}

func validateStandaloneCeremonies(
	plan CommandGuardPlan,
	challenges []domain.CeremonyChallenge,
) ([]domain.CeremonyChallenge, error) {
	expected := make(map[domain.CeremonyID]CeremonyClaim)
	for _, claim := range plan.ceremonies {
		if claim.kind == CeremonyConsumeStandalone {
			expected[claim.id] = claim
		}
	}
	if len(challenges) != len(expected) {
		return nil, ErrInvalidCommandContext
	}
	cloned := append([]domain.CeremonyChallenge(nil), challenges...)
	sort.Slice(cloned, func(left, right int) bool { return cloned[left].ID().String() < cloned[right].ID().String() })
	for index, challenge := range cloned {
		claim, declared := expected[challenge.ID()]
		if challenge.IsZero() || challenge.Status() != domain.CeremonyPending || !declared ||
			challenge.Purpose() != claim.purpose || challenge.ProofDigest() != claim.proof ||
			(index > 0 && cloned[index-1].ID() == challenge.ID()) {
			return nil, ErrInvalidCommandContext
		}
	}
	return cloned, nil
}

func evidenceMatchesLockedStates(guards []EvidenceGuard, states []IdentityState) bool {
	byTarget := make(map[string]IdentityState, len(states))
	for _, state := range states {
		byTarget[state.Target().String()] = state
	}
	for _, guard := range guards {
		key := guard.targetKind + ":" + guard.targetID
		switch guard.kind {
		case EvidenceLifecycleStatus:
			state, exists := byTarget[key]
			if !exists || identityStateStatus(state) != guard.status {
				return false
			}
		case EvidenceDeviceTrustRevision:
			state, exists := byTarget[key]
			device, valid := state.value.(domain.DeviceState)
			if !exists || !valid || device.TrustRevision() != guard.revision {
				return false
			}
		case EvidencePolicyRevision:
			if state, exists := byTarget[key]; exists {
				workspace, valid := state.value.(domain.WorkspaceState)
				if !valid || workspace.PolicyRevision() != guard.policyRevision {
					return false
				}
			}
		case EvidenceBootstrapGeneration:
			matched := false
			for _, state := range states {
				invitation, valid := state.value.(domain.InstallationInvitationState)
				if valid && invitation.InstallationID().String() == guard.targetID {
					matched = invitation.BootstrapGenerationID() == guard.bootstrapGeneration
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

func identityStateStatus(state IdentityState) string {
	switch value := state.value.(type) {
	case domain.InstallationInvitationState:
		return string(value.Status())
	case domain.PrincipalState:
		return string(value.Status())
	case domain.DeviceState:
		return string(value.Status())
	case domain.GrantState:
		return string(value.Status())
	case domain.WorkspaceState:
		return string(value.Status())
	case domain.MembershipState:
		return string(value.Status())
	case domain.ActorState:
		return string(value.Status())
	case domain.ActorDelegationState:
		return string(value.Status())
	case domain.ActorSessionState:
		return string(value.Status())
	default:
		return ""
	}
}

func validReceiptResolution(spec CommandSpec, resolution ReceiptResolution) bool {
	switch resolution.kind {
	case ReceiptAdmitted:
		return !resolution.hasRecord
	case ReceiptExactReplay:
		return resolution.hasRecord && resolution.receipt.identity == spec.receiptIdentity &&
			resolution.receipt.requestFingerprint == spec.requestFingerprint &&
			resolution.receipt.capsuleRequirement == spec.recoveryCapsule.requirement &&
			((spec.recoveryCapsule.requirement == RecoveryCapsuleRequired &&
				resolution.receipt.hasRecoveryCapsule) ||
				(spec.recoveryCapsule.requirement == RecoveryCapsuleNotApplicable &&
					!resolution.receipt.hasRecoveryCapsule))
	case ReceiptCommandIDConflict, ReceiptIdempotencyConflict, ReceiptInProgress:
		return resolution.hasRecord && !resolution.conflict.IsZero()
	case ReceiptIntegrityConflict:
		return !resolution.hasRecord
	default:
		return false
	}
}

func sameGuardPlan(left, right CommandGuardPlan) bool {
	if left.admissionScope != right.admissionScope || left.admissionGeneration != right.admissionGeneration ||
		!equalEvidenceGuards(left.evidence, right.evidence) ||
		len(left.authorization) != len(right.authorization) || len(left.references) != len(right.references) ||
		len(left.disclosure) != len(right.disclosure) ||
		len(left.mutations) != len(right.mutations) || len(left.ceremonies) != len(right.ceremonies) ||
		(left.genesis == nil) != (right.genesis == nil) {
		return false
	}
	if left.genesis != nil && *left.genesis != *right.genesis {
		return false
	}
	for index := range left.authorization {
		if left.authorization[index] != right.authorization[index] {
			return false
		}
	}
	for index := range left.references {
		if left.references[index] != right.references[index] {
			return false
		}
	}
	for index := range left.disclosure {
		if left.disclosure[index] != right.disclosure[index] {
			return false
		}
	}
	for index := range left.mutations {
		if left.mutations[index].Kind() != right.mutations[index].Kind() ||
			left.mutations[index].Target() != right.mutations[index].Target() {
			return false
		}
		leftVersion, leftHas := left.mutations[index].Version()
		rightVersion, rightHas := right.mutations[index].Version()
		if leftHas != rightHas || leftVersion != rightVersion {
			return false
		}
	}
	for index := range left.ceremonies {
		if left.ceremonies[index] != right.ceremonies[index] {
			return false
		}
	}
	return true
}

func statesSatisfyReadPlan(plan CommandGuardPlan, states []IdentityState, includeMutations bool) bool {
	byTarget := make(map[domain.AggregateTarget]domain.Version, len(states))
	for _, state := range states {
		byTarget[state.Target()] = state.Version()
	}
	if !includeMutations {
		if len(byTarget) != len(plan.disclosure) {
			return false
		}
		for _, target := range plan.disclosure {
			if _, exists := byTarget[target]; !exists {
				return false
			}
		}
		return true
	}
	expected := make(map[domain.AggregateTarget]domain.Version)
	for _, group := range [][]domain.AggregateRef{plan.authorization, plan.references} {
		for _, ref := range group {
			expected[ref.Target()] = ref.Version()
		}
	}
	for _, expectation := range plan.mutations {
		version, hasVersion := expectation.Version()
		if hasVersion {
			expected[expectation.Target()] = version
		}
	}
	if len(byTarget) != len(expected) {
		return false
	}
	for target, version := range expected {
		if byTarget[target] != version {
			return false
		}
	}
	return true
}

func (commandContext CommandContext) Spec() CommandSpec { return commandContext.spec }
func (commandContext CommandContext) TimeEvidence() CommandTimeEvidence {
	return commandContext.timeEvidence
}
func (commandContext CommandContext) AuthorityTime() (time.Time, bool) {
	return commandContext.timeEvidence.value,
		commandContext.timeEvidence.mode == CommandTimePersistedWrite
}
func (commandContext CommandContext) DisclosureTime() (time.Time, bool) {
	return commandContext.timeEvidence.value,
		commandContext.timeEvidence.mode == CommandTimeReadOnlyDisclosure
}
func (commandContext CommandContext) States() []IdentityState {
	return append([]IdentityState(nil), commandContext.states...)
}
func (commandContext CommandContext) StandaloneCeremonies() []domain.CeremonyChallenge {
	return append([]domain.CeremonyChallenge(nil), commandContext.standaloneCeremonies...)
}
func (commandContext CommandContext) ReceiptResolution() ReceiptResolution {
	return commandContext.resolution
}
func (commandContext CommandContext) GuardEvidence() AppliedGuardEvidence {
	return commandContext.guardEvidence
}
func (commandContext CommandContext) State(target domain.AggregateTarget) (IdentityState, bool) {
	index := sort.Search(len(commandContext.states), func(index int) bool {
		return commandContext.states[index].Target().String() >= target.String()
	})
	if index >= len(commandContext.states) || commandContext.states[index].Target() != target {
		return IdentityState{}, false
	}
	return commandContext.states[index], true
}

type ReplayDisclosure string

const (
	ReplayDiscloseResult      ReplayDisclosure = "result"
	ReplayDiscloseAppliedOnly ReplayDisclosure = "already_applied_only"
)

type FactIntent struct {
	eventID domain.EventID
	fact    domain.IdentityFact
}

func NewFactIntent(eventID domain.EventID, fact domain.IdentityFact) (FactIntent, error) {
	if eventID.IsZero() || isNilInterface(fact) || reflect.TypeOf(fact).Kind() != reflect.Struct ||
		!identityEventType(fact.Type()) || fact.Origin().IsZero() {
		return FactIntent{}, ErrInvalidCommandDecision
	}
	return FactIntent{eventID: eventID, fact: fact}, nil
}

func (intent FactIntent) EventID() domain.EventID   { return intent.eventID }
func (intent FactIntent) Fact() domain.IdentityFact { return intent.fact }

// OperationCommit is an unforgeable (outside this package) state/fact bundle
// constructed only from one of the eleven immutable domain transition results.
// It prevents a caller from pairing state from one transition with same-origin
// facts or ceremony claims from another.
type OperationCommit struct {
	operation  CommandOperation
	writes     []IdentityState
	facts      []FactIntent
	ceremonies []CeremonyTransition
}

type CeremonyTransition struct {
	kind      CeremonyClaimKind
	challenge domain.CeremonyChallenge
}

func (transition CeremonyTransition) Kind() CeremonyClaimKind { return transition.kind }
func (transition CeremonyTransition) Challenge() domain.CeremonyChallenge {
	return transition.challenge
}

func withCeremonyTransitions(
	commit OperationCommit,
	transitions ...CeremonyTransition,
) (OperationCommit, error) {
	if len(transitions) == 0 || len(transitions) > MaxCommandGuards {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	commit.ceremonies = append([]CeremonyTransition(nil), transitions...)
	return commit, nil
}

func newOperationCommit(
	commandContext CommandContext,
	operation CommandOperation,
	values []any,
	facts []domain.IdentityFact,
) (OperationCommit, error) {
	if commandContext.spec.commandOperation != operation || len(values) == 0 ||
		len(facts) != len(commandContext.spec.expectedFacts) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	writes := make([]IdentityState, len(values))
	for index, value := range values {
		state, err := NewIdentityState(value)
		if err != nil {
			return OperationCommit{}, ErrInvalidCommandDecision
		}
		if expectation, exists := mutationExpectation(commandContext.spec.guards.mutations, state.target); exists && expectation.Kind() == domain.ExpectationExpectedVersion {
			prior, loaded := commandContext.State(state.target)
			if !loaded || !lockedTransitionMatches(operation, prior, state) {
				return OperationCommit{}, ErrInvalidCommandDecision
			}
		}
		writes[index] = state
	}
	intents := make([]FactIntent, len(facts))
	for index, fact := range facts {
		intent, err := NewFactIntent(commandContext.spec.expectedFacts[index].eventID, fact)
		if err != nil {
			return OperationCommit{}, ErrInvalidCommandDecision
		}
		intents[index] = intent
	}
	if !writesMatchPlan(writes, commandContext.spec.guards.mutations) ||
		!factsMatchPlan(intents, commandContext.spec.expectedFacts) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	return OperationCommit{operation: operation, writes: writes, facts: intents}, nil
}

func mutationExpectation(
	expectations []domain.AggregateExpectation,
	target domain.AggregateTarget,
) (domain.AggregateExpectation, bool) {
	for _, expectation := range expectations {
		if expectation.Target() == target {
			return expectation, true
		}
	}
	return domain.AggregateExpectation{}, false
}

func lockedTransitionMatches(operation CommandOperation, prior, next IdentityState) bool {
	if prior.kind != next.kind || prior.target != next.target {
		return false
	}
	switch operation {
	case CommandBootstrapInstallation:
		before, beforeOK := prior.value.(domain.InstallationInvitationState)
		after, afterOK := next.value.(domain.InstallationInvitationState)
		return beforeOK && afterOK && before.ID() == after.ID() &&
			before.InstallationID() == after.InstallationID() &&
			before.InstallationPublicKey() == after.InstallationPublicKey() &&
			before.InvitationVerifier() == after.InvitationVerifier() &&
			before.BootstrapGenerationID() == after.BootstrapGenerationID() &&
			before.ExpiresAt().Equal(after.ExpiresAt()) && before.FailedAttempts() == after.FailedAttempts()
	case CommandAcceptWorkspaceMembership:
		before, beforeOK := prior.value.(domain.MembershipState)
		after, afterOK := next.value.(domain.MembershipState)
		return beforeOK && afterOK && before.ID() == after.ID() &&
			before.WorkspaceID() == after.WorkspaceID() && before.PrincipalID() == after.PrincipalID() &&
			before.Capabilities().Equal(after.Capabilities())
	case CommandActivateActorDelegation:
		before, beforeOK := prior.value.(domain.ActorDelegationState)
		after, afterOK := next.value.(domain.ActorDelegationState)
		return beforeOK && afterOK && before.ID() == after.ID() &&
			before.WorkspaceID() == after.WorkspaceID() && before.PrincipalID() == after.PrincipalID() &&
			before.ActorID() == after.ActorID() && before.MembershipID() == after.MembershipID() &&
			before.Capabilities().Equal(after.Capabilities())
	case CommandPairDevice:
		before, beforeOK := prior.value.(domain.DeviceState)
		after, afterOK := next.value.(domain.DeviceState)
		return beforeOK && afterOK && before.ID() == after.ID() &&
			before.InstallationID() == after.InstallationID() && before.PrincipalID() == after.PrincipalID() &&
			before.DisplayName() == after.DisplayName() && before.PublicKeyReference() == after.PublicKeyReference()
	default:
		return false
	}
}

func BootstrapInstallationCommit(
	commandContext CommandContext,
	result domain.BootstrapInstallationResult,
) (OperationCommit, error) {
	if result.Outcome() != domain.BootstrapInstallationCompleted {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	return newOperationCommit(commandContext, CommandBootstrapInstallation, []any{
		result.Invitation(), result.Principal(), result.Device(), result.OwnerGrant(),
	}, result.Facts())
}

func RegisterPrincipalCommit(
	commandContext CommandContext,
	result domain.RegisterPrincipalResult,
) (OperationCommit, error) {
	return newOperationCommit(commandContext, CommandRegisterPrincipal, []any{result.Principal()}, result.Facts())
}

func CreateWorkspaceCommit(
	commandContext CommandContext,
	result domain.CreateWorkspaceResult,
) (OperationCommit, error) {
	return newOperationCommit(commandContext, CommandCreateWorkspace,
		[]any{result.Workspace(), result.OwnerMembership()}, result.Facts())
}

func InviteWorkspaceMemberCommit(
	commandContext CommandContext,
	result domain.InviteWorkspaceMemberResult,
) (OperationCommit, error) {
	if !reservedCeremonyMatchesState(commandContext.spec.guards, result.Membership().AcceptanceChallenge(),
		mustStateTarget(result.Membership())) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	commit, err := newOperationCommit(commandContext, CommandInviteWorkspaceMember,
		[]any{result.Membership()}, result.Facts())
	if err != nil {
		return OperationCommit{}, err
	}
	return withCeremonyTransitions(commit, CeremonyTransition{
		kind: CeremonyReserveAbsent, challenge: result.Membership().AcceptanceChallenge(),
	})
}

func AcceptWorkspaceMembershipCommit(
	commandContext CommandContext,
	result domain.AcceptWorkspaceMembershipResult,
) (OperationCommit, error) {
	if !consumedEmbeddedCeremonyMatchesState(commandContext,
		result.Membership().AcceptanceChallenge(), mustStateTarget(result.Membership())) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	commit, err := newOperationCommit(commandContext, CommandAcceptWorkspaceMembership,
		[]any{result.Membership()}, result.Facts())
	if err != nil {
		return OperationCommit{}, err
	}
	return withCeremonyTransitions(commit, CeremonyTransition{
		kind: CeremonyConsumeEmbedded, challenge: result.Membership().AcceptanceChallenge(),
	})
}

func CreateActorCommit(
	commandContext CommandContext,
	result domain.CreateActorResult,
) (OperationCommit, error) {
	return newOperationCommit(commandContext, CommandCreateActor, []any{result.Actor()}, result.Facts())
}

func ProposeActorDelegationCommit(
	commandContext CommandContext,
	result domain.ProposeActorDelegationResult,
) (OperationCommit, error) {
	if !reservedCeremonyMatchesState(commandContext.spec.guards, result.Delegation().ActivationChallenge(),
		mustStateTarget(result.Delegation())) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	commit, err := newOperationCommit(commandContext, CommandProposeActorDelegation,
		[]any{result.Delegation()}, result.Facts())
	if err != nil {
		return OperationCommit{}, err
	}
	return withCeremonyTransitions(commit, CeremonyTransition{
		kind: CeremonyReserveAbsent, challenge: result.Delegation().ActivationChallenge(),
	})
}

func ActivateActorDelegationCommit(
	commandContext CommandContext,
	result domain.ActivateActorDelegationResult,
) (OperationCommit, error) {
	target := mustStateTarget(result.Delegation())
	if !consumedEmbeddedCeremonyMatchesState(commandContext,
		result.Delegation().ActivationChallenge(), target) ||
		!reservedCeremonyMatchesState(commandContext.spec.guards, result.SessionStartChallenge(), target) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	commit, err := newOperationCommit(commandContext, CommandActivateActorDelegation,
		[]any{result.Delegation()}, result.Facts())
	if err != nil {
		return OperationCommit{}, err
	}
	return withCeremonyTransitions(commit,
		CeremonyTransition{kind: CeremonyConsumeEmbedded, challenge: result.Delegation().ActivationChallenge()},
		CeremonyTransition{kind: CeremonyReserveAbsent, challenge: result.SessionStartChallenge()},
	)
}

func BeginDevicePairingCommit(
	commandContext CommandContext,
	result domain.BeginDevicePairingResult,
) (OperationCommit, error) {
	if !reservedCeremonyMatchesState(commandContext.spec.guards, result.Device().PairingChallenge(),
		mustStateTarget(result.Device())) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	commit, err := newOperationCommit(commandContext, CommandBeginDevicePairing,
		[]any{result.Device()}, result.Facts())
	if err != nil {
		return OperationCommit{}, err
	}
	return withCeremonyTransitions(commit, CeremonyTransition{
		kind: CeremonyReserveAbsent, challenge: result.Device().PairingChallenge(),
	})
}

func PairDeviceCommit(
	commandContext CommandContext,
	result domain.PairDeviceResult,
) (OperationCommit, error) {
	if !consumedEmbeddedCeremonyMatchesState(commandContext, result.Device().PairingChallenge(),
		mustStateTarget(result.Device())) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	commit, err := newOperationCommit(commandContext, CommandPairDevice, []any{result.Device()}, result.Facts())
	if err != nil {
		return OperationCommit{}, err
	}
	return withCeremonyTransitions(commit, CeremonyTransition{
		kind: CeremonyConsumeEmbedded, challenge: result.Device().PairingChallenge(),
	})
}

func StartActorSessionCommit(
	commandContext CommandContext,
	result domain.StartActorSessionResult,
) (OperationCommit, error) {
	consumed, hasConsumed := result.ConsumedHandoff()
	if hasConsumed != (len(commandContext.standaloneCeremonies) == 1) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	if hasConsumed && !standaloneCeremonyTransitionMatches(
		commandContext.spec.guards, commandContext.standaloneCeremonies[0], consumed,
	) {
		return OperationCommit{}, ErrInvalidCommandDecision
	}
	commit, err := newOperationCommit(commandContext, CommandStartActorSession,
		[]any{result.Session()}, result.Facts())
	if err != nil || !hasConsumed {
		return commit, err
	}
	return withCeremonyTransitions(commit, CeremonyTransition{
		kind: CeremonyConsumeStandalone, challenge: consumed,
	})
}

func mustStateTarget(value any) domain.AggregateTarget {
	state, _ := NewIdentityState(value)
	return state.target
}

func challengeMatchesClaim(challenge domain.CeremonyChallenge, claim CeremonyClaim) bool {
	return !challenge.IsZero() && challenge.ID() == claim.id && challenge.Purpose() == claim.purpose &&
		challenge.ProofDigest() == claim.proof
}

func reservedCeremonyMatchesState(
	plan CommandGuardPlan,
	challenge domain.CeremonyChallenge,
	owner domain.AggregateTarget,
) bool {
	for _, claim := range plan.ceremonies {
		if claim.kind == CeremonyReserveAbsent && claim.ownerTarget == owner &&
			challenge.Status() == domain.CeremonyPending && challengeMatchesClaim(challenge, claim) &&
			challenge.ExpiresAt().Equal(claim.expiresAt) && sameCeremonyBinding(challenge, claim.challenge) {
			return true
		}
	}
	return false
}

func consumedEmbeddedCeremonyMatchesState(
	commandContext CommandContext,
	challenge domain.CeremonyChallenge,
	owner domain.AggregateTarget,
) bool {
	priorState, exists := commandContext.State(owner)
	if !exists {
		return false
	}
	prior := embeddedChallenge(priorState)
	if prior.IsZero() || !sameCeremonyBinding(prior, challenge) ||
		prior.Status() != domain.CeremonyPending || challenge.Status() != domain.CeremonyConsumed {
		return false
	}
	for _, claim := range commandContext.spec.guards.ceremonies {
		if claim.kind == CeremonyConsumeEmbedded && claim.ownerRef.Target() == owner &&
			challenge.Status() == domain.CeremonyConsumed && challengeMatchesClaim(challenge, claim) {
			return true
		}
	}
	return false
}

func embeddedChallenge(state IdentityState) domain.CeremonyChallenge {
	switch value := state.value.(type) {
	case domain.MembershipState:
		return value.AcceptanceChallenge()
	case domain.ActorDelegationState:
		return value.ActivationChallenge()
	case domain.DeviceState:
		return value.PairingChallenge()
	default:
		return domain.CeremonyChallenge{}
	}
}

func sameCeremonyBinding(left, right domain.CeremonyChallenge) bool {
	return left.ID() == right.ID() && left.Purpose() == right.Purpose() &&
		left.ProofDigest() == right.ProofDigest() && left.ExpiresAt().Equal(right.ExpiresAt()) &&
		left.InstallationID() == right.InstallationID() && left.WorkspaceID() == right.WorkspaceID() &&
		left.PrincipalID() == right.PrincipalID() && left.MembershipID() == right.MembershipID() &&
		left.ActorID() == right.ActorID() && left.DelegationID() == right.DelegationID() &&
		left.DeviceID() == right.DeviceID()
}

func standaloneCeremonyTransitionMatches(
	plan CommandGuardPlan,
	pending domain.CeremonyChallenge,
	consumed domain.CeremonyChallenge,
) bool {
	if pending.Status() != domain.CeremonyPending || consumed.Status() != domain.CeremonyConsumed ||
		!sameCeremonyBinding(pending, consumed) {
		return false
	}
	for _, claim := range plan.ceremonies {
		if claim.kind == CeremonyConsumeStandalone && challengeMatchesClaim(pending, claim) {
			return true
		}
	}
	return false
}

// ReceiptResultPlan is the sealed, allocation-independent semantic result of
// an admitted command. Storage allocates stream positions and the final chain
// digest only after the command has been applied; it must materialize the
// final ResultEnvelope from this plan rather than accepting handler bytes.
type ReceiptResultPlan struct {
	operation           CommandOperation
	commandID           domain.CommandID
	operationMajor      OperationMajor
	authorityID         domain.AuthorityID
	authorityEpoch      domain.AuthorityEpoch
	scope               domain.AuthorityScope
	acceptedAt          time.Time
	commandFingerprint  domain.CommandFingerprint
	authorizationDigest domain.AuthorizationDigest
	resources           []domain.AggregateRef
	issuedCeremonies    []domain.CeremonyChallenge
	eventIDs            []domain.EventID
	capsulePlan         RecoveryCapsulePlan
	sessionBinding      domain.SessionBinding
	sessionClient       domain.ClientInstanceID
	presentation        domain.PresentationCredentialBinding
	hasSession          bool
}

// StoredReceiptResultPlanParams is the typed persistence boundary used to
// verify a result after restart. OriginalCommandID is the command that first
// committed the receipt; it is intentionally distinct from a later command
// that reaches the same receipt through the secondary idempotency identity.
type StoredReceiptResultPlanParams struct {
	OriginalCommandID      domain.CommandID
	AcceptedAuthorityID    domain.AuthorityID
	AcceptedAuthorityEpoch domain.AuthorityEpoch
	AcceptedAt             time.Time
	AuthorizationDigest    domain.AuthorizationDigest
	Resources              []domain.AggregateRef
	IssuedCeremonies       []domain.CeremonyChallenge
	EventIDs               []domain.EventID
	SessionBinding         *domain.SessionBinding
	SessionClient          domain.ClientInstanceID
	PresentationCredential domain.PresentationCredentialBinding
}

// NewStoredReceiptResultPlan reconstructs only the allocation-independent
// verification contract. Every caller-supplied semantic identity is checked
// against the already-validated command spec; the domain transition is never
// re-executed during replay.
func NewStoredReceiptResultPlan(
	spec CommandSpec,
	params StoredReceiptResultPlanParams,
) (ReceiptResultPlan, error) {
	contract, cataloged := operationContracts[spec.commandOperation]
	if !cataloged || params.OriginalCommandID.IsZero() || params.AcceptedAuthorityID.IsZero() ||
		params.AcceptedAuthorityEpoch.IsZero() || params.AcceptedAt.IsZero() ||
		params.AuthorizationDigest.IsZero() ||
		!storedResourcesMatchSpec(params.Resources, spec.guards.mutations) ||
		!storedEventIDsMatchSpec(params.EventIDs, spec.expectedFacts) ||
		!storedIssuedCeremoniesMatchSpec(params.IssuedCeremonies, spec.guards.ceremonies) {
		return ReceiptResultPlan{}, ErrInvalidApplicationContract
	}
	hasSession := params.SessionBinding != nil
	if hasSession != (contract.operation == CommandStartActorSession) ||
		hasSession != !params.SessionClient.IsZero() ||
		hasSession != validPresentationCredentialBinding(params.PresentationCredential) {
		return ReceiptResultPlan{}, ErrInvalidApplicationContract
	}
	plan := ReceiptResultPlan{
		operation: spec.commandOperation, commandID: params.OriginalCommandID,
		operationMajor: spec.operationMajor, authorityID: params.AcceptedAuthorityID,
		authorityEpoch: params.AcceptedAuthorityEpoch, scope: spec.scope, acceptedAt: params.AcceptedAt.UTC(),
		commandFingerprint: spec.requestFingerprint, authorizationDigest: params.AuthorizationDigest,
		resources:        append([]domain.AggregateRef(nil), params.Resources...),
		issuedCeremonies: append([]domain.CeremonyChallenge(nil), params.IssuedCeremonies...),
		eventIDs:         append([]domain.EventID(nil), params.EventIDs...),
		capsulePlan:      cloneRecoveryCapsulePlan(spec.recoveryCapsule),
		sessionClient:    params.SessionClient, presentation: params.PresentationCredential, hasSession: hasSession,
	}
	if hasSession {
		plan.sessionBinding = *params.SessionBinding
	}
	return plan, nil
}

func storedResourcesMatchSpec(
	resources []domain.AggregateRef,
	expectations []domain.AggregateExpectation,
) bool {
	expected := make(map[domain.AggregateTarget]domain.Version, len(expectations))
	postVersions := mutationPostVersions(expectations)
	for _, expectation := range expectations {
		if expectation.Target().Kind() == domain.AggregateKindInvitation {
			continue
		}
		postVersion, exists := postVersions[expectation.Target()]
		if !exists {
			return false
		}
		expected[expectation.Target()] = postVersion
	}
	if len(resources) != len(expected) {
		return false
	}
	for _, resource := range resources {
		version, exists := expected[resource.Target()]
		if resource.IsZero() || !exists || resource.Version() != version {
			return false
		}
		delete(expected, resource.Target())
	}
	return len(expected) == 0
}

func storedEventIDsMatchSpec(eventIDs []domain.EventID, facts []FactExpectation) bool {
	if len(eventIDs) != len(facts) {
		return false
	}
	for index, eventID := range eventIDs {
		if eventID.IsZero() || eventID != facts[index].eventID {
			return false
		}
	}
	return true
}

func storedIssuedCeremoniesMatchSpec(
	ceremonies []domain.CeremonyChallenge,
	claims []CeremonyClaim,
) bool {
	expected := make(map[domain.CeremonyID]CeremonyClaim)
	for _, claim := range claims {
		if claim.kind == CeremonyReserveAbsent {
			expected[claim.id] = claim
		}
	}
	if len(ceremonies) != len(expected) {
		return false
	}
	for _, ceremony := range ceremonies {
		claim, exists := expected[ceremony.ID()]
		if ceremony.Status() != domain.CeremonyPending || !exists || !challengeMatchesClaim(ceremony, claim) ||
			!ceremony.ExpiresAt().Equal(claim.expiresAt) || !sameCeremonyBinding(ceremony, claim.challenge) {
			return false
		}
		delete(expected, ceremony.ID())
	}
	return len(expected) == 0
}

func ceremonyOwnerMatchesTarget(
	ceremony domain.CeremonyChallenge,
	target domain.AggregateTarget,
) bool {
	switch target.Kind() {
	case domain.AggregateKindMembership:
		return ceremony.MembershipID().String() == target.ID()
	case domain.AggregateKindActorDelegation:
		return ceremony.DelegationID().String() == target.ID()
	case domain.AggregateKindDevice:
		return ceremony.DeviceID().String() == target.ID()
	default:
		return false
	}
}

func newReceiptResultPlan(
	commandContext CommandContext,
	commit OperationCommit,
) (ReceiptResultPlan, error) {
	if commandContext.resolution.kind != ReceiptAdmitted ||
		commandContext.timeEvidence.mode != CommandTimePersistedWrite ||
		commandContext.timeEvidence.value.IsZero() {
		return ReceiptResultPlan{}, ErrInvalidCommandDecision
	}
	resources := make([]domain.AggregateRef, 0, len(commit.writes))
	var session domain.ActorSessionState
	for _, write := range commit.writes {
		// The bootstrap invitation is a consumed admission artifact, not a
		// result resource in the canonical receipt profile.
		if write.kind == StateInstallationInvitation {
			continue
		}
		ref, err := identityStateRef(write)
		if err != nil {
			return ReceiptResultPlan{}, ErrInvalidCommandDecision
		}
		resources = append(resources, ref)
		if write.kind == StateActorSession {
			session = write.value.(domain.ActorSessionState)
		}
	}
	issued := make([]domain.CeremonyChallenge, 0, len(commit.ceremonies))
	for _, transition := range commit.ceremonies {
		if transition.kind == CeremonyReserveAbsent {
			issued = append(issued, transition.challenge)
		}
	}
	eventIDs := make([]domain.EventID, len(commit.facts))
	for index, fact := range commit.facts {
		eventIDs[index] = fact.eventID
	}
	plan := ReceiptResultPlan{
		operation: commit.operation, commandID: commandContext.spec.commandID,
		operationMajor: commandContext.spec.operationMajor, authorityID: commandContext.spec.authorityID,
		authorityEpoch: commandContext.spec.requestedEpoch, scope: commandContext.spec.scope,
		acceptedAt:          commandContext.timeEvidence.value,
		commandFingerprint:  commandContext.spec.requestFingerprint,
		authorizationDigest: commandContext.guardEvidence.digest,
		resources:           resources, issuedCeremonies: issued, eventIDs: eventIDs,
		capsulePlan: cloneRecoveryCapsulePlan(commandContext.spec.recoveryCapsule),
	}
	if !session.IsZero() {
		plan.sessionBinding = session.Binding()
		plan.sessionClient = session.ClientInstanceID()
		plan.presentation = session.PresentationCredential()
		plan.hasSession = true
	}
	return plan, nil
}

func identityStateRef(state IdentityState) (domain.AggregateRef, error) {
	switch value := state.value.(type) {
	case domain.PrincipalState:
		return domain.NewAggregateRef(value.ID(), value.Version())
	case domain.DeviceState:
		return domain.NewAggregateRef(value.ID(), value.Version())
	case domain.GrantState:
		return domain.NewAggregateRef(value.ID(), value.Version())
	case domain.WorkspaceState:
		return domain.NewAggregateRef(value.ID(), value.Version())
	case domain.MembershipState:
		return domain.NewAggregateRef(value.ID(), value.Version())
	case domain.ActorState:
		return domain.NewAggregateRef(value.ID(), value.Version())
	case domain.ActorDelegationState:
		return domain.NewAggregateRef(value.ID(), value.Version())
	case domain.ActorSessionState:
		return domain.NewAggregateRef(value.ID(), value.Version())
	default:
		return domain.AggregateRef{}, ErrInvalidCommandDecision
	}
}

func (plan ReceiptResultPlan) Operation() CommandOperation           { return plan.operation }
func (plan ReceiptResultPlan) CommandID() domain.CommandID           { return plan.commandID }
func (plan ReceiptResultPlan) OperationMajor() OperationMajor        { return plan.operationMajor }
func (plan ReceiptResultPlan) AuthorityID() domain.AuthorityID       { return plan.authorityID }
func (plan ReceiptResultPlan) AuthorityEpoch() domain.AuthorityEpoch { return plan.authorityEpoch }
func (plan ReceiptResultPlan) Scope() domain.AuthorityScope          { return plan.scope }
func (plan ReceiptResultPlan) AcceptedAt() time.Time                 { return plan.acceptedAt }
func (plan ReceiptResultPlan) CommandFingerprint() domain.CommandFingerprint {
	return plan.commandFingerprint
}
func (plan ReceiptResultPlan) AuthorizationDigest() domain.AuthorizationDigest {
	return plan.authorizationDigest
}
func (plan ReceiptResultPlan) Resources() []domain.AggregateRef {
	return append([]domain.AggregateRef(nil), plan.resources...)
}
func (plan ReceiptResultPlan) IssuedCeremonies() []domain.CeremonyChallenge {
	return append([]domain.CeremonyChallenge(nil), plan.issuedCeremonies...)
}
func (plan ReceiptResultPlan) EventIDs() []domain.EventID {
	return append([]domain.EventID(nil), plan.eventIDs...)
}
func (plan ReceiptResultPlan) CapsuleRequirement() RecoveryCapsuleRequirement {
	return plan.capsulePlan.requirement
}
func (plan ReceiptResultPlan) RecoveryCapsulePlan() RecoveryCapsulePlan {
	return cloneRecoveryCapsulePlan(plan.capsulePlan)
}
func (plan ReceiptResultPlan) Session() (domain.SessionBinding, domain.ClientInstanceID, bool) {
	return plan.sessionBinding, plan.sessionClient, plan.hasSession
}
func (plan ReceiptResultPlan) PresentationCredential() domain.PresentationCredentialBinding {
	return plan.presentation
}

func validPresentationCredentialBinding(binding domain.PresentationCredentialBinding) bool {
	validated, err := domain.NewPresentationCredentialBinding(
		binding.Digest(), binding.Reference(), binding.Audience(), binding.Version(),
	)
	return err == nil && validated == binding
}

func cloneReceiptResultPlan(plan ReceiptResultPlan) ReceiptResultPlan {
	plan.resources = append([]domain.AggregateRef(nil), plan.resources...)
	plan.issuedCeremonies = append([]domain.CeremonyChallenge(nil), plan.issuedCeremonies...)
	plan.eventIDs = append([]domain.EventID(nil), plan.eventIDs...)
	plan.capsulePlan = cloneRecoveryCapsulePlan(plan.capsulePlan)
	return plan
}

type CommandDecisionKind string

const (
	CommandDecisionApplied  CommandDecisionKind = "applied"
	CommandDecisionReplay   CommandDecisionKind = "replay"
	CommandDecisionRollback CommandDecisionKind = "rollback"
)

type CommandDecision struct {
	kind           CommandDecisionKind
	writes         []IdentityState
	facts          []FactIntent
	ceremonies     []CeremonyTransition
	resultPlan     ReceiptResultPlan
	audit          AuditIntent
	effects        EffectSet
	replay         ReceiptSnapshot
	appliedOnly    AppliedOnlyReceipt
	disclosure     ReplayDisclosure
	rejection      *domain.CommandError
	denialAudit    SecuritySpec
	hasDenialAudit bool
}

// AppliedOnlyReceipt is the complete redacted replay shape. It deliberately
// has no result bytes, event range, guard digest, or recovery capsule draft.
type AppliedOnlyReceipt struct {
	receiptID domain.ReceiptID
	commandID domain.CommandID
}

func newAppliedOnlyReceipt(receipt ReceiptSnapshot) AppliedOnlyReceipt {
	return AppliedOnlyReceipt{receiptID: receipt.receiptID, commandID: receipt.commandID}
}

func (receipt AppliedOnlyReceipt) ReceiptID() domain.ReceiptID { return receipt.receiptID }
func (receipt AppliedOnlyReceipt) CommandID() domain.CommandID { return receipt.commandID }

func ApplyCommand(
	commandContext CommandContext,
	commit OperationCommit,
	audit AuditIntent,
	effects EffectSet,
) (CommandDecision, error) {
	if commandContext.resolution.kind != ReceiptAdmitted ||
		commit.operation != commandContext.spec.commandOperation ||
		audit.outcome != AuditCommandApplied || audit.operation != commandContext.spec.operation ||
		audit.fingerprint != commandContext.spec.requestFingerprint ||
		!writesMatchPlan(commit.writes, commandContext.spec.guards.mutations) ||
		!factsMatchPlan(commit.facts, commandContext.spec.expectedFacts) ||
		!ceremonyTransitionsMatchPlan(commit.ceremonies, commandContext.spec.guards.ceremonies) ||
		!effectsReferToFacts(effects, commit.facts) {
		return CommandDecision{}, ErrInvalidCommandDecision
	}
	resultPlan, err := newReceiptResultPlan(commandContext, commit)
	if err != nil {
		return CommandDecision{}, err
	}
	audit, err = finalizeCommandAudit(audit, commandContext, commit)
	if err != nil {
		return CommandDecision{}, err
	}
	return CommandDecision{
		kind: CommandDecisionApplied, writes: append([]IdentityState(nil), commit.writes...),
		facts:      append([]FactIntent(nil), commit.facts...),
		ceremonies: append([]CeremonyTransition(nil), commit.ceremonies...),
		resultPlan: cloneReceiptResultPlan(resultPlan), audit: audit,
		effects: cloneEffects(effects),
	}, nil
}

func ceremonyTransitionsMatchPlan(transitions []CeremonyTransition, claims []CeremonyClaim) bool {
	if len(transitions) != len(claims) {
		return false
	}
	matched := make(map[domain.CeremonyID]struct{}, len(transitions))
	for _, transition := range transitions {
		if transition.challenge.IsZero() {
			return false
		}
		found := false
		for _, claim := range claims {
			if transition.kind == claim.kind && challengeMatchesClaim(transition.challenge, claim) {
				if _, duplicate := matched[claim.id]; duplicate {
					return false
				}
				matched[claim.id] = struct{}{}
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return len(matched) == len(claims)
}

func writesMatchPlan(writes []IdentityState, expectations []domain.AggregateExpectation) bool {
	if len(writes) != len(expectations) || len(writes) == 0 || len(writes) > MaxCommandMutations {
		return false
	}
	byTarget := make(map[domain.AggregateTarget]domain.Version, len(writes))
	for _, write := range writes {
		if write.target.IsZero() || write.version.IsZero() {
			return false
		}
		if _, duplicate := byTarget[write.target]; duplicate {
			return false
		}
		byTarget[write.target] = write.version
	}
	for target, postVersion := range mutationPostVersions(expectations) {
		if byTarget[target] != postVersion {
			return false
		}
	}
	return true
}

func factsMatchPlan(facts []FactIntent, expectations []FactExpectation) bool {
	if len(facts) != len(expectations) || len(facts) == 0 || len(facts) > MaxCommandFacts {
		return false
	}
	for index, expectation := range expectations {
		fact := facts[index]
		if fact.fact == nil || fact.eventID != expectation.eventID ||
			fact.fact.Type() != expectation.eventType || fact.fact.Origin() != expectation.origin {
			return false
		}
	}
	return true
}

func effectsReferToFacts(effects EffectSet, facts []FactIntent) bool {
	events := make(map[domain.EventID]struct{}, len(facts))
	for _, fact := range facts {
		events[fact.eventID] = struct{}{}
	}
	for _, effect := range effects.intents {
		if _, exists := events[effect.causingEvent]; !exists {
			return false
		}
	}
	return true
}

func cloneEffects(effects EffectSet) EffectSet {
	cloned := append([]EffectIntent(nil), effects.intents...)
	for index := range cloned {
		cloned[index].metadata = append([]byte(nil), cloned[index].metadata...)
	}
	return EffectSet{intents: cloned}
}

func ReplayCommand(
	commandContext CommandContext,
	disclosure ReplayDisclosure,
) (CommandDecision, error) {
	receipt, replay := commandContext.resolution.Receipt()
	if !replay || (disclosure != ReplayDiscloseResult && disclosure != ReplayDiscloseAppliedOnly) {
		return CommandDecision{}, ErrInvalidCommandDecision
	}
	decision := CommandDecision{kind: CommandDecisionReplay, disclosure: disclosure}
	if disclosure == ReplayDiscloseResult {
		decision.replay = receipt
	} else {
		decision.appliedOnly = newAppliedOnlyReceipt(receipt)
	}
	return decision, nil
}

func RollbackCommand(
	commandContext CommandContext,
	rejection *domain.CommandError,
) (CommandDecision, error) {
	if rejection == nil || requiresDenialAudit(rejection) ||
		!rejectionMatchesResolution(rejection, commandContext.resolution.kind) {
		return CommandDecision{}, ErrInvalidCommandDecision
	}
	return CommandDecision{kind: CommandDecisionRollback, rejection: rejection}, nil
}

func RollbackCommandWithSecurityAudit(
	commandContext CommandContext,
	rejection *domain.CommandError,
	denialAudit SecuritySpec,
) (CommandDecision, error) {
	if rejection == nil || !requiresDenialAudit(rejection) ||
		!rejectionMatchesResolution(rejection, commandContext.resolution.kind) ||
		denialAudit.operation != SecurityRecordCommandDenial ||
		denialAudit.scope != commandContext.spec.scope ||
		denialAudit.authorityID != commandContext.spec.authorityID ||
		denialAudit.epoch != commandContext.spec.requestedEpoch ||
		denialAudit.admission != commandContext.spec.guards.admissionGeneration ||
		denialAudit.commandDenial.operation != commandContext.spec.operation ||
		denialAudit.commandDenial.requestFingerprint != commandContext.spec.requestFingerprint ||
		denialAudit.commandDenial.correlation != commandContext.spec.correlationID ||
		(denialAudit.commandDenial.subject.kind == DenialAttributedSubject &&
			denialAudit.commandDenial.subject.principal != commandContext.spec.authorship.principal) ||
		!denialClassMatchesRejection(denialAudit.commandDenial.class, rejection, commandContext.resolution.kind) {
		return CommandDecision{}, ErrInvalidCommandDecision
	}
	return CommandDecision{
		kind: CommandDecisionRollback, rejection: rejection,
		denialAudit: denialAudit, hasDenialAudit: true,
	}, nil
}

func denialClassMatchesRejection(
	class CommandDenialClass,
	rejection *domain.CommandError,
	resolution ReceiptResolutionKind,
) bool {
	if rejection == nil {
		return false
	}
	switch rejection.Code() {
	case domain.ErrorCodeUnauthenticated, domain.ErrorCodeSessionExpired:
		return class == DenialAuthentication
	case domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired:
		if resolution == ReceiptExactReplay {
			return class == DenialResultDisclosure
		}
		return class == DenialAuthorization
	case domain.ErrorCodeRateLimited:
		return class == DenialSecurityRateQuota
	default:
		kind, conflict := rejection.ConflictKind()
		return conflict && kind == domain.ConflictAuthorityMismatch && class == DenialAuthorityMismatch
	}
}

func requiresDenialAudit(rejection *domain.CommandError) bool {
	if rejection == nil {
		return false
	}
	switch rejection.Code() {
	case domain.ErrorCodeUnauthenticated, domain.ErrorCodeSessionExpired,
		domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired,
		domain.ErrorCodeRateLimited:
		return true
	default:
		kind, conflict := rejection.ConflictKind()
		return conflict && kind == domain.ConflictAuthorityMismatch
	}
}

func rejectionMatchesResolution(rejection *domain.CommandError, resolution ReceiptResolutionKind) bool {
	switch resolution {
	case ReceiptCommandIDConflict:
		return rejection.Code() == domain.ErrorCodeCommandIDReused
	case ReceiptIdempotencyConflict:
		return rejection.Code() == domain.ErrorCodeIdempotencyKeyReused
	case ReceiptInProgress:
		return rejection.Code() == domain.ErrorCodeCommandInProgress
	case ReceiptIntegrityConflict:
		return rejection.Code() == domain.ErrorCodeInternal
	case ReceiptExactReplay:
		return rejection.Code() == domain.ErrorCodeForbidden || rejection.Code() == domain.ErrorCodeUnauthenticated ||
			rejection.Code() == domain.ErrorCodeSessionExpired
	case ReceiptAdmitted:
		return true
	default:
		return false
	}
}

func (decision CommandDecision) Kind() CommandDecisionKind { return decision.kind }
func (decision CommandDecision) Writes() []IdentityState {
	return append([]IdentityState(nil), decision.writes...)
}
func (decision CommandDecision) Facts() []FactIntent {
	return append([]FactIntent(nil), decision.facts...)
}
func (decision CommandDecision) CeremonyTransitions() []CeremonyTransition {
	return append([]CeremonyTransition(nil), decision.ceremonies...)
}
func (decision CommandDecision) ResultPlan() ReceiptResultPlan {
	return cloneReceiptResultPlan(decision.resultPlan)
}
func (decision CommandDecision) Audit() AuditIntent { return decision.audit }
func (decision CommandDecision) Effects() EffectSet { return cloneEffects(decision.effects) }
func (decision CommandDecision) Replay() (ReceiptSnapshot, ReplayDisclosure, bool) {
	return decision.replay, decision.disclosure,
		decision.kind == CommandDecisionReplay && decision.disclosure == ReplayDiscloseResult
}
func (decision CommandDecision) AppliedOnlyReplay() (AppliedOnlyReceipt, bool) {
	return decision.appliedOnly,
		decision.kind == CommandDecisionReplay && decision.disclosure == ReplayDiscloseAppliedOnly
}
func (decision CommandDecision) Rejection() (*domain.CommandError, bool) {
	return decision.rejection, decision.kind == CommandDecisionRollback
}
func (decision CommandDecision) DenialAudit() (SecuritySpec, bool) {
	return decision.denialAudit, decision.hasDenialAudit
}

type CommandExecutionKind string

const (
	CommandApplied                 CommandExecutionKind = "applied"
	CommandReplayed                CommandExecutionKind = "replay"
	CommandRejected                CommandExecutionKind = "rejected"
	CommandIndeterminate           CommandExecutionKind = "indeterminate"
	CommandCommittedCapsulePending CommandExecutionKind = "committed_capsule_pending"
)

type CommandExecution struct {
	kind        CommandExecutionKind
	receipt     ReceiptSnapshot
	appliedOnly AppliedOnlyReceipt
	disclosure  ReplayDisclosure
	rejection   *domain.CommandError
	retry       CommandRetryIdentity
	capsule     RecoveryCapsuleEnvelope
	hasCapsule  bool
}

func AppliedCommandExecution(
	receipt ReceiptSnapshot,
	capsule *RecoveryCapsuleEnvelope,
) (CommandExecution, error) {
	if receipt.receiptID.IsZero() {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	if receipt.hasRecoveryCapsule != (capsule != nil) {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	execution := CommandExecution{kind: CommandApplied, receipt: receipt}
	if capsule != nil {
		if !receipt.hasRecoveryCapsule || !sameRecoveryCapsuleDraft(capsule.draft, receipt.recoveryCapsule) {
			return CommandExecution{}, ErrInvalidCommandExecution
		}
		execution.capsule, execution.hasCapsule = *capsule, true
	}
	return execution, nil
}

func ReplayedCommandExecution(
	receipt ReceiptSnapshot,
	disclosure ReplayDisclosure,
	capsule *RecoveryCapsuleEnvelope,
) (CommandExecution, error) {
	if receipt.receiptID.IsZero() || (disclosure != ReplayDiscloseResult && disclosure != ReplayDiscloseAppliedOnly) {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	if disclosure == ReplayDiscloseResult && receipt.hasRecoveryCapsule != (capsule != nil) {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	if disclosure == ReplayDiscloseAppliedOnly && capsule != nil {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	execution := CommandExecution{kind: CommandReplayed, disclosure: disclosure}
	if disclosure == ReplayDiscloseResult {
		execution.receipt = receipt
	} else {
		execution.appliedOnly = newAppliedOnlyReceipt(receipt)
	}
	if capsule != nil {
		if !receipt.hasRecoveryCapsule || !sameRecoveryCapsuleDraft(capsule.draft, receipt.recoveryCapsule) {
			return CommandExecution{}, ErrInvalidCommandExecution
		}
		execution.capsule, execution.hasCapsule = *capsule, true
	}
	return execution, nil
}

func RejectedCommandExecution(rejection *domain.CommandError) (CommandExecution, error) {
	if rejection == nil {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	return CommandExecution{kind: CommandRejected, rejection: rejection}, nil
}

func IndeterminateCommandExecution(spec CommandSpec) (CommandExecution, error) {
	identity, err := newCommandRetryIdentity(spec)
	if err != nil {
		return CommandExecution{}, err
	}
	return CommandExecution{kind: CommandIndeterminate, retry: identity}, nil
}

// CommittedCapsulePendingCommandExecution means the database commit is known durable;
// only post-commit deterministic signing failed. It is never DB-indeterminate.
func CommittedCapsulePendingCommandExecution(receipt ReceiptSnapshot) (CommandExecution, error) {
	if receipt.receiptID.IsZero() || !receipt.hasRecoveryCapsule {
		return CommandExecution{}, ErrInvalidCommandExecution
	}
	return CommandExecution{kind: CommandCommittedCapsulePending, receipt: receipt}, nil
}

func (execution CommandExecution) Kind() CommandExecutionKind { return execution.kind }
func (execution CommandExecution) Receipt() (ReceiptSnapshot, bool) {
	return execution.receipt, execution.kind == CommandApplied || execution.kind == CommandCommittedCapsulePending ||
		(execution.kind == CommandReplayed && execution.disclosure == ReplayDiscloseResult)
}

// CommandRetryIdentity is the immutable receipt admission identity needed to
// resolve an unknown commit. A retry must reuse all four values exactly.
type CommandRetryIdentity struct {
	commandID          domain.CommandID
	receiptID          domain.ReceiptID
	receiptIdentity    ReceiptIdentity
	requestFingerprint domain.CommandFingerprint
}

func newCommandRetryIdentity(spec CommandSpec) (CommandRetryIdentity, error) {
	identity := CommandRetryIdentity{
		commandID: spec.commandID, receiptID: spec.receiptID,
		receiptIdentity: spec.receiptIdentity, requestFingerprint: spec.requestFingerprint,
	}
	if !validCommandRetryIdentity(identity) {
		return CommandRetryIdentity{}, ErrInvalidCommandExecution
	}
	return identity, nil
}

func validCommandRetryIdentity(identity CommandRetryIdentity) bool {
	return !identity.commandID.IsZero() && !identity.receiptID.IsZero() &&
		identity.receiptIdentity.kind != "" && !identity.requestFingerprint.IsZero()
}

func (identity CommandRetryIdentity) CommandID() domain.CommandID { return identity.commandID }
func (identity CommandRetryIdentity) ReceiptID() domain.ReceiptID { return identity.receiptID }
func (identity CommandRetryIdentity) ReceiptIdentity() ReceiptIdentity {
	return identity.receiptIdentity
}
func (identity CommandRetryIdentity) RequestFingerprint() domain.CommandFingerprint {
	return identity.requestFingerprint
}

type CommandTransactionExecutionKind string

const (
	CommandTransactionCommitted     CommandTransactionExecutionKind = "committed"
	CommandTransactionReplayed      CommandTransactionExecutionKind = "replay"
	CommandTransactionRejected      CommandTransactionExecutionKind = "rejected"
	CommandTransactionIndeterminate CommandTransactionExecutionKind = "indeterminate"
)

// CommandTransactionExecution closes the database outcome before any required
// post-commit capsule signing is attempted.
type CommandTransactionExecution struct {
	kind          CommandTransactionExecutionKind
	receipt       ReceiptSnapshot
	appliedOnly   AppliedOnlyReceipt
	disclosure    ReplayDisclosure
	rejection     *domain.CommandError
	denialAudit   SecuritySpec
	retryIdentity CommandRetryIdentity
}

func CommittedCommandTransactionExecution(receipt ReceiptSnapshot) (CommandTransactionExecution, error) {
	if receipt.receiptID.IsZero() {
		return CommandTransactionExecution{}, ErrInvalidCommandExecution
	}
	return CommandTransactionExecution{kind: CommandTransactionCommitted, receipt: receipt}, nil
}

func ReplayedCommandTransactionExecution(
	receipt ReceiptSnapshot,
	disclosure ReplayDisclosure,
) (CommandTransactionExecution, error) {
	if receipt.receiptID.IsZero() || (disclosure != ReplayDiscloseResult && disclosure != ReplayDiscloseAppliedOnly) {
		return CommandTransactionExecution{}, ErrInvalidCommandExecution
	}
	execution := CommandTransactionExecution{kind: CommandTransactionReplayed, disclosure: disclosure}
	if disclosure == ReplayDiscloseResult {
		execution.receipt = receipt
	} else {
		execution.appliedOnly = newAppliedOnlyReceipt(receipt)
	}
	return execution, nil
}

func RejectedCommandTransactionExecution(
	rejection *domain.CommandError,
	denialAudit SecuritySpec,
) (CommandTransactionExecution, error) {
	hasDenial := denialAudit.operation != ""
	if rejection == nil || hasDenial != requiresDenialAudit(rejection) ||
		(hasDenial && denialAudit.operation != SecurityRecordCommandDenial) {
		return CommandTransactionExecution{}, ErrInvalidCommandExecution
	}
	return CommandTransactionExecution{
		kind: CommandTransactionRejected, rejection: rejection, denialAudit: denialAudit,
	}, nil
}

func IndeterminateCommandTransactionExecution(spec CommandSpec) (CommandTransactionExecution, error) {
	identity, err := newCommandRetryIdentity(spec)
	if err != nil {
		return CommandTransactionExecution{}, err
	}
	return CommandTransactionExecution{kind: CommandTransactionIndeterminate, retryIdentity: identity}, nil
}

func (execution CommandTransactionExecution) Kind() CommandTransactionExecutionKind {
	return execution.kind
}
func (execution CommandTransactionExecution) Receipt() (ReceiptSnapshot, bool) {
	return execution.receipt, execution.kind == CommandTransactionCommitted ||
		(execution.kind == CommandTransactionReplayed && execution.disclosure == ReplayDiscloseResult)
}
func (execution CommandTransactionExecution) AppliedOnlyReceipt() (AppliedOnlyReceipt, bool) {
	return execution.appliedOnly,
		execution.kind == CommandTransactionReplayed && execution.disclosure == ReplayDiscloseAppliedOnly
}
func (execution CommandTransactionExecution) ReplayDisclosure() (ReplayDisclosure, bool) {
	return execution.disclosure, execution.kind == CommandTransactionReplayed
}
func (execution CommandTransactionExecution) Rejection() (*domain.CommandError, bool) {
	return execution.rejection, execution.kind == CommandTransactionRejected
}
func (execution CommandTransactionExecution) DenialAudit() (SecuritySpec, bool) {
	return execution.denialAudit,
		execution.kind == CommandTransactionRejected && execution.denialAudit.operation == SecurityRecordCommandDenial
}
func (execution CommandTransactionExecution) RetryIdentity() (CommandRetryIdentity, bool) {
	return execution.retryIdentity, execution.kind == CommandTransactionIndeterminate
}

// ValidateCommandTransactionResult rejects ambiguous result/error pairs. A
// known outcome has no competing Go error. A zero execution is legal only for
// failure before an outcome exists.
func ValidateCommandTransactionResult(execution CommandTransactionExecution, executionErr error) error {
	if execution.kind == "" {
		var rejection *domain.CommandError
		if executionErr != nil && !errors.As(executionErr, &rejection) {
			return nil
		}
		return ErrInvalidCommandExecution
	}
	if execution.kind == CommandTransactionIndeterminate {
		if executionErr != nil || !validCommandRetryIdentity(execution.retryIdentity) ||
			!execution.receipt.receiptID.IsZero() || !execution.appliedOnly.receiptID.IsZero() ||
			execution.disclosure != "" || execution.rejection != nil || execution.denialAudit.operation != "" {
			return ErrInvalidCommandExecution
		}
		return nil
	}
	if executionErr != nil {
		return ErrInvalidCommandExecution
	}
	switch execution.kind {
	case CommandTransactionCommitted:
		if execution.receipt.receiptID.IsZero() || !execution.appliedOnly.receiptID.IsZero() ||
			execution.disclosure != "" || execution.rejection != nil || execution.denialAudit.operation != "" ||
			validCommandRetryIdentity(execution.retryIdentity) {
			return ErrInvalidCommandExecution
		}
	case CommandTransactionReplayed:
		if execution.rejection != nil || execution.denialAudit.operation != "" || validCommandRetryIdentity(execution.retryIdentity) {
			return ErrInvalidCommandExecution
		}
		if execution.disclosure == ReplayDiscloseResult &&
			(execution.receipt.receiptID.IsZero() || !execution.appliedOnly.receiptID.IsZero()) {
			return ErrInvalidCommandExecution
		}
		if execution.disclosure == ReplayDiscloseAppliedOnly &&
			(execution.appliedOnly.receiptID.IsZero() || !execution.receipt.receiptID.IsZero()) {
			return ErrInvalidCommandExecution
		}
		if execution.disclosure != ReplayDiscloseResult && execution.disclosure != ReplayDiscloseAppliedOnly {
			return ErrInvalidCommandExecution
		}
	case CommandTransactionRejected:
		hasDenial := execution.denialAudit.operation != ""
		if execution.rejection == nil || !execution.receipt.receiptID.IsZero() ||
			!execution.appliedOnly.receiptID.IsZero() || execution.disclosure != "" ||
			validCommandRetryIdentity(execution.retryIdentity) ||
			hasDenial != requiresDenialAudit(execution.rejection) ||
			(hasDenial && execution.denialAudit.operation != SecurityRecordCommandDenial) {
			return ErrInvalidCommandExecution
		}
	default:
		return ErrInvalidCommandExecution
	}
	return nil
}
func (execution CommandExecution) AppliedOnlyReceipt() (AppliedOnlyReceipt, bool) {
	return execution.appliedOnly,
		execution.kind == CommandReplayed && execution.disclosure == ReplayDiscloseAppliedOnly
}

func sameRecoveryCapsuleDraft(left, right RecoveryCapsuleDraft) bool {
	return left.digest == right.digest && left.keyID == right.keyID && string(left.canonical) == string(right.canonical)
}
func (execution CommandExecution) ReplayDisclosure() (ReplayDisclosure, bool) {
	return execution.disclosure, execution.kind == CommandReplayed
}
func (execution CommandExecution) Rejection() (*domain.CommandError, bool) {
	return execution.rejection, execution.kind == CommandRejected
}
func (execution CommandExecution) RetryIdentity() (CommandRetryIdentity, bool) {
	return execution.retry, execution.kind == CommandIndeterminate
}
func (execution CommandExecution) RecoveryCapsule() (RecoveryCapsuleEnvelope, bool) {
	envelope := execution.capsule
	envelope.signature = append([]byte(nil), envelope.signature...)
	envelope.draft.canonical = append([]byte(nil), envelope.draft.canonical...)
	return envelope, execution.hasCapsule
}

// UnitOfWork is the only transaction port exposed to application services.
//
// Implementations MUST roll back if decide returns an error, panics, returns a
// zero/invalid decision, or proposes a shape outside spec. A callback error is
// never compatible with a known transaction outcome. ExecuteCommand returns
// before post-commit capsule signing. Whole-command retries use the identical
// immutable spec and rerun decide against newly locked state.
type UnitOfWork interface {
	ExecuteCommand(
		context.Context,
		CommandSpec,
		func(CommandContext) (CommandDecision, error),
	) (CommandTransactionExecution, error)

	ExecuteSecurity(
		context.Context,
		SecuritySpec,
		func(SecurityContext) (SecurityDecision, error),
	) (SecurityExecution, error)
}

type SecurityOperation string

const (
	SecurityInitializeInstallation    SecurityOperation = "initialize_installation"
	SecurityRotateBootstrapGeneration SecurityOperation = "rotate_bootstrap_generation"
	SecurityResumeBootstrapGeneration SecurityOperation = "resume_bootstrap_generation"
	SecurityRecordBootstrapDenial     SecurityOperation = "record_bootstrap_denial"
	SecurityRecordCommandDenial       SecurityOperation = "record_command_denial"
)

const (
	MaxDistinctDenialsPerMinute    = 20
	MaxDenialEntriesPerScopeMinute = 1000
)

type CommandDenialClass string

const (
	DenialAuthentication    CommandDenialClass = "authentication"
	DenialAuthorization     CommandDenialClass = "authorization"
	DenialAuthorityMismatch CommandDenialClass = "authority_mismatch"
	DenialResultDisclosure  CommandDenialClass = "result_disclosure"
	DenialSecurityRateQuota CommandDenialClass = "security_rate_quota"
)

func (class CommandDenialClass) Valid() bool {
	switch class {
	case DenialAuthentication, DenialAuthorization, DenialAuthorityMismatch,
		DenialResultDisclosure, DenialSecurityRateQuota:
		return true
	default:
		return false
	}
}

type DenialSubjectKind string

const (
	DenialAttributedSubject  DenialSubjectKind = "attributed_subject"
	DenialUnattributedSource DenialSubjectKind = "unattributed_source"
)

type DenialSubject struct {
	kind      DenialSubjectKind
	principal domain.PrincipalID
	device    domain.DeviceID
	hasDevice bool
	source    Digest
}

func AttributedDenialSubject(principal domain.PrincipalID, device *domain.DeviceID) (DenialSubject, error) {
	if principal.IsZero() {
		return DenialSubject{}, ErrInvalidSecuritySpec
	}
	subject := DenialSubject{kind: DenialAttributedSubject, principal: principal}
	if device != nil {
		if device.IsZero() {
			return DenialSubject{}, ErrInvalidSecuritySpec
		}
		subject.device, subject.hasDevice = *device, true
	}
	return subject, nil
}

func UnattributedDenialSource(sourceOrChannelDigest Digest) (DenialSubject, error) {
	if sourceOrChannelDigest.IsZero() {
		return DenialSubject{}, ErrInvalidSecuritySpec
	}
	return DenialSubject{kind: DenialUnattributedSource, source: sourceOrChannelDigest}, nil
}

func (subject DenialSubject) Kind() DenialSubjectKind         { return subject.kind }
func (subject DenialSubject) PrincipalID() domain.PrincipalID { return subject.principal }
func (subject DenialSubject) DeviceID() (domain.DeviceID, bool) {
	return subject.device, subject.hasDevice
}
func (subject DenialSubject) SourceDigest() (Digest, bool) {
	return subject.source, subject.kind == DenialUnattributedSource
}

type CommandDenialDraft struct {
	operation          domain.OperationName
	operationMajor     OperationMajor
	class              CommandDenialClass
	reason             string
	requestFingerprint domain.CommandFingerprint
	denialFingerprint  Digest
	subject            DenialSubject
	policy             domain.PolicyRevision
	hasPolicy          bool
	correlation        domain.CorrelationID
}

func NewCommandDenialDraft(
	operation domain.OperationName,
	major OperationMajor,
	class CommandDenialClass,
	safeReason string,
	requestFingerprint domain.CommandFingerprint,
	subject DenialSubject,
	policy *domain.PolicyRevision,
	correlation domain.CorrelationID,
) (CommandDenialDraft, error) {
	if !operationHasMajor(operation, major) ||
		!class.Valid() ||
		!validToken(safeReason, 64) || requestFingerprint.IsZero() ||
		(subject.kind != DenialAttributedSubject && subject.kind != DenialUnattributedSource) || correlation.IsZero() {
		return CommandDenialDraft{}, ErrInvalidSecuritySpec
	}
	draft := CommandDenialDraft{
		operation: operation, operationMajor: major, class: class, reason: safeReason,
		requestFingerprint: requestFingerprint, subject: subject, correlation: correlation,
	}
	if policy != nil {
		if policy.String() == "" {
			return CommandDenialDraft{}, ErrInvalidSecuritySpec
		}
		draft.policy, draft.hasPolicy = *policy, true
	}
	return draft, nil
}

func (draft CommandDenialDraft) Operation() domain.OperationName { return draft.operation }
func (draft CommandDenialDraft) OperationMajor() OperationMajor  { return draft.operationMajor }
func (draft CommandDenialDraft) Class() CommandDenialClass       { return draft.class }
func (draft CommandDenialDraft) SafeReason() string              { return draft.reason }
func (draft CommandDenialDraft) RequestFingerprint() domain.CommandFingerprint {
	return draft.requestFingerprint
}
func (draft CommandDenialDraft) DenialFingerprint() Digest           { return draft.denialFingerprint }
func (draft CommandDenialDraft) Subject() DenialSubject              { return draft.subject }
func (draft CommandDenialDraft) CorrelationID() domain.CorrelationID { return draft.correlation }
func (draft CommandDenialDraft) PolicyRevision() (domain.PolicyRevision, bool) {
	return draft.policy, draft.hasPolicy
}

type SecuritySpec struct {
	operation       SecurityOperation
	scope           domain.AuthorityScope
	authorityID     domain.AuthorityID
	epoch           domain.AuthorityEpoch
	admission       GuardGeneration
	invitation      domain.AggregateExpectation
	attempt         domain.CommandFingerprint
	oldGeneration   domain.BootstrapGenerationID
	newGeneration   domain.BootstrapGenerationID
	resumeApproval  domain.CommandFingerprint
	initialState    domain.InstallationInvitationState
	initialization  Digest
	commandDenial   CommandDenialDraft
	auditRequest    AuditRequestContext
	provenance      AuditProvenanceEvidence
	hasAuditContext bool
}

func bindSecurityAuditContext(
	spec SecuritySpec,
	request AuditRequestContext,
	provenance AuditProvenanceEvidence,
) (SecuritySpec, error) {
	if spec.operation == "" || !validAuditRequestContext(request) || !validAuditProvenanceEvidence(provenance) ||
		spec.hasAuditContext {
		return SecuritySpec{}, ErrInvalidSecuritySpec
	}
	spec.auditRequest, spec.provenance, spec.hasAuditContext = request, provenance, true
	return spec, nil
}

// BootstrapAttempt is a secret-free, canonically fingerprinted rejected proof.
// It retains only already-derived transcript, nonce, channel, and proof digests.
type BootstrapAttempt struct {
	invitation  domain.InvitationID
	fingerprint domain.CommandFingerprint
}

func NewBootstrapAttempt(
	invitation domain.InvitationID,
	transcriptHash domain.CommandFingerprint,
	clientNonceDigest domain.CommandFingerprint,
	serverNonceDigest domain.CommandFingerprint,
	channelBindingDigest domain.CommandFingerprint,
	presentedProofDigest domain.CommandFingerprint,
) (BootstrapAttempt, error) {
	if invitation.IsZero() || transcriptHash.IsZero() || clientNonceDigest.IsZero() ||
		serverNonceDigest.IsZero() || channelBindingDigest.IsZero() || presentedProofDigest.IsZero() {
		return BootstrapAttempt{}, ErrInvalidSecuritySpec
	}
	invitationID, err := NewCanonicalIdentifier(invitation.String())
	if err != nil {
		return BootstrapAttempt{}, ErrInvalidSecuritySpec
	}
	digests := [...]domain.CommandFingerprint{
		transcriptHash, clientNonceDigest, serverNonceDigest, channelBindingDigest, presentedProofDigest,
	}
	canonical := make([]CanonicalDigest, len(digests))
	for index, digest := range digests {
		canonical[index], err = NewCanonicalDigest(hex.EncodeToString(digest[:]))
		if err != nil {
			return BootstrapAttempt{}, ErrInvalidSecuritySpec
		}
	}
	view, err := NewBootstrapAttemptViewV1(
		invitationID, canonical[0], canonical[1], canonical[2], canonical[3], canonical[4],
	)
	if err != nil {
		return BootstrapAttempt{}, ErrInvalidSecuritySpec
	}
	digest, err := NewProductionCanonicalCodec().HashBootstrapAttempt(view)
	if err != nil {
		return BootstrapAttempt{}, ErrInvalidSecuritySpec
	}
	return BootstrapAttempt{invitation: invitation, fingerprint: domain.CommandFingerprint(digest)}, nil
}

func (attempt BootstrapAttempt) InvitationID() domain.InvitationID { return attempt.invitation }
func (attempt BootstrapAttempt) Fingerprint() domain.CommandFingerprint {
	return attempt.fingerprint
}

func InitializeInstallationSecurity(
	scope domain.AuthorityScope,
	authorityID domain.AuthorityID,
	epoch domain.AuthorityEpoch,
	admission GuardGeneration,
	invitation domain.InstallationInvitationState,
	initializationGuard Digest,
) (SecuritySpec, error) {
	if scope.IsZero() || scope.Kind() != domain.ScopeKindInstallation || authorityID.IsZero() || epoch.IsZero() ||
		admission.IsZero() || invitation.IsZero() || invitation.Version() != domain.InitialVersion() ||
		initializationGuard.IsZero() || invitation.InstallationID().String() != scope.ID() {
		return SecuritySpec{}, ErrInvalidSecuritySpec
	}
	expectation, err := domain.ExpectAggregateAbsent(invitation.ID())
	if err != nil {
		return SecuritySpec{}, ErrInvalidSecuritySpec
	}
	return SecuritySpec{
		operation: SecurityInitializeInstallation, scope: scope, authorityID: authorityID, epoch: epoch,
		admission: admission, invitation: expectation, initialState: invitation, initialization: initializationGuard,
	}, nil
}

func RotateBootstrapGenerationSecurity(
	scope domain.AuthorityScope,
	authorityID domain.AuthorityID,
	epoch domain.AuthorityEpoch,
	admission GuardGeneration,
	oldGeneration domain.BootstrapGenerationID,
	newGeneration domain.BootstrapGenerationID,
) (SecuritySpec, error) {
	if scope.IsZero() || scope.Kind() != domain.ScopeKindInstallation || authorityID.IsZero() || epoch.IsZero() ||
		admission.IsZero() || oldGeneration.IsZero() || newGeneration.IsZero() || oldGeneration == newGeneration {
		return SecuritySpec{}, ErrInvalidSecuritySpec
	}
	return SecuritySpec{
		operation: SecurityRotateBootstrapGeneration, scope: scope, authorityID: authorityID, epoch: epoch,
		admission: admission, oldGeneration: oldGeneration, newGeneration: newGeneration,
	}, nil
}

func ResumeBootstrapGenerationSecurity(
	scope domain.AuthorityScope,
	authorityID domain.AuthorityID,
	epoch domain.AuthorityEpoch,
	admission GuardGeneration,
	invitation domain.AggregateExpectation,
	oldGeneration domain.BootstrapGenerationID,
	newGeneration domain.BootstrapGenerationID,
	verifiedApproval domain.CommandFingerprint,
) (SecuritySpec, error) {
	version, hasVersion := invitation.Version()
	if scope.IsZero() || scope.Kind() != domain.ScopeKindInstallation || authorityID.IsZero() || epoch.IsZero() ||
		admission.IsZero() || invitation.Target().Kind() != domain.AggregateKindInvitation || !hasVersion || version.IsZero() ||
		oldGeneration.IsZero() || newGeneration.IsZero() || oldGeneration == newGeneration || verifiedApproval.IsZero() {
		return SecuritySpec{}, ErrInvalidSecuritySpec
	}
	return SecuritySpec{
		operation: SecurityResumeBootstrapGeneration, scope: scope, authorityID: authorityID, epoch: epoch,
		admission: admission, invitation: invitation, oldGeneration: oldGeneration,
		newGeneration: newGeneration, resumeApproval: verifiedApproval,
	}, nil
}

func RecordBootstrapDenialSecurity(
	scope domain.AuthorityScope,
	authorityID domain.AuthorityID,
	epoch domain.AuthorityEpoch,
	admission GuardGeneration,
	invitation domain.AggregateExpectation,
	attempt BootstrapAttempt,
) (SecuritySpec, error) {
	version, hasVersion := invitation.Version()
	if scope.IsZero() || scope.Kind() != domain.ScopeKindInstallation || authorityID.IsZero() || epoch.IsZero() ||
		admission.IsZero() || invitation.Target().Kind() != domain.AggregateKindInvitation || !hasVersion ||
		version.IsZero() || version.Uint64() >= MaxCanonicalInteger || attempt.fingerprint.IsZero() ||
		invitation.Target().ID() != attempt.invitation.String() {
		return SecuritySpec{}, ErrInvalidSecuritySpec
	}
	return SecuritySpec{
		operation: SecurityRecordBootstrapDenial, scope: scope, authorityID: authorityID, epoch: epoch,
		admission: admission, invitation: invitation, attempt: attempt.fingerprint,
	}, nil
}

func RecordCommandDenialSecurity(
	scope domain.AuthorityScope,
	authorityID domain.AuthorityID,
	epoch domain.AuthorityEpoch,
	admission GuardGeneration,
	draft CommandDenialDraft,
) (SecuritySpec, error) {
	if scope.IsZero() || authorityID.IsZero() || epoch.IsZero() || admission.IsZero() ||
		draft.operation.String() == "" || !draft.denialFingerprint.IsZero() {
		return SecuritySpec{}, ErrInvalidSecuritySpec
	}
	fingerprint, err := hashCommandDenial(scope, authorityID, epoch, admission, draft)
	if err != nil {
		return SecuritySpec{}, ErrInvalidSecuritySpec
	}
	draft.denialFingerprint = fingerprint
	return SecuritySpec{
		operation: SecurityRecordCommandDenial, scope: scope, authorityID: authorityID,
		epoch: epoch, admission: admission, commandDenial: draft,
	}, nil
}

type commandDenialSubjectHashViewV1 struct {
	Kind       DenialSubjectKind    `json:"kind"`
	Principal  *CanonicalIdentifier `json:"principal_id"`
	Device     *CanonicalIdentifier `json:"device_id"`
	SourceHash *CanonicalDigest     `json:"source_digest"`
}

type commandDenialHashViewV1 struct {
	ScopeKind          string                         `json:"scope_kind"`
	ScopeID            CanonicalIdentifier            `json:"scope_id"`
	AuthorityID        CanonicalIdentifier            `json:"authority_id"`
	AuthorityEpoch     CanonicalIdentifier            `json:"authority_epoch"`
	Admission          uint64                         `json:"admission_generation"`
	Operation          string                         `json:"operation"`
	OperationMajor     uint16                         `json:"operation_major"`
	Class              CommandDenialClass             `json:"rejection_class"`
	Reason             string                         `json:"reason"`
	RequestFingerprint CanonicalDigest                `json:"request_fingerprint"`
	Subject            commandDenialSubjectHashViewV1 `json:"subject"`
	PolicyRevision     *string                        `json:"policy_revision"`
	CorrelationID      CanonicalIdentifier            `json:"correlation_id"`
}

func (commandDenialHashViewV1) canonicalView()         {}
func (commandDenialHashViewV1) commandDenialHashView() {}

func hashCommandDenial(
	scope domain.AuthorityScope,
	authorityID domain.AuthorityID,
	epoch domain.AuthorityEpoch,
	admission GuardGeneration,
	draft CommandDenialDraft,
) (Digest, error) {
	scopeID, err := NewCanonicalIdentifier(scope.ID())
	if err != nil {
		return Digest{}, err
	}
	authority, err := NewCanonicalIdentifier(authorityID.String())
	if err != nil {
		return Digest{}, err
	}
	authorityEpoch, err := NewCanonicalIdentifier(epoch.String())
	if err != nil {
		return Digest{}, err
	}
	request, err := NewCanonicalDigest(hex.EncodeToString(draft.requestFingerprint[:]))
	if err != nil {
		return Digest{}, err
	}
	correlation, err := NewCanonicalIdentifier(draft.correlation.String())
	if err != nil {
		return Digest{}, err
	}
	subject := commandDenialSubjectHashViewV1{Kind: draft.subject.kind}
	switch draft.subject.kind {
	case DenialAttributedSubject:
		principal, principalErr := NewCanonicalIdentifier(draft.subject.principal.String())
		if principalErr != nil {
			return Digest{}, principalErr
		}
		subject.Principal = &principal
		if draft.subject.hasDevice {
			device, deviceErr := NewCanonicalIdentifier(draft.subject.device.String())
			if deviceErr != nil {
				return Digest{}, deviceErr
			}
			subject.Device = &device
		}
	case DenialUnattributedSource:
		source, sourceErr := CanonicalDigestFromDigest(draft.subject.source)
		if sourceErr != nil {
			return Digest{}, sourceErr
		}
		subject.SourceHash = &source
	default:
		return Digest{}, ErrCanonicalProfile
	}
	var policy *string
	if draft.hasPolicy {
		value := draft.policy.String()
		policy = &value
	}
	view := commandDenialHashViewV1{
		ScopeKind: string(scope.Kind()), ScopeID: scopeID, AuthorityID: authority,
		AuthorityEpoch: authorityEpoch, Admission: admission.Uint64(), Operation: draft.operation.String(),
		OperationMajor: draft.operationMajor.Uint16(), Class: draft.class, Reason: draft.reason,
		RequestFingerprint: request, Subject: subject, PolicyRevision: policy, CorrelationID: correlation,
	}
	return NewProductionCanonicalCodec().HashCommandDenial(view)
}

func (spec SecuritySpec) Operation() SecurityOperation          { return spec.operation }
func (spec SecuritySpec) Scope() domain.AuthorityScope          { return spec.scope }
func (spec SecuritySpec) AuthorityID() domain.AuthorityID       { return spec.authorityID }
func (spec SecuritySpec) AuthorityEpoch() domain.AuthorityEpoch { return spec.epoch }
func (spec SecuritySpec) AdmissionGeneration() GuardGeneration  { return spec.admission }
func (spec SecuritySpec) InvitationExpectation() (domain.AggregateExpectation, bool) {
	return spec.invitation, !spec.invitation.Target().IsZero()
}
func (spec SecuritySpec) AttemptFingerprint() (domain.CommandFingerprint, bool) {
	return spec.attempt, spec.operation == SecurityRecordBootstrapDenial
}
func (spec SecuritySpec) Generations() (domain.BootstrapGenerationID, domain.BootstrapGenerationID, bool) {
	return spec.oldGeneration, spec.newGeneration,
		spec.operation == SecurityRotateBootstrapGeneration || spec.operation == SecurityResumeBootstrapGeneration
}
func (spec SecuritySpec) ResumeApproval() (domain.CommandFingerprint, bool) {
	return spec.resumeApproval, spec.operation == SecurityResumeBootstrapGeneration
}
func (spec SecuritySpec) InitialInvitation() (domain.InstallationInvitationState, bool) {
	return spec.initialState, spec.operation == SecurityInitializeInstallation
}
func (spec SecuritySpec) InitializationGuard() (Digest, bool) {
	return spec.initialization, spec.operation == SecurityInitializeInstallation
}
func (spec SecuritySpec) CommandDenial() (CommandDenialDraft, bool) {
	return spec.commandDenial, spec.operation == SecurityRecordCommandDenial
}
func (spec SecuritySpec) RequiresReservedAdmission() bool {
	return spec.operation == SecurityRecordBootstrapDenial || spec.operation == SecurityRecordCommandDenial
}

type SecurityAttemptResolutionKind string

const (
	SecurityAttemptFresh  SecurityAttemptResolutionKind = "fresh"
	SecurityAttemptReplay SecurityAttemptResolutionKind = "replay"
)

type DenialAdmissionKind string

const (
	DenialAdmitDistinct          DenialAdmissionKind = "admit_distinct"
	DenialAdmitSaturation        DenialAdmissionKind = "admit_saturation_summary"
	DenialAdmitScopeSaturation   DenialAdmissionKind = "admit_scope_saturation_summary"
	DenialSuppressDuplicate      DenialAdmissionKind = "suppress_duplicate"
	DenialSuppressSaturated      DenialAdmissionKind = "suppress_saturated"
	DenialSuppressScopeSaturated DenialAdmissionKind = "suppress_scope_saturated"
)

type DenialAdmission struct {
	kind              DenialAdmissionKind
	bucket            int64
	priorDistinct     uint8
	priorScopeEntries uint16
}

func NewDenialAdmission(
	kind DenialAdmissionKind,
	authorityTime time.Time,
	priorDistinct uint8,
	priorScopeEntries uint16,
) (DenialAdmission, error) {
	bucket := authorityTime.UTC().Unix() / 60
	if authorityTime.IsZero() || authorityTime.UTC().Unix() < 0 || bucket < 0 || uint64(bucket) > MaxCanonicalInteger ||
		priorDistinct > MaxDistinctDenialsPerMinute ||
		priorScopeEntries > MaxDenialEntriesPerScopeMinute {
		return DenialAdmission{}, ErrInvalidSecurityContext
	}
	switch kind {
	case DenialAdmitDistinct:
		if priorDistinct >= MaxDistinctDenialsPerMinute || priorScopeEntries >= MaxDenialEntriesPerScopeMinute {
			return DenialAdmission{}, ErrInvalidSecurityContext
		}
	case DenialAdmitSaturation:
		if priorDistinct != MaxDistinctDenialsPerMinute || priorScopeEntries >= MaxDenialEntriesPerScopeMinute {
			return DenialAdmission{}, ErrInvalidSecurityContext
		}
	case DenialAdmitScopeSaturation:
		if priorScopeEntries != MaxDenialEntriesPerScopeMinute {
			return DenialAdmission{}, ErrInvalidSecurityContext
		}
	case DenialSuppressDuplicate:
	case DenialSuppressSaturated:
		if priorDistinct != MaxDistinctDenialsPerMinute {
			return DenialAdmission{}, ErrInvalidSecurityContext
		}
	case DenialSuppressScopeSaturated:
		if priorScopeEntries != MaxDenialEntriesPerScopeMinute {
			return DenialAdmission{}, ErrInvalidSecurityContext
		}
	default:
		return DenialAdmission{}, ErrInvalidSecurityContext
	}
	return DenialAdmission{
		kind: kind, bucket: bucket,
		priorDistinct: priorDistinct, priorScopeEntries: priorScopeEntries,
	}, nil
}

func (admission DenialAdmission) Kind() DenialAdmissionKind { return admission.kind }
func (admission DenialAdmission) MinuteBucket() int64       { return admission.bucket }
func (admission DenialAdmission) PriorDistinct() uint8      { return admission.priorDistinct }
func (admission DenialAdmission) PriorScopeEntries() uint16 { return admission.priorScopeEntries }

type SecurityDenialRecord struct {
	invitation domain.InvitationID
	attempt    domain.CommandFingerprint
	version    domain.Version
	deniedAt   time.Time
}

func NewSecurityDenialRecord(
	invitation domain.InvitationID,
	attempt domain.CommandFingerprint,
	version domain.Version,
	deniedAt time.Time,
) (SecurityDenialRecord, error) {
	if invitation.IsZero() || attempt.IsZero() || version.IsZero() ||
		version.Uint64() > MaxCanonicalInteger || deniedAt.IsZero() {
		return SecurityDenialRecord{}, ErrInvalidSecurityContext
	}
	return SecurityDenialRecord{
		invitation: invitation, attempt: attempt, version: version, deniedAt: deniedAt.UTC(),
	}, nil
}

func (record SecurityDenialRecord) InvitationID() domain.InvitationID { return record.invitation }
func (record SecurityDenialRecord) AttemptFingerprint() domain.CommandFingerprint {
	return record.attempt
}
func (record SecurityDenialRecord) InvitationVersion() domain.Version { return record.version }
func (record SecurityDenialRecord) DeniedAt() time.Time               { return record.deniedAt }

type SecurityAttemptResolution struct {
	kind   SecurityAttemptResolutionKind
	record SecurityDenialRecord
}

func FreshSecurityAttempt() SecurityAttemptResolution {
	return SecurityAttemptResolution{kind: SecurityAttemptFresh}
}

func ReplaySecurityAttempt(record SecurityDenialRecord) (SecurityAttemptResolution, error) {
	if record.invitation.IsZero() {
		return SecurityAttemptResolution{}, ErrInvalidSecurityContext
	}
	return SecurityAttemptResolution{kind: SecurityAttemptReplay, record: record}, nil
}

func (resolution SecurityAttemptResolution) Kind() SecurityAttemptResolutionKind {
	return resolution.kind
}
func (resolution SecurityAttemptResolution) Record() (SecurityDenialRecord, bool) {
	return resolution.record, resolution.kind == SecurityAttemptReplay
}

type SecurityContext struct {
	spec            SecuritySpec
	authorityTime   time.Time
	invitation      domain.InstallationInvitationState
	attempt         SecurityAttemptResolution
	denialAdmission DenialAdmission
	guardDigest     domain.AuthorizationDigest
}

func NewSecurityContext(
	spec SecuritySpec,
	authorityTime time.Time,
	invitation domain.InstallationInvitationState,
	attempt SecurityAttemptResolution,
	denialAdmission DenialAdmission,
	guardDigest domain.AuthorizationDigest,
) (SecurityContext, error) {
	if spec.operation == "" || authorityTime.IsZero() || guardDigest.IsZero() {
		return SecurityContext{}, ErrInvalidSecurityContext
	}
	requestBound := spec.operation == SecurityRecordBootstrapDenial || spec.operation == SecurityRecordCommandDenial
	if requestBound != spec.hasAuditContext ||
		(spec.hasAuditContext && (!validAuditRequestContext(spec.auditRequest) ||
			!validAuditProvenanceEvidence(spec.provenance))) {
		return SecurityContext{}, ErrInvalidSecurityContext
	}
	if spec.operation == SecurityRecordBootstrapDenial || spec.operation == SecurityResumeBootstrapGeneration {
		version, _ := spec.invitation.Version()
		if invitation.IsZero() || invitation.ID().String() != spec.invitation.Target().ID() ||
			invitation.InstallationID().String() != spec.scope.ID() {
			return SecurityContext{}, ErrInvalidSecurityContext
		}
		if spec.operation == SecurityResumeBootstrapGeneration && invitation.Version() != version {
			return SecurityContext{}, ErrInvalidSecurityContext
		}
	}
	if (spec.operation == SecurityInitializeInstallation ||
		spec.operation == SecurityRotateBootstrapGeneration ||
		spec.operation == SecurityRecordCommandDenial) && !invitation.IsZero() {
		return SecurityContext{}, ErrInvalidSecurityContext
	}
	if spec.operation == SecurityRecordBootstrapDenial {
		switch attempt.kind {
		case SecurityAttemptFresh:
			version, _ := spec.invitation.Version()
			if invitation.Version() != version {
				return SecurityContext{}, ErrInvalidSecurityContext
			}
		case SecurityAttemptReplay:
			if attempt.record.invitation != invitation.ID() || attempt.record.attempt != spec.attempt ||
				invitation.Version().Uint64() < attempt.record.version.Uint64() {
				return SecurityContext{}, ErrInvalidSecurityContext
			}
		default:
			return SecurityContext{}, ErrInvalidSecurityContext
		}
	} else if attempt.kind != "" {
		return SecurityContext{}, ErrInvalidSecurityContext
	}
	if spec.operation == SecurityRecordCommandDenial {
		if denialAdmission.kind == "" || denialAdmission.bucket != authorityTime.UTC().Unix()/60 {
			return SecurityContext{}, ErrInvalidSecurityContext
		}
	} else if denialAdmission.kind != "" {
		return SecurityContext{}, ErrInvalidSecurityContext
	}
	return SecurityContext{
		spec: spec, authorityTime: authorityTime.UTC(), invitation: invitation,
		attempt: attempt, denialAdmission: denialAdmission, guardDigest: guardDigest,
	}, nil
}

func (securityContext SecurityContext) Spec() SecuritySpec { return securityContext.spec }
func (securityContext SecurityContext) AuthorityTime() time.Time {
	return securityContext.authorityTime
}
func (securityContext SecurityContext) Invitation() domain.InstallationInvitationState {
	return securityContext.invitation
}
func (securityContext SecurityContext) AttemptResolution() SecurityAttemptResolution {
	return securityContext.attempt
}
func (securityContext SecurityContext) DenialAdmission() (DenialAdmission, bool) {
	return securityContext.denialAdmission, securityContext.spec.operation == SecurityRecordCommandDenial
}
func (securityContext SecurityContext) GuardDigest() domain.AuthorizationDigest {
	return securityContext.guardDigest
}

type SecurityDecisionKind string

const (
	SecurityDecisionInitialize     SecurityDecisionKind = "initialize"
	SecurityDecisionGeneration     SecurityDecisionKind = "generation"
	SecurityDecisionDeny           SecurityDecisionKind = "deny"
	SecurityDecisionAuditDenial    SecurityDecisionKind = "audit_denial"
	SecurityDecisionSuppressDenial SecurityDecisionKind = "suppress_denial"
	SecurityDecisionReplay         SecurityDecisionKind = "replay"
	SecurityDecisionRollback       SecurityDecisionKind = "rollback"
)

type SecurityDecision struct {
	kind               SecurityDecisionKind
	invitation         domain.InstallationInvitationState
	oldGeneration      domain.BootstrapGenerationID
	newGeneration      domain.BootstrapGenerationID
	denial             SecurityDenialRecord
	audit              AuditIntent
	commandDenialAudit CommandDenialAuditRecord
	rejection          *domain.CommandError
}

type CommandDenialAuditVariant string

const (
	CommandDenialAuditDetail            CommandDenialAuditVariant = "detail"
	CommandDenialAuditSubjectSaturation CommandDenialAuditVariant = "subject_saturation"
	CommandDenialAuditScopeSaturation   CommandDenialAuditVariant = "scope_saturation"
)

type CommandDenialAuditRecord struct {
	variant CommandDenialAuditVariant
	draft   CommandDenialDraft
	bucket  int64
}

func (record CommandDenialAuditRecord) Variant() CommandDenialAuditVariant { return record.variant }
func (record CommandDenialAuditRecord) Draft() CommandDenialDraft          { return record.draft }
func (record CommandDenialAuditRecord) MinuteBucket() int64                { return record.bucket }

func InitializeSecurity(
	securityContext SecurityContext,
	audit AuditIntent,
) (SecurityDecision, error) {
	if securityContext.spec.operation != SecurityInitializeInstallation ||
		audit.outcome != AuditSecurityMutation || securityContext.spec.initialState.IsZero() ||
		!auditMatchesSecuritySpec(audit, securityContext.spec) {
		return SecurityDecision{}, ErrInvalidSecurityDecision
	}
	audit, err := finalizeSecurityAudit(audit, securityContext, auditResources([]domain.AggregateExpectation{
		securityContext.spec.invitation,
	}))
	if err != nil {
		return SecurityDecision{}, err
	}
	return SecurityDecision{
		kind: SecurityDecisionInitialize, invitation: securityContext.spec.initialState, audit: audit,
	}, nil
}

func ChangeBootstrapGenerationSecurity(
	securityContext SecurityContext,
	audit AuditIntent,
) (SecurityDecision, error) {
	if (securityContext.spec.operation != SecurityRotateBootstrapGeneration &&
		securityContext.spec.operation != SecurityResumeBootstrapGeneration) ||
		audit.outcome != AuditSecurityMutation || !auditMatchesSecuritySpec(audit, securityContext.spec) ||
		securityContext.spec.oldGeneration.IsZero() ||
		securityContext.spec.newGeneration.IsZero() {
		return SecurityDecision{}, ErrInvalidSecurityDecision
	}
	audit, err := finalizeSecurityAudit(audit, securityContext, nil)
	if err != nil {
		return SecurityDecision{}, err
	}
	return SecurityDecision{
		kind: SecurityDecisionGeneration, oldGeneration: securityContext.spec.oldGeneration,
		newGeneration: securityContext.spec.newGeneration, audit: audit,
	}, nil
}

func DenyBootstrapSecurity(
	securityContext SecurityContext,
	invitation domain.InstallationInvitationState,
	audit AuditIntent,
) (SecurityDecision, error) {
	if securityContext.spec.operation != SecurityRecordBootstrapDenial ||
		securityContext.attempt.kind != SecurityAttemptFresh || audit.outcome != AuditSecurityDenied ||
		!auditMatchesSecuritySpec(audit, securityContext.spec) ||
		!validDeniedInvitationTransition(securityContext.invitation, invitation) {
		return SecurityDecision{}, ErrInvalidSecurityDecision
	}
	record, err := NewSecurityDenialRecord(
		invitation.ID(), securityContext.spec.attempt, invitation.Version(), securityContext.authorityTime,
	)
	if err != nil {
		return SecurityDecision{}, ErrInvalidSecurityDecision
	}
	audit, err = finalizeSecurityAudit(audit, securityContext, []AuditResourceVersion{{
		target: securityContext.spec.invitation.Target(), before: securityContext.invitation.Version(), hasBefore: true,
		after: invitation.Version(), hasAfter: true,
	}})
	if err != nil {
		return SecurityDecision{}, err
	}
	return SecurityDecision{
		kind: SecurityDecisionDeny, invitation: invitation, denial: record, audit: audit,
	}, nil
}

func validDeniedInvitationTransition(
	prior domain.InstallationInvitationState,
	next domain.InstallationInvitationState,
) bool {
	if prior.IsZero() || next.IsZero() || prior.Status() != domain.InstallationInvitationPending ||
		prior.ID() != next.ID() || prior.InstallationID() != next.InstallationID() ||
		prior.InstallationPublicKey() != next.InstallationPublicKey() ||
		prior.InvitationVerifier() != next.InvitationVerifier() ||
		prior.BootstrapGenerationID() != next.BootstrapGenerationID() ||
		!prior.ExpiresAt().Equal(next.ExpiresAt()) || next.FailedAttempts() != prior.FailedAttempts()+1 {
		return false
	}
	nextVersion, err := prior.Version().Next()
	if err != nil || next.Version() != nextVersion {
		return false
	}
	wantStatus := domain.InstallationInvitationPending
	if next.FailedAttempts() >= domain.MaxBootstrapFailedAttempts {
		wantStatus = domain.InstallationInvitationExhausted
	}
	return next.Status() == wantStatus
}

func ReplayBootstrapDenialSecurity(securityContext SecurityContext) (SecurityDecision, error) {
	record, replay := securityContext.attempt.Record()
	if securityContext.spec.operation != SecurityRecordBootstrapDenial || !replay {
		return SecurityDecision{}, ErrInvalidSecurityDecision
	}
	return SecurityDecision{kind: SecurityDecisionReplay, denial: record}, nil
}

func AuditCommandDenialSecurity(
	securityContext SecurityContext,
	audit AuditIntent,
) (SecurityDecision, error) {
	if securityContext.spec.operation != SecurityRecordCommandDenial ||
		(securityContext.denialAdmission.kind != DenialAdmitDistinct &&
			securityContext.denialAdmission.kind != DenialAdmitSaturation &&
			securityContext.denialAdmission.kind != DenialAdmitScopeSaturation) ||
		audit.outcome != AuditSecurityDenied ||
		!auditMatchesSecuritySpec(audit, securityContext.spec) {
		return SecurityDecision{}, ErrInvalidSecurityDecision
	}
	var err error
	audit, err = finalizeSecurityAudit(audit, securityContext, nil)
	if err != nil {
		return SecurityDecision{}, err
	}
	variant := CommandDenialAuditDetail
	switch securityContext.denialAdmission.kind {
	case DenialAdmitSaturation:
		variant = CommandDenialAuditSubjectSaturation
	case DenialAdmitScopeSaturation:
		variant = CommandDenialAuditScopeSaturation
	}
	return SecurityDecision{
		kind: SecurityDecisionAuditDenial, audit: audit,
		commandDenialAudit: CommandDenialAuditRecord{
			variant: variant, draft: securityContext.spec.commandDenial,
			bucket: securityContext.denialAdmission.bucket,
		},
	}, nil
}

func auditMatchesSecuritySpec(audit AuditIntent, spec SecuritySpec) bool {
	operation, fingerprint, ok := ExpectedSecurityAudit(spec)
	return ok && audit.operation.String() == operation && audit.fingerprint == fingerprint
}

func finalizeSecurityAudit(
	seed AuditIntent,
	securityContext SecurityContext,
	resources []AuditResourceVersion,
) (AuditIntent, error) {
	spec := securityContext.spec
	if seed.finalized || !auditMatchesSecuritySpec(seed, spec) || securityContext.authorityTime.IsZero() ||
		(seed.outcome != AuditSecurityMutation && seed.outcome != AuditSecurityDenied) {
		return AuditIntent{}, ErrInvalidSecurityDecision
	}
	seed.invocation = AuditInvocation{kind: AuditInvocationSecurity, securityOperation: spec.operation}
	seed.timing.persistedAuthorityTime = securityContext.authorityTime.UTC()
	seed.provenance = AuditProvenance{sourceAuthority: spec.authorityID}
	if spec.hasAuditContext {
		seed.invocation.requestID = &spec.auditRequest.requestID
		seed.invocation.traceID = &spec.auditRequest.traceID
		seed.timing.serverReceivedTime = ptrTime(spec.auditRequest.serverReceived)
		if spec.auditRequest.hasClientTime {
			seed.timing.clientTime = ptrTime(spec.auditRequest.clientTime)
		}
		seed.provenance = AuditProvenance{
			sourceAuthority:    spec.provenance.sourceAuthority,
			federationEnvelope: cloneCanonicalIdentifier(spec.provenance.federationEnvelope),
		}
	}
	seed.authorization = AuditAuthorization{
		guardDigest: securityContext.guardDigest, admissionGeneration: spec.admission,
	}
	seed.resources = append([]AuditResourceVersion(nil), resources...)
	switch spec.operation {
	case SecurityInitializeInstallation:
		seed.subject = AuditSubject{kind: AuditSubjectUnattributed, unattributed: spec.initialization}
	case SecurityRotateBootstrapGeneration, SecurityResumeBootstrapGeneration:
		seed.subject = AuditSubject{
			kind: AuditSubjectUnattributed, unattributed: Digest(securityGenerationFingerprint(spec)),
		}
		seed.authorization.oldGeneration = spec.oldGeneration
		seed.authorization.newGeneration = spec.newGeneration
		seed.authorization.hasGenerationChange = true
		if spec.operation == SecurityResumeBootstrapGeneration {
			seed.approvalEvidence = []Digest{Digest(spec.resumeApproval)}
		}
	case SecurityRecordBootstrapDenial:
		if !spec.hasAuditContext {
			return AuditIntent{}, ErrInvalidSecurityDecision
		}
		seed.subject = AuditSubject{kind: AuditSubjectUnattributed, unattributed: Digest(spec.attempt)}
	case SecurityRecordCommandDenial:
		if !spec.hasAuditContext {
			return AuditIntent{}, ErrInvalidSecurityDecision
		}
		draft := spec.commandDenial
		trace, err := NewCanonicalIdentifier(draft.correlation.String())
		if err != nil {
			return AuditIntent{}, ErrInvalidSecurityDecision
		}
		seed.invocation.correlationID = &trace
		if draft.hasPolicy {
			seed.authorization.policy, seed.authorization.hasPolicy = draft.policy, true
		}
		switch draft.subject.kind {
		case DenialAttributedSubject:
			seed.subject = AuditSubject{
				kind: AuditSubjectAttributed, principal: draft.subject.principal,
				device: draft.subject.device, hasDevice: draft.subject.hasDevice,
			}
		case DenialUnattributedSource:
			seed.subject = AuditSubject{kind: AuditSubjectUnattributed, unattributed: draft.subject.source}
		default:
			return AuditIntent{}, ErrInvalidSecurityDecision
		}
	default:
		return AuditIntent{}, ErrInvalidSecurityDecision
	}
	if seed.subject.kind == "" || seed.authorization.guardDigest.IsZero() {
		return AuditIntent{}, ErrInvalidSecurityDecision
	}
	seed.finalized = true
	return seed, nil
}

func ptrTime(value time.Time) *time.Time {
	copy := value
	return &copy
}

func cloneCanonicalIdentifier(value *CanonicalIdentifier) *CanonicalIdentifier {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

// ExpectedSecurityAudit returns the only operation/fingerprint pair accepted
// for a closed security specification.
func ExpectedSecurityAudit(spec SecuritySpec) (string, domain.CommandFingerprint, bool) {
	switch spec.operation {
	case SecurityInitializeInstallation:
		return "installation.initialize.v1", domain.CommandFingerprint(spec.initialization), !spec.initialization.IsZero()
	case SecurityRotateBootstrapGeneration:
		return "installation.bootstrap_generation.rotate.v1", securityGenerationFingerprint(spec), true
	case SecurityResumeBootstrapGeneration:
		return "installation.bootstrap_generation.resume.v1", securityGenerationFingerprint(spec), true
	case SecurityRecordBootstrapDenial:
		return "installation.bootstrap.v1", spec.attempt, !spec.attempt.IsZero()
	case SecurityRecordCommandDenial:
		return spec.commandDenial.operation.String(), spec.commandDenial.requestFingerprint,
			spec.commandDenial.operation.String() != "" && !spec.commandDenial.requestFingerprint.IsZero()
	default:
		return "", domain.CommandFingerprint{}, false
	}
}

func securityGenerationFingerprint(spec SecuritySpec) domain.CommandFingerprint {
	material := "blackbird.bootstrap-generation-security/v1\x00" + string(spec.operation) + "\x00" +
		spec.scope.ID() + "\x00" + spec.authorityID.String() + "\x00" + spec.epoch.String() + "\x00" +
		spec.oldGeneration.String() + "\x00" + spec.newGeneration.String() + "\x00"
	if spec.operation == SecurityResumeBootstrapGeneration {
		material += spec.invitation.Target().String() + "\x00" + spec.resumeApprovalString()
	}
	return domain.FingerprintCommand([]byte(material))
}

func (spec SecuritySpec) resumeApprovalString() string {
	return hex.EncodeToString(spec.resumeApproval[:])
}

func SuppressCommandDenialSecurity(securityContext SecurityContext) (SecurityDecision, error) {
	if securityContext.spec.operation != SecurityRecordCommandDenial ||
		(securityContext.denialAdmission.kind != DenialSuppressDuplicate &&
			securityContext.denialAdmission.kind != DenialSuppressSaturated &&
			securityContext.denialAdmission.kind != DenialSuppressScopeSaturated) {
		return SecurityDecision{}, ErrInvalidSecurityDecision
	}
	return SecurityDecision{kind: SecurityDecisionSuppressDenial}, nil
}

func RollbackSecurity(
	securityContext SecurityContext,
	rejection *domain.CommandError,
) (SecurityDecision, error) {
	if securityContext.spec.operation == "" || rejection == nil {
		return SecurityDecision{}, ErrInvalidSecurityDecision
	}
	return SecurityDecision{kind: SecurityDecisionRollback, rejection: rejection}, nil
}

func (decision SecurityDecision) Kind() SecurityDecisionKind { return decision.kind }
func (decision SecurityDecision) Invitation() (domain.InstallationInvitationState, bool) {
	return decision.invitation,
		decision.kind == SecurityDecisionInitialize || decision.kind == SecurityDecisionDeny
}
func (decision SecurityDecision) Generations() (
	domain.BootstrapGenerationID,
	domain.BootstrapGenerationID,
	bool,
) {
	return decision.oldGeneration, decision.newGeneration, decision.kind == SecurityDecisionGeneration
}
func (decision SecurityDecision) Denial() (SecurityDenialRecord, bool) {
	return decision.denial, decision.kind == SecurityDecisionDeny || decision.kind == SecurityDecisionReplay
}
func (decision SecurityDecision) Audit() (AuditIntent, bool) {
	return decision.audit, decision.kind != SecurityDecisionReplay &&
		decision.kind != SecurityDecisionSuppressDenial && decision.kind != SecurityDecisionRollback
}
func (decision SecurityDecision) CommandDenialAudit() (CommandDenialAuditRecord, bool) {
	return decision.commandDenialAudit, decision.kind == SecurityDecisionAuditDenial
}
func (decision SecurityDecision) Rejection() (*domain.CommandError, bool) {
	return decision.rejection, decision.kind == SecurityDecisionRollback
}

// ValidateSecurityDecision proves that a callback decision was constructed
// from this exact locked context without exposing private audit bindings to a
// storage adapter.
func ValidateSecurityDecision(locked SecurityContext, decision SecurityDecision) error {
	seed := AuditIntent{
		operation: decision.audit.operation, outcome: decision.audit.outcome,
		fingerprint: decision.audit.fingerprint, detail: decision.audit.detail,
	}
	var (
		expected SecurityDecision
		err      error
	)
	switch decision.kind {
	case SecurityDecisionInitialize:
		expected, err = InitializeSecurity(locked, seed)
	case SecurityDecisionGeneration:
		expected, err = ChangeBootstrapGenerationSecurity(locked, seed)
	case SecurityDecisionDeny:
		expected, err = DenyBootstrapSecurity(locked, decision.invitation, seed)
	case SecurityDecisionAuditDenial:
		expected, err = AuditCommandDenialSecurity(locked, seed)
	case SecurityDecisionSuppressDenial:
		expected, err = SuppressCommandDenialSecurity(locked)
	case SecurityDecisionReplay:
		expected, err = ReplayBootstrapDenialSecurity(locked)
	case SecurityDecisionRollback:
		expected, err = RollbackSecurity(locked, decision.rejection)
	default:
		err = ErrInvalidSecurityDecision
	}
	if err != nil || !reflect.DeepEqual(expected, decision) {
		return ErrInvalidSecurityDecision
	}
	return nil
}

type SecurityExecutionKind string

const (
	SecurityApplied                 SecurityExecutionKind = "applied"
	SecurityDenialCommitted         SecurityExecutionKind = "denial_committed"
	SecurityDenialReplayed          SecurityExecutionKind = "denial_replay"
	SecurityCommandDenialAudited    SecurityExecutionKind = "command_denial_audited"
	SecurityCommandDenialSuppressed SecurityExecutionKind = "command_denial_suppressed"
	SecurityRejected                SecurityExecutionKind = "rejected"
	SecurityIndeterminate           SecurityExecutionKind = "indeterminate"
)

type SecurityExecution struct {
	kind      SecurityExecutionKind
	operation SecurityOperation
	denial    SecurityDenialRecord
	rejection *domain.CommandError
}

func AppliedSecurityExecution(operation SecurityOperation) (SecurityExecution, error) {
	if operation != SecurityInitializeInstallation && operation != SecurityRotateBootstrapGeneration &&
		operation != SecurityResumeBootstrapGeneration {
		return SecurityExecution{}, ErrInvalidSecurityExecution
	}
	return SecurityExecution{kind: SecurityApplied, operation: operation}, nil
}

func CommittedDenialSecurityExecution(record SecurityDenialRecord) (SecurityExecution, error) {
	if record.invitation.IsZero() {
		return SecurityExecution{}, ErrInvalidSecurityExecution
	}
	return SecurityExecution{
		kind: SecurityDenialCommitted, operation: SecurityRecordBootstrapDenial, denial: record,
	}, nil
}

func ReplayedDenialSecurityExecution(record SecurityDenialRecord) (SecurityExecution, error) {
	if record.invitation.IsZero() {
		return SecurityExecution{}, ErrInvalidSecurityExecution
	}
	return SecurityExecution{
		kind: SecurityDenialReplayed, operation: SecurityRecordBootstrapDenial, denial: record,
	}, nil
}

func CommandDenialSecurityExecution(audited bool) SecurityExecution {
	if audited {
		return SecurityExecution{kind: SecurityCommandDenialAudited, operation: SecurityRecordCommandDenial}
	}
	return SecurityExecution{kind: SecurityCommandDenialSuppressed, operation: SecurityRecordCommandDenial}
}

func RejectedSecurityExecution(
	operation SecurityOperation,
	rejection *domain.CommandError,
) (SecurityExecution, error) {
	if !operation.Valid() || rejection == nil {
		return SecurityExecution{}, ErrInvalidSecurityExecution
	}
	return SecurityExecution{kind: SecurityRejected, operation: operation, rejection: rejection}, nil
}

func IndeterminateSecurityExecution(operation SecurityOperation) (SecurityExecution, error) {
	if !operation.Valid() {
		return SecurityExecution{}, ErrInvalidSecurityExecution
	}
	return SecurityExecution{kind: SecurityIndeterminate, operation: operation}, nil
}

func (operation SecurityOperation) Valid() bool {
	switch operation {
	case SecurityInitializeInstallation, SecurityRotateBootstrapGeneration,
		SecurityResumeBootstrapGeneration, SecurityRecordBootstrapDenial, SecurityRecordCommandDenial:
		return true
	default:
		return false
	}
}

// ValidateSecurityExecutionResult applies the same unambiguous error matrix as
// command transactions while requiring every outcome to retain its operation.
func ValidateSecurityExecutionResult(execution SecurityExecution, executionErr error) error {
	if execution.kind == "" {
		var rejection *domain.CommandError
		if executionErr != nil && !errors.As(executionErr, &rejection) {
			return nil
		}
		return ErrInvalidSecurityExecution
	}
	if !execution.operation.Valid() {
		return ErrInvalidSecurityExecution
	}
	if execution.kind == SecurityIndeterminate {
		if executionErr != nil || !securityDenialRecordZero(execution.denial) || execution.rejection != nil {
			return ErrInvalidSecurityExecution
		}
		return nil
	}
	if executionErr != nil {
		return ErrInvalidSecurityExecution
	}
	switch execution.kind {
	case SecurityApplied:
		if execution.operation != SecurityInitializeInstallation &&
			execution.operation != SecurityRotateBootstrapGeneration &&
			execution.operation != SecurityResumeBootstrapGeneration ||
			!securityDenialRecordZero(execution.denial) || execution.rejection != nil {
			return ErrInvalidSecurityExecution
		}
	case SecurityDenialCommitted, SecurityDenialReplayed:
		if execution.operation != SecurityRecordBootstrapDenial || execution.denial.invitation.IsZero() ||
			execution.rejection != nil {
			return ErrInvalidSecurityExecution
		}
	case SecurityCommandDenialAudited, SecurityCommandDenialSuppressed:
		if execution.operation != SecurityRecordCommandDenial ||
			!securityDenialRecordZero(execution.denial) || execution.rejection != nil {
			return ErrInvalidSecurityExecution
		}
	case SecurityRejected:
		if execution.rejection == nil || !securityDenialRecordZero(execution.denial) {
			return ErrInvalidSecurityExecution
		}
	default:
		return ErrInvalidSecurityExecution
	}
	return nil
}

func securityDenialRecordZero(record SecurityDenialRecord) bool {
	return record.invitation.IsZero() && record.attempt.IsZero() && record.version.IsZero() && record.deniedAt.IsZero()
}

func (execution SecurityExecution) Kind() SecurityExecutionKind  { return execution.kind }
func (execution SecurityExecution) Operation() SecurityOperation { return execution.operation }
func (execution SecurityExecution) Denial() (SecurityDenialRecord, bool) {
	return execution.denial,
		execution.kind == SecurityDenialCommitted || execution.kind == SecurityDenialReplayed
}
func (execution SecurityExecution) Rejection() (*domain.CommandError, bool) {
	return execution.rejection, execution.kind == SecurityRejected
}

// ProofDecision keeps an expected cryptographic rejection in data. Operational
// verifier failure is the only failure returned as error.
type ProofDecisionKind string

const (
	ProofValid                     ProofDecisionKind = "valid"
	ProofCryptographicallyRejected ProofDecisionKind = "cryptographically_rejected"
)

type ProofDecision[Verified any] struct {
	kind     ProofDecisionKind
	verified Verified
}

func ValidProof[Verified any](verified Verified) ProofDecision[Verified] {
	value := reflect.ValueOf(verified)
	if !value.IsValid() || ((value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface ||
		value.Kind() == reflect.Map || value.Kind() == reflect.Slice || value.Kind() == reflect.Func ||
		value.Kind() == reflect.Chan) && value.IsNil()) || value.IsZero() {
		return ProofDecision[Verified]{}
	}
	return ProofDecision[Verified]{kind: ProofValid, verified: verified}
}

func CryptographicallyRejectedProof[Verified any]() ProofDecision[Verified] {
	return ProofDecision[Verified]{kind: ProofCryptographicallyRejected}
}

func (decision ProofDecision[Verified]) Kind() ProofDecisionKind { return decision.kind }
func (decision ProofDecision[Verified]) Verified() (Verified, bool) {
	return decision.verified, decision.kind == ProofValid
}

type ProofVerifier[Evidence, Verified any] interface {
	Verify(context.Context, Evidence) (ProofDecision[Verified], error)
}

// IDSource allocates all identifiers before transaction entry. Stable resource
// identifiers remain command input; these methods cover UoW-owned journal IDs.
type IDSource interface {
	NewReceiptID() (domain.ReceiptID, error)
	NewEventID() (domain.EventID, error)
}

// AuthorityTimeSource is implemented inside a storage UoW and may be invoked
// only after the authority stream is locked. Application handlers receive its
// result through CommandContext/SecurityContext, never this port directly.
type AuthorityTimeSource interface {
	LockedAuthorityTime(context.Context, domain.AuthorityScope, domain.AuthorityEpoch) (time.Time, error)
}

type EffectPlanningInput struct {
	commandID domain.CommandID
	facts     []FactIntent
}

func NewEffectPlanningInput(
	commandID domain.CommandID,
	facts []FactIntent,
) (EffectPlanningInput, error) {
	if commandID.IsZero() || len(facts) == 0 || len(facts) > MaxCommandFacts {
		return EffectPlanningInput{}, ErrInvalidApplicationContract
	}
	return EffectPlanningInput{commandID: commandID, facts: append([]FactIntent(nil), facts...)}, nil
}

func (input EffectPlanningInput) CommandID() domain.CommandID { return input.commandID }
func (input EffectPlanningInput) Facts() []FactIntent {
	return append([]FactIntent(nil), input.facts...)
}

// EffectPlanner is intentionally context-free: planning is pure, bounded, and
// cannot perform provider I/O.
type EffectPlanner interface {
	PlanEffects(EffectPlanningInput) (EffectSet, error)
}

// CanonicalCodec owns typed RFC 8785 bytes. Implementations must validate the
// schema both before and after canonical transformation.
type CanonicalCodec[Value any] interface {
	EncodeCanonical(Value) ([]byte, error)
}

// EventAuditVerifier is the production composition seam. Storage must use the
// reviewed implementation for every event and audit entry; application tests
// may record calls but cannot weaken domain.EventEnvelope construction.
type EventAuditVerifier interface {
	domain.EventDigestVerifier
	VerifyAuditEntry(previous Digest, canonicalEntry []byte, expected Digest) error
}
