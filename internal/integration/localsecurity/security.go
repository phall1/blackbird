// Package localsecurity implements the credential-vault and cryptographic
// boundary for Blackbird's local pairing profile.
package localsecurity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/lexfrei/keychain"
	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	pairingExporterLabel    = "EXPORTER-Blackbird-Pair-v1"
	sessionExporterLabel    = "EXPORTER-Blackbird-Session-v1"
	transcriptDomain        = "blackbird-pairing-transcript/v1"
	bindingSize             = 32
	credentialService       = "com.phall1.blackbird.credentials.v1"
	credentialIDMaxBytes    = 128
	maxTransportAccessTTL   = 15 * time.Minute
	maxPairingInvitationTTL = 5 * time.Minute
	maxPairingAttempts      = 5
	proofEvidenceVersion    = 1
	maxProofEvidenceBytes   = 16 * 1024
	maxProofNonceBytes      = 64
)

var (
	ErrInvalidKeyMaterial  = errors.New("invalid Ed25519 key material")
	ErrInvalidCertificate  = errors.New("invalid local certificate")
	ErrInvalidPin          = errors.New("invalid peer SPKI pin")
	ErrPeerVerification    = errors.New("pinned TLS peer verification failed")
	ErrExporter            = errors.New("TLS exporter unavailable")
	ErrInvalidTranscript   = errors.New("invalid pairing transcript")
	ErrInvalidProof        = errors.New("invalid pairing proof")
	ErrInvalidCredential   = errors.New("invalid credential reference")
	ErrCredentialExists    = errors.New("credential already exists")
	ErrCredentialNotFound  = errors.New("credential not found")
	ErrVaultUnavailable    = errors.New("OS credential vault unavailable")
	ErrCredentialDestroyed = errors.New("credential key material destroyed")
	ErrAccessDenied        = errors.New("local transport access denied")
	ErrInvalidAccess       = errors.New("invalid transport access request")
	ErrInvitationInvalid   = errors.New("pairing invitation invalid")
	ErrInvitationSuspended = errors.New("pairing invitation requires explicit resume")
	ErrSecurityDependency  = errors.New("local security dependency unavailable")
)

var (
	_ application.AuthenticationPreparer         = (*AuthenticationPreparer)(nil)
	_ application.PolicyPreparer                 = (*PolicyPreparer)(nil)
	_ application.CurrentLockedAuthorization     = (*LockedAuthorization)(nil)
	_ application.ReplayDisclosureAuthorization  = (*ReplayAuthorization)(nil)
	_ application.PresentationCredentialPreparer = (*GeneratedPresentationCredentialPreparer)(nil)
	_ application.RecoveryCapsuleSignerLookup    = (*VaultRecoveryCapsuleSignerLookup)(nil)
	_ application.EffectPlanner                  = BoundedEffectPlanner{}
	_ application.DenialSecurityPolicy           = StrictDenialSecurityPolicy{}
	_ application.BootstrapProofVerifier         = (*CryptographicProofVerifier)(nil)
	_ application.CeremonyProofVerifier          = (*CryptographicProofVerifier)(nil)
	_ application.PairingRedemptionVerifier      = (*CryptographicProofVerifier)(nil)
)

// ProductionOrchestrationAdapters is the securely composable subset of the
// non-storage orchestration dependencies supported by the current application
// contracts.
type ProductionOrchestrationAdapters struct {
	Authentication      application.AuthenticationPreparer
	Policy              application.PolicyPreparer
	LockedAuthorization application.CurrentLockedAuthorization
	ReplayDisclosure    application.ReplayDisclosureAuthorization
	Presentations       application.PresentationCredentialPreparer
	SignerLookup        application.RecoveryCapsuleSignerLookup
	EffectPlanner       application.EffectPlanner
	DenialPolicy        application.DenialSecurityPolicy
}

func NewProductionOrchestrationAdapters(
	vault *CredentialVault,
	references map[string]CredentialReference,
	authentication *AuthenticationRegistry,
	policies *PolicyRegistry,
	assurance domain.AssuranceClass,
	maxSessionLifetime time.Duration,
) (ProductionOrchestrationAdapters, error) {
	signers, err := NewVaultRecoveryCapsuleSignerLookup(vault, references)
	if err != nil {
		return ProductionOrchestrationAdapters{}, err
	}
	authenticationPreparer, err := NewAuthenticationPreparer(authentication)
	if err != nil {
		return ProductionOrchestrationAdapters{}, err
	}
	policyPreparer, err := NewPolicyPreparer(policies)
	if err != nil {
		return ProductionOrchestrationAdapters{}, err
	}
	authorizer, err := NewLockedAuthorization(assurance, maxSessionLifetime)
	if err != nil {
		return ProductionOrchestrationAdapters{}, err
	}
	presentations, err := NewGeneratedPresentationCredentialPreparer(rand.Reader)
	if err != nil {
		return ProductionOrchestrationAdapters{}, err
	}
	return ProductionOrchestrationAdapters{
		Authentication: authenticationPreparer, Policy: policyPreparer,
		LockedAuthorization: authorizer, ReplayDisclosure: &ReplayAuthorization{authorization: authorizer},
		Presentations: presentations,
		SignerLookup:  signers, EffectPlanner: BoundedEffectPlanner{}, DenialPolicy: StrictDenialSecurityPolicy{},
	}, nil
}

type AuthenticationRegistry struct {
	mu      sync.RWMutex
	current map[string]application.AuthenticationRequest
}

func NewAuthenticationRegistry() *AuthenticationRegistry {
	return &AuthenticationRegistry{current: make(map[string]application.AuthenticationRequest)}
}

func (registry *AuthenticationRegistry) Register(request application.AuthenticationRequest) error {
	key, err := authenticationRequestKey(request)
	if registry == nil || err != nil {
		return ErrInvalidAccess
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.current[key] = request
	return nil
}

func (registry *AuthenticationRegistry) Revoke(request application.AuthenticationRequest) error {
	key, err := authenticationRequestKey(request)
	if registry == nil || err != nil {
		return ErrInvalidAccess
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.current[key]; !exists {
		return ErrAccessDenied
	}
	delete(registry.current, key)
	return nil
}

func authenticationRequestKey(request application.AuthenticationRequest) (string, error) {
	if request.Operation() == "" || request.Scope().IsZero() || request.PrincipalID().IsZero() ||
		request.PrincipalRevision().IsZero() || request.ChannelBinding().IsZero() ||
		request.Audience().String() == "" || request.VerifiedAt().IsZero() {
		return "", ErrInvalidAccess
	}
	device, deviceVersion, trust, revoke, credential, hasDevice := request.Device()
	session, sessionVersion, hasSession := request.ActorSession()
	key := fmt.Sprintf("%v\x00%v\x00%v\x00%v\x00%v\x00%v\x00%v\x00%v\x00%v\x00%v\x00%x\x00%v\x00%v\x00%v\x00%x\x00%v\x00%v",
		request.Operation(), request.Scope().Kind(), request.Scope().ID(), request.PrincipalID(), request.PrincipalRevision(),
		device, deviceVersion, hasDevice, trust, revoke, credential.Bytes(), session, sessionVersion.Uint64(), hasSession,
		request.ChannelBinding(), request.Audience().String(), request.VerifiedAt().UTC().Format(time.RFC3339Nano))
	for _, revision := range request.GrantRevisions() {
		key += "\x00" + revision.Target().String() + "@" + revision.Version().String()
	}
	return key, nil
}

type AuthenticationPreparer struct{ registry *AuthenticationRegistry }

func NewAuthenticationPreparer(registry *AuthenticationRegistry) (*AuthenticationPreparer, error) {
	if registry == nil {
		return nil, ErrSecurityDependency
	}
	return &AuthenticationPreparer{registry: registry}, nil
}

func (preparer *AuthenticationPreparer) PrepareAuthentication(
	ctx context.Context,
	request application.AuthenticationRequest,
) (application.AuthenticationDecision, error) {
	if err := ctx.Err(); err != nil {
		return application.AuthenticationDecision{}, err
	}
	key, err := authenticationRequestKey(request)
	if err != nil || preparer == nil || preparer.registry == nil {
		return application.AuthenticationDecision{}, ErrAccessDenied
	}
	preparer.registry.mu.RLock()
	registered, exists := preparer.registry.current[key]
	preparer.registry.mu.RUnlock()
	if !exists || registered.VerifiedAt() != request.VerifiedAt() {
		return application.AuthenticationDecision{}, ErrAccessDenied
	}
	evidence, err := application.NewAuthenticationEvidence(registered)
	if err != nil {
		return application.AuthenticationDecision{}, ErrAccessDenied
	}
	return application.ValidAuthentication(evidence)
}

type policyRecord struct {
	revision domain.PolicyRevision
	digest   application.Digest
}

type PolicyRegistry struct {
	mu      sync.RWMutex
	current map[domain.AuthorityScope]policyRecord
}

func NewPolicyRegistry() *PolicyRegistry {
	return &PolicyRegistry{current: make(map[domain.AuthorityScope]policyRecord)}
}

func (registry *PolicyRegistry) Register(
	scope domain.AuthorityScope,
	revision domain.PolicyRevision,
	digest application.Digest,
) error {
	if registry == nil || scope.IsZero() || revision.String() == "" || digest.IsZero() {
		return ErrInvalidAccess
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.current[scope] = policyRecord{revision: revision, digest: digest}
	return nil
}

type PolicyPreparer struct{ registry *PolicyRegistry }

func NewPolicyPreparer(registry *PolicyRegistry) (*PolicyPreparer, error) {
	if registry == nil {
		return nil, ErrSecurityDependency
	}
	return &PolicyPreparer{registry: registry}, nil
}

func (preparer *PolicyPreparer) PreparePolicy(
	ctx context.Context,
	request application.PolicyPreparationRequest,
) (application.PreparedPolicy, error) {
	if err := ctx.Err(); err != nil {
		return application.PreparedPolicy{}, err
	}
	if preparer == nil || preparer.registry == nil || request.Operation() == "" || request.Scope().IsZero() ||
		request.PrincipalID().IsZero() || request.ChannelBinding().IsZero() || request.Audience().String() == "" ||
		request.VerifiedAt().IsZero() {
		return application.PreparedPolicy{}, ErrAccessDenied
	}
	preparer.registry.mu.RLock()
	current, exists := preparer.registry.current[request.Scope()]
	preparer.registry.mu.RUnlock()
	if !exists || current.revision != request.PolicyRevision() || current.digest != request.PolicyDigest() {
		return application.PreparedPolicy{}, ErrAccessDenied
	}
	return application.NewPreparedPolicy(current.revision, current.digest)
}

type LockedAuthorization struct {
	assurance          domain.AssuranceClass
	maxSessionLifetime time.Duration
}

func NewLockedAuthorization(
	assurance domain.AssuranceClass,
	maxSessionLifetime time.Duration,
) (*LockedAuthorization, error) {
	if assurance.String() == "" || maxSessionLifetime <= 0 || maxSessionLifetime > domain.MaxActorSessionLifetime {
		return nil, ErrSecurityDependency
	}
	return &LockedAuthorization{assurance: assurance, maxSessionLifetime: maxSessionLifetime}, nil
}

func (authorization *LockedAuthorization) AuthorizeLocked(
	locked application.CommandContext,
	authentication application.AuthenticationEvidence,
	policy application.PreparedPolicy,
) (domain.IdentityAuthorization, error) {
	return authorization.authorize(locked, authentication, policy, false)
}

func (authorization *LockedAuthorization) authorize(
	locked application.CommandContext,
	authentication application.AuthenticationEvidence,
	policy application.PreparedPolicy,
	replay bool,
) (domain.IdentityAuthorization, error) {
	if authorization == nil || authorization.assurance.String() == "" || policy.Revision().String() == "" || policy.Digest().IsZero() {
		return domain.IdentityAuthorization{}, ErrAccessDenied
	}
	now, present := locked.AuthorityTime()
	if replay {
		now, present = locked.DisclosureTime()
	}
	if !present {
		return domain.IdentityAuthorization{}, ErrAccessDenied
	}
	request := authentication.Request()
	if request.VerifiedAt().After(now) || request.Scope() != locked.Spec().Scope() ||
		request.Operation() != locked.Spec().CommandOperation() || request.PrincipalID() != locked.Spec().Authorship().PrincipalID() {
		return domain.IdentityAuthorization{}, ErrAccessDenied
	}
	states := locked.States()
	var principal domain.PrincipalState
	var workspace domain.WorkspaceState
	var membership domain.MembershipState
	var delegation domain.ActorDelegationState
	var session domain.ActorSessionState
	grants := make(map[domain.AggregateTarget]domain.GrantState)
	devices := make(map[domain.DeviceID]domain.DeviceState)
	actors := make(map[domain.ActorID]domain.ActorState)
	for _, state := range states {
		switch value := state.Value().(type) {
		case domain.PrincipalState:
			if value.ID() == request.PrincipalID() {
				principal = value
			}
		case domain.DeviceState:
			devices[value.ID()] = value
		case domain.WorkspaceState:
			if value.ID().String() == request.Scope().ID() {
				workspace = value
			}
		case domain.MembershipState:
			if value.PrincipalID() == request.PrincipalID() {
				membership = value
			}
		case domain.ActorState:
			actors[value.ID()] = value
		case domain.ActorDelegationState:
			if value.PrincipalID() == request.PrincipalID() {
				delegation = value
			}
		case domain.ActorSessionState:
			if id, _, ok := request.ActorSession(); ok && value.ID() == id {
				session = value
			}
		case domain.GrantState:
			grants[state.Target()] = value
		}
	}
	if principal.IsZero() || principal.Status() != domain.PrincipalActive || principal.Version() != request.PrincipalRevision() {
		return domain.IdentityAuthorization{}, ErrAccessDenied
	}
	installation := principal.InstallationID()
	var deviceID domain.DeviceID
	var deviceTrust domain.Version
	if expectedID, expectedVersion, expectedTrust, expectedRevoke, fingerprint, hasDevice := request.Device(); hasDevice {
		device, exists := devices[expectedID]
		if !exists || device.Status() != domain.DeviceTrusted || device.PrincipalID() != request.PrincipalID() ||
			device.InstallationID() != installation || device.Version() != expectedVersion ||
			device.TrustRevision() != expectedTrust || device.RevocationRevision() != expectedRevoke ||
			!device.AcceptsCredential(fingerprint, request.VerifiedAt()) {
			return domain.IdentityAuthorization{}, ErrAccessDenied
		}
		deviceID, deviceTrust = expectedID, expectedTrust
	}
	capabilitySets := make([]domain.CapabilitySet, 0, 4)
	grantCapabilities := make(map[domain.Capability]struct{})
	for _, revision := range request.GrantRevisions() {
		grant, exists := grants[revision.Target()]
		if !exists || grant.Status() != domain.GrantActive || grant.Version() != revision.Version() ||
			grant.PrincipalID() != request.PrincipalID() || grant.InstallationID() != installation ||
			(!grant.WorkspaceID().IsZero() && grant.WorkspaceID().String() != request.Scope().ID()) {
			return domain.IdentityAuthorization{}, ErrAccessDenied
		}
		for _, capability := range grant.Capabilities().Values() {
			grantCapabilities[capability] = struct{}{}
		}
	}
	if len(grantCapabilities) > 0 {
		values := make([]domain.Capability, 0, len(grantCapabilities))
		for capability := range grantCapabilities {
			values = append(values, capability)
		}
		combined, err := domain.NewCapabilitySet(values...)
		if err != nil {
			return domain.IdentityAuthorization{}, ErrAccessDenied
		}
		capabilitySets = append(capabilitySets, combined)
	}
	assurance := authorization.assurance
	if request.Scope().Kind() == domain.ScopeKindWorkspace {
		if workspace.IsZero() || workspace.Status() != domain.WorkspaceActive || workspace.InstallationID() != installation ||
			workspace.AuthorityID() != locked.Spec().AuthorityID() || workspace.AuthorityEpoch() != locked.Spec().RequestedEpoch() ||
			workspace.PolicyRevision() != policy.Revision() {
			return domain.IdentityAuthorization{}, ErrAccessDenied
		}
		if !membership.IsZero() {
			if membership.Status() != domain.MembershipActive || membership.WorkspaceID() != workspace.ID() {
				return domain.IdentityAuthorization{}, ErrAccessDenied
			}
			capabilitySets = append(capabilitySets, membership.Capabilities())
		}
	}
	if sessionID, sessionVersion, hasSession := request.ActorSession(); hasSession {
		if session.IsZero() || session.ID() != sessionID || session.Version() != sessionVersion ||
			session.Status() != domain.ActorSessionActive || !now.Before(session.Binding().AbsoluteExpiry()) ||
			session.Binding().PrincipalID() != request.PrincipalID() || session.Binding().WorkspaceID().String() != request.Scope().ID() ||
			session.Binding().AuthorityID() != locked.Spec().AuthorityID() || session.Binding().AuthorityEpoch() != locked.Spec().RequestedEpoch() ||
			session.Binding().PolicyRevision() != policy.Revision() || session.PresentationCredential().Audience() != request.Audience() {
			return domain.IdentityAuthorization{}, ErrAccessDenied
		}
		membershipRef := session.Binding().MembershipRevision()
		delegationRef := session.Binding().DelegationRevision()
		actor := actors[session.Binding().ActorID()]
		if membership.IsZero() || membership.ID().String() != membershipRef.ID() || membership.Version() != membershipRef.Version() ||
			delegation.IsZero() || delegation.ID().String() != delegationRef.ID() || delegation.Version() != delegationRef.Version() ||
			delegation.Status() != domain.DelegationActive || actor.IsZero() || actor.Status() != domain.ActorActive ||
			actor.ID() != delegation.ActorID() || delegation.MembershipID() != membership.ID() {
			return domain.IdentityAuthorization{}, ErrAccessDenied
		}
		if boundDevice, bound := session.Binding().DeviceRevision(); bound {
			device, exists := devices[deviceID]
			boundTrust, _ := session.Binding().DeviceTrustRevision()
			if !exists || boundDevice.ID() != device.ID().String() || boundDevice.Version() != device.Version() || boundTrust != device.TrustRevision() {
				return domain.IdentityAuthorization{}, ErrAccessDenied
			}
		}
		if !sameAggregateRefs(session.Binding().GrantRevisions(), request.GrantRevisions()) {
			return domain.IdentityAuthorization{}, ErrAccessDenied
		}
		capabilitySets = append(capabilitySets, delegation.Capabilities(), session.Capabilities())
		assurance = session.Binding().AssuranceClass()
	}
	capabilities, err := intersectCapabilities(capabilitySets)
	if err != nil {
		return domain.IdentityAuthorization{}, ErrAccessDenied
	}
	if request.Scope().Kind() == domain.ScopeKindInstallation {
		return domain.NewIdentityAuthorization(
			locked.Spec().AuthorityID(), locked.Spec().RequestedEpoch(), installation, request.PrincipalID(),
			capabilities, policy.Revision(), assurance, now, authorization.maxSessionLifetime,
		)
	}
	if request.Scope().Kind() != domain.ScopeKindWorkspace {
		return domain.IdentityAuthorization{}, ErrAccessDenied
	}
	if requestDevice, _, _, _, _, hasDevice := request.Device(); hasDevice {
		return domain.NewDeviceBoundWorkspaceIdentityAuthorization(
			locked.Spec().AuthorityID(), locked.Spec().RequestedEpoch(), installation, workspace.ID(), request.PrincipalID(),
			capabilities, policy.Revision(), assurance, now, authorization.maxSessionLifetime, requestDevice, deviceTrust,
		)
	}
	return domain.NewWorkspaceIdentityAuthorization(
		locked.Spec().AuthorityID(), locked.Spec().RequestedEpoch(), installation, workspace.ID(), request.PrincipalID(),
		capabilities, policy.Revision(), assurance, now, authorization.maxSessionLifetime,
	)
}

func intersectCapabilities(sets []domain.CapabilitySet) (domain.CapabilitySet, error) {
	if len(sets) == 0 {
		return domain.CapabilitySet{}, ErrAccessDenied
	}
	values := sets[0].Values()
	for _, set := range sets[1:] {
		kept := values[:0]
		for _, capability := range values {
			if set.Contains(capability) {
				kept = append(kept, capability)
			}
		}
		values = kept
	}
	if len(values) == 0 {
		return domain.CapabilitySet{}, ErrAccessDenied
	}
	return domain.NewCapabilitySet(values...)
}

func sameAggregateRefs(left, right []domain.AggregateRef) bool {
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

type ReplayAuthorization struct{ authorization *LockedAuthorization }

func NewReplayAuthorization(authorization *LockedAuthorization) (*ReplayAuthorization, error) {
	if authorization == nil {
		return nil, ErrSecurityDependency
	}
	return &ReplayAuthorization{authorization: authorization}, nil
}

func (authorization *ReplayAuthorization) AuthorizeReplay(
	locked application.CommandContext,
	authentication application.AuthenticationEvidence,
	policy application.PreparedPolicy,
) (application.ReplayDisclosure, error) {
	if authorization == nil || authorization.authorization == nil ||
		locked.ReceiptResolution().Kind() != application.ReceiptExactReplay {
		return "", ErrAccessDenied
	}
	if _, err := authorization.authorization.authorize(locked, authentication, policy, true); err != nil {
		return "", err
	}
	return application.ReplayDiscloseResult, nil
}

type GeneratedPresentationCredentialPreparer struct {
	mu     sync.Mutex
	random io.Reader
	used   map[string]struct{}
}

func NewGeneratedPresentationCredentialPreparer(random io.Reader) (*GeneratedPresentationCredentialPreparer, error) {
	if random == nil {
		return nil, ErrSecurityDependency
	}
	return &GeneratedPresentationCredentialPreparer{random: random, used: make(map[string]struct{})}, nil
}

func (preparer *GeneratedPresentationCredentialPreparer) PreparePresentationCredential(
	ctx context.Context,
	request application.PresentationCredentialRequest,
) (domain.PresentationCredentialBinding, error) {
	if err := ctx.Err(); err != nil {
		return domain.PresentationCredentialBinding{}, err
	}
	if preparer == nil || preparer.random == nil || request.Operation() != application.CommandStartActorSession ||
		request.PrincipalID().IsZero() || request.SessionID().IsZero() || request.Audience().String() == "" ||
		request.ChannelBinding().IsZero() || request.DeliveryReference() == "" {
		return domain.PresentationCredentialBinding{}, ErrInvalidAccess
	}
	preparer.mu.Lock()
	if _, exists := preparer.used[request.DeliveryReference()]; exists {
		preparer.mu.Unlock()
		return domain.PresentationCredentialBinding{}, ErrAccessDenied
	}
	preparer.used[request.DeliveryReference()] = struct{}{}
	secret := make([]byte, sha256.Size)
	if _, err := io.ReadFull(preparer.random, secret); err != nil {
		delete(preparer.used, request.DeliveryReference())
		preparer.mu.Unlock()
		clear(secret)
		return domain.PresentationCredentialBinding{}, ErrSecurityDependency
	}
	preparer.mu.Unlock()
	defer clear(secret)
	device, hasDevice := request.DeviceID()
	bound := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(bound, "blackbird-presentation/v1\x00%s\x00%s\x00%s\x00%t\x00%s\x00%x",
		request.PrincipalID(), request.SessionID(), device, hasDevice, request.Audience().String(), request.ChannelBinding())
	digestBytes := [sha256.Size]byte(bound.Sum(nil))
	digest, err := domain.NewCredentialDigest(digestBytes)
	if err != nil {
		return domain.PresentationCredentialBinding{}, ErrSecurityDependency
	}
	reference, err := domain.NewCredentialReference("presentation:" + request.DeliveryReference())
	if err != nil {
		return domain.PresentationCredentialBinding{}, ErrInvalidCredential
	}
	binding, err := domain.NewPresentationCredentialBinding(digest, reference, request.Audience(), domain.PresentationCredentialVersion)
	if err != nil {
		return domain.PresentationCredentialBinding{}, ErrInvalidCredential
	}
	if err := request.Deliver(ctx, secret); err != nil {
		return domain.PresentationCredentialBinding{}, fmt.Errorf("%w: credential delivery", ErrSecurityDependency)
	}
	return binding, nil
}

// VaultRecoveryCapsuleSignerLookup resolves public key identity during
// preflight and loads private material from the protected vault only for the
// duration of an individual signature operation.
type VaultRecoveryCapsuleSignerLookup struct {
	vault      *CredentialVault
	references map[string]CredentialReference
}

func NewVaultRecoveryCapsuleSignerLookup(
	vault *CredentialVault,
	references map[string]CredentialReference,
) (*VaultRecoveryCapsuleSignerLookup, error) {
	if vault == nil || len(references) == 0 {
		return nil, ErrSecurityDependency
	}
	cloned := make(map[string]CredentialReference, len(references))
	for keyID, reference := range references {
		if !validCredentialIdentifier(keyID) || validateCredentialReference(reference) != nil {
			return nil, ErrInvalidCredential
		}
		cloned[keyID] = reference
	}
	return &VaultRecoveryCapsuleSignerLookup{vault: vault, references: cloned}, nil
}

func (lookup *VaultRecoveryCapsuleSignerLookup) PrepareRecoveryCapsuleSigner(
	ctx context.Context,
	keyID string,
) (application.PreparedRecoveryCapsuleSigner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lookup == nil || lookup.vault == nil {
		return nil, ErrSecurityDependency
	}
	reference, exists := lookup.references[keyID]
	if !exists || !validCredentialIdentifier(keyID) {
		return nil, ErrCredentialNotFound
	}
	credential, err := lookup.vault.LoadCredential(reference)
	if err != nil {
		return nil, err
	}
	publicKey, err := credential.PublicKey()
	credential.Destroy()
	if err != nil {
		return nil, err
	}
	return &vaultRecoveryCapsuleSigner{
		keyID: keyID, reference: reference, vault: lookup.vault,
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
	}, nil
}

type vaultRecoveryCapsuleSigner struct {
	keyID     string
	reference CredentialReference
	vault     *CredentialVault
	publicKey ed25519.PublicKey
}

func (signer *vaultRecoveryCapsuleSigner) KeyID() string { return signer.keyID }

func (signer *vaultRecoveryCapsuleSigner) Ed25519PublicKey() ed25519.PublicKey {
	if signer == nil {
		return nil
	}
	return append(ed25519.PublicKey(nil), signer.publicKey...)
}

func (signer *vaultRecoveryCapsuleSigner) SignRecoveryCapsule(
	ctx context.Context,
	message []byte,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if signer == nil || signer.vault == nil || len(message) == 0 ||
		len(message) > application.MaxRecoveryCapsuleBytes {
		return nil, ErrSecurityDependency
	}
	credential, err := signer.vault.LoadCredential(signer.reference)
	if err != nil {
		return nil, err
	}
	defer credential.Destroy()
	return credential.Sign(rand.Reader, message, crypto.Hash(0))
}

func (signer *vaultRecoveryCapsuleSigner) String() string {
	return "[REDACTED recovery capsule signer]"
}

func (signer *vaultRecoveryCapsuleSigner) GoString() string { return signer.String() }

// BoundedEffectPlanner emits one deterministic projection intent per committed
// identity fact. Application constructors enforce bounds, metadata size, and
// logical uniqueness.
type BoundedEffectPlanner struct{}

func (BoundedEffectPlanner) PlanEffects(input application.EffectPlanningInput) (application.EffectSet, error) {
	facts := input.Facts()
	if input.CommandID().IsZero() || len(facts) == 0 || len(facts) > application.MaxCommandEffects {
		return application.EffectSet{}, application.ErrInvalidApplicationContract
	}
	major, err := application.NewOperationMajor(1)
	if err != nil {
		return application.EffectSet{}, err
	}
	intents := make([]application.EffectIntent, len(facts))
	for index, fact := range facts {
		if fact.Fact() == nil || fact.EventID().IsZero() || fact.Fact().Origin().IsZero() {
			return application.EffectSet{}, application.ErrInvalidApplicationContract
		}
		metadata := []byte(fmt.Sprintf(
			`{"event_type":%q,"origin":%q}`,
			fact.Fact().Type(), fact.Fact().Origin().Target().String(),
		))
		intent, intentErr := application.NewEffectIntent(
			fact.EventID(), "identity_projection", major,
			fact.Fact().Origin().Target().String(), uint16(index), metadata,
		)
		if intentErr != nil {
			return application.EffectSet{}, intentErr
		}
		intents[index] = intent
	}
	return application.NewEffectSet(intents...)
}

// StrictDenialSecurityPolicy records only safe, cataloged denial classes. It
// derives authority and admission data from the locked command context rather
// than from caller-controlled error text.
type StrictDenialSecurityPolicy struct{}

func (StrictDenialSecurityPolicy) DenialFollowUp(
	locked application.CommandContext,
	authentication application.AuthenticationEvidence,
	policy application.PreparedPolicy,
	rejection *domain.CommandError,
) (application.SecuritySpec, error) {
	if rejection == nil || authentication.PrincipalID().IsZero() ||
		policy.Revision().String() == "" || policy.Digest().IsZero() {
		return application.SecuritySpec{}, application.ErrInvalidSecuritySpec
	}
	spec := locked.Spec()
	if locked.ReceiptResolution().Kind() != application.ReceiptAdmitted ||
		spec.Authorship().PrincipalID() != authentication.PrincipalID() {
		return application.SecuritySpec{}, application.ErrInvalidSecuritySpec
	}
	device, hasDevice := authentication.DeviceID()
	var devicePointer *domain.DeviceID
	if hasDevice {
		devicePointer = &device
	}
	subject, err := application.AttributedDenialSubject(authentication.PrincipalID(), devicePointer)
	if err != nil {
		return application.SecuritySpec{}, err
	}
	class, reason, valid := safeDenialClassification(rejection)
	if !valid {
		return application.SecuritySpec{}, application.ErrInvalidSecuritySpec
	}
	draft, err := application.NewCommandDenialDraft(
		spec.Operation(), spec.OperationMajor(), class, reason, spec.RequestFingerprint(),
		subject, ptrPolicyRevision(policy.Revision()), spec.CorrelationID(),
	)
	if err != nil {
		return application.SecuritySpec{}, err
	}
	return application.RecordCommandDenialSecurity(
		spec.Scope(), spec.AuthorityID(), spec.RequestedEpoch(),
		spec.Guards().AdmissionGeneration(), draft,
	)
}

func safeDenialClassification(rejection *domain.CommandError) (application.CommandDenialClass, string, bool) {
	if rejection == nil {
		return "", "", false
	}
	switch rejection.Code() {
	case domain.ErrorCodeUnauthenticated, domain.ErrorCodeSessionExpired:
		return application.DenialAuthentication, "credential_rejected", true
	case domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired:
		return application.DenialAuthorization, "authorization_denied", true
	default:
		return "", "", false
	}
}

func ptrPolicyRevision(revision domain.PolicyRevision) *domain.PolicyRevision { return &revision }

// CredentialKind identifies a long-lived local Ed25519 credential class.
type CredentialKind string

const (
	InstallationCredential CredentialKind = "installation"
	DeviceCredential       CredentialKind = "device"
)

// CredentialReference is an opaque, non-secret handle suitable for persisted
// metadata. It never contains seed material.
type CredentialReference struct {
	kind       CredentialKind
	identifier string
}

// NewCredentialReference validates an application identifier and builds a
// handle for an installation or device credential.
func NewCredentialReference(kind CredentialKind, identifier string) (CredentialReference, error) {
	if kind != InstallationCredential && kind != DeviceCredential || !validCredentialIdentifier(identifier) {
		return CredentialReference{}, ErrInvalidCredential
	}
	return CredentialReference{kind: kind, identifier: identifier}, nil
}

func InstallationCredentialReference(identifier string) (CredentialReference, error) {
	return NewCredentialReference(InstallationCredential, identifier)
}

func DeviceCredentialReference(identifier string) (CredentialReference, error) {
	return NewCredentialReference(DeviceCredential, identifier)
}

func (reference CredentialReference) Kind() CredentialKind { return reference.kind }

func (reference CredentialReference) String() string {
	if reference.kind == "" || reference.identifier == "" {
		return ""
	}
	return "credential:" + string(reference.kind) + ":" + reference.identifier
}

func (reference CredentialReference) account() string {
	return "ed25519-seed/v1/" + string(reference.kind) + "/" + reference.identifier
}

// SecretStore is the injectable byte-oriented vault surface. Implementations
// must not log, persist outside a protected vault, or retain caller buffers.
type SecretStore interface {
	Set(service, account string, secret []byte) error
	Get(service, account string) ([]byte, error)
	Delete(service, account string) error
}

type osSecretStore struct {
	keychain *keychain.Keychain
}

func (store osSecretStore) Set(service, account string, secret []byte) error {
	return store.keychain.Set(service, account, secret)
}

func (store osSecretStore) Get(service, account string) ([]byte, error) {
	return store.keychain.Get(service, account)
}

func (store osSecretStore) Delete(service, account string) error {
	return store.keychain.Delete(service, account)
}

// CredentialVault owns local Ed25519 seed lifecycle operations. Operations are
// serialized so create and rotate semantics are deterministic within a process.
type CredentialVault struct {
	mu     sync.Mutex
	store  SecretStore
	random io.Reader
}

// NewOSCredentialVault uses the silent, native, CGo-free platform keychain.
// It deliberately does not enable the macOS CLI fallback because that fallback
// places the secret in a process argument.
func NewOSCredentialVault() *CredentialVault {
	return NewCredentialVault(osSecretStore{keychain: keychain.New()}, rand.Reader)
}

// NewCredentialVault injects a vault and entropy source. Supplying nil causes
// lifecycle calls to fail closed with ErrVaultUnavailable.
func NewCredentialVault(store SecretStore, random io.Reader) *CredentialVault {
	return &CredentialVault{store: store, random: random}
}

// Ed25519Credential keeps a loaded seed inside this boundary and implements
// crypto.Signer. Call Destroy as soon as the signing lifetime ends. Go cannot
// guarantee zeroization of copies made by the runtime or operating system.
type Ed25519Credential struct {
	mu        sync.RWMutex
	reference CredentialReference
	seed      [ed25519.SeedSize]byte
	destroyed bool
}

func (credential *Ed25519Credential) Reference() CredentialReference {
	if credential == nil {
		return CredentialReference{}
	}
	return credential.reference
}

func (credential *Ed25519Credential) String() string   { return "[REDACTED Ed25519 credential]" }
func (credential *Ed25519Credential) GoString() string { return credential.String() }

func (credential *Ed25519Credential) Public() crypto.PublicKey {
	publicKey, err := credential.PublicKey()
	if err != nil {
		return nil
	}
	return publicKey
}

func (credential *Ed25519Credential) PublicKey() (ed25519.PublicKey, error) {
	if credential == nil {
		return nil, ErrCredentialDestroyed
	}
	credential.mu.RLock()
	defer credential.mu.RUnlock()
	if credential.destroyed {
		return nil, ErrCredentialDestroyed
	}
	privateKey := ed25519.NewKeyFromSeed(credential.seed[:])
	defer clear(privateKey)
	return append(ed25519.PublicKey(nil), privateKey[ed25519.SeedSize:]...), nil
}

func (credential *Ed25519Credential) Sign(_ io.Reader, message []byte, options crypto.SignerOpts) ([]byte, error) {
	if credential == nil {
		return nil, ErrCredentialDestroyed
	}
	if options != nil && options.HashFunc() != crypto.Hash(0) {
		return nil, ErrInvalidKeyMaterial
	}
	credential.mu.RLock()
	defer credential.mu.RUnlock()
	if credential.destroyed {
		return nil, ErrCredentialDestroyed
	}
	privateKey := ed25519.NewKeyFromSeed(credential.seed[:])
	defer clear(privateKey)
	return ed25519.Sign(privateKey, message), nil
}

func (credential *Ed25519Credential) NewCertificate(validity CertificateValidity) (tls.Certificate, SPKIPin, error) {
	publicKey, err := credential.PublicKey()
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, err
	}
	return newCertificate(publicKey, credential, validity)
}

// SignTranscript signs a pairing transcript without exporting vault key
// material into the pairing layer.
func (credential *Ed25519Credential) SignTranscript(transcript TranscriptHash) ([]byte, error) {
	return SignTranscript(credential, transcript)
}

func (credential *Ed25519Credential) Destroy() {
	if credential == nil {
		return
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	clear(credential.seed[:])
	credential.destroyed = true
}

func (vault *CredentialVault) CreateCredential(reference CredentialReference) (*Ed25519Credential, error) {
	return vault.create(reference, false)
}

func (vault *CredentialVault) LoadCredential(reference CredentialReference) (*Ed25519Credential, error) {
	if err := validateCredentialReference(reference); err != nil {
		return nil, err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	return vault.load(reference)
}

func (vault *CredentialVault) RotateCredential(reference CredentialReference) (*Ed25519Credential, error) {
	return vault.create(reference, true)
}

func (vault *CredentialVault) DeleteCredential(reference CredentialReference) error {
	if err := validateCredentialReference(reference); err != nil {
		return err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	material, err := vault.get(reference)
	if err != nil {
		return err
	}
	clear(material)
	if err := vault.store.Delete(credentialService, reference.account()); err != nil {
		return vaultError("delete", err)
	}
	return nil
}

func (vault *CredentialVault) create(reference CredentialReference, rotate bool) (*Ed25519Credential, error) {
	if err := validateCredentialReference(reference); err != nil {
		return nil, err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	material, err := vault.get(reference)
	switch {
	case err == nil:
		clear(material)
		if !rotate {
			return nil, ErrCredentialExists
		}
	case errors.Is(err, ErrCredentialNotFound):
		if rotate {
			return nil, err
		}
	default:
		return nil, err
	}
	if vault.random == nil {
		return nil, fmt.Errorf("%w: entropy source is not configured", ErrVaultUnavailable)
	}
	var seed [ed25519.SeedSize]byte
	if _, err := io.ReadFull(vault.random, seed[:]); err != nil {
		clear(seed[:])
		return nil, fmt.Errorf("%w: generate Ed25519 seed", ErrVaultUnavailable)
	}
	if err := vault.store.Set(credentialService, reference.account(), seed[:]); err != nil {
		clear(seed[:])
		return nil, vaultError("store", err)
	}
	credential := &Ed25519Credential{reference: reference, seed: seed}
	clear(seed[:])
	return credential, nil
}

func (vault *CredentialVault) load(reference CredentialReference) (*Ed25519Credential, error) {
	material, err := vault.get(reference)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	if len(material) != ed25519.SeedSize {
		return nil, ErrInvalidKeyMaterial
	}
	credential := &Ed25519Credential{reference: reference}
	copy(credential.seed[:], material)
	return credential, nil
}

func (vault *CredentialVault) get(reference CredentialReference) ([]byte, error) {
	if vault == nil || vault.store == nil {
		return nil, fmt.Errorf("%w: no credential store is configured", ErrVaultUnavailable)
	}
	material, err := vault.store.Get(credentialService, reference.account())
	if err != nil {
		clear(material)
		return nil, vaultError("read", err)
	}
	return material, nil
}

func vaultError(operation string, err error) error {
	if errors.Is(err, keychain.ErrNotFound) || errors.Is(err, ErrCredentialNotFound) {
		return ErrCredentialNotFound
	}
	return fmt.Errorf("%w: cannot %s credential: %w", ErrVaultUnavailable, operation, err)
}

func validateCredentialReference(reference CredentialReference) error {
	if reference.kind != InstallationCredential && reference.kind != DeviceCredential ||
		!validCredentialIdentifier(reference.identifier) {
		return ErrInvalidCredential
	}
	return nil
}

func validCredentialIdentifier(identifier string) bool {
	if identifier == "" || len(identifier) > credentialIDMaxBytes || strings.TrimSpace(identifier) != identifier {
		return false
	}
	for _, value := range identifier {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' || value == '-' || value == '_' || value == '.' {
			continue
		}
		return false
	}
	return true
}

// TransportAccessCredential is a short-lived opaque secret. It is useful only
// with the mTLS connection whose exporter binding was supplied at issuance.
type TransportAccessCredential struct {
	mu        sync.RWMutex
	material  [sha256.Size]byte
	destroyed bool
}

func (credential *TransportAccessCredential) String() string {
	return "[REDACTED transport access credential]"
}

func (credential *TransportAccessCredential) GoString() string { return credential.String() }

// Bytes returns a disposable copy for transport encoding. Callers should clear
// it immediately after writing it to the authenticated connection.
func (credential *TransportAccessCredential) Bytes() ([]byte, error) {
	if credential == nil {
		return nil, ErrAccessDenied
	}
	credential.mu.RLock()
	defer credential.mu.RUnlock()
	if credential.destroyed {
		return nil, ErrAccessDenied
	}
	return append([]byte(nil), credential.material[:]...), nil
}

func (credential *TransportAccessCredential) Destroy() {
	if credential == nil {
		return
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	clear(credential.material[:])
	credential.destroyed = true
}

// TransportAccessClaims are authenticated identity and authorization revisions
// attached to one paired connection. Identifier fields are metadata, not
// caller-overridable request values.
type TransportAccessClaims struct {
	PrincipalID       string
	DeviceID          string
	AuthorityEpoch    string
	GrantsRevision    uint64
	CredentialVersion uint64
	RevocationVersion uint64
}

// TransportAccessCurrent is authoritative state checked on every acceptance.
// Exact epoch equality is intentional; epochs have no ordering semantics.
type TransportAccessCurrent struct {
	AuthorityEpoch    string
	GrantsRevision    uint64
	CredentialVersion uint64
	RevocationVersion uint64
}

// LocalAccessRequest contains evidence available at the local transport edge.
// Origin-bearing browser requests are rejected even if they reach loopback.
type LocalAccessRequest struct {
	Credential    []byte
	Binding       Binding
	BrowserOrigin string
}

type transportAccessRecord struct {
	claims            TransportAccessClaims
	bindingDigest     [sha256.Size]byte
	serverIncarnation [sha256.Size]byte
	expiresAt         time.Time
}

// TransportAccessIssuer issues and verifies sender-constrained access for a
// single daemon incarnation. Restart invalidates all issued credentials.
type TransportAccessIssuer struct {
	mu                sync.Mutex
	random            io.Reader
	now               func() time.Time
	serverIncarnation [sha256.Size]byte
	records           map[[sha256.Size]byte]transportAccessRecord
	healthy           bool
}

func NewTransportAccessIssuer(random io.Reader, now func() time.Time) (*TransportAccessIssuer, error) {
	if random == nil || now == nil {
		return nil, ErrInvalidAccess
	}
	issuer := &TransportAccessIssuer{random: random, now: now, records: make(map[[sha256.Size]byte]transportAccessRecord)}
	if err := issuer.rotateIncarnation(); err != nil {
		return nil, err
	}
	issuer.healthy = true
	return issuer, nil
}

func (issuer *TransportAccessIssuer) Issue(
	claims TransportAccessClaims,
	binding Binding,
	ttl time.Duration,
) (*TransportAccessCredential, error) {
	if issuer == nil || !validTransportClaims(claims) || binding == (Binding{}) || ttl <= 0 || ttl > maxTransportAccessTTL {
		return nil, ErrInvalidAccess
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if !issuer.healthy {
		return nil, ErrAccessDenied
	}
	return issuer.issueLocked(claims, binding, ttl)
}

func (issuer *TransportAccessIssuer) issueLocked(
	claims TransportAccessClaims,
	binding Binding,
	ttl time.Duration,
) (*TransportAccessCredential, error) {
	var material [sha256.Size]byte
	var digest [sha256.Size]byte
	generated := false
	for range 4 {
		if _, err := io.ReadFull(issuer.random, material[:]); err != nil {
			clear(material[:])
			return nil, fmt.Errorf("%w: access credential entropy unavailable", ErrInvalidAccess)
		}
		digest = sha256.Sum256(material[:])
		if _, exists := issuer.records[digest]; !exists {
			generated = true
			break
		}
		clear(material[:])
	}
	if !generated {
		return nil, fmt.Errorf("%w: access credential collision", ErrInvalidAccess)
	}
	record := transportAccessRecord{
		claims: claims, bindingDigest: sha256.Sum256(binding[:]),
		serverIncarnation: issuer.serverIncarnation, expiresAt: issuer.now().Add(ttl),
	}
	issuer.records[digest] = record
	return &TransportAccessCredential{material: material}, nil
}

// Rotate replaces an accepted credential. The old credential remains valid if
// generation of its replacement fails.
func (issuer *TransportAccessIssuer) Rotate(
	oldCredential []byte,
	claims TransportAccessClaims,
	binding Binding,
	ttl time.Duration,
) (*TransportAccessCredential, error) {
	if issuer == nil || len(oldCredential) != sha256.Size || !validTransportClaims(claims) ||
		binding == (Binding{}) || ttl <= 0 || ttl > maxTransportAccessTTL {
		return nil, ErrInvalidAccess
	}
	oldDigest := sha256.Sum256(oldCredential)
	bindingDigest := sha256.Sum256(binding[:])
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if !issuer.healthy {
		return nil, ErrAccessDenied
	}
	oldRecord, ok := issuer.records[oldDigest]
	if !ok || !issuer.now().Before(oldRecord.expiresAt) ||
		subtle.ConstantTimeCompare(oldRecord.bindingDigest[:], bindingDigest[:]) != 1 ||
		claims.PrincipalID != oldRecord.claims.PrincipalID || claims.DeviceID != oldRecord.claims.DeviceID ||
		claims.AuthorityEpoch != oldRecord.claims.AuthorityEpoch ||
		claims.GrantsRevision != oldRecord.claims.GrantsRevision ||
		claims.RevocationVersion != oldRecord.claims.RevocationVersion ||
		oldRecord.claims.CredentialVersion == ^uint64(0) ||
		claims.CredentialVersion != oldRecord.claims.CredentialVersion+1 {
		return nil, ErrAccessDenied
	}
	replacement, err := issuer.issueLocked(claims, binding, ttl)
	if err != nil {
		return nil, err
	}
	delete(issuer.records, oldDigest)
	return replacement, nil
}

// VerifyLocalAccess denies browser-originated and unpaired callers before
// returning server-established identity claims.
func (issuer *TransportAccessIssuer) VerifyLocalAccess(
	request LocalAccessRequest,
	current TransportAccessCurrent,
) (TransportAccessClaims, error) {
	if issuer == nil || request.BrowserOrigin != "" || len(request.Credential) != sha256.Size ||
		request.Binding == (Binding{}) || !validTransportCurrent(current) {
		return TransportAccessClaims{}, ErrAccessDenied
	}
	credentialDigest := sha256.Sum256(request.Credential)
	bindingDigest := sha256.Sum256(request.Binding[:])
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	record, ok := issuer.records[credentialDigest]
	if issuer.healthy && ok && subtle.ConstantTimeCompare(record.bindingDigest[:], bindingDigest[:]) == 1 &&
		record.serverIncarnation == issuer.serverIncarnation && issuer.now().Before(record.expiresAt) &&
		record.claims.AuthorityEpoch == current.AuthorityEpoch &&
		record.claims.GrantsRevision == current.GrantsRevision &&
		record.claims.CredentialVersion == current.CredentialVersion &&
		record.claims.RevocationVersion == current.RevocationVersion {
		return record.claims, nil
	}
	return TransportAccessClaims{}, ErrAccessDenied
}

func (issuer *TransportAccessIssuer) Revoke(credential []byte) error {
	if issuer == nil || len(credential) != sha256.Size {
		return ErrAccessDenied
	}
	digest := sha256.Sum256(credential)
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if !issuer.healthy {
		return ErrAccessDenied
	}
	if _, ok := issuer.records[digest]; !ok {
		return ErrAccessDenied
	}
	delete(issuer.records, digest)
	return nil
}

// Restart rotates the opaque server incarnation and invalidates every live
// assertion. Durable actor sessions are deliberately not represented here;
// callers must issue fresh access and explicitly resume them elsewhere.
func (issuer *TransportAccessIssuer) Restart() error {
	if issuer == nil {
		return ErrInvalidAccess
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	issuer.healthy = false
	if err := issuer.rotateIncarnationLocked(); err != nil {
		return err
	}
	clear(issuer.records)
	issuer.healthy = true
	return nil
}

func (issuer *TransportAccessIssuer) rotateIncarnation() error {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.rotateIncarnationLocked()
}

func (issuer *TransportAccessIssuer) rotateIncarnationLocked() error {
	if _, err := io.ReadFull(issuer.random, issuer.serverIncarnation[:]); err != nil {
		clear(issuer.serverIncarnation[:])
		return fmt.Errorf("%w: server incarnation entropy unavailable", ErrInvalidAccess)
	}
	return nil
}

func validTransportClaims(claims TransportAccessClaims) bool {
	return validAccessIdentifier(claims.PrincipalID) && validAccessIdentifier(claims.DeviceID) &&
		validAccessIdentifier(claims.AuthorityEpoch) && claims.GrantsRevision > 0 &&
		claims.CredentialVersion > 0 && claims.RevocationVersion > 0
}

func validTransportCurrent(current TransportAccessCurrent) bool {
	return validAccessIdentifier(current.AuthorityEpoch) && current.GrantsRevision > 0 &&
		current.CredentialVersion > 0 && current.RevocationVersion > 0
}

func validAccessIdentifier(identifier string) bool {
	return identifier != "" && len(identifier) <= credentialIDMaxBytes && strings.TrimSpace(identifier) == identifier
}

// PairingInvitationID is a non-secret lookup identifier.
type PairingInvitationID [16]byte

func (identifier PairingInvitationID) String() string { return hex.EncodeToString(identifier[:]) }

// PairingInvitationSecret is a one-time secret with no serializable fields.
// Bytes returns the deliberate handoff representation.
type PairingInvitationSecret struct {
	material [sha256.Size]byte
}

func (secret PairingInvitationSecret) String() string   { return "[REDACTED pairing invitation]" }
func (secret PairingInvitationSecret) GoString() string { return secret.String() }

func (secret PairingInvitationSecret) Bytes() []byte {
	return append([]byte(nil), secret.material[:]...)
}

type pairingInvitationRecord struct {
	digest    [sha256.Size]byte
	expiresAt time.Time
	attempts  int
	suspended bool
}

// PairingInvitationRegistry enforces one-time use, attempt limits, expiry, and
// explicit proof-of-secret resume after a daemon restart.
type PairingInvitationRegistry struct {
	mu      sync.Mutex
	random  io.Reader
	now     func() time.Time
	records map[PairingInvitationID]pairingInvitationRecord
}

func NewPairingInvitationRegistry(random io.Reader, now func() time.Time) *PairingInvitationRegistry {
	return &PairingInvitationRegistry{random: random, now: now, records: make(map[PairingInvitationID]pairingInvitationRecord)}
}

func (registry *PairingInvitationRegistry) Issue(ttl time.Duration) (PairingInvitationID, PairingInvitationSecret, error) {
	if registry == nil || registry.random == nil || registry.now == nil || ttl <= 0 || ttl > maxPairingInvitationTTL {
		return PairingInvitationID{}, PairingInvitationSecret{}, ErrInvitationInvalid
	}
	var identifier PairingInvitationID
	var secret PairingInvitationSecret
	registry.mu.Lock()
	defer registry.mu.Unlock()
	generated := false
	for range 4 {
		if _, err := io.ReadFull(registry.random, identifier[:]); err != nil {
			return PairingInvitationID{}, PairingInvitationSecret{}, ErrInvitationInvalid
		}
		if _, exists := registry.records[identifier]; !exists {
			generated = true
			break
		}
	}
	if !generated {
		return PairingInvitationID{}, PairingInvitationSecret{}, ErrInvitationInvalid
	}
	if _, err := io.ReadFull(registry.random, secret.material[:]); err != nil {
		clear(secret.material[:])
		return PairingInvitationID{}, PairingInvitationSecret{}, ErrInvitationInvalid
	}
	registry.records[identifier] = pairingInvitationRecord{
		digest: sha256.Sum256(secret.material[:]), expiresAt: registry.now().Add(ttl),
	}
	return identifier, secret, nil
}

func (registry *PairingInvitationRegistry) Restart() {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for identifier, record := range registry.records {
		record.suspended = true
		registry.records[identifier] = record
	}
}

func (registry *PairingInvitationRegistry) Resume(identifier PairingInvitationID, secret PairingInvitationSecret) error {
	return registry.update(identifier, secret, true)
}

func (registry *PairingInvitationRegistry) Redeem(identifier PairingInvitationID, secret PairingInvitationSecret) error {
	return registry.update(identifier, secret, false)
}

func (registry *PairingInvitationRegistry) update(
	identifier PairingInvitationID,
	secret PairingInvitationSecret,
	resume bool,
) error {
	if registry == nil || registry.now == nil || identifier == (PairingInvitationID{}) ||
		secret.material == ([sha256.Size]byte{}) {
		return ErrInvitationInvalid
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	record, ok := registry.records[identifier]
	if !ok || !registry.now().Before(record.expiresAt) || record.attempts >= maxPairingAttempts {
		delete(registry.records, identifier)
		return ErrInvitationInvalid
	}
	presented := sha256.Sum256(secret.material[:])
	if subtle.ConstantTimeCompare(record.digest[:], presented[:]) != 1 {
		record.attempts++
		if record.attempts >= maxPairingAttempts {
			delete(registry.records, identifier)
		} else {
			registry.records[identifier] = record
		}
		return ErrInvitationInvalid
	}
	if resume {
		if !record.suspended {
			return ErrInvitationInvalid
		}
		record.suspended = false
		registry.records[identifier] = record
		return nil
	}
	if record.suspended {
		return ErrInvitationSuspended
	}
	delete(registry.records, identifier)
	return nil
}

// ProofPublicKeyRegistry resolves stable domain key references without placing
// private key material in proof state. Vault-backed references are loaded only
// long enough to derive their public key.
type ProofPublicKeyRegistry struct {
	vault      *CredentialVault
	references map[string]CredentialReference
	publicKeys map[string]ed25519.PublicKey
}

func NewProofPublicKeyRegistry(
	vault *CredentialVault,
	references map[string]CredentialReference,
	publicKeys map[string]ed25519.PublicKey,
) (*ProofPublicKeyRegistry, error) {
	if vault == nil && len(publicKeys) == 0 {
		return nil, ErrSecurityDependency
	}
	registry := &ProofPublicKeyRegistry{
		vault: vault, references: make(map[string]CredentialReference, len(references)),
		publicKeys: make(map[string]ed25519.PublicKey, len(publicKeys)),
	}
	for keyReference, reference := range references {
		if _, err := domain.NewPublicKeyReference(keyReference); err != nil || validateCredentialReference(reference) != nil {
			return nil, ErrInvalidCredential
		}
		registry.references[keyReference] = reference
	}
	for keyReference, publicKey := range publicKeys {
		if _, err := domain.NewPublicKeyReference(keyReference); err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrInvalidCredential
		}
		registry.publicKeys[keyReference] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return registry, nil
}

func (registry *ProofPublicKeyRegistry) resolve(reference domain.PublicKeyReference) (ed25519.PublicKey, error) {
	if registry == nil || reference.String() == "" {
		return nil, ErrSecurityDependency
	}
	if publicKey, exists := registry.publicKeys[reference.String()]; exists {
		return append(ed25519.PublicKey(nil), publicKey...), nil
	}
	vaultReference, exists := registry.references[reference.String()]
	if !exists || registry.vault == nil {
		return nil, ErrCredentialNotFound
	}
	credential, err := registry.vault.LoadCredential(vaultReference)
	if err != nil {
		return nil, err
	}
	defer credential.Destroy()
	return credential.PublicKey()
}

// BootstrapProofContext is verifier-owned state for one bootstrap invitation.
// It contains no invitation secret and is removed after successful redemption.
type BootstrapProofContext struct {
	PairingInvitationID   PairingInvitationID
	InvitationID          domain.InvitationID
	InstallationID        domain.InstallationID
	InstallationKey       domain.PublicKeyReference
	Protocol              domain.PairingProtocol
	Role                  domain.BootstrapRole
	PrincipalID           domain.PrincipalID
	PrincipalDisplayName  domain.DisplayName
	DeviceID              domain.DeviceID
	DeviceDisplayName     domain.DisplayName
	DevicePublicKey       domain.PublicKeyReference
	DeviceSPKIFingerprint domain.CredentialDigest
	OwnerGrantID          domain.GrantID
	OwnerCapabilities     domain.CapabilitySet
	Binding               Binding
}

type ceremonyScope struct {
	InstallationID string `json:"installation_id,omitempty"`
	WorkspaceID    string `json:"workspace_id,omitempty"`
	MembershipID   string `json:"membership_id,omitempty"`
	ActorID        string `json:"actor_id,omitempty"`
	DelegationID   string `json:"delegation_id,omitempty"`
}

// CeremonyProofContext is the complete verifier-owned expectation for one
// challenge. PairingAuthorization is required only for device_pairing.
type CeremonyProofContext struct {
	ChallengeID          domain.CeremonyID
	Purpose              domain.CeremonyPurpose
	PrincipalID          domain.PrincipalID
	DeviceID             domain.DeviceID
	InstallationID       domain.InstallationID
	WorkspaceID          domain.WorkspaceID
	MembershipID         domain.MembershipID
	ActorID              domain.ActorID
	DelegationID         domain.ActorDelegationID
	SignerKey            domain.PublicKeyReference
	Binding              Binding
	ExpiresAt            time.Time
	PairingAuthorization *PairingAuthorizationContext
}

// PairingAuthorizationContext supplies policy output that must be bound into a
// verified device-pairing transcript before a domain authorization is created.
type PairingAuthorizationContext struct {
	AuthorityID           domain.AuthorityID
	AuthorityEpoch        domain.AuthorityEpoch
	PolicyRevision        domain.PolicyRevision
	AssuranceClass        domain.AssuranceClass
	DeviceSPKIFingerprint domain.CredentialDigest
}

type proofChallengeRecord struct {
	context  CeremonyProofContext
	consumed bool
}

// ProofChallengeRegistry owns purpose, scope, expiry, and one-use state.
type ProofChallengeRegistry struct {
	mu         sync.Mutex
	now        func() time.Time
	bootstrap  map[domain.InvitationID]BootstrapProofContext
	ceremonies map[domain.CeremonyID]proofChallengeRecord
}

func NewProofChallengeRegistry(now func() time.Time) *ProofChallengeRegistry {
	return &ProofChallengeRegistry{
		now: now, bootstrap: make(map[domain.InvitationID]BootstrapProofContext),
		ceremonies: make(map[domain.CeremonyID]proofChallengeRecord),
	}
}

func (registry *ProofChallengeRegistry) RegisterBootstrap(context BootstrapProofContext) error {
	if registry == nil || registry.now == nil || !validBootstrapContext(context) {
		return ErrInvalidProof
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.bootstrap[context.InvitationID]; exists {
		return ErrInvalidProof
	}
	registry.bootstrap[context.InvitationID] = context
	return nil
}

func (registry *ProofChallengeRegistry) RegisterCeremony(context CeremonyProofContext) error {
	if registry == nil || registry.now == nil || !validCeremonyContext(context) ||
		!registry.now().Before(context.ExpiresAt) {
		return ErrInvalidProof
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.ceremonies[context.ChallengeID]; exists {
		return ErrInvalidProof
	}
	registry.ceremonies[context.ChallengeID] = proofChallengeRecord{context: context}
	return nil
}

// CryptographicProofVerifier verifies all proof ports that have sufficient
// application context. It retains only verifier-owned metadata and digests.
type CryptographicProofVerifier struct {
	invitations *PairingInvitationRegistry
	keys        *ProofPublicKeyRegistry
	challenges  *ProofChallengeRegistry
}

func NewCryptographicProofVerifier(
	invitations *PairingInvitationRegistry,
	keys *ProofPublicKeyRegistry,
	challenges *ProofChallengeRegistry,
) (*CryptographicProofVerifier, error) {
	if invitations == nil || keys == nil || challenges == nil || challenges.now == nil {
		return nil, ErrSecurityDependency
	}
	return &CryptographicProofVerifier{invitations: invitations, keys: keys, challenges: challenges}, nil
}

type bootstrapProofEnvelopeV1 struct {
	Version             int    `json:"version"`
	Purpose             string `json:"purpose"`
	InvitationID        string `json:"invitation_id"`
	PairingInvitationID string `json:"pairing_invitation_id"`
	Binding             string `json:"channel_binding"`
	ClientNonce         string `json:"client_nonce"`
	ServerNonce         string `json:"server_nonce"`
	InvitationSecret    string `json:"invitation_secret"`
	PairingProof        string `json:"pairing_proof"`
	Signature           string `json:"signature"`
}

type bootstrapTranscriptV1 struct {
	Domain               string   `json:"domain"`
	Version              int      `json:"version"`
	Purpose              string   `json:"purpose"`
	InvitationID         string   `json:"invitation_id"`
	PairingInvitationID  string   `json:"pairing_invitation_id"`
	InstallationID       string   `json:"installation_id"`
	InstallationKey      string   `json:"installation_key"`
	Protocol             string   `json:"protocol"`
	Role                 string   `json:"role"`
	PrincipalID          string   `json:"principal_id"`
	PrincipalDisplayName string   `json:"principal_display_name"`
	DeviceID             string   `json:"device_id"`
	DeviceDisplayName    string   `json:"device_display_name"`
	DevicePublicKey      string   `json:"device_public_key"`
	DeviceSPKI           string   `json:"device_spki_sha256"`
	OwnerGrantID         string   `json:"owner_grant_id"`
	OwnerCapabilities    []string `json:"owner_capabilities"`
	Binding              string   `json:"channel_binding"`
	ClientNonce          string   `json:"client_nonce"`
	ServerNonce          string   `json:"server_nonce"`
}

// NewBootstrapProofEvidence creates the exact opaque envelope accepted by the
// bootstrap verifier. The invitation secret copy is cleared before return.
func NewBootstrapProofEvidence(
	context BootstrapProofContext,
	secret PairingInvitationSecret,
	clientNonce []byte,
	serverNonce []byte,
	signer crypto.Signer,
) (application.BootstrapProofEvidence, error) {
	if !validBootstrapContext(context) || len(clientNonce) == 0 || len(clientNonce) > maxProofNonceBytes ||
		len(serverNonce) == 0 || len(serverNonce) > maxProofNonceBytes {
		return application.BootstrapProofEvidence{}, ErrInvalidProof
	}
	transcript, err := bootstrapTranscript(context, clientNonce, serverNonce)
	if err != nil {
		return application.BootstrapProofEvidence{}, err
	}
	signature, err := SignTranscript(signer, transcript)
	if err != nil {
		return application.BootstrapProofEvidence{}, ErrInvalidProof
	}
	secretBytes := secret.Bytes()
	defer clear(secretBytes)
	pairingProof, err := PairingProof(secretBytes, context.Binding, transcript)
	if err != nil {
		return application.BootstrapProofEvidence{}, err
	}
	envelope := bootstrapProofEnvelopeV1{
		Version: proofEvidenceVersion, Purpose: "bootstrap", InvitationID: context.InvitationID.String(),
		PairingInvitationID: context.PairingInvitationID.String(), Binding: encodeProofBytes(context.Binding[:]),
		ClientNonce: encodeProofBytes(clientNonce), ServerNonce: encodeProofBytes(serverNonce),
		InvitationSecret: encodeProofBytes(secretBytes), PairingProof: encodeProofBytes(pairingProof[:]),
		Signature: encodeProofBytes(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > maxProofEvidenceBytes {
		return application.BootstrapProofEvidence{}, ErrInvalidProof
	}
	return application.NewBootstrapProofEvidence(encoded)
}

func (verifier *CryptographicProofVerifier) VerifyBootstrapProof(
	ctx context.Context,
	evidence application.BootstrapProofEvidence,
) (application.BootstrapProofVerification, error) {
	if err := ctx.Err(); err != nil {
		return application.BootstrapProofVerification{}, err
	}
	var envelope bootstrapProofEnvelopeV1
	if decodeProofEnvelope(evidence.Bytes(), &envelope) != nil || envelope.Version != proofEvidenceVersion ||
		envelope.Purpose != "bootstrap" {
		return application.BootstrapProofVerification{}, ErrInvalidProof
	}
	invitationID, err := domain.ParseInvitationID(envelope.InvitationID)
	if err != nil {
		return application.BootstrapProofVerification{}, ErrInvalidProof
	}
	verifier.challenges.mu.Lock()
	defer verifier.challenges.mu.Unlock()
	expected, exists := verifier.challenges.bootstrap[invitationID]
	if !exists || expected.PairingInvitationID.String() != envelope.PairingInvitationID {
		return verifier.rejectedBootstrap(invitationID, envelope), nil
	}
	clientNonce, clientOK := decodeProofBytes(envelope.ClientNonce, maxProofNonceBytes)
	serverNonce, serverOK := decodeProofBytes(envelope.ServerNonce, maxProofNonceBytes)
	binding, bindingOK := decodeProofArray32(envelope.Binding)
	secretBytes, secretOK := decodeProofArray32(envelope.InvitationSecret)
	presentedProof, proofOK := decodeProofArray32(envelope.PairingProof)
	signature, signatureOK := decodeProofArray64(envelope.Signature)
	defer clear(secretBytes[:])
	transcript, transcriptErr := bootstrapTranscript(expected, clientNonce, serverNonce)
	publicKey, keyErr := verifier.keys.resolve(expected.DevicePublicKey)
	valid := clientOK && serverOK && bindingOK && secretOK && proofOK && signatureOK &&
		binding == [bindingSize]byte(expected.Binding) && transcriptErr == nil && keyErr == nil &&
		VerifyPairingProof(secretBytes[:], expected.Binding, transcript, presentedProof[:]) == nil &&
		VerifyTranscript(publicKey, transcript, signature[:]) == nil
	if !valid {
		return verifier.rejectedBootstrap(invitationID, envelope), nil
	}
	var pairingID PairingInvitationID
	decodedPairingID, decodeErr := hex.DecodeString(envelope.PairingInvitationID)
	if decodeErr != nil || len(decodedPairingID) != len(pairingID) {
		return verifier.rejectedBootstrap(invitationID, envelope), nil
	}
	copy(pairingID[:], decodedPairingID)
	var secret PairingInvitationSecret
	copy(secret.material[:], secretBytes[:])
	if verifier.invitations.Redeem(pairingID, secret) != nil {
		return verifier.rejectedBootstrap(invitationID, envelope), nil
	}
	delete(verifier.challenges.bootstrap, invitationID)
	invitationDigest := domain.CommandFingerprint(sha256.Sum256(secretBytes[:]))
	clientDigest := domain.CommandFingerprint(sha256.Sum256(clientNonce))
	serverDigest := domain.CommandFingerprint(sha256.Sum256(serverNonce))
	proof, err := domain.NewBootstrapProof(domain.BootstrapProofParams{
		InvitationID: expected.InvitationID, InstallationID: expected.InstallationID,
		InstallationKey: expected.InstallationKey, InvitationEvidence: invitationDigest,
		TranscriptFingerprint: domain.CommandFingerprint(transcript), ClientNonceDigest: clientDigest,
		ServerNonceDigest: serverDigest, Protocol: expected.Protocol, Role: expected.Role,
		PrincipalID: expected.PrincipalID, PrincipalDisplayName: expected.PrincipalDisplayName,
		DeviceID: expected.DeviceID, DeviceDisplayName: expected.DeviceDisplayName,
		DevicePublicKey: expected.DevicePublicKey, DeviceSPKIFingerprint: expected.DeviceSPKIFingerprint,
		OwnerGrantID: expected.OwnerGrantID, OwnerCapabilities: expected.OwnerCapabilities,
	})
	if err != nil {
		return application.BootstrapProofVerification{}, ErrInvalidProof
	}
	return application.VerifiedBootstrapProof(proof), nil
}

func (verifier *CryptographicProofVerifier) rejectedBootstrap(
	invitationID domain.InvitationID,
	envelope bootstrapProofEnvelopeV1,
) application.BootstrapProofVerification {
	transcript := domain.CommandFingerprint(sha256.Sum256([]byte("blackbird-bootstrap-rejected/v1\x00" + envelope.InvitationID)))
	client := domain.CommandFingerprint(sha256.Sum256([]byte(envelope.ClientNonce)))
	server := domain.CommandFingerprint(sha256.Sum256([]byte(envelope.ServerNonce)))
	binding := domain.CommandFingerprint(sha256.Sum256([]byte(envelope.Binding)))
	presented := domain.CommandFingerprint(sha256.Sum256([]byte(envelope.PairingProof + envelope.Signature)))
	attempt, err := application.NewBootstrapAttempt(invitationID, transcript, client, server, binding, presented)
	if err != nil {
		return application.BootstrapProofVerification{}
	}
	return application.RejectedBootstrapProof(attempt)
}

type ceremonyProofEnvelopeV1 struct {
	Version     int           `json:"version"`
	Purpose     string        `json:"purpose"`
	ChallengeID string        `json:"challenge_id"`
	PrincipalID string        `json:"principal_id"`
	DeviceID    string        `json:"device_id,omitempty"`
	Scope       ceremonyScope `json:"scope"`
	Binding     string        `json:"channel_binding"`
	Signature   string        `json:"signature"`
}

type ceremonyTranscriptV1 struct {
	Domain      string        `json:"domain"`
	Version     int           `json:"version"`
	Purpose     string        `json:"purpose"`
	ChallengeID string        `json:"challenge_id"`
	PrincipalID string        `json:"principal_id"`
	DeviceID    string        `json:"device_id,omitempty"`
	Scope       ceremonyScope `json:"scope"`
	SignerKey   string        `json:"signer_key"`
	Binding     string        `json:"channel_binding"`
}

func NewCeremonyProofEvidence(
	context CeremonyProofContext,
	signer crypto.Signer,
) (application.CeremonyProofEvidence, error) {
	if !validCeremonyContext(context) {
		return application.CeremonyProofEvidence{}, ErrInvalidProof
	}
	transcript, err := ceremonyTranscript(context)
	if err != nil {
		return application.CeremonyProofEvidence{}, err
	}
	signature, err := SignTranscript(signer, transcript)
	if err != nil {
		return application.CeremonyProofEvidence{}, ErrInvalidProof
	}
	envelope := ceremonyEnvelope(context)
	envelope.Signature = encodeProofBytes(signature)
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > maxProofEvidenceBytes {
		return application.CeremonyProofEvidence{}, ErrInvalidProof
	}
	return application.NewCeremonyProofEvidence(encoded)
}

func (verifier *CryptographicProofVerifier) VerifyMembershipAcceptance(ctx context.Context, evidence application.CeremonyProofEvidence) (application.CeremonyProofVerification, error) {
	return verifier.verifyCeremony(ctx, evidence, domain.CeremonyPurposeMembershipAcceptance)
}

func (verifier *CryptographicProofVerifier) VerifyDelegationActivation(ctx context.Context, evidence application.CeremonyProofEvidence) (application.CeremonyProofVerification, error) {
	return verifier.verifyCeremony(ctx, evidence, domain.CeremonyPurposeDelegationActivation)
}

func (verifier *CryptographicProofVerifier) VerifyActorSessionHandoff(ctx context.Context, evidence application.CeremonyProofEvidence) (application.CeremonyProofVerification, error) {
	return verifier.verifyCeremony(ctx, evidence, domain.CeremonyPurposeActorSessionStart)
}

func (verifier *CryptographicProofVerifier) verifyCeremony(
	ctx context.Context,
	evidence application.CeremonyProofEvidence,
	purpose domain.CeremonyPurpose,
) (application.CeremonyProofVerification, error) {
	proof, subject, valid, err := verifier.verifyCeremonyProof(ctx, evidence, purpose, false)
	if err != nil {
		return application.CeremonyProofVerification{}, err
	}
	if valid {
		return application.ValidCeremonyProof(proof)
	}
	return application.RejectedCeremonyProof(subject)
}

func (verifier *CryptographicProofVerifier) VerifyPairingRedemption(
	ctx context.Context,
	evidence application.CeremonyProofEvidence,
) (application.PairingRedemptionDecision, error) {
	proof, subject, valid, err := verifier.verifyCeremonyProof(ctx, evidence, domain.CeremonyPurposeDevicePairing, true)
	if err != nil {
		return application.PairingRedemptionDecision{}, err
	}
	if !valid {
		return application.RejectedPairingRedemption(subject)
	}
	verifier.challenges.mu.Lock()
	record := verifier.challenges.ceremonies[proof.ChallengeID()]
	delete(verifier.challenges.ceremonies, proof.ChallengeID())
	verifier.challenges.mu.Unlock()
	context := record.context
	authorizationContext := context.PairingAuthorization
	credential, err := domain.NewDeviceCredentialBinding(
		context.SignerKey, authorizationContext.DeviceSPKIFingerprint, proof.ProofDigest(),
	)
	if err != nil {
		return application.PairingRedemptionDecision{}, ErrInvalidProof
	}
	authorization, err := domain.NewPairingRedemptionAuthorization(
		authorizationContext.AuthorityID, authorizationContext.AuthorityEpoch, context.InstallationID,
		context.PrincipalID, context.DeviceID, authorizationContext.PolicyRevision,
		authorizationContext.AssuranceClass, verifier.challenges.now(), context.ChallengeID,
		proof.ProofDigest(), credential,
	)
	if err != nil {
		return application.PairingRedemptionDecision{}, ErrInvalidProof
	}
	verification, err := application.NewPairingRedemptionVerification(authorization, proof)
	if err != nil {
		return application.PairingRedemptionDecision{}, err
	}
	return application.ValidPairingRedemption(verification)
}

func (verifier *CryptographicProofVerifier) verifyCeremonyProof(
	ctx context.Context,
	evidence application.CeremonyProofEvidence,
	purpose domain.CeremonyPurpose,
	preserveRecord bool,
) (domain.CeremonyProof, application.DenialSubject, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.CeremonyProof{}, application.DenialSubject{}, false, err
	}
	raw := evidence.Bytes()
	var envelope ceremonyProofEnvelopeV1
	if decodeProofEnvelope(raw, &envelope) != nil || envelope.Version != proofEvidenceVersion || envelope.Purpose != string(purpose) {
		subject, _ := application.UnattributedDenialSource(application.DigestBytes(raw))
		return domain.CeremonyProof{}, subject, false, nil
	}
	challengeID, err := domain.ParseCeremonyID(envelope.ChallengeID)
	if err != nil {
		subject, _ := application.UnattributedDenialSource(application.DigestBytes(raw))
		return domain.CeremonyProof{}, subject, false, nil
	}
	verifier.challenges.mu.Lock()
	defer verifier.challenges.mu.Unlock()
	record, exists := verifier.challenges.ceremonies[challengeID]
	subject := denialSubject(envelope, raw)
	if exists {
		var device *domain.DeviceID
		if !record.context.DeviceID.IsZero() {
			device = &record.context.DeviceID
		}
		subject, _ = application.AttributedDenialSubject(record.context.PrincipalID, device)
	}
	if !exists || record.consumed || !verifier.challenges.now().Before(record.context.ExpiresAt) ||
		record.context.Purpose != purpose || ceremonyEnvelope(record.context).unsigned() != envelope.unsigned() {
		return domain.CeremonyProof{}, subject, false, nil
	}
	transcript, transcriptErr := ceremonyTranscript(record.context)
	publicKey, keyErr := verifier.keys.resolve(record.context.SignerKey)
	signature, signatureOK := decodeProofArray64(envelope.Signature)
	if transcriptErr != nil || keyErr != nil || !signatureOK || VerifyTranscript(publicKey, transcript, signature[:]) != nil {
		return domain.CeremonyProof{}, subject, false, nil
	}
	record.consumed = true
	if preserveRecord {
		verifier.challenges.ceremonies[challengeID] = record
	} else {
		delete(verifier.challenges.ceremonies, challengeID)
	}
	proof, err := domain.NewCeremonyProof(
		challengeID, purpose, domain.CommandFingerprint(transcript), record.context.PrincipalID, record.context.DeviceID,
	)
	if err != nil {
		return domain.CeremonyProof{}, application.DenialSubject{}, false, ErrInvalidProof
	}
	return proof, application.DenialSubject{}, true, nil
}

type unsignedCeremonyEnvelope struct {
	Version     int
	Purpose     string
	ChallengeID string
	PrincipalID string
	DeviceID    string
	Scope       ceremonyScope
	Binding     string
}

func (envelope ceremonyProofEnvelopeV1) unsigned() unsignedCeremonyEnvelope {
	return unsignedCeremonyEnvelope{
		envelope.Version, envelope.Purpose, envelope.ChallengeID, envelope.PrincipalID,
		envelope.DeviceID, envelope.Scope, envelope.Binding,
	}
}

func ceremonyEnvelope(context CeremonyProofContext) ceremonyProofEnvelopeV1 {
	return ceremonyProofEnvelopeV1{
		Version: proofEvidenceVersion, Purpose: string(context.Purpose), ChallengeID: context.ChallengeID.String(),
		PrincipalID: context.PrincipalID.String(), DeviceID: context.DeviceID.String(),
		Scope: ceremonyScope{
			InstallationID: context.InstallationID.String(), WorkspaceID: context.WorkspaceID.String(),
			MembershipID: context.MembershipID.String(), ActorID: context.ActorID.String(),
			DelegationID: context.DelegationID.String(),
		},
		Binding: encodeProofBytes(context.Binding[:]),
	}
}

func ceremonyTranscript(context CeremonyProofContext) (TranscriptHash, error) {
	envelope := ceremonyEnvelope(context)
	canonical, err := json.Marshal(ceremonyTranscriptV1{
		Domain: "blackbird-ceremony-proof/v1", Version: envelope.Version, Purpose: envelope.Purpose,
		ChallengeID: envelope.ChallengeID, PrincipalID: envelope.PrincipalID, DeviceID: envelope.DeviceID,
		Scope: envelope.Scope, SignerKey: context.SignerKey.String(), Binding: envelope.Binding,
	})
	if err != nil {
		return TranscriptHash{}, ErrInvalidTranscript
	}
	return HashTranscript(canonical)
}

func bootstrapTranscript(context BootstrapProofContext, clientNonce, serverNonce []byte) (TranscriptHash, error) {
	capabilities := context.OwnerCapabilities.Values()
	capabilityNames := make([]string, len(capabilities))
	for index, capability := range capabilities {
		capabilityNames[index] = capability.String()
	}
	spkiFingerprint := context.DeviceSPKIFingerprint.Bytes()
	canonical, err := json.Marshal(bootstrapTranscriptV1{
		Domain: "blackbird-bootstrap-proof/v1", Version: proofEvidenceVersion, Purpose: "bootstrap",
		InvitationID: context.InvitationID.String(), PairingInvitationID: context.PairingInvitationID.String(),
		InstallationID: context.InstallationID.String(), InstallationKey: context.InstallationKey.String(),
		Protocol: string(context.Protocol), Role: string(context.Role), PrincipalID: context.PrincipalID.String(),
		PrincipalDisplayName: context.PrincipalDisplayName.String(), DeviceID: context.DeviceID.String(),
		DeviceDisplayName: context.DeviceDisplayName.String(), DevicePublicKey: context.DevicePublicKey.String(),
		DeviceSPKI: hex.EncodeToString(spkiFingerprint[:]), OwnerGrantID: context.OwnerGrantID.String(),
		OwnerCapabilities: capabilityNames, Binding: encodeProofBytes(context.Binding[:]),
		ClientNonce: encodeProofBytes(clientNonce), ServerNonce: encodeProofBytes(serverNonce),
	})
	if err != nil {
		return TranscriptHash{}, ErrInvalidTranscript
	}
	return HashTranscript(canonical)
}

func validBootstrapContext(context BootstrapProofContext) bool {
	return context.PairingInvitationID != (PairingInvitationID{}) && !context.InvitationID.IsZero() &&
		!context.InstallationID.IsZero() && context.InstallationKey.String() != "" && context.Protocol.Valid() &&
		context.Role.Valid() && !context.PrincipalID.IsZero() && context.PrincipalDisplayName.String() != "" &&
		!context.DeviceID.IsZero() && context.DeviceDisplayName.String() != "" && context.DevicePublicKey.String() != "" &&
		!context.DeviceSPKIFingerprint.IsZero() && !context.OwnerGrantID.IsZero() &&
		!context.OwnerCapabilities.IsZero() && context.Binding != (Binding{})
}

func validCeremonyContext(context CeremonyProofContext) bool {
	if context.ChallengeID.IsZero() || !context.Purpose.Valid() || context.PrincipalID.IsZero() ||
		context.SignerKey.String() == "" || context.Binding == (Binding{}) || context.ExpiresAt.IsZero() {
		return false
	}
	switch context.Purpose {
	case domain.CeremonyPurposeMembershipAcceptance:
		return !context.WorkspaceID.IsZero() && !context.MembershipID.IsZero() && context.InstallationID.IsZero() &&
			context.ActorID.IsZero() && context.DelegationID.IsZero() && context.DeviceID.IsZero() && context.PairingAuthorization == nil
	case domain.CeremonyPurposeDelegationActivation, domain.CeremonyPurposeActorSessionStart:
		return !context.WorkspaceID.IsZero() && !context.ActorID.IsZero() && !context.DelegationID.IsZero() &&
			context.InstallationID.IsZero() && context.MembershipID.IsZero() && context.DeviceID.IsZero() && context.PairingAuthorization == nil
	case domain.CeremonyPurposeDevicePairing:
		authorization := context.PairingAuthorization
		return !context.InstallationID.IsZero() && !context.DeviceID.IsZero() && context.WorkspaceID.IsZero() &&
			context.MembershipID.IsZero() && context.ActorID.IsZero() && context.DelegationID.IsZero() && authorization != nil &&
			!authorization.AuthorityID.IsZero() && !authorization.AuthorityEpoch.IsZero() &&
			authorization.PolicyRevision.String() != "" && authorization.AssuranceClass.String() != "" &&
			!authorization.DeviceSPKIFingerprint.IsZero()
	default:
		return false
	}
}

func denialSubject(envelope ceremonyProofEnvelopeV1, raw []byte) application.DenialSubject {
	principal, principalErr := domain.ParsePrincipalID(envelope.PrincipalID)
	if principalErr == nil {
		if envelope.DeviceID == "" {
			subject, _ := application.AttributedDenialSubject(principal, nil)
			return subject
		}
		device, deviceErr := domain.ParseDeviceID(envelope.DeviceID)
		if deviceErr == nil {
			subject, _ := application.AttributedDenialSubject(principal, &device)
			return subject
		}
	}
	subject, _ := application.UnattributedDenialSource(application.DigestBytes(raw))
	return subject
}

func decodeProofEnvelope(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > maxProofEvidenceBytes {
		return ErrInvalidProof
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidProof
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidProof
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return ErrInvalidProof
	}
	return nil
}

func encodeProofBytes(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func decodeProofBytes(encoded string, maximum int) ([]byte, bool) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return decoded, err == nil && len(decoded) > 0 && len(decoded) <= maximum
}

func decodeProofArray32(encoded string) ([sha256.Size]byte, bool) {
	var fixed [sha256.Size]byte
	decoded, valid := decodeProofBytes(encoded, len(fixed))
	if !valid || len(decoded) != len(fixed) {
		return fixed, false
	}
	copy(fixed[:], decoded)
	return fixed, true
}

func decodeProofArray64(encoded string) ([ed25519.SignatureSize]byte, bool) {
	var fixed [ed25519.SignatureSize]byte
	decoded, valid := decodeProofBytes(encoded, len(fixed))
	if !valid || len(decoded) != len(fixed) {
		return fixed, false
	}
	copy(fixed[:], decoded)
	return fixed, true
}

// SPKIPin is SHA-256 over the canonical DER SubjectPublicKeyInfo encoding.
type SPKIPin [sha256.Size]byte

// Binding is a fixed-size tls-exporter channel binding.
type Binding [bindingSize]byte

// TranscriptHash is the SHA-256 digest of an already JCS-canonical transcript.
type TranscriptHash [sha256.Size]byte

// CertificateValidity fixes the identity certificate's validity window.
type CertificateValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// NewCertificate creates a self-signed Ed25519 client/server certificate from
// an Ed25519 seed or private key. The caller remains responsible for keeping
// the supplied key material in a credential vault.
func NewCertificate(keyMaterial []byte, validity CertificateValidity) (tls.Certificate, SPKIPin, error) {
	privateKey, err := privateKeyFromMaterial(keyMaterial)
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return newCertificate(publicKey, privateKey, validity)
}

func newCertificate(
	publicKey ed25519.PublicKey,
	privateKey crypto.Signer,
	validity CertificateValidity,
) (tls.Certificate, SPKIPin, error) {
	pin, err := PinPublicKey(publicKey)
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, err
	}
	if validity.NotBefore.IsZero() || !validity.NotAfter.After(validity.NotBefore) {
		return tls.Certificate{}, SPKIPin{}, ErrInvalidCertificate
	}

	serialBytes := append([]byte(nil), pin[:20]...)
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Blackbird local peer"},
		NotBefore:    validity.NotBefore.UTC(),
		NotAfter:     validity.NotAfter.UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, fmt.Errorf("%w: create certificate", ErrInvalidCertificate)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, SPKIPin{}, fmt.Errorf("%w: parse certificate", ErrInvalidCertificate)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, pin, nil
}

// PinPublicKey returns the canonical SHA-256 SPKI pin for an Ed25519 key.
func PinPublicKey(publicKey ed25519.PublicKey) (SPKIPin, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return SPKIPin{}, ErrInvalidKeyMaterial
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return SPKIPin{}, fmt.Errorf("%w: marshal SPKI", ErrInvalidKeyMaterial)
	}
	return sha256.Sum256(spki), nil
}

// PairingClientTLSConfig creates the first-contact TLS client. The daemon is
// pinned from the invitation; the not-yet-trusted client key is authenticated
// by the signed pairing transcript rather than a client certificate.
// InsecureSkipVerify is intentional: ambient roots and DNS identity are
// replaced by VerifyConnection's certificate, key-usage, and SPKI checks.
func PairingClientTLSConfig(serverPins ...SPKIPin) (*tls.Config, error) {
	if err := validatePins(serverPins); err != nil {
		return nil, err
	}
	pins := append([]SPKIPin(nil), serverPins...)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Verification is pin-based below; no ambient roots.
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPinnedPeer(state, pins, x509.ExtKeyUsageServerAuth, time.Now())
		},
	}, nil
}

// PairingServerTLSConfig creates the daemon side of first-contact TLS. Client
// authentication is completed by the exporter-bound transcript protocol.
func PairingServerTLSConfig(certificate tls.Certificate) (*tls.Config, error) {
	if err := validateLocalCertificate(certificate); err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert,
	}, nil
}

// PairedClientTLSConfig creates a TLS 1.3-only mTLS client with explicit server pins.
func PairedClientTLSConfig(certificate tls.Certificate, serverPins ...SPKIPin) (*tls.Config, error) {
	if err := validateLocalCertificate(certificate); err != nil {
		return nil, err
	}
	config, err := PairingClientTLSConfig(serverPins...)
	if err != nil {
		return nil, err
	}
	config.Certificates = []tls.Certificate{certificate}
	return config, nil
}

// PairedServerTLSConfig creates a TLS 1.3-only mTLS server with explicit client pins.
// RequireAnyClientCert obtains a certificate without consulting ambient roots;
// VerifyConnection performs the complete peer check.
func PairedServerTLSConfig(certificate tls.Certificate, clientPins ...SPKIPin) (*tls.Config, error) {
	if err := validateLocalCertificate(certificate); err != nil {
		return nil, err
	}
	if err := validatePins(clientPins); err != nil {
		return nil, err
	}
	pins := append([]SPKIPin(nil), clientPins...)
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPinnedPeer(state, pins, x509.ExtKeyUsageClientAuth, time.Now())
		},
	}, nil
}

// PairingBinding derives the reviewed pairing channel-binding value.
func PairingBinding(state tls.ConnectionState) (Binding, error) {
	return exportBinding(state, pairingExporterLabel)
}

// SessionBinding derives the reviewed paired-session channel-binding value.
func SessionBinding(state tls.ConnectionState) (Binding, error) {
	return exportBinding(state, sessionExporterLabel)
}

// HashTranscript hashes an already validated RFC 8785 JCS encoding. This
// boundary intentionally does not accept or normalize noncanonical JSON.
func HashTranscript(canonicalJCS []byte) (TranscriptHash, error) {
	if len(canonicalJCS) == 0 {
		return TranscriptHash{}, ErrInvalidTranscript
	}
	return sha256.Sum256(canonicalJCS), nil
}

// SignTranscript signs the transcript digest under the reviewed domain through
// an Ed25519 signer, including a vault-backed Ed25519Credential.
func SignTranscript(signer crypto.Signer, transcript TranscriptHash) ([]byte, error) {
	if signer == nil || transcript == (TranscriptHash{}) {
		return nil, ErrInvalidTranscript
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidTranscript
	}
	signature, err := signer.Sign(rand.Reader, transcriptMessage(transcript), crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidTranscript
	}
	return signature, nil
}

// VerifyTranscript verifies a transcript signature and its domain binding.
func VerifyTranscript(publicKey ed25519.PublicKey, transcript TranscriptHash, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize || transcript == (TranscriptHash{}) ||
		len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, transcriptMessage(transcript), signature) {
		return ErrInvalidTranscript
	}
	return nil
}

// PairingProof computes HMAC-SHA-256(secret, exporter || transcript_hash).
func PairingProof(invitationSecret []byte, binding Binding, transcript TranscriptHash) ([sha256.Size]byte, error) {
	if len(invitationSecret) != 32 || binding == (Binding{}) || transcript == (TranscriptHash{}) {
		return [sha256.Size]byte{}, ErrInvalidProof
	}
	mac := hmac.New(sha256.New, invitationSecret)
	_, _ = mac.Write(binding[:])
	_, _ = mac.Write(transcript[:])
	var proof [sha256.Size]byte
	copy(proof[:], mac.Sum(nil))
	return proof, nil
}

// VerifyPairingProof compares a presented proof without exposing it in errors.
func VerifyPairingProof(invitationSecret []byte, binding Binding, transcript TranscriptHash, proof []byte) error {
	want, err := PairingProof(invitationSecret, binding, transcript)
	if err != nil || len(proof) != sha256.Size || subtle.ConstantTimeCompare(want[:], proof) != 1 {
		return ErrInvalidProof
	}
	return nil
}

func privateKeyFromMaterial(material []byte) (ed25519.PrivateKey, error) {
	var privateKey ed25519.PrivateKey
	switch len(material) {
	case ed25519.SeedSize:
		seed := append([]byte(nil), material...)
		privateKey = ed25519.NewKeyFromSeed(seed)
		clear(seed)
	case ed25519.PrivateKeySize:
		privateKey = append(ed25519.PrivateKey(nil), material...)
		derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
		if subtle.ConstantTimeCompare(privateKey, derived) != 1 {
			clear(privateKey)
			return nil, ErrInvalidKeyMaterial
		}
	default:
		return nil, ErrInvalidKeyMaterial
	}
	return privateKey, nil
}

func validPrivateKey(privateKey ed25519.PrivateKey) bool {
	if len(privateKey) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	return subtle.ConstantTimeCompare(privateKey, derived) == 1
}

func validateLocalCertificate(certificate tls.Certificate) error {
	if len(certificate.Certificate) != 1 || certificate.PrivateKey == nil {
		return ErrInvalidCertificate
	}
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return ErrInvalidCertificate
		}
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	signer, signerOK := certificate.PrivateKey.(crypto.Signer)
	if !ok || !signerOK {
		return ErrInvalidCertificate
	}
	signerPublicKey, publicOK := signer.Public().(ed25519.PublicKey)
	if !publicOK || len(signerPublicKey) != ed25519.PublicKeySize || !signerPublicKey.Equal(publicKey) {
		return ErrInvalidCertificate
	}
	if privateKey, privateOK := certificate.PrivateKey.(ed25519.PrivateKey); privateOK && !validPrivateKey(privateKey) {
		return ErrInvalidCertificate
	}
	return nil
}

func validatePins(pins []SPKIPin) error {
	if len(pins) == 0 {
		return ErrInvalidPin
	}
	for _, pin := range pins {
		if pin == (SPKIPin{}) {
			return ErrInvalidPin
		}
	}
	return nil
}

func verifyPinnedPeer(state tls.ConnectionState, pins []SPKIPin, usage x509.ExtKeyUsage, now time.Time) error {
	// VerifyConnection runs before ConnectionState.HandshakeComplete is set.
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) != 1 {
		return ErrPeerVerification
	}
	peer := state.PeerCertificates[0]
	publicKey, ok := peer.PublicKey.(ed25519.PublicKey)
	if !ok || now.Before(peer.NotBefore) || now.After(peer.NotAfter) || peer.IsCA ||
		peer.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasUsage(peer, usage) ||
		peer.CheckSignature(peer.SignatureAlgorithm, peer.RawTBSCertificate, peer.Signature) != nil {
		return ErrPeerVerification
	}
	pin, err := PinPublicKey(publicKey)
	if err != nil {
		return ErrPeerVerification
	}
	for _, expected := range pins {
		if subtle.ConstantTimeCompare(pin[:], expected[:]) == 1 {
			return nil
		}
	}
	return ErrPeerVerification
}

func hasUsage(certificate *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == want {
			return true
		}
	}
	return false
}

func exportBinding(state tls.ConnectionState, label string) (Binding, error) {
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return Binding{}, ErrExporter
	}
	material, err := state.ExportKeyingMaterial(label, nil, bindingSize)
	if err != nil || len(material) != bindingSize {
		return Binding{}, ErrExporter
	}
	var binding Binding
	copy(binding[:], material)
	clear(material)
	return binding, nil
}

func transcriptMessage(transcript TranscriptHash) []byte {
	message := make([]byte, 2+len(transcriptDomain)+len(transcript))
	binary.BigEndian.PutUint16(message[:2], uint16(len(transcriptDomain)))
	copy(message[2:], transcriptDomain)
	copy(message[2+len(transcriptDomain):], transcript[:])
	return message
}
