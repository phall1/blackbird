package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	// MaxCanonicalJSONBytes bounds every v1 hash view before a narrower
	// profile-specific limit is applied.
	// A semantic event envelope may contain a maximum-sized 64 KiB payload
	// plus its bounded journal metadata. Payload and field-specific limits are
	// enforced by their typed constructors before this outer document bound.
	MaxCanonicalJSONBytes = 2 * domain.MaxEventPayloadBytes
	// MaxCanonicalJSONDepth counts the root array or object as depth one.
	MaxCanonicalJSONDepth = domain.MaxEventPayloadDepth
	maxCanonicalIDBytes   = 255
)

var (
	ErrCanonicalEncoding   = errors.New("canonical encoding failed")
	ErrCanonicalSchema     = errors.New("invalid canonical schema")
	ErrCanonicalJSON       = errors.New("invalid canonical JSON")
	ErrCanonicalLimit      = errors.New("canonical encoding limit exceeded")
	ErrCanonicalNumber     = errors.New("invalid canonical number")
	ErrCanonicalIdentifier = errors.New("invalid canonical identifier")
	ErrCanonicalInstant    = errors.New("invalid canonical instant")
	ErrCanonicalProfile    = errors.New("invalid canonical hash profile")
)

const (
	commandFingerprintDomain   = "blackbird.command-fingerprint/v1\x00"
	authorizationGuardDomain   = "blackbird.authorization-guards/v1\x00"
	receiptResultDomain        = "blackbird.receipt-result/v1\x00"
	sessionBindingDomain       = "blackbird.session-binding/v1\x00"
	recoveryCapsuleDomain      = "blackbird.recovery-capsule/v1\x00"
	commandDenialDomain        = "blackbird-command-denial/v1\x00"
	bootstrapAttemptDomain     = "blackbird-bootstrap-attempt/v1\x00"
	eventDigestDomain          = "blackbird.event-digest/v1\x00"
	streamGenesisDomain        = "blackbird.stream-genesis/v1\x00"
	streamChainDomain          = "blackbird.stream-chain/v1\x00"
	auditEntryDomain           = "blackbird-audit-entry/v1\x00"
	auditReceiptIdentityDomain = "blackbird.audit-receipt-identity/v1\x00"
)

// CanonicalView is deliberately sealed to the application package. Every
// cryptographic view is a reviewed, typed struct; raw JSON and maps cannot
// cross this boundary.
type CanonicalView interface{ canonicalView() }

type CommandHashView interface {
	CanonicalView
	commandHashView()
}

type AuthorizationGuardHashView interface {
	CanonicalView
	authorizationGuardHashView()
}

type ReceiptResultHashView interface {
	CanonicalView
	receiptResultHashView()
}

type RecoveryCapsuleHashView interface {
	CanonicalView
	recoveryCapsuleHashView()
}

type CommandDenialHashView interface {
	CanonicalView
	commandDenialHashView()
}

type BootstrapAttemptHashView interface {
	CanonicalView
	bootstrapAttemptHashView()
}

type EventSemanticHashView interface {
	CanonicalView
	eventSemanticHashView()
}

type StreamGenesisHashView interface {
	CanonicalView
	streamGenesisHashView()
}

type AuditEntryHashView interface {
	CanonicalView
	auditEntryHashView()
}

// IdentityFactPayloadView is the closed payload catalog for the eleven W0
// identity facts. Implementations are package-sealed so arbitrary JSON cannot
// become journal payload material.
type IdentityFactPayloadView interface {
	CanonicalView
	identityFactPayloadView()
}

// canonicalScalar marks reviewed scalar wrappers whose private state is
// exposed only through a validating JSON marshaler.
type canonicalScalar interface{ canonicalScalar() }

// ProductionCanonicalCodec is Blackbird's pinned RFC 8785 implementation. It
// validates the typed schema and JSON both before and after transformation.
type ProductionCanonicalCodec struct{}

func NewProductionCanonicalCodec() ProductionCanonicalCodec { return ProductionCanonicalCodec{} }

func (ProductionCanonicalCodec) EncodeCanonical(value CanonicalView) ([]byte, error) {
	return encodeCanonical(value, MaxCanonicalJSONBytes)
}

type canonicalDocument struct {
	canonical []byte
	digest    Digest
}

func newCanonicalDocument(domainSeparator string, value CanonicalView, maxBytes int) (canonicalDocument, error) {
	canonical, err := encodeCanonical(value, maxBytes)
	if err != nil {
		return canonicalDocument{}, err
	}
	digest := digestCanonical(domainSeparator, canonical)
	return canonicalDocument{canonical: canonical, digest: digest}, nil
}

func (document canonicalDocument) isZero() bool {
	return len(document.canonical) == 0 || document.digest.IsZero()
}

func (document canonicalDocument) canonicalBytes() []byte {
	return append([]byte(nil), document.canonical...)
}

// ReceiptResultDocument is the sealed canonical semantic core of a receipt.
// Its digest includes the catalog-derived capsule_required bit but excludes
// capsule draft, digest, and signature. A later capsule draft binds this
// digest; including capsule output here would make the digest graph cyclic.
// Raw caller bytes cannot construct this value.
type ReceiptResultDocument struct {
	document  canonicalDocument
	operation CommandOperation
	wire      receiptResultWire
}

func (document ReceiptResultDocument) IsZero() bool {
	_, cataloged := receiptCatalog(document.operation)
	return document.document.isZero() || !cataloged
}
func (document ReceiptResultDocument) CanonicalBytes() []byte {
	return document.document.canonicalBytes()
}
func (document ReceiptResultDocument) Digest() Digest { return document.document.digest }
func (document ReceiptResultDocument) Operation() CommandOperation {
	return document.operation
}

func (codec ProductionCanonicalCodec) EncodeReceiptResult(
	view W0ReceiptResultView,
) (ReceiptResultDocument, error) {
	document, err := newCanonicalDocument(receiptResultDomain, view, MaxReceiptResultBytes)
	if err != nil {
		return ReceiptResultDocument{}, err
	}
	return ReceiptResultDocument{
		document: document, operation: view.Operation(), wire: cloneReceiptResultWire(view.wire),
	}, nil
}

// MaterializeReceiptResult is the only production bridge from an applied
// command decision to persisted result bytes. The plan is sealed and contains
// only facts known inside the transaction callback; storage supplies the
// contiguous positions and final stream digest after journal materialization.
// This prevents handlers from predicting or fabricating post-append cursor
// state and prevents a same-operation result from another command being paired
// with the commit.
func (codec ProductionCanonicalCodec) MaterializeReceiptResult(
	plan ReceiptResultPlan,
	firstPosition domain.StreamPosition,
	lastPosition domain.StreamPosition,
	finalStreamDigest domain.StreamDigest,
) (ResultEnvelope, error) {
	catalog, exists := receiptCatalog(plan.Operation())
	if !exists {
		return ResultEnvelope{}, ErrCanonicalProfile
	}
	expectedCapsule := RecoveryCapsuleNotApplicable
	if catalog.capsuleRequired {
		expectedCapsule = RecoveryCapsuleRequired
	}
	if plan.CapsuleRequirement() != expectedCapsule {
		return ResultEnvelope{}, ErrCanonicalProfile
	}
	binding, client, hasSession := plan.Session()
	var bindingPointer *domain.SessionBinding
	if hasSession {
		bindingCopy := binding
		bindingPointer = &bindingCopy
	} else if !client.IsZero() {
		return ResultEnvelope{}, ErrCanonicalProfile
	}
	view, err := NewW0ReceiptResultView(W0ReceiptResultParams{
		Operation: plan.Operation(), AuthorityID: plan.AuthorityID(), AuthorityEpoch: plan.AuthorityEpoch(),
		Scope: plan.Scope(), AcceptedAt: plan.AcceptedAt(), CommandFingerprint: plan.CommandFingerprint(),
		AuthorizationDigest: plan.AuthorizationDigest(), Resources: plan.Resources(),
		IssuedCeremonies: plan.IssuedCeremonies(), FirstEventPosition: firstPosition,
		LastEventPosition: lastPosition, EventIDs: plan.EventIDs(), FinalStreamDigest: finalStreamDigest,
		SessionBinding: bindingPointer, SessionClient: client,
		PresentationCredential: plan.PresentationCredential(),
	})
	if err != nil {
		return ResultEnvelope{}, err
	}
	document, err := codec.EncodeReceiptResult(view)
	if err != nil {
		return ResultEnvelope{}, err
	}
	envelope, err := NewResultEnvelope(document)
	if err != nil {
		return ResultEnvelope{}, err
	}
	return bindResultEnvelopePlan(envelope, plan)
}

// RecoveryCapsuleDocument is a sealed, canonical, profile-bound unsigned
// recovery capsule draft. Trusted constructors accept this type, never bytes.
type RecoveryCapsuleDocument struct {
	document     canonicalDocument
	resultDigest Digest
	signingKeyID string
}

func (document RecoveryCapsuleDocument) IsZero() bool { return document.document.isZero() }
func (document RecoveryCapsuleDocument) CanonicalBytes() []byte {
	return document.document.canonicalBytes()
}
func (document RecoveryCapsuleDocument) Digest() Digest       { return document.document.digest }
func (document RecoveryCapsuleDocument) ResultDigest() Digest { return document.resultDigest }
func (document RecoveryCapsuleDocument) SigningKeyID() string { return document.signingKeyID }
func (document RecoveryCapsuleDocument) MatchesResult(result ReceiptResultDocument) bool {
	return !document.IsZero() && !result.IsZero() && document.resultDigest == result.Digest()
}

func (codec ProductionCanonicalCodec) EncodeRecoveryCapsule(
	view W0RecoveryCapsuleView,
) (RecoveryCapsuleDocument, error) {
	document, err := newCanonicalDocument(recoveryCapsuleDomain, view, MaxRecoveryCapsuleBytes)
	if err != nil {
		return RecoveryCapsuleDocument{}, err
	}
	return RecoveryCapsuleDocument{
		document: document, resultDigest: view.resultDigest, signingKeyID: view.wire.SigningKeyID,
	}, nil
}

// MaterializeRecoveryCapsule derives the complete W0 capsule from the same
// sealed plan used for the receipt result. No adapter-supplied command identity,
// operation major, signing key, resource, event, or result digest is accepted.
func (codec ProductionCanonicalCodec) MaterializeRecoveryCapsule(
	plan ReceiptResultPlan,
	result ResultEnvelope,
) (RecoveryCapsuleDocument, error) {
	if result.IsZero() || plan.RecoveryCapsulePlan().Requirement() != RecoveryCapsuleRequired {
		return RecoveryCapsuleDocument{}, ErrCanonicalProfile
	}
	wire := result.ReceiptDocument().wire
	first, err := domain.NewStreamPosition(wire.Events.FirstPosition)
	if err != nil {
		return RecoveryCapsuleDocument{}, ErrCanonicalProfile
	}
	last, err := domain.NewStreamPosition(wire.Events.LastPosition)
	if err != nil {
		return RecoveryCapsuleDocument{}, ErrCanonicalProfile
	}
	finalDigestBytes, err := hex.DecodeString(wire.Events.FinalStreamDigest.String())
	if err != nil || len(finalDigestBytes) != sha256.Size {
		return RecoveryCapsuleDocument{}, ErrCanonicalProfile
	}
	var finalDigestArray [sha256.Size]byte
	copy(finalDigestArray[:], finalDigestBytes)
	finalDigest, err := domain.NewStreamDigest(finalDigestArray)
	if err != nil {
		return RecoveryCapsuleDocument{}, ErrCanonicalProfile
	}
	expected, err := codec.MaterializeReceiptResult(plan, first, last, finalDigest)
	if err != nil || expected.ResponseDigest() != result.ResponseDigest() ||
		!bytes.Equal(expected.CanonicalBytes(), result.CanonicalBytes()) {
		return RecoveryCapsuleDocument{}, fmt.Errorf("%w: result does not match receipt plan", ErrCanonicalProfile)
	}
	view, err := NewW0RecoveryCapsuleView(
		result, plan.CommandID(), plan.OperationMajor(), plan.RecoveryCapsulePlan(),
	)
	if err != nil {
		return RecoveryCapsuleDocument{}, err
	}
	return codec.EncodeRecoveryCapsule(view)
}

func encodeCanonical(value CanonicalView, maxBytes int) ([]byte, error) {
	if isNilInterface(value) {
		return nil, fmt.Errorf("%w: nil view", ErrCanonicalSchema)
	}
	if err := validateTypedView(reflect.TypeOf(value)); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal typed view: %w", ErrCanonicalEncoding, err)
	}
	return canonicalizeStrict(raw, maxBytes, MaxCanonicalJSONDepth)
}

func canonicalizeStrict(raw []byte, maxBytes, maxDepth int) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > MaxCanonicalJSONBytes || maxDepth <= 0 || maxDepth > MaxCanonicalJSONDepth {
		return nil, fmt.Errorf("%w: invalid codec bound", ErrCanonicalLimit)
	}
	if err := validateStrictJSON(raw, maxBytes, maxDepth); err != nil {
		return nil, err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: RFC 8785 transform: %w", ErrCanonicalEncoding, err)
	}
	if err := validateStrictJSON(canonical, maxBytes, maxDepth); err != nil {
		return nil, fmt.Errorf("%w: transformed output: %w", ErrCanonicalEncoding, err)
	}
	again, err := jcs.Transform(canonical)
	if err != nil || !bytes.Equal(again, canonical) {
		return nil, fmt.Errorf("%w: non-idempotent RFC 8785 output", ErrCanonicalEncoding)
	}
	return canonical, nil
}

// ValidateCanonicalBytes validates retained bytes and requires that they are
// already in their single RFC 8785 representation. It does not turn untyped
// JSON into a hashable view.
func (ProductionCanonicalCodec) ValidateCanonicalBytes(canonical []byte, maxBytes int) error {
	transformed, err := canonicalizeStrict(canonical, maxBytes, MaxCanonicalJSONDepth)
	if err != nil {
		return err
	}
	if !bytes.Equal(transformed, canonical) {
		return fmt.Errorf("%w: input is not RFC 8785 canonical", ErrCanonicalEncoding)
	}
	return nil
}

type canonicalEventPayload struct{ canonical []byte }

func (canonicalEventPayload) canonicalScalar() {}
func (payload canonicalEventPayload) MarshalJSON() ([]byte, error) {
	if len(payload.canonical) == 0 {
		return nil, ErrCanonicalProfile
	}
	return append([]byte(nil), payload.canonical...), nil
}

type identityPayloadInstallationBootstrapped struct {
	InstallationID        CanonicalIdentifier `json:"installation_id"`
	InvitationID          CanonicalIdentifier `json:"invitation_id"`
	PrincipalID           CanonicalIdentifier `json:"principal_id"`
	DeviceID              CanonicalIdentifier `json:"device_id"`
	GrantID               CanonicalIdentifier `json:"grant_id"`
	TranscriptFingerprint CanonicalDigest     `json:"transcript_fingerprint"`
}
type identityPayloadPrincipalRegistered struct {
	InstallationID     CanonicalIdentifier `json:"installation_id"`
	PrincipalID        CanonicalIdentifier `json:"principal_id"`
	Kind               string              `json:"kind"`
	DisplayName        string              `json:"display_name"`
	PublicKeyReference *string             `json:"public_key_reference"`
}
type identityPayloadDevicePairingBegan struct {
	InstallationID     CanonicalIdentifier `json:"installation_id"`
	DeviceID           CanonicalIdentifier `json:"device_id"`
	PrincipalID        CanonicalIdentifier `json:"principal_id"`
	CeremonyID         CanonicalIdentifier `json:"ceremony_id"`
	DisplayName        string              `json:"display_name"`
	PublicKeyReference string              `json:"public_key_reference"`
}
type identityPayloadDevicePaired struct {
	InstallationID                  CanonicalIdentifier `json:"installation_id"`
	DeviceID                        CanonicalIdentifier `json:"device_id"`
	PrincipalID                     CanonicalIdentifier `json:"principal_id"`
	DisplayName                     string              `json:"display_name"`
	TranscriptFingerprint           CanonicalDigest     `json:"transcript_fingerprint"`
	TrustRevision                   uint64              `json:"trust_revision"`
	RevocationRevision              uint64              `json:"revocation_revision"`
	CredentialActivatedAt           CanonicalInstant    `json:"credential_activated_at"`
	CredentialAlgorithm             string              `json:"credential_algorithm"`
	PublicKeyReference              string              `json:"public_key_reference"`
	SPKIFingerprint                 CanonicalDigest     `json:"spki_fingerprint"`
	CredentialTranscriptFingerprint CanonicalDigest     `json:"credential_transcript_fingerprint"`
}
type identityPayloadDeviceCredentialRotated struct {
	DeviceID                    CanonicalIdentifier `json:"device_id"`
	PreviousPublicKeyReference  string              `json:"previous_public_key_reference"`
	PreviousSPKIFingerprint     CanonicalDigest     `json:"previous_spki_fingerprint"`
	ActivePublicKeyReference    string              `json:"active_public_key_reference"`
	ActiveSPKIFingerprint       CanonicalDigest     `json:"active_spki_fingerprint"`
	TrustRevision               uint64              `json:"trust_revision"`
	RevocationRevision          uint64              `json:"revocation_revision"`
	TranscriptFingerprint       CanonicalDigest     `json:"transcript_fingerprint"`
	RotatedAt                   CanonicalInstant    `json:"rotated_at"`
	RetiringCredentialExpiresAt CanonicalInstant    `json:"retiring_credential_expires_at"`
}
type identityPayloadDeviceRevoked struct {
	DeviceID              CanonicalIdentifier `json:"device_id"`
	PublicKeyReference    string              `json:"public_key_reference"`
	SPKIFingerprint       CanonicalDigest     `json:"spki_fingerprint"`
	TrustRevision         uint64              `json:"trust_revision"`
	RevocationRevision    uint64              `json:"revocation_revision"`
	RevocationFingerprint CanonicalDigest     `json:"revocation_fingerprint"`
	RevokedAt             CanonicalInstant    `json:"revoked_at"`
}
type identityPayloadWorkspaceCreated struct {
	WorkspaceID      CanonicalIdentifier `json:"workspace_id"`
	AuthorityID      CanonicalIdentifier `json:"authority_id"`
	AuthorityEpoch   CanonicalIdentifier `json:"authority_epoch"`
	Alias            string              `json:"alias"`
	DiscoveryLocator string              `json:"discovery_locator"`
	PolicyRevision   string              `json:"policy_revision"`
}
type identityPayloadWorkspaceMemberInvited struct {
	MembershipID CanonicalIdentifier  `json:"membership_id"`
	WorkspaceID  CanonicalIdentifier  `json:"workspace_id"`
	PrincipalID  CanonicalIdentifier  `json:"principal_id"`
	CeremonyID   *CanonicalIdentifier `json:"ceremony_id"`
	Capabilities []string             `json:"capabilities"`
}
type identityPayloadWorkspaceMembershipAccepted struct {
	MembershipID CanonicalIdentifier `json:"membership_id"`
	WorkspaceID  CanonicalIdentifier `json:"workspace_id"`
	PrincipalID  CanonicalIdentifier `json:"principal_id"`
}
type identityPayloadActorCreated struct {
	ActorID     CanonicalIdentifier `json:"actor_id"`
	WorkspaceID CanonicalIdentifier `json:"workspace_id"`
	Kind        string              `json:"kind"`
	DisplayName string              `json:"display_name"`
}
type identityPayloadActorDelegationProposed struct {
	DelegationID CanonicalIdentifier `json:"delegation_id"`
	WorkspaceID  CanonicalIdentifier `json:"workspace_id"`
	PrincipalID  CanonicalIdentifier `json:"principal_id"`
	ActorID      CanonicalIdentifier `json:"actor_id"`
	CeremonyID   CanonicalIdentifier `json:"ceremony_id"`
}
type identityPayloadActorDelegationActivated struct {
	DelegationID           CanonicalIdentifier `json:"delegation_id"`
	WorkspaceID            CanonicalIdentifier `json:"workspace_id"`
	PrincipalID            CanonicalIdentifier `json:"principal_id"`
	ActorID                CanonicalIdentifier `json:"actor_id"`
	SessionStartCeremonyID CanonicalIdentifier `json:"session_start_ceremony_id"`
}
type identityPayloadActorSessionStarted struct {
	SessionID                       CanonicalIdentifier `json:"session_id"`
	WorkspaceID                     CanonicalIdentifier `json:"workspace_id"`
	ClientInstanceID                CanonicalIdentifier `json:"client_instance_id"`
	ClientName                      string              `json:"client_name"`
	ClientVersion                   string              `json:"client_version"`
	BindingDigest                   CanonicalDigest     `json:"binding_digest"`
	Capabilities                    []string            `json:"capabilities"`
	PresentationCredentialReference string              `json:"presentation_credential_reference"`
	PresentationCredentialDigest    CanonicalDigest     `json:"presentation_credential_digest"`
	PresentationCredentialAudience  string              `json:"presentation_credential_audience"`
	PresentationCredentialVersion   uint16              `json:"presentation_credential_version"`
}

func (identityPayloadInstallationBootstrapped) canonicalView()              {}
func (identityPayloadInstallationBootstrapped) identityFactPayloadView()    {}
func (identityPayloadPrincipalRegistered) canonicalView()                   {}
func (identityPayloadPrincipalRegistered) identityFactPayloadView()         {}
func (identityPayloadDevicePairingBegan) canonicalView()                    {}
func (identityPayloadDevicePairingBegan) identityFactPayloadView()          {}
func (identityPayloadDevicePaired) canonicalView()                          {}
func (identityPayloadDevicePaired) identityFactPayloadView()                {}
func (identityPayloadDeviceCredentialRotated) canonicalView()               {}
func (identityPayloadDeviceCredentialRotated) identityFactPayloadView()     {}
func (identityPayloadDeviceRevoked) canonicalView()                         {}
func (identityPayloadDeviceRevoked) identityFactPayloadView()               {}
func (identityPayloadWorkspaceCreated) canonicalView()                      {}
func (identityPayloadWorkspaceCreated) identityFactPayloadView()            {}
func (identityPayloadWorkspaceMemberInvited) canonicalView()                {}
func (identityPayloadWorkspaceMemberInvited) identityFactPayloadView()      {}
func (identityPayloadWorkspaceMembershipAccepted) canonicalView()           {}
func (identityPayloadWorkspaceMembershipAccepted) identityFactPayloadView() {}
func (identityPayloadActorCreated) canonicalView()                          {}
func (identityPayloadActorCreated) identityFactPayloadView()                {}
func (identityPayloadActorDelegationProposed) canonicalView()               {}
func (identityPayloadActorDelegationProposed) identityFactPayloadView()     {}
func (identityPayloadActorDelegationActivated) canonicalView()              {}
func (identityPayloadActorDelegationActivated) identityFactPayloadView()    {}
func (identityPayloadActorSessionStarted) canonicalView()                   {}
func (identityPayloadActorSessionStarted) identityFactPayloadView()         {}

func canonicalFactID(text string) (CanonicalIdentifier, error) {
	identifier, err := NewCanonicalIdentifier(text)
	if err != nil {
		return CanonicalIdentifier{}, ErrCanonicalProfile
	}
	return identifier, nil
}

func canonicalFactDigest(bytes [sha256.Size]byte) (CanonicalDigest, error) {
	return NewCanonicalDigest(hex.EncodeToString(bytes[:]))
}

func capabilityStrings(set domain.CapabilitySet) []string {
	values := set.Values()
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

// MaterializeIdentityFactPayload materializes the only payload forms accepted
// by the W0 journal. The returned domain payload contains exact typed JCS bytes.
func (codec ProductionCanonicalCodec) MaterializeIdentityFactPayload(
	fact domain.IdentityFact,
) (domain.EventPayload, error) {
	view, err := identityFactPayloadView(fact)
	if err != nil {
		return domain.EventPayload{}, err
	}
	canonical, err := encodeCanonical(view, domain.MaxEventPayloadBytes)
	if err != nil {
		return domain.EventPayload{}, err
	}
	payload, err := domain.NewEventPayload(canonical)
	if err != nil {
		return domain.EventPayload{}, fmt.Errorf("%w: materialize identity fact payload: %v", ErrCanonicalProfile, err)
	}
	return payload, nil
}

func identityFactPayloadView(fact domain.IdentityFact) (IdentityFactPayloadView, error) {
	if isNilInterface(fact) || reflect.TypeOf(fact).Kind() != reflect.Struct ||
		fact.Origin().IsZero() || fact.Origin().Version().Uint64() > MaxCanonicalInteger {
		return nil, ErrCanonicalProfile
	}
	id := func(text string) CanonicalIdentifier {
		value, _ := canonicalFactID(text)
		return value
	}
	digest := func(value [sha256.Size]byte) CanonicalDigest {
		result, _ := canonicalFactDigest(value)
		return result
	}
	switch value := fact.(type) {
	case domain.InstallationBootstrappedFact:
		return identityPayloadInstallationBootstrapped{
			InstallationID: id(value.InstallationID().String()), InvitationID: id(value.InvitationID().String()),
			PrincipalID: id(value.PrincipalID().String()), DeviceID: id(value.DeviceID().String()),
			GrantID: id(value.GrantID().String()), TranscriptFingerprint: digest([sha256.Size]byte(value.TranscriptFingerprint())),
		}, nil
	case domain.PrincipalRegisteredFact:
		view := identityPayloadPrincipalRegistered{
			InstallationID: id(value.InstallationID().String()), PrincipalID: id(value.PrincipalID().String()),
			Kind: string(value.PrincipalKind()), DisplayName: value.DisplayName().String(),
		}
		if value.PublicKeyReference().String() != "" {
			publicKey := value.PublicKeyReference().String()
			view.PublicKeyReference = &publicKey
		}
		return view, nil
	case domain.DevicePairingBeganFact:
		return identityPayloadDevicePairingBegan{
			InstallationID: id(value.InstallationID().String()), DeviceID: id(value.DeviceID().String()),
			PrincipalID: id(value.PrincipalID().String()),
			CeremonyID:  id(value.CeremonyID().String()), DisplayName: value.DisplayName().String(),
			PublicKeyReference: value.PublicKeyReference().String(),
		}, nil
	case domain.DevicePairedFact:
		credential := value.CredentialBinding()
		activatedAt, err := NewCanonicalInstant(value.CredentialActivatedAt())
		if err != nil {
			return nil, ErrCanonicalProfile
		}
		return identityPayloadDevicePaired{
			InstallationID: id(value.InstallationID().String()), DeviceID: id(value.DeviceID().String()),
			PrincipalID: id(value.PrincipalID().String()),
			DisplayName: value.DisplayName().String(), TranscriptFingerprint: digest([sha256.Size]byte(value.TranscriptFingerprint())),
			TrustRevision: value.TrustRevision().Uint64(), RevocationRevision: value.RevocationRevision().Uint64(),
			CredentialActivatedAt: activatedAt, CredentialAlgorithm: credential.Algorithm(),
			PublicKeyReference:              credential.PublicKeyReference().String(),
			SPKIFingerprint:                 digest(credential.SPKIFingerprint().Bytes()),
			CredentialTranscriptFingerprint: digest([sha256.Size]byte(credential.TranscriptFingerprint())),
		}, nil
	case domain.DeviceCredentialRotatedFact:
		previous, active := value.PreviousCredential(), value.ActiveCredential()
		rotatedAt, rotatedErr := NewCanonicalInstant(value.RotatedAt())
		expiresAt, expiresErr := NewCanonicalInstant(value.RetiringCredentialExpiresAt())
		if rotatedErr != nil || expiresErr != nil {
			return nil, ErrCanonicalProfile
		}
		return identityPayloadDeviceCredentialRotated{
			DeviceID: id(value.DeviceID().String()), PreviousPublicKeyReference: previous.PublicKeyReference().String(),
			PreviousSPKIFingerprint:  digest(previous.SPKIFingerprint().Bytes()),
			ActivePublicKeyReference: active.PublicKeyReference().String(),
			ActiveSPKIFingerprint:    digest(active.SPKIFingerprint().Bytes()), TrustRevision: value.TrustRevision().Uint64(),
			RevocationRevision:    value.RevocationRevision().Uint64(),
			TranscriptFingerprint: digest([sha256.Size]byte(value.TranscriptFingerprint())),
			RotatedAt:             rotatedAt, RetiringCredentialExpiresAt: expiresAt,
		}, nil
	case domain.DeviceRevokedFact:
		credential := value.CredentialBinding()
		revokedAt, err := NewCanonicalInstant(value.RevokedAt())
		if err != nil {
			return nil, ErrCanonicalProfile
		}
		return identityPayloadDeviceRevoked{
			DeviceID: id(value.DeviceID().String()), PublicKeyReference: credential.PublicKeyReference().String(),
			SPKIFingerprint: digest(credential.SPKIFingerprint().Bytes()), TrustRevision: value.TrustRevision().Uint64(),
			RevocationRevision:    value.RevocationRevision().Uint64(),
			RevocationFingerprint: digest([sha256.Size]byte(value.RevocationFingerprint())), RevokedAt: revokedAt,
		}, nil
	case domain.WorkspaceCreatedFact:
		return identityPayloadWorkspaceCreated{
			WorkspaceID: id(value.WorkspaceID().String()), AuthorityID: id(value.AuthorityID().String()),
			AuthorityEpoch: id(value.AuthorityEpoch().String()), Alias: value.Alias().String(),
			DiscoveryLocator: value.DiscoveryLocator().String(), PolicyRevision: value.PolicyRevision().String(),
		}, nil
	case domain.WorkspaceMemberInvitedFact:
		view := identityPayloadWorkspaceMemberInvited{
			MembershipID: id(value.MembershipID().String()), WorkspaceID: id(value.WorkspaceID().String()),
			PrincipalID: id(value.PrincipalID().String()), Capabilities: capabilityStrings(value.Capabilities()),
		}
		if !value.CeremonyID().IsZero() {
			ceremony := id(value.CeremonyID().String())
			view.CeremonyID = &ceremony
		}
		return view, nil
	case domain.WorkspaceMembershipAcceptedFact:
		return identityPayloadWorkspaceMembershipAccepted{
			MembershipID: id(value.MembershipID().String()), WorkspaceID: id(value.WorkspaceID().String()),
			PrincipalID: id(value.PrincipalID().String()),
		}, nil
	case domain.ActorCreatedFact:
		return identityPayloadActorCreated{
			ActorID: id(value.ActorID().String()), WorkspaceID: id(value.WorkspaceID().String()),
			Kind: string(value.ActorKind()), DisplayName: value.Profile().DisplayName().String(),
		}, nil
	case domain.ActorDelegationProposedFact:
		return identityPayloadActorDelegationProposed{
			DelegationID: id(value.DelegationID().String()), WorkspaceID: id(value.WorkspaceID().String()),
			PrincipalID: id(value.PrincipalID().String()), ActorID: id(value.ActorID().String()),
			CeremonyID: id(value.CeremonyID().String()),
		}, nil
	case domain.ActorDelegationActivatedFact:
		return identityPayloadActorDelegationActivated{
			DelegationID: id(value.DelegationID().String()), WorkspaceID: id(value.WorkspaceID().String()),
			PrincipalID: id(value.PrincipalID().String()),
			ActorID:     id(value.ActorID().String()), SessionStartCeremonyID: id(value.SessionStartCeremonyID().String()),
		}, nil
	case domain.ActorSessionStartedFact:
		bindingDigest, digestErr := hashSessionFactBinding(value)
		if digestErr != nil {
			return nil, digestErr
		}
		presentation := value.PresentationCredential()
		return identityPayloadActorSessionStarted{
			SessionID: id(value.SessionID().String()), WorkspaceID: id(value.WorkspaceID().String()),
			ClientInstanceID: id(value.ClientInstanceID().String()),
			ClientName:       value.ClientMetadata().Name(), ClientVersion: value.ClientMetadata().Version(),
			BindingDigest: bindingDigest, Capabilities: capabilityStrings(value.Capabilities()),
			PresentationCredentialReference: presentation.Reference().String(),
			PresentationCredentialDigest:    digest(presentation.Digest().Bytes()),
			PresentationCredentialAudience:  presentation.Audience().String(),
			PresentationCredentialVersion:   presentation.Version(),
		}, nil
	default:
		return nil, ErrCanonicalProfile
	}
}

func hashSessionFactBinding(fact domain.ActorSessionStartedFact) (CanonicalDigest, error) {
	binding := fact.Binding()
	presentation := fact.PresentationCredential()
	identifier := func(text string) (CanonicalIdentifier, error) { return NewCanonicalIdentifier(text) }
	client, err := identifier(fact.ClientInstanceID().String())
	if err != nil {
		return CanonicalDigest{}, err
	}
	authority, err := identifier(binding.AuthorityID().String())
	if err != nil {
		return CanonicalDigest{}, err
	}
	epoch, err := identifier(binding.AuthorityEpoch().String())
	if err != nil {
		return CanonicalDigest{}, err
	}
	workspace, err := identifier(binding.WorkspaceID().String())
	if err != nil {
		return CanonicalDigest{}, err
	}
	principal, err := identifier(binding.PrincipalID().String())
	if err != nil {
		return CanonicalDigest{}, err
	}
	actor, err := identifier(binding.ActorID().String())
	if err != nil {
		return CanonicalDigest{}, err
	}
	membership, err := receiptResource(binding.MembershipRevision())
	if err != nil {
		return CanonicalDigest{}, err
	}
	delegation, err := receiptResource(binding.DelegationRevision())
	if err != nil {
		return CanonicalDigest{}, err
	}
	grants, err := receiptGrantResources(binding.GrantRevisions())
	if err != nil {
		return CanonicalDigest{}, err
	}
	issuedAt, err := NewCanonicalInstant(binding.IssuedAt())
	if err != nil {
		return CanonicalDigest{}, err
	}
	expiry, err := NewCanonicalInstant(binding.AbsoluteExpiry())
	if err != nil {
		return CanonicalDigest{}, err
	}
	presentationDigest, err := canonicalFactDigest(presentation.Digest().Bytes())
	if err != nil {
		return CanonicalDigest{}, err
	}
	view := receiptSessionBindingHashView{
		Schema: "blackbird.session-binding/v1", ClientInstanceID: client, AuthorityID: authority,
		AuthorityEpoch: epoch, WorkspaceID: workspace, PrincipalID: principal, ActorID: actor,
		Membership: membership, Delegation: delegation, Grants: grants,
		PolicyRevision: binding.PolicyRevision().String(), AssuranceClass: binding.AssuranceClass().String(),
		IssuedAt: issuedAt, AbsoluteExpiry: expiry,
		PresentationCredentialReference: presentation.Reference().String(),
		PresentationCredentialDigest:    presentationDigest,
		PresentationCredentialAudience:  presentation.Audience().String(),
		PresentationCredentialVersion:   presentation.Version(),
	}
	if device, present := binding.DeviceRevision(); present {
		deviceWire, deviceErr := receiptResource(device)
		trust, hasTrust := binding.DeviceTrustRevision()
		if deviceErr != nil || !hasTrust || !trust.Valid() {
			return CanonicalDigest{}, ErrCanonicalProfile
		}
		trustValue := trust.Uint64()
		view.Device = &deviceWire
		view.DeviceTrustRevision = &trustValue
	}
	canonical, err := encodeCanonical(view, MaxRecoveryCapsuleBytes)
	if err != nil {
		return CanonicalDigest{}, err
	}
	return NewCanonicalDigest(digestCanonical(sessionBindingDomain, canonical).String())
}

func decodeCanonicalDocument(canonical []byte, maxBytes int, target any) error {
	if target == nil {
		return ErrCanonicalSchema
	}
	if err := (ProductionCanonicalCodec{}).ValidateCanonicalBytes(canonical, maxBytes); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode retained document: %v", ErrCanonicalSchema, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing retained document data", ErrCanonicalSchema)
	}
	return nil
}

// VerifyReceiptResult rehydrates retained canonical bytes only after proving
// both their closed schema and their domain-separated digest. Replay and
// storage adapters use this path; they never trust a stored digest or JSON
// parser independently.
func (codec ProductionCanonicalCodec) VerifyReceiptResult(
	canonical []byte,
	expectedDigest Digest,
	binding ReceiptResultReplayBinding,
) (ResultEnvelope, error) {
	if expectedDigest.IsZero() {
		return ResultEnvelope{}, ErrCanonicalProfile
	}
	var wire receiptResultWire
	if err := decodeCanonicalDocument(canonical, MaxReceiptResultBytes, &wire); err != nil {
		return ResultEnvelope{}, err
	}
	view := W0ReceiptResultView{wire: wire}
	if wire.SessionBinding != nil {
		view.sessionBindingDigest = wire.SessionBinding.BindingDigest
	}
	if !view.valid() {
		return ResultEnvelope{}, ErrCanonicalProfile
	}
	document, err := codec.EncodeReceiptResult(view)
	if err != nil || !bytes.Equal(document.CanonicalBytes(), canonical) || document.Digest() != expectedDigest {
		return ResultEnvelope{}, fmt.Errorf("%w: retained receipt result mismatch", ErrCanonicalEncoding)
	}
	identity := binding.Identity()
	events := binding.Events()
	fingerprint := binding.RequestFingerprint()
	if binding.OriginalCommandID().IsZero() || binding.OperationMajor().IsZero() ||
		wire.Operation != string(binding.Operation()) || identity.Operation().String() != wire.Operation ||
		wire.ScopeKind != string(identity.Scope().Kind()) || wire.ScopeID.String() != identity.Scope().ID() ||
		wire.AuthorityID.String() != binding.AuthorityID().String() ||
		wire.AuthorityEpoch.String() != binding.AuthorityEpoch().String() ||
		wire.CommandFingerprint.String() != hex.EncodeToString(fingerprint[:]) ||
		wire.AuthorizationDigest.String() != binding.GuardDigest().String() ||
		wire.Events.FirstPosition != events.First().Uint64() || wire.Events.LastPosition != events.Last().Uint64() ||
		wire.Events.Count != events.Count() ||
		wire.CapsuleRequired != (binding.RecoveryCapsulePlan().Requirement() == RecoveryCapsuleRequired) {
		return ResultEnvelope{}, fmt.Errorf("%w: retained receipt result does not match replay binding", ErrCanonicalProfile)
	}
	expected, err := codec.MaterializeReceiptResult(
		binding.ExpectedPlan(), events.First(), events.Last(), binding.FinalStreamDigest(),
	)
	if err != nil || expected.ResponseDigest() != expectedDigest ||
		!bytes.Equal(expected.CanonicalBytes(), canonical) {
		return ResultEnvelope{}, fmt.Errorf("%w: retained receipt body does not match replay plan", ErrCanonicalProfile)
	}
	return expected, nil
}

// VerifyRecoveryCapsule rehydrates an unsigned stored draft only after
// checking its closed schema, capsule digest, exact receipt-result binding,
// command identity, operation major, signing key, and all receipt-derived
// semantic fields. The returned document is safe to pass to the application
// draft constructor.
func (codec ProductionCanonicalCodec) VerifyRecoveryCapsule(
	canonical []byte,
	expectedCapsuleDigest Digest,
	result ResultEnvelope,
	binding ReceiptResultReplayBinding,
) (RecoveryCapsuleDocument, error) {
	expectedCommandID := binding.OriginalCommandID()
	expectedOperationMajor := binding.OperationMajor()
	expectedSigningKeyID := binding.RecoveryCapsulePlan().KeyID()
	if expectedCapsuleDigest.IsZero() || result.IsZero() || expectedCommandID.IsZero() ||
		expectedOperationMajor.IsZero() || !validOpaqueText(expectedSigningKeyID, 256) ||
		result.Operation() != binding.Operation() ||
		result.RecoveryCapsulePlan().KeyID() != expectedSigningKeyID {
		return RecoveryCapsuleDocument{}, ErrCanonicalProfile
	}
	var wire recoveryCapsuleWire
	if err := decodeCanonicalDocument(canonical, MaxRecoveryCapsuleBytes, &wire); err != nil {
		return RecoveryCapsuleDocument{}, err
	}
	view := W0RecoveryCapsuleView{wire: wire, resultDigest: result.ResponseDigest()}
	resultWire := result.ReceiptDocument().wire
	if !view.valid() || wire.CommandID.String() != expectedCommandID.String() ||
		wire.OperationMajor != expectedOperationMajor.Uint16() || wire.SigningKeyID != expectedSigningKeyID ||
		wire.Operation != string(result.Operation()) || wire.AuthorityID != resultWire.AuthorityID ||
		wire.AuthorityEpoch != resultWire.AuthorityEpoch || wire.ScopeKind != resultWire.ScopeKind ||
		wire.ScopeID != resultWire.ScopeID || wire.AcceptedAt != resultWire.AcceptedAt ||
		wire.RequestDigest != resultWire.CommandFingerprint ||
		wire.ReceiptResultDigest.String() != result.ResponseDigest().String() ||
		!reflect.DeepEqual(wire.Resources, resultWire.Resources) ||
		!reflect.DeepEqual(wire.Events, resultWire.Events) {
		return RecoveryCapsuleDocument{}, ErrCanonicalProfile
	}
	document, err := codec.EncodeRecoveryCapsule(view)
	if err != nil || document.Digest() != expectedCapsuleDigest || !bytes.Equal(document.CanonicalBytes(), canonical) {
		return RecoveryCapsuleDocument{}, fmt.Errorf("%w: retained recovery capsule mismatch", ErrCanonicalEncoding)
	}
	return document, nil
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validateTypedView(root reflect.Type) error {
	for root.Kind() == reflect.Pointer {
		root = root.Elem()
	}
	if root.Kind() != reflect.Struct {
		return fmt.Errorf("%w: hash-view root must be a struct", ErrCanonicalSchema)
	}
	return validateTypedShape(root, make(map[reflect.Type]bool))
}

func validateTypedShape(current reflect.Type, visiting map[reflect.Type]bool) error {
	if current.Implements(reflect.TypeFor[canonicalScalar]()) ||
		reflect.PointerTo(current).Implements(reflect.TypeFor[canonicalScalar]()) {
		return nil
	}
	switch current.Kind() {
	case reflect.Bool, reflect.String:
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Errorf("%w: signed integer fields are forbidden in production hash views", ErrCanonicalSchema)
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("%w: floating fields are forbidden in production hash views", ErrCanonicalSchema)
	case reflect.Pointer, reflect.Slice, reflect.Array:
		if current.Elem().Kind() == reflect.Uint8 {
			return fmt.Errorf("%w: byte arrays require a reviewed text wrapper", ErrCanonicalSchema)
		}
		return validateTypedShape(current.Elem(), visiting)
	case reflect.Map, reflect.Interface, reflect.Func, reflect.Chan, reflect.Complex64,
		reflect.Complex128, reflect.UnsafePointer:
		return fmt.Errorf("%w: unsupported %s field", ErrCanonicalSchema, current.Kind())
	case reflect.Struct:
		if visiting[current] {
			return fmt.Errorf("%w: recursive hash-view type", ErrCanonicalSchema)
		}
		visiting[current] = true
		defer delete(visiting, current)
		return validateStructShape(current, visiting)
	default:
		return fmt.Errorf("%w: unsupported %s field", ErrCanonicalSchema, current.Kind())
	}
}

func validateStructShape(current reflect.Type, visiting map[reflect.Type]bool) error {
	names := make(map[string]struct{}, current.NumField())
	for index := range current.NumField() {
		field := current.Field(index)
		if !field.IsExported() || field.Anonymous {
			return fmt.Errorf("%w: %s.%s must be exported and non-embedded", ErrCanonicalSchema, current, field.Name)
		}
		tag, present := field.Tag.Lookup("json")
		if !present || tag == "" || tag == "-" || strings.Contains(tag, ",") {
			return fmt.Errorf("%w: %s.%s needs one explicit non-omitting JSON name", ErrCanonicalSchema, current, field.Name)
		}
		if !validJSONFieldName(tag) {
			return fmt.Errorf("%w: invalid JSON field name %q", ErrCanonicalSchema, tag)
		}
		if _, duplicate := names[tag]; duplicate {
			return fmt.Errorf("%w: duplicate JSON field name %q", ErrCanonicalSchema, tag)
		}
		names[tag] = struct{}{}
		if err := validateTypedShape(field.Type, visiting); err != nil {
			return err
		}
	}
	return nil
}

func validJSONFieldName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	for _, character := range name {
		if character < 0x20 || character == '\\' || character == '"' {
			return false
		}
	}
	return true
}

func validateStrictJSON(raw []byte, maxBytes, maxDepth int) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: empty input", ErrCanonicalJSON)
	}
	if len(raw) > maxBytes {
		return fmt.Errorf("%w: %d > %d bytes", ErrCanonicalLimit, len(raw), maxBytes)
	}
	if !utf8.Valid(raw) || !validJSONSurrogates(raw) {
		return fmt.Errorf("%w: invalid UTF-8 or surrogate pair", ErrCanonicalJSON)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0, maxDepth); err != nil {
		return fmt.Errorf("%w: %w", ErrCanonicalJSON, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrCanonicalJSON)
		}
		return fmt.Errorf("%w: trailing data: %v", ErrCanonicalJSON, err)
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth, maxDepth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		if depth == maxDepth {
			return ErrCanonicalLimit
		}
		switch value {
		case '{':
			return validateJSONObject(decoder, depth+1, maxDepth)
		case '[':
			return validateJSONArray(decoder, depth+1, maxDepth)
		default:
			return fmt.Errorf("unexpected delimiter %q", value)
		}
	case json.Number:
		return validateJSONNumber(value.String())
	case string, bool, nil:
		return nil
	default:
		return fmt.Errorf("unexpected JSON token %T", token)
	}
}

func validateJSONObject(decoder *json.Decoder, depth, maxDepth int) error {
	names := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("object member name is not a string")
		}
		if _, duplicate := names[name]; duplicate {
			return fmt.Errorf("duplicate object member %q", name)
		}
		names[name] = struct{}{}
		if err := validateJSONValue(decoder, depth, maxDepth); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("unterminated object")
	}
	return nil
}

func validateJSONArray(decoder *json.Decoder, depth, maxDepth int) error {
	for decoder.More() {
		if err := validateJSONValue(decoder, depth, maxDepth); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return errors.New("unterminated array")
	}
	return nil
}

func validateJSONNumber(text string) error {
	number, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
		return ErrCanonicalNumber
	}
	// Integer semantics are constrained regardless of source spelling. An
	// exponent or decimal point must not bypass the interoperable range.
	// Fractional RFC 8785 vectors remain valid; production typed views forbid
	// floating fields in Blackbird hash schemas.
	if math.Trunc(number) == number && (number < 0 || number > float64(MaxCanonicalInteger)) {
		return ErrCanonicalNumber
	}
	return nil
}

func validJSONSurrogates(raw []byte) bool {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(raw) {
				continue
			}
			index++
			if raw[index] != 'u' {
				continue
			}
			unit, ok := parseUTF16Unit(raw, index+1)
			if !ok {
				return false
			}
			index += 4
			switch {
			case unit >= 0xd800 && unit <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return false
				}
				low, validLow := parseUTF16Unit(raw, index+3)
				if !validLow || low < 0xdc00 || low > 0xdfff {
					return false
				}
				index += 6
			case unit >= 0xdc00 && unit <= 0xdfff:
				return false
			}
		}
	}
	return !inString
}

func parseUTF16Unit(raw []byte, start int) (uint64, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	unit, err := strconv.ParseUint(string(raw[start:start+4]), 16, 16)
	return unit, err == nil
}

// CanonicalIdentifier is lowercase ASCII identifier text. Specific domain
// constructors still own identifier kind and UUID version validity.
type CanonicalIdentifier struct{ text string }

func NewCanonicalIdentifier(text string) (CanonicalIdentifier, error) {
	if len(text) == 0 || len(text) > maxCanonicalIDBytes || strings.ToLower(text) != text {
		return CanonicalIdentifier{}, ErrCanonicalIdentifier
	}
	for index, character := range []byte(text) {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && strings.ContainsRune("-_.:/", rune(character))) {
			continue
		}
		return CanonicalIdentifier{}, ErrCanonicalIdentifier
	}
	return CanonicalIdentifier{text: text}, nil
}

func (identifier CanonicalIdentifier) String() string { return identifier.text }
func (CanonicalIdentifier) canonicalScalar()          {}

func (identifier CanonicalIdentifier) MarshalJSON() ([]byte, error) {
	validated, err := NewCanonicalIdentifier(identifier.text)
	if err != nil || validated != identifier {
		return nil, ErrCanonicalIdentifier
	}
	return json.Marshal(identifier.text)
}

func (identifier *CanonicalIdentifier) UnmarshalJSON(raw []byte) error {
	var text string
	if identifier == nil || json.Unmarshal(raw, &text) != nil {
		return ErrCanonicalIdentifier
	}
	validated, err := NewCanonicalIdentifier(text)
	if err != nil {
		return err
	}
	*identifier = validated
	return nil
}

// CanonicalDigest is exact lowercase hexadecimal SHA-256 text.
type CanonicalDigest struct{ text string }

func NewCanonicalDigest(text string) (CanonicalDigest, error) {
	if len(text) != hex.EncodedLen(sha256.Size) || strings.ToLower(text) != text {
		return CanonicalDigest{}, ErrCanonicalIdentifier
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != sha256.Size || bytes.Equal(decoded, make([]byte, sha256.Size)) {
		return CanonicalDigest{}, ErrCanonicalIdentifier
	}
	return CanonicalDigest{text: text}, nil
}

func CanonicalDigestFromDigest(digest Digest) (CanonicalDigest, error) {
	if digest.IsZero() {
		return CanonicalDigest{}, ErrCanonicalIdentifier
	}
	return NewCanonicalDigest(digest.String())
}

func (digest CanonicalDigest) String() string { return digest.text }
func (CanonicalDigest) canonicalScalar()      {}

func (digest CanonicalDigest) MarshalJSON() ([]byte, error) {
	validated, err := NewCanonicalDigest(digest.text)
	if err != nil || validated != digest {
		return nil, ErrCanonicalIdentifier
	}
	return json.Marshal(digest.text)
}

func (digest *CanonicalDigest) UnmarshalJSON(raw []byte) error {
	var text string
	if digest == nil || json.Unmarshal(raw, &text) != nil {
		return ErrCanonicalIdentifier
	}
	validated, err := NewCanonicalDigest(text)
	if err != nil {
		return err
	}
	*digest = validated
	return nil
}

// CanonicalAuditHash is lowercase SHA-256 text and, unlike CanonicalDigest,
// permits the all-zero audit-genesis predecessor required by ADR-0007.
type CanonicalAuditHash struct{ text string }

func NewCanonicalAuditHash(text string) (CanonicalAuditHash, error) {
	if len(text) != hex.EncodedLen(sha256.Size) || strings.ToLower(text) != text {
		return CanonicalAuditHash{}, ErrCanonicalIdentifier
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != sha256.Size {
		return CanonicalAuditHash{}, ErrCanonicalIdentifier
	}
	return CanonicalAuditHash{text: text}, nil
}
func (hash CanonicalAuditHash) String() string { return hash.text }
func (CanonicalAuditHash) canonicalScalar()    {}
func (hash CanonicalAuditHash) MarshalJSON() ([]byte, error) {
	validated, err := NewCanonicalAuditHash(hash.text)
	if err != nil || validated != hash {
		return nil, ErrCanonicalIdentifier
	}
	return json.Marshal(hash.text)
}
func (hash *CanonicalAuditHash) UnmarshalJSON(raw []byte) error {
	var text string
	if hash == nil || json.Unmarshal(raw, &text) != nil {
		return ErrCanonicalIdentifier
	}
	validated, err := NewCanonicalAuditHash(text)
	if err != nil {
		return err
	}
	*hash = validated
	return nil
}

func (digest Digest) String() string {
	if digest.IsZero() {
		return ""
	}
	return hex.EncodeToString(digest[:])
}

// CanonicalInstant normalizes an instant to UTC with exactly microsecond
// precision. Sub-microsecond input is rejected rather than rounded.
type CanonicalInstant struct{ value time.Time }

func NewCanonicalInstant(value time.Time) (CanonicalInstant, error) {
	normalized := value.UTC()
	if value.IsZero() || normalized.Year() < 1 || normalized.Year() > 9999 || value.Nanosecond()%1_000 != 0 {
		return CanonicalInstant{}, ErrCanonicalInstant
	}
	return CanonicalInstant{value: normalized}, nil
}

func ParseCanonicalInstant(text string) (CanonicalInstant, error) {
	value, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return CanonicalInstant{}, fmt.Errorf("%w: %v", ErrCanonicalInstant, err)
	}
	return NewCanonicalInstant(value)
}

func (instant CanonicalInstant) Time() time.Time { return instant.value }
func (instant CanonicalInstant) String() string {
	if instant.value.IsZero() {
		return ""
	}
	return instant.value.UTC().Format("2006-01-02T15:04:05.000000Z")
}
func (CanonicalInstant) canonicalScalar() {}

func (instant CanonicalInstant) MarshalJSON() ([]byte, error) {
	validated, err := NewCanonicalInstant(instant.value)
	if err != nil || !validated.value.Equal(instant.value) {
		return nil, ErrCanonicalInstant
	}
	return json.Marshal(instant.String())
}

func (instant *CanonicalInstant) UnmarshalJSON(raw []byte) error {
	var text string
	if instant == nil || json.Unmarshal(raw, &text) != nil {
		return ErrCanonicalInstant
	}
	validated, err := ParseCanonicalInstant(text)
	if err != nil || validated.String() != text {
		return ErrCanonicalInstant
	}
	*instant = validated
	return nil
}

type StreamScopeKind string

const (
	StreamScopeInstallation StreamScopeKind = "installation"
	StreamScopeWorkspace    StreamScopeKind = "workspace"
)

func (kind StreamScopeKind) Valid() bool {
	return kind == StreamScopeInstallation || kind == StreamScopeWorkspace
}

func (kind StreamScopeKind) MarshalJSON() ([]byte, error) {
	if !kind.Valid() {
		return nil, ErrCanonicalProfile
	}
	return json.Marshal(string(kind))
}

// StreamGenesisViewV1 is the exact ADR-0011/ADR-0004 stream genesis object.
type StreamGenesisViewV1 struct {
	AuthorityID                 CanonicalIdentifier `json:"authority_id"`
	AuthorityEpoch              CanonicalIdentifier `json:"authority_epoch"`
	ScopeKind                   StreamScopeKind     `json:"scope_kind"`
	ScopeID                     CanonicalIdentifier `json:"scope_id"`
	PredecessorTransitionDigest *CanonicalDigest    `json:"predecessor_transition_digest"`
}

func NewStreamGenesisViewV1(
	authorityID CanonicalIdentifier,
	authorityEpoch CanonicalIdentifier,
	scopeKind StreamScopeKind,
	scopeID CanonicalIdentifier,
	predecessor *CanonicalDigest,
) (StreamGenesisViewV1, error) {
	if authorityID.String() == "" || authorityEpoch.String() == "" || !scopeKind.Valid() || scopeID.String() == "" ||
		(predecessor != nil && predecessor.String() == "") {
		return StreamGenesisViewV1{}, ErrCanonicalProfile
	}
	view := StreamGenesisViewV1{
		AuthorityID: authorityID, AuthorityEpoch: authorityEpoch, ScopeKind: scopeKind,
		ScopeID: scopeID,
	}
	if predecessor != nil {
		copyOfDigest := *predecessor
		view.PredecessorTransitionDigest = &copyOfDigest
	}
	return view, nil
}

func (StreamGenesisViewV1) canonicalView()         {}
func (StreamGenesisViewV1) streamGenesisHashView() {}

const commandHashSchemaV1 = "blackbird.command-hash-view/v1"

// W0CommandHashContextParams contains the semantic request envelope shared by
// every W0 command. Routing authority, authority epoch, command/request IDs,
// receipt and idempotency IDs, deadlines, retry counters, and response options
// are deliberately not representable here.
type W0CommandHashContextParams struct {
	ScopeKind            StreamScopeKind
	ScopeID              CanonicalIdentifier
	PrincipalID          CanonicalIdentifier
	ClientInstanceID     CanonicalIdentifier
	ActorID              CanonicalIdentifier
	ActorSessionID       CanonicalIdentifier
	CorrelationID        CanonicalIdentifier
	CausationEventID     CanonicalIdentifier
	ProtocolCapabilities []string
}

type commandHashContextWire struct {
	Schema               string               `json:"schema"`
	Operation            string               `json:"operation"`
	OperationMajor       uint16               `json:"operation_major"`
	ScopeKind            StreamScopeKind      `json:"scope_kind"`
	ScopeID              CanonicalIdentifier  `json:"scope_id"`
	PrincipalID          *CanonicalIdentifier `json:"principal_id"`
	ClientInstanceID     *CanonicalIdentifier `json:"client_instance_id"`
	ActorID              *CanonicalIdentifier `json:"actor_id"`
	ActorSessionID       *CanonicalIdentifier `json:"actor_session_id"`
	CorrelationID        CanonicalIdentifier  `json:"correlation_id"`
	CausationEventID     *CanonicalIdentifier `json:"causation_event_id"`
	ProtocolCapabilities []string             `json:"protocol_capabilities"`
}

type CommandExpectedResource struct {
	ID              CanonicalIdentifier `json:"id"`
	ExpectedVersion uint64              `json:"expected_version"`
}

type CommandCeremony struct {
	ID          CanonicalIdentifier `json:"id"`
	ExpiresAt   CanonicalInstant    `json:"expires_at"`
	ProofDigest CanonicalDigest     `json:"proof_digest"`
}

func commandHashContext(operation CommandOperation, params W0CommandHashContextParams) (commandHashContextWire, error) {
	contract, exists := operationContracts[operation]
	expectedScope := StreamScopeKind(contract.scope)
	if !exists || !params.ScopeKind.Valid() || params.ScopeKind != expectedScope ||
		params.ScopeID.String() == "" || params.PrincipalID.String() == "" ||
		params.CorrelationID.String() == "" ||
		(operation != CommandBootstrapInstallation && params.ClientInstanceID.String() == "") ||
		(contract.attribution == attributionForbidden && (params.ActorID.String() != "" || params.ActorSessionID.String() != "")) ||
		contract.attribution == attributionOptional && ((params.ActorID.String() == "") != (params.ActorSessionID.String() == "")) {
		return commandHashContextWire{}, ErrCanonicalProfile
	}
	capabilities, err := canonicalProtocolCapabilities(params.ProtocolCapabilities)
	if err != nil {
		return commandHashContextWire{}, err
	}
	return commandHashContextWire{
		Schema: commandHashSchemaV1, Operation: string(operation), OperationMajor: 1,
		ScopeKind: params.ScopeKind, ScopeID: params.ScopeID,
		PrincipalID: optionalCanonicalID(params.PrincipalID), ClientInstanceID: optionalCanonicalID(params.ClientInstanceID),
		ActorID: optionalCanonicalID(params.ActorID), ActorSessionID: optionalCanonicalID(params.ActorSessionID),
		CorrelationID: params.CorrelationID, CausationEventID: optionalCanonicalID(params.CausationEventID),
		ProtocolCapabilities: capabilities,
	}, nil
}

func optionalCanonicalID(value CanonicalIdentifier) *CanonicalIdentifier {
	if value.String() == "" {
		return nil
	}
	copyOfValue := value
	return &copyOfValue
}

func canonicalProtocolCapabilities(values []string) ([]string, error) {
	result := make([]string, len(values))
	for index, value := range values {
		capability, err := domain.NewCapability(value)
		if err != nil {
			return nil, ErrCanonicalProfile
		}
		result[index] = capability.String()
	}
	slices.Sort(result)
	for index, value := range result {
		if index > 0 && result[index-1] == value {
			return nil, ErrCanonicalProfile
		}
	}
	return result, nil
}

func canonicalStringSet(values []string) ([]string, error) {
	return canonicalProtocolCapabilities(values)
}

func canonicalCapabilitySet(values []string) ([]string, error) {
	capabilities := make([]domain.Capability, len(values))
	for index, value := range values {
		capability, err := domain.NewCapability(value)
		if err != nil {
			return nil, ErrCanonicalProfile
		}
		capabilities[index] = capability
	}
	set, err := domain.NewCapabilitySet(capabilities...)
	if err != nil {
		return nil, ErrCanonicalProfile
	}
	return capabilityStrings(set), nil
}

func validCommandDisplayName(value string) bool {
	_, err := domain.NewDisplayName(value)
	return err == nil
}

func validCommandPublicKey(value string) bool {
	_, err := domain.NewPublicKeyReference(value)
	return err == nil
}

func validCommandWorkspaceMetadata(alias, locator string) bool {
	_, aliasErr := domain.NewWorkspaceAlias(alias)
	_, locatorErr := domain.NewDiscoveryLocator(locator)
	return aliasErr == nil && locatorErr == nil
}

func validCommandClientMetadata(name, version string) bool {
	_, err := domain.NewClientMetadata(name, version)
	return err == nil
}

func validCommandPresentation(reference, audience string) bool {
	_, referenceErr := domain.NewCredentialReference(reference)
	_, audienceErr := domain.NewCredentialAudience(audience)
	return referenceErr == nil && audienceErr == nil
}

func validCommandResource(value CommandExpectedResource) bool {
	return value.ID.String() != "" && value.ExpectedVersion > 0 && value.ExpectedVersion <= MaxCanonicalInteger
}

func validCommandCeremony(value CommandCeremony) bool {
	return value.ID.String() != "" && value.ExpiresAt.String() != "" && value.ProofDigest.String() != ""
}

type BootstrapInstallationCommandHashParams struct {
	InstallationID           CanonicalIdentifier
	Invitation               CommandExpectedResource
	BootstrapGenerationID    CanonicalIdentifier
	ApprovedTranscript       CanonicalDigest
	PrincipalID              CanonicalIdentifier
	PrincipalDisplayName     string
	DeviceID                 CanonicalIdentifier
	DeviceDisplayName        string
	DevicePublicKeyReference string
	DeviceSPKIFingerprint    CanonicalDigest
	OwnerGrantID             CanonicalIdentifier
	OwnerGrantCapabilities   []string
}

type bootstrapInstallationCommandBody struct {
	InstallationID           CanonicalIdentifier     `json:"installation_id"`
	Invitation               CommandExpectedResource `json:"invitation"`
	BootstrapGenerationID    CanonicalIdentifier     `json:"bootstrap_generation_id"`
	ApprovedTranscript       CanonicalDigest         `json:"approved_transcript_fingerprint"`
	PrincipalID              CanonicalIdentifier     `json:"principal_id"`
	PrincipalDisplayName     string                  `json:"principal_display_name"`
	DeviceID                 CanonicalIdentifier     `json:"device_id"`
	DeviceDisplayName        string                  `json:"device_display_name"`
	DevicePublicKeyReference string                  `json:"device_public_key_reference"`
	DeviceSPKIFingerprint    CanonicalDigest         `json:"device_spki_fingerprint"`
	OwnerGrantID             CanonicalIdentifier     `json:"owner_grant_id"`
	OwnerGrantCapabilities   []string                `json:"owner_grant_capabilities"`
}

type bootstrapInstallationCommandHashView struct {
	Command commandHashContextWire           `json:"command"`
	Body    bootstrapInstallationCommandBody `json:"body"`
}

func NewBootstrapInstallationCommandHashView(context W0CommandHashContextParams, params BootstrapInstallationCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandBootstrapInstallation, context)
	capabilities, capabilityErr := canonicalCapabilitySet(params.OwnerGrantCapabilities)
	if err != nil || capabilityErr != nil || params.InstallationID.String() == "" || !validCommandResource(params.Invitation) ||
		params.BootstrapGenerationID.String() == "" || params.ApprovedTranscript.String() == "" ||
		params.PrincipalID.String() == "" || !validCommandDisplayName(params.PrincipalDisplayName) ||
		params.DeviceID.String() == "" || !validCommandDisplayName(params.DeviceDisplayName) ||
		!validCommandPublicKey(params.DevicePublicKeyReference) || params.DeviceSPKIFingerprint.String() == "" ||
		params.OwnerGrantID.String() == "" || len(capabilities) == 0 {
		return nil, ErrCanonicalProfile
	}
	return bootstrapInstallationCommandHashView{Command: command, Body: bootstrapInstallationCommandBody{
		InstallationID: params.InstallationID, Invitation: params.Invitation,
		BootstrapGenerationID: params.BootstrapGenerationID, ApprovedTranscript: params.ApprovedTranscript,
		PrincipalID: params.PrincipalID, PrincipalDisplayName: params.PrincipalDisplayName,
		DeviceID: params.DeviceID, DeviceDisplayName: params.DeviceDisplayName,
		DevicePublicKeyReference: params.DevicePublicKeyReference, DeviceSPKIFingerprint: params.DeviceSPKIFingerprint,
		OwnerGrantID: params.OwnerGrantID, OwnerGrantCapabilities: capabilities,
	}}, nil
}

func (bootstrapInstallationCommandHashView) canonicalView()   {}
func (bootstrapInstallationCommandHashView) commandHashView() {}

type RegisterPrincipalCommandHashParams struct {
	Registrar          CommandExpectedResource `json:"registrar"`
	PrincipalID        CanonicalIdentifier     `json:"principal_id"`
	Kind               string                  `json:"kind"`
	DisplayName        string                  `json:"display_name"`
	PublicKeyReference string                  `json:"public_key_reference"`
}

type registerPrincipalCommandHashView struct {
	Command commandHashContextWire             `json:"command"`
	Body    RegisterPrincipalCommandHashParams `json:"body"`
}

func NewRegisterPrincipalCommandHashView(context W0CommandHashContextParams, params RegisterPrincipalCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandRegisterPrincipal, context)
	if err != nil || !validCommandResource(params.Registrar) || params.PrincipalID.String() == "" ||
		!domain.PrincipalKind(params.Kind).Valid() || !validCommandDisplayName(params.DisplayName) ||
		(params.Kind != string(domain.PrincipalKindHuman) && params.PublicKeyReference == "") ||
		(params.PublicKeyReference != "" && !validCommandPublicKey(params.PublicKeyReference)) {
		return nil, ErrCanonicalProfile
	}
	return registerPrincipalCommandHashView{Command: command, Body: params}, nil
}

func (registerPrincipalCommandHashView) canonicalView()   {}
func (registerPrincipalCommandHashView) commandHashView() {}

type CreateWorkspaceCommandHashParams struct {
	Owner             CommandExpectedResource `json:"owner"`
	InstallationGrant CommandExpectedResource `json:"installation_grant"`
	WorkspaceID       CanonicalIdentifier     `json:"workspace_id"`
	Alias             string                  `json:"alias"`
	DiscoveryLocator  string                  `json:"discovery_locator"`
	OwnerMembershipID CanonicalIdentifier     `json:"owner_membership_id"`
	OwnerCapabilities []string                `json:"owner_capabilities"`
}

type createWorkspaceCommandHashView struct {
	Command commandHashContextWire           `json:"command"`
	Body    CreateWorkspaceCommandHashParams `json:"body"`
}

func NewCreateWorkspaceCommandHashView(context W0CommandHashContextParams, params CreateWorkspaceCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandCreateWorkspace, context)
	capabilities, capabilityErr := canonicalCapabilitySet(params.OwnerCapabilities)
	if err != nil || capabilityErr != nil || !validCommandResource(params.Owner) ||
		!validCommandResource(params.InstallationGrant) || params.WorkspaceID.String() == "" ||
		!validCommandWorkspaceMetadata(params.Alias, params.DiscoveryLocator) ||
		params.OwnerMembershipID.String() == "" || len(capabilities) == 0 {
		return nil, ErrCanonicalProfile
	}
	params.OwnerCapabilities = capabilities
	return createWorkspaceCommandHashView{Command: command, Body: params}, nil
}

func (createWorkspaceCommandHashView) canonicalView()   {}
func (createWorkspaceCommandHashView) commandHashView() {}

type InviteWorkspaceMemberCommandHashParams struct {
	Administrator CommandExpectedResource `json:"administrator"`
	Workspace     CommandExpectedResource `json:"workspace"`
	Principal     CommandExpectedResource `json:"principal"`
	MembershipID  CanonicalIdentifier     `json:"membership_id"`
	Capabilities  []string                `json:"capabilities"`
	Challenge     CommandCeremony         `json:"challenge"`
}

type inviteWorkspaceMemberCommandHashView struct {
	Command commandHashContextWire                 `json:"command"`
	Body    InviteWorkspaceMemberCommandHashParams `json:"body"`
}

func NewInviteWorkspaceMemberCommandHashView(context W0CommandHashContextParams, params InviteWorkspaceMemberCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandInviteWorkspaceMember, context)
	capabilities, capabilityErr := canonicalCapabilitySet(params.Capabilities)
	if err != nil || capabilityErr != nil || !validCommandResource(params.Administrator) ||
		!validCommandResource(params.Workspace) || !validCommandResource(params.Principal) ||
		params.MembershipID.String() == "" || len(capabilities) == 0 || !validCommandCeremony(params.Challenge) {
		return nil, ErrCanonicalProfile
	}
	params.Capabilities = capabilities
	return inviteWorkspaceMemberCommandHashView{Command: command, Body: params}, nil
}

func (inviteWorkspaceMemberCommandHashView) canonicalView()   {}
func (inviteWorkspaceMemberCommandHashView) commandHashView() {}

type AcceptWorkspaceMembershipCommandHashParams struct {
	Workspace  CommandExpectedResource `json:"workspace"`
	Principal  CommandExpectedResource `json:"principal"`
	Membership CommandExpectedResource `json:"membership"`
	Proof      CommandCeremony         `json:"proof"`
}

type acceptWorkspaceMembershipCommandHashView struct {
	Command commandHashContextWire                     `json:"command"`
	Body    AcceptWorkspaceMembershipCommandHashParams `json:"body"`
}

func NewAcceptWorkspaceMembershipCommandHashView(context W0CommandHashContextParams, params AcceptWorkspaceMembershipCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandAcceptWorkspaceMembership, context)
	if err != nil || !validCommandResource(params.Workspace) || !validCommandResource(params.Principal) ||
		!validCommandResource(params.Membership) || !validCommandCeremony(params.Proof) {
		return nil, ErrCanonicalProfile
	}
	return acceptWorkspaceMembershipCommandHashView{Command: command, Body: params}, nil
}

func (acceptWorkspaceMembershipCommandHashView) canonicalView()   {}
func (acceptWorkspaceMembershipCommandHashView) commandHashView() {}

type CreateActorCommandHashParams struct {
	Administrator CommandExpectedResource `json:"administrator"`
	Workspace     CommandExpectedResource `json:"workspace"`
	ActorID       CanonicalIdentifier     `json:"actor_id"`
	Kind          string                  `json:"kind"`
	DisplayName   string                  `json:"display_name"`
}

type createActorCommandHashView struct {
	Command commandHashContextWire       `json:"command"`
	Body    CreateActorCommandHashParams `json:"body"`
}

func NewCreateActorCommandHashView(context W0CommandHashContextParams, params CreateActorCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandCreateActor, context)
	if err != nil || !validCommandResource(params.Administrator) || !validCommandResource(params.Workspace) ||
		params.ActorID.String() == "" || !domain.ActorKind(params.Kind).Valid() || !validCommandDisplayName(params.DisplayName) {
		return nil, ErrCanonicalProfile
	}
	return createActorCommandHashView{Command: command, Body: params}, nil
}

func (createActorCommandHashView) canonicalView()   {}
func (createActorCommandHashView) commandHashView() {}

type ProposeActorDelegationCommandHashParams struct {
	Administrator CommandExpectedResource `json:"administrator"`
	Workspace     CommandExpectedResource `json:"workspace"`
	Principal     CommandExpectedResource `json:"principal"`
	Actor         CommandExpectedResource `json:"actor"`
	Membership    CommandExpectedResource `json:"membership"`
	DelegationID  CanonicalIdentifier     `json:"delegation_id"`
	Capabilities  []string                `json:"capabilities"`
	Challenge     CommandCeremony         `json:"challenge"`
}

type proposeActorDelegationCommandHashView struct {
	Command commandHashContextWire                  `json:"command"`
	Body    ProposeActorDelegationCommandHashParams `json:"body"`
}

func NewProposeActorDelegationCommandHashView(context W0CommandHashContextParams, params ProposeActorDelegationCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandProposeActorDelegation, context)
	capabilities, capabilityErr := canonicalCapabilitySet(params.Capabilities)
	if err != nil || capabilityErr != nil || !validCommandResource(params.Administrator) ||
		!validCommandResource(params.Workspace) || !validCommandResource(params.Principal) ||
		!validCommandResource(params.Actor) || !validCommandResource(params.Membership) ||
		params.DelegationID.String() == "" || len(capabilities) == 0 || !validCommandCeremony(params.Challenge) {
		return nil, ErrCanonicalProfile
	}
	params.Capabilities = capabilities
	return proposeActorDelegationCommandHashView{Command: command, Body: params}, nil
}

func (proposeActorDelegationCommandHashView) canonicalView()   {}
func (proposeActorDelegationCommandHashView) commandHashView() {}

type ActivateActorDelegationCommandHashParams struct {
	Workspace             CommandExpectedResource `json:"workspace"`
	Principal             CommandExpectedResource `json:"principal"`
	Actor                 CommandExpectedResource `json:"actor"`
	Membership            CommandExpectedResource `json:"membership"`
	Delegation            CommandExpectedResource `json:"delegation"`
	ActivationProof       CommandCeremony         `json:"activation_proof"`
	SessionStartChallenge CommandCeremony         `json:"session_start_challenge"`
}

type activateActorDelegationCommandHashView struct {
	Command commandHashContextWire                   `json:"command"`
	Body    ActivateActorDelegationCommandHashParams `json:"body"`
}

func NewActivateActorDelegationCommandHashView(context W0CommandHashContextParams, params ActivateActorDelegationCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandActivateActorDelegation, context)
	if err != nil || !validCommandResource(params.Workspace) || !validCommandResource(params.Principal) ||
		!validCommandResource(params.Actor) || !validCommandResource(params.Membership) ||
		!validCommandResource(params.Delegation) || !validCommandCeremony(params.ActivationProof) ||
		!validCommandCeremony(params.SessionStartChallenge) {
		return nil, ErrCanonicalProfile
	}
	return activateActorDelegationCommandHashView{Command: command, Body: params}, nil
}

func (activateActorDelegationCommandHashView) canonicalView()   {}
func (activateActorDelegationCommandHashView) commandHashView() {}

type BeginDevicePairingCommandHashParams struct {
	Principal          CommandExpectedResource `json:"principal"`
	DeviceID           CanonicalIdentifier     `json:"device_id"`
	DisplayName        string                  `json:"display_name"`
	PublicKeyReference string                  `json:"public_key_reference"`
	Challenge          CommandCeremony         `json:"challenge"`
}

type beginDevicePairingCommandHashView struct {
	Command commandHashContextWire              `json:"command"`
	Body    BeginDevicePairingCommandHashParams `json:"body"`
}

func NewBeginDevicePairingCommandHashView(context W0CommandHashContextParams, params BeginDevicePairingCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandBeginDevicePairing, context)
	if err != nil || !validCommandResource(params.Principal) || params.DeviceID.String() == "" ||
		!validCommandDisplayName(params.DisplayName) || !validCommandPublicKey(params.PublicKeyReference) ||
		!validCommandCeremony(params.Challenge) {
		return nil, ErrCanonicalProfile
	}
	return beginDevicePairingCommandHashView{Command: command, Body: params}, nil
}

func (beginDevicePairingCommandHashView) canonicalView()   {}
func (beginDevicePairingCommandHashView) commandHashView() {}

type PairDeviceCommandHashParams struct {
	Principal             CommandExpectedResource `json:"principal"`
	Device                CommandExpectedResource `json:"device"`
	ExpectedTrustRevision uint64                  `json:"expected_trust_revision"`
	Proof                 CommandCeremony         `json:"proof"`
	CredentialPublicKey   string                  `json:"credential_public_key_reference"`
	CredentialSPKIDigest  CanonicalDigest         `json:"credential_spki_fingerprint"`
	CredentialTranscript  CanonicalDigest         `json:"credential_transcript_fingerprint"`
}

type pairDeviceCommandHashView struct {
	Command commandHashContextWire      `json:"command"`
	Body    PairDeviceCommandHashParams `json:"body"`
}

func NewPairDeviceCommandHashView(context W0CommandHashContextParams, params PairDeviceCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandPairDevice, context)
	if err != nil || !validCommandResource(params.Principal) || !validCommandResource(params.Device) ||
		params.ExpectedTrustRevision == 0 || params.ExpectedTrustRevision > MaxCanonicalInteger ||
		!validCommandCeremony(params.Proof) || !validCommandPublicKey(params.CredentialPublicKey) ||
		params.CredentialSPKIDigest.String() == "" || params.CredentialTranscript.String() == "" {
		return nil, ErrCanonicalProfile
	}
	return pairDeviceCommandHashView{Command: command, Body: params}, nil
}

func (pairDeviceCommandHashView) canonicalView()   {}
func (pairDeviceCommandHashView) commandHashView() {}

type StartActorSessionCommandHashParams struct {
	SessionID             CanonicalIdentifier       `json:"session_id"`
	ClientName            string                    `json:"client_name"`
	ClientVersion         string                    `json:"client_version"`
	Workspace             CommandExpectedResource   `json:"workspace"`
	Principal             CommandExpectedResource   `json:"principal"`
	Membership            CommandExpectedResource   `json:"membership"`
	Actor                 CommandExpectedResource   `json:"actor"`
	Delegation            CommandExpectedResource   `json:"delegation"`
	Grants                []CommandExpectedResource `json:"grants"`
	StartAuthorityKind    string                    `json:"start_authority_kind"`
	Device                *CommandExpectedResource  `json:"device"`
	ExpectedDeviceTrust   *uint64                   `json:"expected_device_trust_revision"`
	HandoffProof          *CommandCeremony          `json:"handoff_proof"`
	AbsoluteExpiry        CanonicalInstant          `json:"absolute_expiry"`
	PresentationReference string                    `json:"presentation_credential_reference"`
	PresentationDigest    CanonicalDigest           `json:"presentation_credential_digest"`
	PresentationAudience  string                    `json:"presentation_credential_audience"`
	PresentationVersion   uint16                    `json:"presentation_credential_version"`
}

type startActorSessionCommandHashView struct {
	Command commandHashContextWire             `json:"command"`
	Body    StartActorSessionCommandHashParams `json:"body"`
}

func NewStartActorSessionCommandHashView(context W0CommandHashContextParams, params StartActorSessionCommandHashParams) (CommandHashView, error) {
	command, err := commandHashContext(CommandStartActorSession, context)
	if err != nil || params.SessionID.String() == "" || !validCommandClientMetadata(params.ClientName, params.ClientVersion) ||
		!validCommandResource(params.Workspace) ||
		!validCommandResource(params.Principal) || !validCommandResource(params.Membership) ||
		!validCommandResource(params.Actor) || !validCommandResource(params.Delegation) ||
		params.AbsoluteExpiry.String() == "" ||
		!validCommandPresentation(params.PresentationReference, params.PresentationAudience) ||
		params.PresentationDigest.String() == "" || params.PresentationVersion != domain.PresentationCredentialVersion {
		return nil, ErrCanonicalProfile
	}
	grants := append([]CommandExpectedResource{}, params.Grants...)
	for _, grant := range grants {
		if !validCommandResource(grant) {
			return nil, ErrCanonicalProfile
		}
	}
	slices.SortFunc(grants, func(left, right CommandExpectedResource) int {
		return strings.Compare(left.ID.String(), right.ID.String())
	})
	for index := 1; index < len(grants); index++ {
		if grants[index-1].ID == grants[index].ID {
			return nil, ErrCanonicalProfile
		}
	}
	params.Grants = grants
	switch params.StartAuthorityKind {
	case string(domain.SessionStartByTrustedDevice):
		if params.Device == nil || !validCommandResource(*params.Device) || params.ExpectedDeviceTrust == nil ||
			*params.ExpectedDeviceTrust == 0 || *params.ExpectedDeviceTrust > MaxCanonicalInteger || params.HandoffProof != nil {
			return nil, ErrCanonicalProfile
		}
		deviceCopy := *params.Device
		trustCopy := *params.ExpectedDeviceTrust
		params.Device, params.ExpectedDeviceTrust = &deviceCopy, &trustCopy
	case string(domain.SessionStartByHandoff):
		if params.Device != nil || params.ExpectedDeviceTrust != nil || params.HandoffProof == nil || !validCommandCeremony(*params.HandoffProof) {
			return nil, ErrCanonicalProfile
		}
		proofCopy := *params.HandoffProof
		params.HandoffProof = &proofCopy
	default:
		return nil, ErrCanonicalProfile
	}
	return startActorSessionCommandHashView{Command: command, Body: params}, nil
}

func (startActorSessionCommandHashView) canonicalView()   {}
func (startActorSessionCommandHashView) commandHashView() {}

// BootstrapAttemptViewV1 is the retained, secret-free invalid-proof identity.
type BootstrapAttemptViewV1 struct {
	InvitationID         CanonicalIdentifier `json:"invitation_id"`
	TranscriptHash       CanonicalDigest     `json:"transcript_hash"`
	ClientNonceDigest    CanonicalDigest     `json:"client_nonce_digest"`
	ServerNonceDigest    CanonicalDigest     `json:"server_nonce_digest"`
	ChannelBindingDigest CanonicalDigest     `json:"channel_binding_digest"`
	PresentedProofDigest CanonicalDigest     `json:"presented_proof_digest"`
}

func NewBootstrapAttemptViewV1(
	invitationID CanonicalIdentifier,
	transcriptHash CanonicalDigest,
	clientNonceDigest CanonicalDigest,
	serverNonceDigest CanonicalDigest,
	channelBindingDigest CanonicalDigest,
	presentedProofDigest CanonicalDigest,
) (BootstrapAttemptViewV1, error) {
	if invitationID.String() == "" || transcriptHash.String() == "" || clientNonceDigest.String() == "" ||
		serverNonceDigest.String() == "" || channelBindingDigest.String() == "" || presentedProofDigest.String() == "" {
		return BootstrapAttemptViewV1{}, ErrCanonicalProfile
	}
	return BootstrapAttemptViewV1{
		InvitationID: invitationID, TranscriptHash: transcriptHash, ClientNonceDigest: clientNonceDigest,
		ServerNonceDigest: serverNonceDigest, ChannelBindingDigest: channelBindingDigest,
		PresentedProofDigest: presentedProofDigest,
	}, nil
}

func (BootstrapAttemptViewV1) canonicalView()            {}
func (BootstrapAttemptViewV1) bootstrapAttemptHashView() {}

const receiptResultSchemaV1 = "blackbird.receipt-result/v1"

// W0ReceiptOperation is the closed persisted semantic-result catalog. These
// names are application identities, not public transport DTO discriminators.
type W0ReceiptOperation = CommandOperation

const (
	ReceiptOperationInstallationBootstrap     = CommandBootstrapInstallation
	ReceiptOperationPrincipalRegister         = CommandRegisterPrincipal
	ReceiptOperationDevicePairingBegin        = CommandBeginDevicePairing
	ReceiptOperationDevicePair                = CommandPairDevice
	ReceiptOperationWorkspaceCreate           = CommandCreateWorkspace
	ReceiptOperationWorkspaceMemberInvite     = CommandInviteWorkspaceMember
	ReceiptOperationWorkspaceMembershipAccept = CommandAcceptWorkspaceMembership
	ReceiptOperationActorCreate               = CommandCreateActor
	ReceiptOperationActorDelegationPropose    = CommandProposeActorDelegation
	ReceiptOperationActorDelegationActivate   = CommandActivateActorDelegation
	ReceiptOperationActorSessionStart         = CommandStartActorSession
)

type receiptOperationCatalog struct {
	scopeKind       domain.ScopeKind
	resourceKinds   []domain.AggregateKind
	ceremonyPurpose []domain.CeremonyPurpose
	eventCount      int
	capsuleRequired bool
	sessionRequired bool
}

func receiptCatalog(operation W0ReceiptOperation) (receiptOperationCatalog, bool) {
	installation := domain.ScopeKindInstallation
	workspace := domain.ScopeKindWorkspace
	switch operation {
	case ReceiptOperationInstallationBootstrap:
		return receiptOperationCatalog{
			scopeKind: installation,
			resourceKinds: []domain.AggregateKind{
				domain.AggregateKindPrincipal, domain.AggregateKindDevice, domain.AggregateKindGrant,
			},
			eventCount: 3, capsuleRequired: true,
		}, true
	case ReceiptOperationPrincipalRegister:
		return singleResourceCatalog(installation, domain.AggregateKindPrincipal, true), true
	case ReceiptOperationDevicePairingBegin:
		catalog := singleResourceCatalog(installation, domain.AggregateKindDevice, true)
		catalog.ceremonyPurpose = []domain.CeremonyPurpose{domain.CeremonyPurposeDevicePairing}
		return catalog, true
	case ReceiptOperationDevicePair:
		return singleResourceCatalog(installation, domain.AggregateKindDevice, false), true
	case ReceiptOperationWorkspaceCreate:
		return receiptOperationCatalog{
			scopeKind: workspace,
			resourceKinds: []domain.AggregateKind{
				domain.AggregateKindWorkspace, domain.AggregateKindMembership,
			},
			eventCount: 3, capsuleRequired: true,
		}, true
	case ReceiptOperationWorkspaceMemberInvite:
		catalog := singleResourceCatalog(workspace, domain.AggregateKindMembership, true)
		catalog.ceremonyPurpose = []domain.CeremonyPurpose{domain.CeremonyPurposeMembershipAcceptance}
		return catalog, true
	case ReceiptOperationWorkspaceMembershipAccept:
		return singleResourceCatalog(workspace, domain.AggregateKindMembership, false), true
	case ReceiptOperationActorCreate:
		return singleResourceCatalog(workspace, domain.AggregateKindActor, true), true
	case ReceiptOperationActorDelegationPropose:
		catalog := singleResourceCatalog(workspace, domain.AggregateKindActorDelegation, true)
		catalog.ceremonyPurpose = []domain.CeremonyPurpose{domain.CeremonyPurposeDelegationActivation}
		return catalog, true
	case ReceiptOperationActorDelegationActivate:
		catalog := singleResourceCatalog(workspace, domain.AggregateKindActorDelegation, true)
		catalog.ceremonyPurpose = []domain.CeremonyPurpose{domain.CeremonyPurposeActorSessionStart}
		return catalog, true
	case ReceiptOperationActorSessionStart:
		catalog := singleResourceCatalog(workspace, domain.AggregateKindActorSession, true)
		catalog.sessionRequired = true
		return catalog, true
	default:
		return receiptOperationCatalog{}, false
	}
}

func singleResourceCatalog(
	scopeKind domain.ScopeKind,
	resourceKind domain.AggregateKind,
	capsuleRequired bool,
) receiptOperationCatalog {
	return receiptOperationCatalog{
		scopeKind: scopeKind, resourceKinds: []domain.AggregateKind{resourceKind},
		eventCount: 1, capsuleRequired: capsuleRequired,
	}
}

// W0ReceiptResultParams contains semantic commit metadata only. Replay
// disposition, request IDs, response DTO bytes, capsule digest/signature, and
// transport negotiation are intentionally absent.
type W0ReceiptResultParams struct {
	Operation              W0ReceiptOperation
	AuthorityID            domain.AuthorityID
	AuthorityEpoch         domain.AuthorityEpoch
	Scope                  domain.AuthorityScope
	AcceptedAt             time.Time
	CommandFingerprint     domain.CommandFingerprint
	AuthorizationDigest    domain.AuthorizationDigest
	Resources              []domain.AggregateRef
	IssuedCeremonies       []domain.CeremonyChallenge
	FirstEventPosition     domain.StreamPosition
	LastEventPosition      domain.StreamPosition
	EventIDs               []domain.EventID
	FinalStreamDigest      domain.StreamDigest
	SessionBinding         *domain.SessionBinding
	SessionClient          domain.ClientInstanceID
	PresentationCredential domain.PresentationCredentialBinding
}

type receiptResourceWire struct {
	Kind    string              `json:"kind"`
	ID      CanonicalIdentifier `json:"id"`
	Version uint64              `json:"version"`
}

type receiptCeremonyWire struct {
	ID        CanonicalIdentifier `json:"id"`
	Purpose   string              `json:"purpose"`
	ExpiresAt CanonicalInstant    `json:"expires_at"`
}

type receiptEventRangeWire struct {
	FirstPosition     uint64                `json:"first_position"`
	LastPosition      uint64                `json:"last_position"`
	Count             uint16                `json:"count"`
	EventIDs          []CanonicalIdentifier `json:"event_ids"`
	FinalStreamDigest CanonicalDigest       `json:"final_stream_digest"`
}

// receiptSessionBindingHashView is the complete security snapshot committed
// by session.start.v1. It is hashed separately because the catalog permits up
// to 64 grant revisions, while every durable receipt core has a hard 2 KiB
// bound. The receipt carries the compact client identity and this digest; the
// actor-session aggregate remains the authoritative source of the full typed
// binding.
type receiptSessionBindingHashView struct {
	Schema                          string                `json:"schema"`
	ClientInstanceID                CanonicalIdentifier   `json:"client_instance_id"`
	AuthorityID                     CanonicalIdentifier   `json:"authority_id"`
	AuthorityEpoch                  CanonicalIdentifier   `json:"authority_epoch"`
	WorkspaceID                     CanonicalIdentifier   `json:"workspace_id"`
	PrincipalID                     CanonicalIdentifier   `json:"principal_id"`
	ActorID                         CanonicalIdentifier   `json:"actor_id"`
	Membership                      receiptResourceWire   `json:"membership"`
	Delegation                      receiptResourceWire   `json:"delegation"`
	Device                          *receiptResourceWire  `json:"device"`
	DeviceTrustRevision             *uint64               `json:"device_trust_revision"`
	Grants                          []receiptResourceWire `json:"grants"`
	PolicyRevision                  string                `json:"policy_revision"`
	AssuranceClass                  string                `json:"assurance_class"`
	IssuedAt                        CanonicalInstant      `json:"issued_at"`
	AbsoluteExpiry                  CanonicalInstant      `json:"absolute_expiry"`
	PresentationCredentialReference string                `json:"presentation_credential_reference"`
	PresentationCredentialDigest    CanonicalDigest       `json:"presentation_credential_digest"`
	PresentationCredentialAudience  string                `json:"presentation_credential_audience"`
	PresentationCredentialVersion   uint16                `json:"presentation_credential_version"`
}

func (receiptSessionBindingHashView) canonicalView() {}

type receiptSessionBindingWire struct {
	ClientInstanceID CanonicalIdentifier `json:"client_instance_id"`
	BindingDigest    CanonicalDigest     `json:"binding_digest"`
}

type receiptResultWire struct {
	Schema              string                     `json:"schema"`
	Operation           string                     `json:"operation"`
	Outcome             string                     `json:"outcome"`
	AuthorityID         CanonicalIdentifier        `json:"authority_id"`
	AuthorityEpoch      CanonicalIdentifier        `json:"authority_epoch"`
	ScopeKind           string                     `json:"scope_kind"`
	ScopeID             CanonicalIdentifier        `json:"scope_id"`
	AcceptedAt          CanonicalInstant           `json:"accepted_at"`
	CommandFingerprint  CanonicalDigest            `json:"command_fingerprint"`
	AuthorizationDigest CanonicalDigest            `json:"authorization_digest"`
	Resources           []receiptResourceWire      `json:"resources"`
	IssuedCeremonies    []receiptCeremonyWire      `json:"issued_ceremonies"`
	Events              receiptEventRangeWire      `json:"events"`
	CapsuleRequired     bool                       `json:"capsule_required"`
	SessionBinding      *receiptSessionBindingWire `json:"session_binding"`
}

func cloneReceiptResultWire(wire receiptResultWire) receiptResultWire {
	cloned := wire
	cloned.Resources = append([]receiptResourceWire(nil), wire.Resources...)
	cloned.IssuedCeremonies = append([]receiptCeremonyWire(nil), wire.IssuedCeremonies...)
	cloned.Events.EventIDs = append([]CanonicalIdentifier(nil), wire.Events.EventIDs...)
	if wire.SessionBinding != nil {
		session := *wire.SessionBinding
		cloned.SessionBinding = &session
	}
	return cloned
}

const recoveryCapsuleDraftSchemaV1 = "blackbird.recovery-capsule-draft/v1"

type recoveryCapsuleWire struct {
	Schema               string                      `json:"schema"`
	Operation            string                      `json:"operation"`
	OperationMajor       uint16                      `json:"operation_major"`
	CommandID            CanonicalIdentifier         `json:"command_id"`
	AuthorityID          CanonicalIdentifier         `json:"authority_id"`
	AuthorityEpoch       CanonicalIdentifier         `json:"authority_epoch"`
	ScopeKind            string                      `json:"scope_kind"`
	ScopeID              CanonicalIdentifier         `json:"scope_id"`
	AcceptedAt           CanonicalInstant            `json:"accepted_at"`
	SigningKeyID         string                      `json:"signing_key_id"`
	Resources            []receiptResourceWire       `json:"resources"`
	RecipientSnapshots   []CanonicalDigest           `json:"recipient_snapshots"`
	DestinationSnapshots []CanonicalDigest           `json:"destination_snapshots"`
	Effects              []recoveryCapsuleEffectWire `json:"effects"`
	RequestDigest        CanonicalDigest             `json:"request_digest"`
	ReceiptResultDigest  CanonicalDigest             `json:"receipt_result_digest"`
	Events               receiptEventRangeWire       `json:"events"`
}

type recoveryCapsuleEffectWire struct {
	CausingEventID CanonicalIdentifier `json:"causing_event_id"`
	Handler        string              `json:"handler"`
	ContractMajor  uint16              `json:"contract_major"`
	DestinationKey string              `json:"destination_key"`
	Ordinal        uint16              `json:"ordinal"`
	MetadataDigest CanonicalDigest     `json:"metadata_digest"`
}

// W0RecoveryCapsuleView is the closed W0.4 unsigned recovery draft. The
// identity slice has no recipient/destination snapshot or effect contract yet,
// so those lists are present and empty rather than omitted. Later slices must
// introduce a new schema before populating them.
type W0RecoveryCapsuleView struct {
	wire         recoveryCapsuleWire
	resultDigest Digest
}

func NewW0RecoveryCapsuleView(
	resultEnvelope ResultEnvelope,
	commandID domain.CommandID,
	operationMajor OperationMajor,
	capsulePlan RecoveryCapsulePlan,
) (W0RecoveryCapsuleView, error) {
	result := resultEnvelope.ReceiptDocument()
	signingKeyID := capsulePlan.KeyID()
	if result.IsZero() || commandID.IsZero() || operationMajor.IsZero() ||
		!strings.HasSuffix(string(result.operation), ".v"+strconv.FormatUint(uint64(operationMajor.Uint16()), 10)) ||
		capsulePlan.Requirement() != RecoveryCapsuleRequired || !validOpaqueText(signingKeyID, 256) ||
		!result.wire.CapsuleRequired || resultEnvelope.ResponseDigest() != result.Digest() {
		return W0RecoveryCapsuleView{}, ErrCanonicalProfile
	}
	command, err := NewCanonicalIdentifier(commandID.String())
	if err != nil {
		return W0RecoveryCapsuleView{}, err
	}
	resultDigest, err := NewCanonicalDigest(result.Digest().String())
	if err != nil {
		return W0RecoveryCapsuleView{}, err
	}
	return W0RecoveryCapsuleView{
		wire: recoveryCapsuleWire{
			Schema: recoveryCapsuleDraftSchemaV1, Operation: string(result.operation),
			OperationMajor: operationMajor.Uint16(), CommandID: command,
			AuthorityID: result.wire.AuthorityID, AuthorityEpoch: result.wire.AuthorityEpoch,
			ScopeKind: result.wire.ScopeKind, ScopeID: result.wire.ScopeID,
			AcceptedAt: result.wire.AcceptedAt, SigningKeyID: signingKeyID,
			Resources:          append([]receiptResourceWire(nil), result.wire.Resources...),
			RecipientSnapshots: []CanonicalDigest{}, DestinationSnapshots: []CanonicalDigest{},
			Effects: []recoveryCapsuleEffectWire{}, RequestDigest: result.wire.CommandFingerprint,
			ReceiptResultDigest: resultDigest, Events: cloneReceiptResultWire(result.wire).Events,
		},
		resultDigest: result.Digest(),
	}, nil
}

func (view W0RecoveryCapsuleView) MarshalJSON() ([]byte, error) {
	if !view.valid() {
		return nil, ErrCanonicalProfile
	}
	return json.Marshal(view.wire)
}

func (view W0RecoveryCapsuleView) valid() bool {
	wire := view.wire
	catalog, exists := receiptCatalog(CommandOperation(wire.Operation))
	if !exists || !catalog.capsuleRequired || wire.Schema != recoveryCapsuleDraftSchemaV1 ||
		wire.Resources == nil || wire.RecipientSnapshots == nil || wire.DestinationSnapshots == nil ||
		wire.Effects == nil || wire.Events.EventIDs == nil ||
		wire.OperationMajor == 0 || wire.CommandID.String() == "" || wire.AuthorityID.String() == "" ||
		wire.AuthorityEpoch.String() == "" || wire.ScopeKind != string(catalog.scopeKind) ||
		wire.ScopeID.String() == "" || wire.AcceptedAt.String() == "" || !validOpaqueText(wire.SigningKeyID, 256) ||
		len(wire.Resources) != len(catalog.resourceKinds) || len(wire.RecipientSnapshots) != 0 ||
		len(wire.DestinationSnapshots) != 0 || len(wire.Effects) != 0 || wire.RequestDigest.String() == "" ||
		wire.ReceiptResultDigest.String() == "" || wire.ReceiptResultDigest.String() != view.resultDigest.String() ||
		len(wire.Events.EventIDs) != catalog.eventCount || wire.Events.Count != uint16(catalog.eventCount) ||
		wire.Events.FirstPosition == 0 || wire.Events.LastPosition < wire.Events.FirstPosition ||
		wire.Events.LastPosition-wire.Events.FirstPosition+1 != uint64(catalog.eventCount) ||
		wire.Events.FinalStreamDigest.String() == "" {
		return false
	}
	for index, kind := range catalog.resourceKinds {
		if !validReceiptResourceWire(wire.Resources[index], kind) {
			return false
		}
	}
	seen := make(map[CanonicalIdentifier]struct{}, len(wire.Events.EventIDs))
	for _, eventID := range wire.Events.EventIDs {
		if eventID.String() == "" {
			return false
		}
		if _, duplicate := seen[eventID]; duplicate {
			return false
		}
		seen[eventID] = struct{}{}
	}
	return strings.HasSuffix(wire.Operation, ".v"+strconv.FormatUint(uint64(wire.OperationMajor), 10))
}

func (W0RecoveryCapsuleView) canonicalView()           {}
func (W0RecoveryCapsuleView) canonicalScalar()         {}
func (W0RecoveryCapsuleView) recoveryCapsuleHashView() {}

// W0ReceiptResultView is a closed tagged union over all eleven W0 operations.
// Its private wire form prevents callers from omitting required null/list
// fields or changing a cataloged resource, ceremony, event, or capsule shape.
type W0ReceiptResultView struct {
	wire                 receiptResultWire
	sessionBindingDigest CanonicalDigest
}

func NewW0ReceiptResultView(params W0ReceiptResultParams) (W0ReceiptResultView, error) {
	catalog, exists := receiptCatalog(params.Operation)
	if !exists || params.Scope.IsZero() || params.Scope.Kind() != catalog.scopeKind ||
		params.AuthorityID.IsZero() || params.AuthorityEpoch.IsZero() || params.CommandFingerprint.IsZero() ||
		params.AuthorizationDigest.IsZero() || params.FinalStreamDigest.IsZero() {
		return W0ReceiptResultView{}, ErrCanonicalProfile
	}
	acceptedAt, err := NewCanonicalInstant(params.AcceptedAt)
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	resources, err := receiptResources(params.Resources, catalog.resourceKinds)
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	ceremonies, err := receiptCeremonies(params.IssuedCeremonies, catalog.ceremonyPurpose, acceptedAt)
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	events, err := receiptEventRange(params, catalog.eventCount)
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	session, sessionDigest, err := receiptSessionBinding(
		params.SessionBinding, params.PresentationCredential, params, catalog.sessionRequired,
	)
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	authorityID, err := NewCanonicalIdentifier(params.AuthorityID.String())
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	epoch, err := NewCanonicalIdentifier(params.AuthorityEpoch.String())
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	scopeID, err := NewCanonicalIdentifier(params.Scope.ID())
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	commandDigest, err := commandFingerprintText(params.CommandFingerprint)
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	authorizationDigest, err := NewCanonicalDigest(params.AuthorizationDigest.String())
	if err != nil {
		return W0ReceiptResultView{}, err
	}
	return W0ReceiptResultView{wire: receiptResultWire{
		Schema: receiptResultSchemaV1, Operation: string(params.Operation), Outcome: "applied",
		AuthorityID: authorityID, AuthorityEpoch: epoch, ScopeKind: string(params.Scope.Kind()), ScopeID: scopeID,
		AcceptedAt: acceptedAt, CommandFingerprint: commandDigest, AuthorizationDigest: authorizationDigest,
		Resources: resources, IssuedCeremonies: ceremonies, Events: events,
		CapsuleRequired: catalog.capsuleRequired, SessionBinding: session,
	}, sessionBindingDigest: sessionDigest}, nil
}

func receiptResources(
	provided []domain.AggregateRef,
	expected []domain.AggregateKind,
) ([]receiptResourceWire, error) {
	if len(provided) != len(expected) {
		return nil, ErrCanonicalProfile
	}
	byKind := make(map[domain.AggregateKind]domain.AggregateRef, len(provided))
	for _, resource := range provided {
		if resource.IsZero() || resource.Version().Uint64() > MaxCanonicalInteger {
			return nil, ErrCanonicalProfile
		}
		if _, duplicate := byKind[resource.Kind()]; duplicate {
			return nil, ErrCanonicalProfile
		}
		byKind[resource.Kind()] = resource
	}
	result := make([]receiptResourceWire, 0, len(expected))
	for _, kind := range expected {
		resource, exists := byKind[kind]
		if !exists {
			return nil, ErrCanonicalProfile
		}
		wire, err := receiptResource(resource)
		if err != nil {
			return nil, err
		}
		result = append(result, wire)
	}
	return result, nil
}

func receiptResource(resource domain.AggregateRef) (receiptResourceWire, error) {
	id, err := NewCanonicalIdentifier(resource.ID())
	if err != nil || resource.IsZero() {
		return receiptResourceWire{}, ErrCanonicalProfile
	}
	return receiptResourceWire{
		Kind: string(resource.Kind()), ID: id, Version: resource.Version().Uint64(),
	}, nil
}

func receiptCeremonies(
	provided []domain.CeremonyChallenge,
	expected []domain.CeremonyPurpose,
	acceptedAt CanonicalInstant,
) ([]receiptCeremonyWire, error) {
	if len(provided) != len(expected) {
		return nil, ErrCanonicalProfile
	}
	result := make([]receiptCeremonyWire, 0, len(expected))
	for index, purpose := range expected {
		ceremony := provided[index]
		if ceremony.IsZero() || ceremony.Status() != domain.CeremonyPending || ceremony.Purpose() != purpose ||
			!ceremony.ExpiresAt().After(acceptedAt.Time()) {
			return nil, ErrCanonicalProfile
		}
		id, err := NewCanonicalIdentifier(ceremony.ID().String())
		if err != nil {
			return nil, err
		}
		expiresAt, err := NewCanonicalInstant(ceremony.ExpiresAt())
		if err != nil {
			return nil, err
		}
		result = append(result, receiptCeremonyWire{ID: id, Purpose: string(purpose), ExpiresAt: expiresAt})
	}
	return result, nil
}

func receiptEventRange(params W0ReceiptResultParams, expectedCount int) (receiptEventRangeWire, error) {
	if !params.FirstEventPosition.Valid() || !params.LastEventPosition.Valid() ||
		params.FirstEventPosition.Uint64() > params.LastEventPosition.Uint64() || len(params.EventIDs) != expectedCount ||
		params.LastEventPosition.Uint64()-params.FirstEventPosition.Uint64()+1 != uint64(expectedCount) {
		return receiptEventRangeWire{}, ErrCanonicalProfile
	}
	ids := make([]CanonicalIdentifier, 0, len(params.EventIDs))
	seen := make(map[domain.EventID]struct{}, len(params.EventIDs))
	for _, eventID := range params.EventIDs {
		if eventID.IsZero() {
			return receiptEventRangeWire{}, ErrCanonicalProfile
		}
		if _, duplicate := seen[eventID]; duplicate {
			return receiptEventRangeWire{}, ErrCanonicalProfile
		}
		seen[eventID] = struct{}{}
		canonicalID, err := NewCanonicalIdentifier(eventID.String())
		if err != nil {
			return receiptEventRangeWire{}, err
		}
		ids = append(ids, canonicalID)
	}
	finalDigest, err := NewCanonicalDigest(params.FinalStreamDigest.String())
	if err != nil {
		return receiptEventRangeWire{}, err
	}
	return receiptEventRangeWire{
		FirstPosition: params.FirstEventPosition.Uint64(), LastPosition: params.LastEventPosition.Uint64(),
		Count: uint16(expectedCount), EventIDs: ids, FinalStreamDigest: finalDigest,
	}, nil
}

func receiptSessionBinding(
	binding *domain.SessionBinding,
	presentation domain.PresentationCredentialBinding,
	params W0ReceiptResultParams,
	required bool,
) (*receiptSessionBindingWire, CanonicalDigest, error) {
	if required != (binding != nil) {
		return nil, CanonicalDigest{}, ErrCanonicalProfile
	}
	if binding == nil {
		if !params.SessionClient.IsZero() || !presentation.IsZero() {
			return nil, CanonicalDigest{}, ErrCanonicalProfile
		}
		return nil, CanonicalDigest{}, nil
	}
	if params.SessionClient.IsZero() || !validPresentationCredentialBinding(presentation) {
		return nil, CanonicalDigest{}, ErrCanonicalProfile
	}
	if binding.AuthorityID() != params.AuthorityID || binding.AuthorityEpoch() != params.AuthorityEpoch ||
		params.Scope.Kind() != domain.ScopeKindWorkspace || binding.WorkspaceID().String() != params.Scope.ID() ||
		!binding.IssuedAt().Equal(params.AcceptedAt) {
		return nil, CanonicalDigest{}, ErrCanonicalProfile
	}
	resource := params.Resources[0]
	if resource.Kind() != domain.AggregateKindActorSession {
		return nil, CanonicalDigest{}, ErrCanonicalProfile
	}
	clientInstance, err := NewCanonicalIdentifier(params.SessionClient.String())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	authorityID, err := NewCanonicalIdentifier(binding.AuthorityID().String())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	epoch, err := NewCanonicalIdentifier(binding.AuthorityEpoch().String())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	workspaceID, err := NewCanonicalIdentifier(binding.WorkspaceID().String())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	principalID, err := NewCanonicalIdentifier(binding.PrincipalID().String())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	actorID, err := NewCanonicalIdentifier(binding.ActorID().String())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	membership, err := receiptResource(binding.MembershipRevision())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	delegation, err := receiptResource(binding.DelegationRevision())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	grants, err := receiptGrantResources(binding.GrantRevisions())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	issuedAt, err := NewCanonicalInstant(binding.IssuedAt())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	expiresAt, err := NewCanonicalInstant(binding.AbsoluteExpiry())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	if !validReceiptPolicy(binding.PolicyRevision().String(), binding.AssuranceClass().String()) {
		return nil, CanonicalDigest{}, ErrCanonicalProfile
	}
	presentationBytes := presentation.Digest().Bytes()
	presentationDigest, err := NewCanonicalDigest(hex.EncodeToString(presentationBytes[:]))
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	full := receiptSessionBindingHashView{
		Schema:           "blackbird.session-binding/v1",
		ClientInstanceID: clientInstance, AuthorityID: authorityID, AuthorityEpoch: epoch,
		WorkspaceID: workspaceID, PrincipalID: principalID, ActorID: actorID,
		Membership: membership, Delegation: delegation, Grants: grants,
		PolicyRevision: binding.PolicyRevision().String(), AssuranceClass: binding.AssuranceClass().String(),
		IssuedAt: issuedAt, AbsoluteExpiry: expiresAt,
		PresentationCredentialReference: presentation.Reference().String(),
		PresentationCredentialDigest:    presentationDigest,
		PresentationCredentialAudience:  presentation.Audience().String(),
		PresentationCredentialVersion:   presentation.Version(),
	}
	if device, hasDevice := binding.DeviceRevision(); hasDevice {
		deviceWire, deviceErr := receiptResource(device)
		if deviceErr != nil {
			return nil, CanonicalDigest{}, deviceErr
		}
		trust, hasTrust := binding.DeviceTrustRevision()
		if !hasTrust || !trust.Valid() {
			return nil, CanonicalDigest{}, ErrCanonicalProfile
		}
		trustValue := trust.Uint64()
		full.Device = &deviceWire
		full.DeviceTrustRevision = &trustValue
	}
	canonical, err := encodeCanonical(full, MaxRecoveryCapsuleBytes)
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	digest, err := NewCanonicalDigest(digestCanonical(sessionBindingDomain, canonical).String())
	if err != nil {
		return nil, CanonicalDigest{}, err
	}
	return &receiptSessionBindingWire{
		ClientInstanceID: clientInstance,
		BindingDigest:    digest,
	}, digest, nil
}

func receiptGrantResources(grants []domain.AggregateRef) ([]receiptResourceWire, error) {
	result := make([]receiptResourceWire, 0, len(grants))
	for _, grant := range grants {
		if grant.Kind() != domain.AggregateKindGrant {
			return nil, ErrCanonicalProfile
		}
		wire, err := receiptResource(grant)
		if err != nil {
			return nil, err
		}
		result = append(result, wire)
	}
	return result, nil
}

func commandFingerprintText(fingerprint domain.CommandFingerprint) (CanonicalDigest, error) {
	if fingerprint.IsZero() {
		return CanonicalDigest{}, ErrCanonicalProfile
	}
	return NewCanonicalDigest(hex.EncodeToString(fingerprint[:]))
}

func (view W0ReceiptResultView) MarshalJSON() ([]byte, error) {
	if !view.valid() {
		return nil, ErrCanonicalProfile
	}
	return json.Marshal(view.wire)
}

func (view W0ReceiptResultView) Operation() CommandOperation {
	return CommandOperation(view.wire.Operation)
}

func (view W0ReceiptResultView) valid() bool {
	wire := view.wire
	catalog, exists := receiptCatalog(W0ReceiptOperation(wire.Operation))
	if !exists || wire.Schema != receiptResultSchemaV1 || wire.Outcome != "applied" ||
		wire.ScopeKind != string(catalog.scopeKind) || wire.CapsuleRequired != catalog.capsuleRequired ||
		(wire.SessionBinding != nil) != catalog.sessionRequired ||
		wire.Resources == nil || wire.IssuedCeremonies == nil || wire.Events.EventIDs == nil ||
		len(wire.Resources) != len(catalog.resourceKinds) ||
		len(wire.IssuedCeremonies) != len(catalog.ceremonyPurpose) ||
		len(wire.Events.EventIDs) != catalog.eventCount || wire.Events.Count != uint16(catalog.eventCount) ||
		wire.Events.FirstPosition == 0 ||
		wire.Events.LastPosition < wire.Events.FirstPosition ||
		wire.Events.LastPosition-wire.Events.FirstPosition+1 != uint64(catalog.eventCount) {
		return false
	}
	for index, kind := range catalog.resourceKinds {
		if !validReceiptResourceWire(wire.Resources[index], kind) {
			return false
		}
	}
	seenEvents := make(map[CanonicalIdentifier]struct{}, len(wire.Events.EventIDs))
	for _, eventID := range wire.Events.EventIDs {
		if eventID.String() == "" {
			return false
		}
		if _, duplicate := seenEvents[eventID]; duplicate {
			return false
		}
		seenEvents[eventID] = struct{}{}
	}
	for index, purpose := range catalog.ceremonyPurpose {
		if wire.IssuedCeremonies[index].ID.String() == "" ||
			wire.IssuedCeremonies[index].Purpose != string(purpose) ||
			!wire.IssuedCeremonies[index].ExpiresAt.Time().After(wire.AcceptedAt.Time()) {
			return false
		}
	}
	return validReceiptSessionWire(wire.SessionBinding, view.sessionBindingDigest)
}

func validReceiptSessionWire(session *receiptSessionBindingWire, expectedDigest CanonicalDigest) bool {
	if session == nil {
		return expectedDigest.String() == ""
	}
	return session.ClientInstanceID.String() != "" && session.BindingDigest.String() != "" &&
		expectedDigest.String() != "" && session.BindingDigest == expectedDigest
}

func validReceiptResourceWire(resource receiptResourceWire, kind domain.AggregateKind) bool {
	return resource.Kind == string(kind) && resource.ID.String() != "" &&
		resource.Version > 0 && resource.Version <= MaxCanonicalInteger
}

func validReceiptPolicy(policyRevision, assuranceClass string) bool {
	policy, policyErr := domain.NewPolicyRevision(policyRevision)
	assurance, assuranceErr := domain.NewAssuranceClass(assuranceClass)
	return policyErr == nil && assuranceErr == nil &&
		policy.String() == policyRevision && assurance.String() == assuranceClass
}

func (W0ReceiptResultView) canonicalView()         {}
func (W0ReceiptResultView) canonicalScalar()       {}
func (W0ReceiptResultView) receiptResultHashView() {}

type eventSemanticViewV1 struct {
	Schema              string                `json:"schema"`
	EventID             CanonicalIdentifier   `json:"event_id"`
	CommandID           CanonicalIdentifier   `json:"command_id"`
	AuthorityID         CanonicalIdentifier   `json:"authority_id"`
	AuthorityEpoch      CanonicalIdentifier   `json:"authority_epoch"`
	ScopeKind           string                `json:"scope_kind"`
	ScopeID             CanonicalIdentifier   `json:"scope_id"`
	StreamSequence      uint64                `json:"stream_sequence"`
	AggregateKind       string                `json:"aggregate_kind"`
	AggregateID         CanonicalIdentifier   `json:"aggregate_id"`
	AggregateVersion    uint64                `json:"aggregate_version"`
	EventIndex          uint16                `json:"event_index"`
	EventType           string                `json:"event_type"`
	EventSchema         uint16                `json:"event_schema"`
	Payload             canonicalEventPayload `json:"payload"`
	PrincipalID         CanonicalIdentifier   `json:"principal_id"`
	ActorSessionID      *CanonicalIdentifier  `json:"actor_session_id"`
	AuthorizationDigest CanonicalDigest       `json:"authorization_digest"`
	CommandReceiptID    CanonicalIdentifier   `json:"command_receipt_id"`
	CausationEventID    *CanonicalIdentifier  `json:"causation_event_id"`
	CorrelationID       CanonicalIdentifier   `json:"correlation_id"`
	RecordedAt          CanonicalInstant      `json:"recorded_at"`
}

func (eventSemanticViewV1) canonicalView()         {}
func (eventSemanticViewV1) eventSemanticHashView() {}

func eventSemanticView(event domain.EventEnvelope) (eventSemanticViewV1, error) {
	if !event.StreamPosition().Valid() || event.Aggregate().IsZero() || event.SchemaVersion().Uint16() != 1 {
		return eventSemanticViewV1{}, ErrCanonicalProfile
	}
	payload := event.Payload().Bytes()
	decodedPayload, err := decodeIdentityPayload(event.EventType(), payload)
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	if !identityPayloadMatchesEnvelope(event, decodedPayload) {
		return eventSemanticViewV1{}, ErrCanonicalProfile
	}
	id := func(text string) (CanonicalIdentifier, error) { return NewCanonicalIdentifier(text) }
	eventID, err := id(event.EventID().String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	commandID, err := id(event.CommandID().String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	authorityID, err := id(event.AuthorityID().String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	epoch, err := id(event.AuthorityEpoch().String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	scopeID, err := id(event.Scope().ID())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	aggregateID, err := id(event.Aggregate().ID())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	principalID, err := id(event.PrincipalID().String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	receiptID, err := id(event.CommandReceiptID().String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	correlationID, err := id(event.CorrelationID().String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	authorization, err := NewCanonicalDigest(event.AuthorizationDigest().String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	recordedAt, err := NewCanonicalInstant(event.RecordedAt())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	view := eventSemanticViewV1{
		Schema: domain.EventEnvelopeSchema, EventID: eventID, CommandID: commandID,
		AuthorityID: authorityID, AuthorityEpoch: epoch, ScopeKind: string(event.Scope().Kind()), ScopeID: scopeID,
		StreamSequence: event.StreamPosition().Uint64(), AggregateKind: string(event.Aggregate().Kind()),
		AggregateID: aggregateID, AggregateVersion: event.Aggregate().Version().Uint64(), EventIndex: event.EventIndex(),
		EventType: string(event.EventType()), EventSchema: event.SchemaVersion().Uint16(),
		Payload: canonicalEventPayload{canonical: append([]byte(nil), payload...)}, PrincipalID: principalID,
		AuthorizationDigest: authorization, CommandReceiptID: receiptID, CorrelationID: correlationID, RecordedAt: recordedAt,
	}
	if actor, present := event.ActorSessionID(); present {
		value, idErr := id(actor.String())
		if idErr != nil {
			return eventSemanticViewV1{}, idErr
		}
		view.ActorSessionID = &value
	}
	if cause, present := event.CausationEventID(); present {
		value, idErr := id(cause.String())
		if idErr != nil {
			return eventSemanticViewV1{}, idErr
		}
		view.CausationEventID = &value
	}
	return view, nil
}

func decodeIdentityPayload(eventType domain.EventType, canonical []byte) (any, error) {
	var target any
	switch eventType {
	case domain.EventTypeInstallationBootstrapped:
		target = &identityPayloadInstallationBootstrapped{}
	case domain.EventTypePrincipalRegistered:
		target = &identityPayloadPrincipalRegistered{}
	case domain.EventTypeDevicePairingBegan:
		target = &identityPayloadDevicePairingBegan{}
	case domain.EventTypeDevicePaired:
		target = &identityPayloadDevicePaired{}
	case domain.EventTypeWorkspaceCreated:
		target = &identityPayloadWorkspaceCreated{}
	case domain.EventTypeWorkspaceMemberInvited:
		target = &identityPayloadWorkspaceMemberInvited{}
	case domain.EventTypeWorkspaceMembershipAccepted:
		target = &identityPayloadWorkspaceMembershipAccepted{}
	case domain.EventTypeActorCreated:
		target = &identityPayloadActorCreated{}
	case domain.EventTypeActorDelegationProposed:
		target = &identityPayloadActorDelegationProposed{}
	case domain.EventTypeActorDelegationActivated:
		target = &identityPayloadActorDelegationActivated{}
	case domain.EventTypeActorSessionStarted:
		target = &identityPayloadActorSessionStarted{}
	default:
		return nil, ErrCanonicalProfile
	}
	if err := decodeCanonicalDocument(canonical, domain.MaxEventPayloadBytes, target); err != nil {
		return nil, err
	}
	if !validIdentityPayload(target) {
		return nil, ErrCanonicalProfile
	}
	view, ok := target.(CanonicalView)
	if !ok {
		return nil, ErrCanonicalProfile
	}
	reencoded, err := encodeCanonical(view, domain.MaxEventPayloadBytes)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return nil, fmt.Errorf("%w: retained identity payload mismatch", ErrCanonicalEncoding)
	}
	return target, nil
}

func identityPayloadMatchesEnvelope(event domain.EventEnvelope, payload any) bool {
	aggregate := event.Aggregate()
	if aggregate.Kind() != expectedEventAggregateKind(event.EventType()) ||
		event.Scope().Kind() != expectedEventScopeKind(event.EventType()) {
		return false
	}
	matchesAggregate := func(id CanonicalIdentifier) bool { return id.String() == aggregate.ID() }
	matchesScope := func(id CanonicalIdentifier) bool { return id.String() == event.Scope().ID() }
	switch value := payload.(type) {
	case *identityPayloadInstallationBootstrapped:
		return matchesAggregate(value.InvitationID) && matchesScope(value.InstallationID)
	case *identityPayloadPrincipalRegistered:
		return matchesAggregate(value.PrincipalID) && matchesScope(value.InstallationID)
	case *identityPayloadDevicePairingBegan:
		return matchesAggregate(value.DeviceID) && matchesScope(value.InstallationID)
	case *identityPayloadDevicePaired:
		return matchesAggregate(value.DeviceID) && matchesScope(value.InstallationID)
	case *identityPayloadWorkspaceCreated:
		return matchesAggregate(value.WorkspaceID) && matchesScope(value.WorkspaceID)
	case *identityPayloadWorkspaceMemberInvited:
		return matchesAggregate(value.MembershipID) && matchesScope(value.WorkspaceID)
	case *identityPayloadWorkspaceMembershipAccepted:
		return matchesAggregate(value.MembershipID) && matchesScope(value.WorkspaceID)
	case *identityPayloadActorCreated:
		return matchesAggregate(value.ActorID) && matchesScope(value.WorkspaceID)
	case *identityPayloadActorDelegationProposed:
		return matchesAggregate(value.DelegationID) && matchesScope(value.WorkspaceID)
	case *identityPayloadActorDelegationActivated:
		return matchesAggregate(value.DelegationID) && matchesScope(value.WorkspaceID)
	case *identityPayloadActorSessionStarted:
		return matchesAggregate(value.SessionID) && matchesScope(value.WorkspaceID)
	default:
		return false
	}
}

func expectedEventScopeKind(eventType domain.EventType) domain.ScopeKind {
	switch eventType {
	case domain.EventTypeInstallationBootstrapped, domain.EventTypePrincipalRegistered,
		domain.EventTypeDevicePairingBegan, domain.EventTypeDevicePaired:
		return domain.ScopeKindInstallation
	case domain.EventTypeWorkspaceCreated, domain.EventTypeWorkspaceMemberInvited,
		domain.EventTypeWorkspaceMembershipAccepted, domain.EventTypeActorCreated,
		domain.EventTypeActorDelegationProposed, domain.EventTypeActorDelegationActivated,
		domain.EventTypeActorSessionStarted:
		return domain.ScopeKindWorkspace
	default:
		return ""
	}
}

func expectedEventAggregateKind(eventType domain.EventType) domain.AggregateKind {
	switch eventType {
	case domain.EventTypeInstallationBootstrapped:
		return domain.AggregateKindInvitation
	case domain.EventTypePrincipalRegistered:
		return domain.AggregateKindPrincipal
	case domain.EventTypeDevicePairingBegan, domain.EventTypeDevicePaired:
		return domain.AggregateKindDevice
	case domain.EventTypeWorkspaceCreated:
		return domain.AggregateKindWorkspace
	case domain.EventTypeWorkspaceMemberInvited, domain.EventTypeWorkspaceMembershipAccepted:
		return domain.AggregateKindMembership
	case domain.EventTypeActorCreated:
		return domain.AggregateKindActor
	case domain.EventTypeActorDelegationProposed, domain.EventTypeActorDelegationActivated:
		return domain.AggregateKindActorDelegation
	case domain.EventTypeActorSessionStarted:
		return domain.AggregateKindActorSession
	default:
		return ""
	}
}

func validIdentityPayload(payload any) bool {
	validIDs := func(values ...CanonicalIdentifier) bool {
		for _, value := range values {
			if value.String() == "" {
				return false
			}
		}
		return true
	}
	validCapabilities := func(values []string) bool {
		if len(values) == 0 || len(values) > domain.MaxIdentityCapabilities {
			return false
		}
		capabilities := make([]domain.Capability, len(values))
		for index, value := range values {
			capability, err := domain.NewCapability(value)
			if err != nil {
				return false
			}
			capabilities[index] = capability
		}
		set, err := domain.NewCapabilitySet(capabilities...)
		if err != nil {
			return false
		}
		canonical := capabilityStrings(set)
		return reflect.DeepEqual(values, canonical)
	}
	switch value := payload.(type) {
	case *identityPayloadInstallationBootstrapped:
		return validIDs(value.InstallationID, value.InvitationID, value.PrincipalID, value.DeviceID, value.GrantID) &&
			value.TranscriptFingerprint.String() != ""
	case *identityPayloadPrincipalRegistered:
		kind := domain.PrincipalKind(value.Kind)
		return validIDs(value.InstallationID, value.PrincipalID) && kind.Valid() &&
			validOpaqueText(value.DisplayName, 256) &&
			((kind == domain.PrincipalKindHuman && value.PublicKeyReference == nil) ||
				(value.PublicKeyReference != nil && validOpaqueText(*value.PublicKeyReference, 4096)))
	case *identityPayloadDevicePairingBegan:
		return validIDs(value.InstallationID, value.DeviceID, value.PrincipalID, value.CeremonyID) &&
			validOpaqueText(value.DisplayName, 256) && validOpaqueText(value.PublicKeyReference, 4096)
	case *identityPayloadDevicePaired:
		return validIDs(value.InstallationID, value.DeviceID, value.PrincipalID) && validOpaqueText(value.DisplayName, 256) &&
			value.TranscriptFingerprint.String() != "" && value.TrustRevision > 0 && value.TrustRevision <= MaxCanonicalInteger &&
			value.CredentialAlgorithm == domain.DeviceCredentialAlgorithm && validOpaqueText(value.PublicKeyReference, 4096) &&
			value.SPKIFingerprint.String() != "" && value.CredentialTranscriptFingerprint.String() != ""
	case *identityPayloadWorkspaceCreated:
		return validIDs(value.WorkspaceID, value.AuthorityID, value.AuthorityEpoch) && validOpaqueText(value.Alias, 256) &&
			validOpaqueText(value.DiscoveryLocator, 4096) && validOpaqueText(value.PolicyRevision, 256)
	case *identityPayloadWorkspaceMemberInvited:
		return validIDs(value.MembershipID, value.WorkspaceID, value.PrincipalID) &&
			(value.CeremonyID == nil || value.CeremonyID.String() != "") && validCapabilities(value.Capabilities)
	case *identityPayloadWorkspaceMembershipAccepted:
		return validIDs(value.MembershipID, value.WorkspaceID, value.PrincipalID)
	case *identityPayloadActorCreated:
		return validIDs(value.ActorID, value.WorkspaceID) && validOpaqueText(value.Kind, 64) &&
			validOpaqueText(value.DisplayName, 256)
	case *identityPayloadActorDelegationProposed:
		return validIDs(value.DelegationID, value.WorkspaceID, value.PrincipalID, value.ActorID, value.CeremonyID)
	case *identityPayloadActorDelegationActivated:
		return validIDs(value.DelegationID, value.WorkspaceID, value.PrincipalID, value.ActorID, value.SessionStartCeremonyID)
	case *identityPayloadActorSessionStarted:
		return validIDs(value.SessionID, value.WorkspaceID, value.ClientInstanceID) && validOpaqueText(value.ClientName, 128) &&
			validOpaqueText(value.ClientVersion, 128) && value.BindingDigest.String() != "" &&
			validCapabilities(value.Capabilities) && validOpaqueText(value.PresentationCredentialReference, 256) &&
			value.PresentationCredentialDigest.String() != "" && validOpaqueText(value.PresentationCredentialAudience, 256) &&
			value.PresentationCredentialVersion == domain.PresentationCredentialVersion
	default:
		return false
	}
}

// VerifyEventDigests implements domain.EventDigestVerifier and is the reviewed
// production boundary used by domain.NewEventEnvelope.
func (codec ProductionCanonicalCodec) VerifyEventDigests(event domain.EventEnvelope) error {
	view, err := eventSemanticView(event)
	if err != nil {
		return err
	}
	eventDigest, err := codec.HashEvent(view)
	if err != nil || eventDigest != event.EventDigest() {
		return fmt.Errorf("%w: event semantic digest mismatch", ErrCanonicalEncoding)
	}
	streamDigest, err := codec.ChainStreamDigest(event.PreviousStreamDigest(), event.StreamPosition(), eventDigest)
	if err != nil || streamDigest != event.StreamDigest() {
		return fmt.Errorf("%w: event stream digest mismatch", ErrCanonicalEncoding)
	}
	return nil
}

// MaterializeEvent is the production construction path: callers supply the
// allocated journal fields, while the reviewed codec is installed as the
// mandatory verifier and cannot be substituted at this boundary.
func (codec ProductionCanonicalCodec) MaterializeEvent(
	params domain.EventEnvelopeParams,
) (domain.EventEnvelope, error) {
	return domain.NewEventEnvelope(params, codec)
}

// MaterializeIdentityEvent computes both digest fields from the allocated
// envelope metadata, then constructs the event through the mandatory
// production verifier. Callers cannot inject either digest or a verifier.
func (codec ProductionCanonicalCodec) MaterializeIdentityEvent(
	params domain.EventEnvelopeParams,
) (domain.EventEnvelope, error) {
	if !params.EventDigest.IsZero() || !params.StreamDigest.IsZero() {
		return domain.EventEnvelope{}, ErrCanonicalProfile
	}
	view, err := eventSemanticViewFromParams(params)
	if err != nil {
		return domain.EventEnvelope{}, err
	}
	eventDigest, err := codec.HashEvent(view)
	if err != nil {
		return domain.EventEnvelope{}, err
	}
	streamDigest, err := codec.ChainStreamDigest(params.PreviousStreamDigest, params.StreamPosition, eventDigest)
	if err != nil {
		return domain.EventEnvelope{}, err
	}
	params.EventDigest = eventDigest
	params.StreamDigest = streamDigest
	return codec.MaterializeEvent(params)
}

func eventSemanticViewFromParams(params domain.EventEnvelopeParams) (eventSemanticViewV1, error) {
	if params.EventID.IsZero() || params.CommandID.IsZero() || params.AuthorityID.IsZero() ||
		params.AuthorityEpoch.IsZero() || params.Scope.IsZero() || !params.StreamPosition.Valid() ||
		params.Aggregate.IsZero() || uint64(params.EventIndex) > MaxCanonicalInteger || !params.EventType.Valid() ||
		params.SchemaVersion.Uint16() != 1 || params.Payload.IsZero() || params.PrincipalID.IsZero() ||
		params.AuthorizationDigest.IsZero() || params.CommandReceiptID.IsZero() || params.CorrelationID.IsZero() ||
		params.RecordedAt.IsZero() {
		return eventSemanticViewV1{}, ErrCanonicalProfile
	}
	if _, err := decodeIdentityPayload(params.EventType, params.Payload.Bytes()); err != nil {
		return eventSemanticViewV1{}, err
	}
	id := func(text string) (CanonicalIdentifier, error) { return NewCanonicalIdentifier(text) }
	eventID, err := id(params.EventID.String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	commandID, err := id(params.CommandID.String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	authorityID, err := id(params.AuthorityID.String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	epoch, err := id(params.AuthorityEpoch.String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	scopeID, err := id(params.Scope.ID())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	aggregateID, err := id(params.Aggregate.ID())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	principalID, err := id(params.PrincipalID.String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	receiptID, err := id(params.CommandReceiptID.String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	correlationID, err := id(params.CorrelationID.String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	authorization, err := NewCanonicalDigest(params.AuthorizationDigest.String())
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	recordedAt, err := NewCanonicalInstant(params.RecordedAt)
	if err != nil {
		return eventSemanticViewV1{}, err
	}
	view := eventSemanticViewV1{
		Schema: domain.EventEnvelopeSchema, EventID: eventID, CommandID: commandID,
		AuthorityID: authorityID, AuthorityEpoch: epoch, ScopeKind: string(params.Scope.Kind()), ScopeID: scopeID,
		StreamSequence: params.StreamPosition.Uint64(), AggregateKind: string(params.Aggregate.Kind()),
		AggregateID: aggregateID, AggregateVersion: params.Aggregate.Version().Uint64(), EventIndex: params.EventIndex,
		EventType: string(params.EventType), EventSchema: params.SchemaVersion.Uint16(),
		Payload: canonicalEventPayload{canonical: params.Payload.Bytes()}, PrincipalID: principalID,
		AuthorizationDigest: authorization, CommandReceiptID: receiptID, CorrelationID: correlationID,
		RecordedAt: recordedAt,
	}
	if params.ActorSessionID != nil {
		actor, actorErr := id(params.ActorSessionID.String())
		if actorErr != nil {
			return eventSemanticViewV1{}, actorErr
		}
		view.ActorSessionID = &actor
	}
	if params.CausationEventID != nil {
		cause, causeErr := id(params.CausationEventID.String())
		if causeErr != nil {
			return eventSemanticViewV1{}, causeErr
		}
		view.CausationEventID = &cause
	}
	return view, nil
}

const auditEntrySchemaV1 = "blackbird.audit.entry/v1"

type auditReceiptIdentityWire struct {
	Kind                  ReceiptIdentityKind  `json:"kind"`
	ScopeKind             string               `json:"scope_kind"`
	ScopeID               CanonicalIdentifier  `json:"scope_id"`
	WorkspaceID           *CanonicalIdentifier `json:"workspace_id"`
	InstallationID        *CanonicalIdentifier `json:"installation_id"`
	PrincipalID           *CanonicalIdentifier `json:"principal_id"`
	ClientInstanceID      *CanonicalIdentifier `json:"client_instance_id"`
	TranscriptFingerprint *CanonicalDigest     `json:"transcript_fingerprint"`
	Operation             string               `json:"operation"`
	IdempotencyKey        string               `json:"idempotency_key"`
}

func (auditReceiptIdentityWire) canonicalView() {}

func hashReceiptIdentity(identity ReceiptIdentity) (Digest, error) {
	if identity.kind == "" || identity.scope.IsZero() || identity.operation.String() == "" || identity.key.String() == "" {
		return Digest{}, ErrCanonicalProfile
	}
	scopeID, err := NewCanonicalIdentifier(identity.scope.ID())
	if err != nil {
		return Digest{}, err
	}
	view := auditReceiptIdentityWire{
		Kind: identity.kind, ScopeKind: string(identity.scope.Kind()), ScopeID: scopeID,
		Operation: identity.operation.String(), IdempotencyKey: identity.key.String(),
	}
	identifier := func(text string) (*CanonicalIdentifier, error) {
		if text == "" {
			return nil, nil
		}
		value, valueErr := NewCanonicalIdentifier(text)
		return &value, valueErr
	}
	view.WorkspaceID, err = identifier(identity.workspace.String())
	if err != nil {
		return Digest{}, err
	}
	view.InstallationID, err = identifier(identity.installation.String())
	if err != nil {
		return Digest{}, err
	}
	view.PrincipalID, err = identifier(identity.principal.String())
	if err != nil {
		return Digest{}, err
	}
	view.ClientInstanceID, err = identifier(identity.clientInstance.String())
	if err != nil {
		return Digest{}, err
	}
	if !identity.transcript.IsZero() {
		value, valueErr := commandFingerprintText(identity.transcript)
		if valueErr != nil {
			return Digest{}, valueErr
		}
		view.TranscriptFingerprint = &value
	}
	canonical, err := encodeCanonical(view, MaxAuditMetadataBytes)
	if err != nil {
		return Digest{}, err
	}
	return digestCanonical(auditReceiptIdentityDomain, canonical), nil
}

type auditInvocationWire struct {
	Kind                  AuditInvocationKind  `json:"kind"`
	CommandID             *CanonicalIdentifier `json:"command_id"`
	ReceiptID             *CanonicalIdentifier `json:"receipt_id"`
	ReceiptIdentityDigest *CanonicalDigest     `json:"receipt_identity_digest"`
	RequestID             *CanonicalIdentifier `json:"request_id"`
	CorrelationID         *CanonicalIdentifier `json:"correlation_id"`
	TraceID               *CanonicalIdentifier `json:"trace_id"`
	SecurityOperation     *string              `json:"security_operation"`
}

type auditTimingWire struct {
	PersistedAuthorityAt  CanonicalInstant  `json:"persisted_authority_at"`
	ServerReceivedAt      *CanonicalInstant `json:"server_received_at"`
	AuthenticatedClientAt *CanonicalInstant `json:"authenticated_client_at"`
}

type auditRevisionWire struct {
	Kind    string              `json:"kind"`
	ID      CanonicalIdentifier `json:"id"`
	Version uint64              `json:"version"`
}

type auditSubjectWire struct {
	Kind               AuditSubjectKind     `json:"kind"`
	PrincipalID        *CanonicalIdentifier `json:"principal_id"`
	DeviceID           *CanonicalIdentifier `json:"device_id"`
	WorkloadID         *CanonicalIdentifier `json:"workload_id"`
	ActorID            *CanonicalIdentifier `json:"actor_id"`
	ActorSessionID     *CanonicalIdentifier `json:"actor_session_id"`
	DelegationChain    []auditRevisionWire  `json:"delegation_chain"`
	UnattributedSource *CanonicalDigest     `json:"unattributed_source_digest"`
}

type auditProvenanceWire struct {
	SourceAuthorityID  CanonicalIdentifier  `json:"source_authority_id"`
	FederationEnvelope *CanonicalIdentifier `json:"federation_envelope_id"`
}

type auditAuthorizationWire struct {
	EffectiveGrants        []auditRevisionWire  `json:"effective_grants"`
	AuthorizationRevisions []auditRevisionWire  `json:"authorization_revisions"`
	RevocationRevisions    []auditRevisionWire  `json:"revocation_revisions"`
	PolicyRevision         *string              `json:"policy_revision"`
	DeviceTrustRevision    *uint64              `json:"device_trust_revision"`
	GuardDigest            CanonicalDigest      `json:"guard_digest"`
	AdmissionGeneration    uint64               `json:"admission_generation"`
	OldBootstrapGeneration *CanonicalIdentifier `json:"old_bootstrap_generation_id"`
	NewBootstrapGeneration *CanonicalIdentifier `json:"new_bootstrap_generation_id"`
}

type auditResourceWire struct {
	Kind          string              `json:"kind"`
	ID            CanonicalIdentifier `json:"id"`
	BeforeVersion *uint64             `json:"before_version"`
	AfterVersion  *uint64             `json:"after_version"`
}

type AuditEntryParams struct {
	ChainScopeID      domain.AuthorityScope
	Sequence          uint64
	AuthorityID       domain.AuthorityID
	AuthorityEpoch    domain.AuthorityEpoch
	RecordedAt        time.Time
	Intent            AuditIntent
	PreviousEntryHash Digest
}

type AuditEntryViewV1 struct {
	Schema             string                 `json:"schema"`
	ChainScopeID       CanonicalIdentifier    `json:"chain_scope_id"`
	AuditSequence      uint64                 `json:"audit_sequence"`
	AuthorityID        CanonicalIdentifier    `json:"authority_id"`
	AuthorityEpoch     CanonicalIdentifier    `json:"authority_epoch"`
	RecordedAt         CanonicalInstant       `json:"recorded_at"`
	Action             string                 `json:"action"`
	Outcome            string                 `json:"outcome"`
	CommandFingerprint CanonicalDigest        `json:"command_fingerprint"`
	Invocation         auditInvocationWire    `json:"invocation"`
	Timing             auditTimingWire        `json:"timing"`
	Subject            auditSubjectWire       `json:"subject"`
	Provenance         auditProvenanceWire    `json:"provenance"`
	Authorization      auditAuthorizationWire `json:"authorization"`
	Resources          []auditResourceWire    `json:"resources"`
	ApprovalEvidence   []CanonicalDigest      `json:"approval_evidence_digests"`
	SafeReason         *string                `json:"safe_reason"`
	PreviousEntryHash  CanonicalAuditHash     `json:"previous_entry_hash"`
}

func (AuditEntryViewV1) canonicalView()      {}
func (AuditEntryViewV1) auditEntryHashView() {}

func NewAuditEntryViewV1(params AuditEntryParams) (AuditEntryViewV1, error) {
	if params.ChainScopeID.IsZero() || params.Sequence == 0 || params.Sequence > MaxCanonicalInteger ||
		params.AuthorityID.IsZero() || params.AuthorityEpoch.IsZero() || params.RecordedAt.IsZero() ||
		params.Intent.Operation().String() == "" || params.Intent.Fingerprint().IsZero() || !params.Intent.finalized ||
		(params.Intent.provenance.sourceAuthority != params.AuthorityID) !=
			(params.Intent.provenance.federationEnvelope != nil) {
		return AuditEntryViewV1{}, ErrCanonicalProfile
	}
	scopeID, err := NewCanonicalIdentifier(params.ChainScopeID.ID())
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	authorityID, err := NewCanonicalIdentifier(params.AuthorityID.String())
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	epoch, err := NewCanonicalIdentifier(params.AuthorityEpoch.String())
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	recordedAt, err := NewCanonicalInstant(params.RecordedAt)
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	fingerprint, err := commandFingerprintText(params.Intent.Fingerprint())
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	previousBytes := params.PreviousEntryHash[:]
	previous, err := NewCanonicalAuditHash(hex.EncodeToString(previousBytes))
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	invocation, err := auditInvocationView(params.Intent.invocation)
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	timing, err := auditTimingView(params.Intent.timing)
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	subject, err := auditSubjectView(params.Intent.subject)
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	provenance, err := auditProvenanceView(params.Intent.provenance)
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	authorization, err := auditAuthorizationView(params.Intent.authorization)
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	resources, err := auditResourceViews(params.Intent.resources)
	if err != nil {
		return AuditEntryViewV1{}, err
	}
	approvals := make([]CanonicalDigest, len(params.Intent.approvalEvidence))
	for index, evidence := range params.Intent.approvalEvidence {
		approvals[index], err = CanonicalDigestFromDigest(evidence)
		if err != nil {
			return AuditEntryViewV1{}, err
		}
	}
	var reason *string
	if value := params.Intent.detail.SafeReason(); value != "" {
		reason = &value
	}
	view := AuditEntryViewV1{
		Schema: auditEntrySchemaV1, ChainScopeID: scopeID, AuditSequence: params.Sequence,
		AuthorityID: authorityID, AuthorityEpoch: epoch, RecordedAt: recordedAt,
		Action: params.Intent.Operation().String(), Outcome: string(params.Intent.Outcome()),
		CommandFingerprint: fingerprint, Invocation: invocation, Timing: timing, Subject: subject,
		Provenance: provenance, Authorization: authorization, Resources: resources,
		ApprovalEvidence: approvals, SafeReason: reason, PreviousEntryHash: previous,
	}
	if !view.valid() {
		return AuditEntryViewV1{}, ErrCanonicalProfile
	}
	return view, nil
}

func auditInvocationView(invocation AuditInvocation) (auditInvocationWire, error) {
	view := auditInvocationWire{
		Kind: invocation.kind, RequestID: invocation.requestID,
		CorrelationID: invocation.correlationID, TraceID: invocation.traceID,
	}
	switch invocation.kind {
	case AuditInvocationCommand:
		if invocation.commandID.IsZero() || invocation.receiptID.IsZero() || invocation.receiptIdentityDigest.IsZero() ||
			invocation.securityOperation != "" || invocation.requestID == nil || invocation.traceID == nil ||
			invocation.correlationID == nil {
			return auditInvocationWire{}, ErrCanonicalProfile
		}
		command, err := NewCanonicalIdentifier(invocation.commandID.String())
		if err != nil {
			return auditInvocationWire{}, err
		}
		receipt, err := NewCanonicalIdentifier(invocation.receiptID.String())
		if err != nil {
			return auditInvocationWire{}, err
		}
		digest, err := CanonicalDigestFromDigest(invocation.receiptIdentityDigest)
		if err != nil {
			return auditInvocationWire{}, err
		}
		view.CommandID, view.ReceiptID, view.ReceiptIdentityDigest = &command, &receipt, &digest
	case AuditInvocationSecurity:
		if !invocation.securityOperation.Valid() || !invocation.commandID.IsZero() || !invocation.receiptID.IsZero() ||
			!invocation.receiptIdentityDigest.IsZero() {
			return auditInvocationWire{}, ErrCanonicalProfile
		}
		denial := invocation.securityOperation == SecurityRecordBootstrapDenial ||
			invocation.securityOperation == SecurityRecordCommandDenial
		if denial != (invocation.requestID != nil && invocation.traceID != nil) ||
			(invocation.securityOperation == SecurityRecordCommandDenial) != (invocation.correlationID != nil) {
			return auditInvocationWire{}, ErrCanonicalProfile
		}
		operation := string(invocation.securityOperation)
		view.SecurityOperation = &operation
	default:
		return auditInvocationWire{}, ErrCanonicalProfile
	}
	return view, nil
}

func auditTimingView(timing AuditTiming) (auditTimingWire, error) {
	authority, err := NewCanonicalInstant(timing.persistedAuthorityTime)
	if err != nil {
		return auditTimingWire{}, err
	}
	view := auditTimingWire{PersistedAuthorityAt: authority}
	if timing.serverReceivedTime != nil {
		server, serverErr := NewCanonicalInstant(*timing.serverReceivedTime)
		if serverErr != nil {
			return auditTimingWire{}, serverErr
		}
		view.ServerReceivedAt = &server
	}
	if timing.clientTime != nil {
		client, clientErr := NewCanonicalInstant(*timing.clientTime)
		if clientErr != nil {
			return auditTimingWire{}, clientErr
		}
		view.AuthenticatedClientAt = &client
	}
	return view, nil
}

func auditSubjectView(subject AuditSubject) (auditSubjectWire, error) {
	view := auditSubjectWire{Kind: subject.kind, DelegationChain: []auditRevisionWire{}}
	identifier := func(text string) (*CanonicalIdentifier, error) {
		value, err := NewCanonicalIdentifier(text)
		return &value, err
	}
	var err error
	switch subject.kind {
	case AuditSubjectAttributed:
		if subject.principal.IsZero() || !subject.unattributed.IsZero() {
			return auditSubjectWire{}, ErrCanonicalProfile
		}
		view.PrincipalID, err = identifier(subject.principal.String())
		if err != nil {
			return auditSubjectWire{}, err
		}
		if subject.hasDevice {
			view.DeviceID, err = identifier(subject.device.String())
			if err != nil {
				return auditSubjectWire{}, err
			}
		} else if !subject.device.IsZero() {
			return auditSubjectWire{}, ErrCanonicalProfile
		}
		if subject.hasWorkload {
			view.WorkloadID, err = identifier(subject.workload.String())
			if err != nil {
				return auditSubjectWire{}, err
			}
		} else if !subject.workload.IsZero() {
			return auditSubjectWire{}, ErrCanonicalProfile
		}
		if subject.hasActor {
			if subject.actor.IsZero() || subject.actorSession.IsZero() {
				return auditSubjectWire{}, ErrCanonicalProfile
			}
			view.ActorID, err = identifier(subject.actor.String())
			if err != nil {
				return auditSubjectWire{}, err
			}
			view.ActorSessionID, err = identifier(subject.actorSession.String())
			if err != nil {
				return auditSubjectWire{}, err
			}
		} else if !subject.actor.IsZero() || !subject.actorSession.IsZero() {
			return auditSubjectWire{}, ErrCanonicalProfile
		}
		view.DelegationChain, err = auditAggregateRefViews(subject.delegations)
	case AuditSubjectUnattributed:
		if subject.unattributed.IsZero() || !subject.principal.IsZero() || subject.hasDevice || subject.hasWorkload ||
			subject.hasActor || len(subject.delegations) != 0 {
			return auditSubjectWire{}, ErrCanonicalProfile
		}
		digest, digestErr := CanonicalDigestFromDigest(subject.unattributed)
		if digestErr != nil {
			return auditSubjectWire{}, digestErr
		}
		view.UnattributedSource = &digest
	default:
		return auditSubjectWire{}, ErrCanonicalProfile
	}
	return view, err
}

func auditProvenanceView(provenance AuditProvenance) (auditProvenanceWire, error) {
	if provenance.sourceAuthority.IsZero() {
		return auditProvenanceWire{}, ErrCanonicalProfile
	}
	authority, err := NewCanonicalIdentifier(provenance.sourceAuthority.String())
	if err != nil {
		return auditProvenanceWire{}, err
	}
	return auditProvenanceWire{SourceAuthorityID: authority, FederationEnvelope: provenance.federationEnvelope}, nil
}

func auditAuthorizationView(authorization AuditAuthorization) (auditAuthorizationWire, error) {
	if authorization.guardDigest.IsZero() || authorization.admissionGeneration.IsZero() {
		return auditAuthorizationWire{}, ErrCanonicalProfile
	}
	guard, err := NewCanonicalDigest(authorization.guardDigest.String())
	if err != nil {
		return auditAuthorizationWire{}, err
	}
	view := auditAuthorizationWire{GuardDigest: guard, AdmissionGeneration: authorization.admissionGeneration.Uint64()}
	view.EffectiveGrants, err = auditRevisionViews(authorization.grants)
	if err != nil {
		return auditAuthorizationWire{}, err
	}
	view.AuthorizationRevisions, err = auditRevisionViews(authorization.authorization)
	if err != nil {
		return auditAuthorizationWire{}, err
	}
	view.RevocationRevisions, err = auditRevisionViews(authorization.revocations)
	if err != nil {
		return auditAuthorizationWire{}, err
	}
	if authorization.hasPolicy {
		value := authorization.policy.String()
		if value == "" {
			return auditAuthorizationWire{}, ErrCanonicalProfile
		}
		view.PolicyRevision = &value
	} else if authorization.policy.String() != "" {
		return auditAuthorizationWire{}, ErrCanonicalProfile
	}
	if authorization.hasDeviceTrust {
		if !authorization.deviceTrustRevision.Valid() {
			return auditAuthorizationWire{}, ErrCanonicalProfile
		}
		value := authorization.deviceTrustRevision.Uint64()
		view.DeviceTrustRevision = &value
	} else if !authorization.deviceTrustRevision.IsZero() {
		return auditAuthorizationWire{}, ErrCanonicalProfile
	}
	if authorization.hasGenerationChange {
		oldValue, oldErr := NewCanonicalIdentifier(authorization.oldGeneration.String())
		newValue, newErr := NewCanonicalIdentifier(authorization.newGeneration.String())
		if oldErr != nil || newErr != nil || oldValue == newValue {
			return auditAuthorizationWire{}, ErrCanonicalProfile
		}
		view.OldBootstrapGeneration, view.NewBootstrapGeneration = &oldValue, &newValue
	} else if !authorization.oldGeneration.IsZero() || !authorization.newGeneration.IsZero() {
		return auditAuthorizationWire{}, ErrCanonicalProfile
	}
	return view, nil
}

func auditRevisionViews(revisions []AuditRevision) ([]auditRevisionWire, error) {
	views := make([]auditRevisionWire, len(revisions))
	prior := ""
	for index, revision := range revisions {
		if revision.target.IsZero() || !revision.version.Valid() || revision.version.Uint64() > MaxCanonicalInteger ||
			(index > 0 && revision.target.String() <= prior) {
			return nil, ErrCanonicalProfile
		}
		id, err := NewCanonicalIdentifier(revision.target.ID())
		if err != nil {
			return nil, err
		}
		views[index] = auditRevisionWire{
			Kind: string(revision.target.Kind()), ID: id, Version: revision.version.Uint64(),
		}
		prior = revision.target.String()
	}
	return views, nil
}

func auditAggregateRefViews(refs []domain.AggregateRef) ([]auditRevisionWire, error) {
	views := make([]auditRevisionWire, len(refs))
	prior := ""
	for index, ref := range refs {
		if ref.IsZero() || ref.Version().Uint64() > MaxCanonicalInteger ||
			(index > 0 && ref.Target().String() <= prior) {
			return nil, ErrCanonicalProfile
		}
		id, err := NewCanonicalIdentifier(ref.Target().ID())
		if err != nil {
			return nil, err
		}
		views[index] = auditRevisionWire{Kind: string(ref.Target().Kind()), ID: id, Version: ref.Version().Uint64()}
		prior = ref.Target().String()
	}
	return views, nil
}

func auditResourceViews(resources []AuditResourceVersion) ([]auditResourceWire, error) {
	views := make([]auditResourceWire, len(resources))
	prior := ""
	for index, resource := range resources {
		if resource.target.IsZero() || !resource.hasAfter || !resource.after.Valid() ||
			(index > 0 && resource.target.String() <= prior) {
			return nil, ErrCanonicalProfile
		}
		id, err := NewCanonicalIdentifier(resource.target.ID())
		if err != nil {
			return nil, err
		}
		view := auditResourceWire{Kind: string(resource.target.Kind()), ID: id}
		after := resource.after.Uint64()
		view.AfterVersion = &after
		if resource.hasBefore {
			if !resource.before.Valid() || resource.before.Uint64() >= resource.after.Uint64() {
				return nil, ErrCanonicalProfile
			}
			before := resource.before.Uint64()
			view.BeforeVersion = &before
		} else if !resource.before.IsZero() || resource.after != domain.InitialVersion() {
			return nil, ErrCanonicalProfile
		}
		views[index] = view
		prior = resource.target.String()
	}
	return views, nil
}

func validAuditInvocationWire(view auditInvocationWire) bool {
	switch view.Kind {
	case AuditInvocationCommand:
		return view.CommandID != nil && view.CommandID.String() != "" && view.ReceiptID != nil &&
			view.ReceiptID.String() != "" && view.ReceiptIdentityDigest != nil &&
			view.ReceiptIdentityDigest.String() != "" && view.RequestID != nil && view.TraceID != nil &&
			view.CorrelationID != nil && view.SecurityOperation == nil
	case AuditInvocationSecurity:
		if view.CommandID != nil || view.ReceiptID != nil || view.ReceiptIdentityDigest != nil ||
			view.SecurityOperation == nil || !SecurityOperation(*view.SecurityOperation).Valid() {
			return false
		}
		operation := SecurityOperation(*view.SecurityOperation)
		denial := operation == SecurityRecordBootstrapDenial || operation == SecurityRecordCommandDenial
		return denial == (view.RequestID != nil && view.TraceID != nil) &&
			(operation == SecurityRecordCommandDenial) == (view.CorrelationID != nil)
	default:
		return false
	}
}

func validAuditSubjectWire(view auditSubjectWire) bool {
	if !validAuditRevisionWires(view.DelegationChain) {
		return false
	}
	switch view.Kind {
	case AuditSubjectAttributed:
		return view.PrincipalID != nil && view.PrincipalID.String() != "" && view.UnattributedSource == nil &&
			((view.ActorID == nil) == (view.ActorSessionID == nil))
	case AuditSubjectUnattributed:
		return view.PrincipalID == nil && view.DeviceID == nil && view.WorkloadID == nil && view.ActorID == nil &&
			view.ActorSessionID == nil && len(view.DelegationChain) == 0 && view.UnattributedSource != nil &&
			view.UnattributedSource.String() != ""
	default:
		return false
	}
}

func validAuditAuthorizationWire(view auditAuthorizationWire) bool {
	if view.GuardDigest.String() == "" || view.AdmissionGeneration == 0 ||
		view.AdmissionGeneration > MaxCanonicalInteger || !validAuditRevisionWires(view.EffectiveGrants) ||
		!validAuditRevisionWires(view.AuthorizationRevisions) || !validAuditRevisionWires(view.RevocationRevisions) ||
		((view.OldBootstrapGeneration == nil) != (view.NewBootstrapGeneration == nil)) {
		return false
	}
	for _, grant := range view.EffectiveGrants {
		if grant.Kind != string(domain.AggregateKindGrant) || !slices.Contains(view.AuthorizationRevisions, grant) {
			return false
		}
	}
	if view.PolicyRevision != nil && !validOpaqueText(*view.PolicyRevision, 256) {
		return false
	}
	if view.DeviceTrustRevision != nil && (*view.DeviceTrustRevision == 0 || *view.DeviceTrustRevision > MaxCanonicalInteger) {
		return false
	}
	return view.OldBootstrapGeneration == nil || *view.OldBootstrapGeneration != *view.NewBootstrapGeneration
}

func validAuditRevisionWires(views []auditRevisionWire) bool {
	prior := ""
	for index, view := range views {
		key := view.Kind + ":" + view.ID.String()
		if !domain.AggregateKind(view.Kind).Valid() || view.ID.String() == "" ||
			view.Version == 0 || view.Version > MaxCanonicalInteger ||
			(index > 0 && key <= prior) {
			return false
		}
		prior = key
	}
	return true
}

func validAuditResourceWires(views []auditResourceWire) bool {
	prior := ""
	for index, view := range views {
		key := view.Kind + ":" + view.ID.String()
		if !domain.AggregateKind(view.Kind).Valid() || view.ID.String() == "" ||
			view.AfterVersion == nil || *view.AfterVersion == 0 ||
			*view.AfterVersion > MaxCanonicalInteger || (view.BeforeVersion != nil &&
			(*view.BeforeVersion == 0 || *view.BeforeVersion >= *view.AfterVersion)) ||
			(index > 0 && key <= prior) {
			return false
		}
		if view.BeforeVersion == nil && *view.AfterVersion != domain.InitialVersion().Uint64() {
			return false
		}
		prior = key
	}
	return true
}

func (view AuditEntryViewV1) valid() bool {
	if view.Schema != auditEntrySchemaV1 || view.ChainScopeID.String() == "" || view.AuditSequence == 0 ||
		view.AuditSequence > MaxCanonicalInteger || view.AuthorityID.String() == "" || view.AuthorityEpoch.String() == "" ||
		view.RecordedAt.String() == "" || !validOpaqueText(view.Action, 256) || view.CommandFingerprint.String() == "" ||
		view.PreviousEntryHash.String() == "" || view.Invocation.Kind == "" || view.Timing.PersistedAuthorityAt.String() == "" ||
		view.Subject.Kind == "" || view.Provenance.SourceAuthorityID.String() == "" ||
		view.Authorization.GuardDigest.String() == "" || view.Authorization.AdmissionGeneration == 0 {
		return false
	}
	zeroPrevious := view.PreviousEntryHash.String() == strings.Repeat("0", hex.EncodedLen(sha256.Size))
	if (view.AuditSequence == 1) != zeroPrevious {
		return false
	}
	if !validAuditInvocationWire(view.Invocation) || !validAuditSubjectWire(view.Subject) ||
		!validAuditAuthorizationWire(view.Authorization) || !validAuditResourceWires(view.Resources) {
		return false
	}
	if !auditActionMatchesInvocation(view.Action, view.Invocation) {
		return false
	}
	if (view.Provenance.SourceAuthorityID != view.AuthorityID) != (view.Provenance.FederationEnvelope != nil) {
		return false
	}
	denial := view.Invocation.Kind == AuditInvocationCommand ||
		(view.Invocation.SecurityOperation != nil &&
			(*view.Invocation.SecurityOperation == string(SecurityRecordBootstrapDenial) ||
				*view.Invocation.SecurityOperation == string(SecurityRecordCommandDenial)))
	if denial != (view.Timing.ServerReceivedAt != nil) {
		return false
	}
	switch AuditOutcome(view.Outcome) {
	case AuditCommandApplied:
		return view.Invocation.Kind == AuditInvocationCommand && view.SafeReason == nil
	case AuditSecurityMutation:
		return view.Invocation.Kind == AuditInvocationSecurity && view.SafeReason != nil && validAuditReason(*view.SafeReason) &&
			(*view.Invocation.SecurityOperation == string(SecurityInitializeInstallation) ||
				*view.Invocation.SecurityOperation == string(SecurityRotateBootstrapGeneration) ||
				*view.Invocation.SecurityOperation == string(SecurityResumeBootstrapGeneration))
	case AuditSecurityDenied:
		return view.Invocation.Kind == AuditInvocationSecurity && view.SafeReason != nil && validAuditReason(*view.SafeReason) &&
			(*view.Invocation.SecurityOperation == string(SecurityRecordBootstrapDenial) ||
				*view.Invocation.SecurityOperation == string(SecurityRecordCommandDenial))
	default:
		return false
	}
}

func auditActionMatchesInvocation(action string, invocation auditInvocationWire) bool {
	if invocation.Kind == AuditInvocationCommand {
		_, exists := operationContracts[CommandOperation(action)]
		return exists
	}
	if invocation.SecurityOperation == nil {
		return false
	}
	switch SecurityOperation(*invocation.SecurityOperation) {
	case SecurityInitializeInstallation:
		return action == "installation.initialize.v1"
	case SecurityRotateBootstrapGeneration:
		return action == "installation.bootstrap_generation.rotate.v1"
	case SecurityResumeBootstrapGeneration:
		return action == "installation.bootstrap_generation.resume.v1"
	case SecurityRecordBootstrapDenial:
		return action == "installation.bootstrap.v1"
	case SecurityRecordCommandDenial:
		_, exists := operationContracts[CommandOperation(action)]
		return exists
	default:
		return false
	}
}

func (view AuditEntryViewV1) MarshalJSON() ([]byte, error) {
	if !view.valid() {
		return nil, ErrCanonicalProfile
	}
	type wire AuditEntryViewV1
	return json.Marshal(wire(view))
}

func (codec ProductionCanonicalCodec) EncodeAuditEntry(view AuditEntryViewV1) ([]byte, Digest, error) {
	canonical, err := encodeCanonical(view, MaxAuditEntryBytes)
	if err != nil {
		return nil, Digest{}, err
	}
	return canonical, digestCanonical(auditEntryDomain, canonical), nil
}

// VerifyAuditEntry validates the closed retained schema, predecessor binding,
// canonical representation, and domain-separated entry hash.
func (codec ProductionCanonicalCodec) VerifyAuditEntry(previous Digest, canonicalEntry []byte, expected Digest) error {
	if expected.IsZero() {
		return ErrCanonicalProfile
	}
	var view AuditEntryViewV1
	if err := decodeCanonicalDocument(canonicalEntry, MaxAuditEntryBytes, &view); err != nil {
		return err
	}
	if !view.valid() {
		return ErrCanonicalProfile
	}
	previousText := hex.EncodeToString(previous[:])
	if view.PreviousEntryHash.String() != previousText {
		return fmt.Errorf("%w: audit predecessor mismatch", ErrCanonicalProfile)
	}
	canonical, digest, err := codec.EncodeAuditEntry(view)
	if err != nil || digest != expected || !bytes.Equal(canonical, canonicalEntry) {
		return fmt.Errorf("%w: retained audit entry mismatch", ErrCanonicalEncoding)
	}
	return nil
}

func (codec ProductionCanonicalCodec) HashCommand(view CommandHashView) (domain.CommandFingerprint, error) {
	digest, err := codec.hashTyped(commandFingerprintDomain, view, MaxCanonicalJSONBytes)
	return domain.CommandFingerprint(digest), err
}

func (codec ProductionCanonicalCodec) HashAuthorizationGuards(
	view AuthorizationGuardHashView,
) (domain.AuthorizationDigest, error) {
	digest, err := codec.hashTyped(authorizationGuardDomain, view, MaxCanonicalJSONBytes)
	if err != nil {
		return domain.AuthorizationDigest{}, err
	}
	return domain.NewAuthorizationDigest([sha256.Size]byte(digest))
}

func (codec ProductionCanonicalCodec) HashReceiptResult(view W0ReceiptResultView) (Digest, error) {
	document, err := codec.EncodeReceiptResult(view)
	return document.Digest(), err
}

func (codec ProductionCanonicalCodec) HashRecoveryCapsule(view W0RecoveryCapsuleView) (Digest, error) {
	document, err := codec.EncodeRecoveryCapsule(view)
	return document.Digest(), err
}

func (codec ProductionCanonicalCodec) HashCommandDenial(view CommandDenialHashView) (Digest, error) {
	return codec.hashTyped(commandDenialDomain, view, MaxAuditMetadataBytes)
}

func (codec ProductionCanonicalCodec) HashBootstrapAttempt(view BootstrapAttemptHashView) (Digest, error) {
	return codec.hashTyped(bootstrapAttemptDomain, view, MaxAuditMetadataBytes)
}

func (codec ProductionCanonicalCodec) HashEvent(view EventSemanticHashView) (domain.EventDigest, error) {
	digest, err := codec.hashTyped(eventDigestDomain, view, MaxCanonicalJSONBytes)
	if err != nil {
		return domain.EventDigest{}, err
	}
	return domain.NewEventDigest([sha256.Size]byte(digest))
}

func (codec ProductionCanonicalCodec) HashStreamGenesis(view StreamGenesisHashView) (domain.StreamDigest, error) {
	digest, err := codec.hashTyped(streamGenesisDomain, view, MaxCanonicalJSONBytes)
	if err != nil {
		return domain.StreamDigest{}, err
	}
	return domain.NewStreamDigest([sha256.Size]byte(digest))
}

func (codec ProductionCanonicalCodec) HashAuditEntry(view AuditEntryHashView) (Digest, error) {
	return codec.hashTyped(auditEntryDomain, view, MaxAuditEntryBytes)
}

func (ProductionCanonicalCodec) ChainStreamDigest(
	previous domain.StreamDigest,
	position domain.StreamPosition,
	event domain.EventDigest,
) (domain.StreamDigest, error) {
	if previous.IsZero() || !position.Valid() || event.IsZero() {
		return domain.StreamDigest{}, ErrCanonicalProfile
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(streamChainDomain))
	previousBytes := previous.Bytes()
	_, _ = hash.Write(previousBytes[:])
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], position.Uint64())
	_, _ = hash.Write(sequence[:])
	eventBytes := event.Bytes()
	_, _ = hash.Write(eventBytes[:])
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return domain.NewStreamDigest(digest)
}

func (ProductionCanonicalCodec) AuditGenesisPreviousHash() [sha256.Size]byte {
	return [sha256.Size]byte{}
}

func (codec ProductionCanonicalCodec) hashTyped(domainSeparator string, view CanonicalView, maxBytes int) (Digest, error) {
	if domainSeparator == "" || isNilInterface(view) {
		return Digest{}, ErrCanonicalProfile
	}
	canonical, err := encodeCanonical(view, maxBytes)
	if err != nil {
		return Digest{}, err
	}
	return digestCanonical(domainSeparator, canonical), nil
}

func digestCanonical(domainSeparator string, canonical []byte) Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domainSeparator))
	_, _ = hash.Write(canonical)
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return digest
}
