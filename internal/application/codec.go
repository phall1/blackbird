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
	commandFingerprintDomain = "blackbird.command-fingerprint/v1\x00"
	authorizationGuardDomain = "blackbird.authorization-guards/v1\x00"
	receiptResultDomain      = "blackbird.receipt-result/v1\x00"
	sessionBindingDomain     = "blackbird.session-binding/v1\x00"
	recoveryCapsuleDomain    = "blackbird.recovery-capsule/v1\x00"
	commandDenialDomain      = "blackbird-command-denial/v1\x00"
	bootstrapAttemptDomain   = "blackbird-bootstrap-attempt/v1\x00"
	eventDigestDomain        = "blackbird.event-digest/v1\x00"
	streamGenesisDomain      = "blackbird.stream-genesis/v1\x00"
	streamChainDomain        = "blackbird.stream-chain/v1\x00"
	auditEntryDomain         = "blackbird-audit-entry/v1\x00"
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
	// A token without a decimal point or exponent expresses an integer and
	// must remain exact in every I-JSON consumer. Exponent/fraction tokens are
	// RFC 8785 binary64 values; production typed views forbid float fields.
	if !strings.ContainsAny(text, ".eE") && math.Abs(number) > float64(MaxCanonicalInteger) {
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
	digest, err := codec.hashTyped(eventDigestDomain, view, domain.MaxEventPayloadBytes)
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
	return codec.hashTyped(auditEntryDomain, view, MaxAuditMetadataBytes)
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
