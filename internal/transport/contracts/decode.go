// Package contracts defines Blackbird's transport-neutral JSON vocabulary.
//
// It owns wire decoding and bounded syntactic validation. Validated values are
// composed from domain primitives, but this package does not invent application
// commands or aggregate models. HTTP, MCP, local IPC, and future adapters must
// pass these values to the application layer once that layer defines the
// corresponding use-case inputs.
package contracts

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	MaxCommandJSONBytes = 64 * 1024
	MaxOutcomeJSONBytes = 1024 * 1024

	maxRequestIDBytes           = 128
	maxDisplayNameBytes         = 256
	maxClientNameBytes          = 128
	maxClientVersionBytes       = 128
	maxDiscoveryLocatorBytes    = 4096
	maxCursorBytes              = 4096
	maxOpaqueProviderValueBytes = 4096
	maxObjectiveTitleBytes      = 512
	maxAcceptanceCriteriaBytes  = 8192
	maxRunRoleBytes             = 128
	maxCapabilityCount          = 64
	maxCapabilityBytes          = 128
	maxGrantReferenceCount      = 64
	maxEventIDCount             = 1 + domain.MaxRunParticipants + domain.MaxRunBindings
	maxFieldViolationCount      = 64
	maxSyncPageCount            = 256
	maxContextDeltaCount        = 256
	maxJSONNestingDepth         = 64
)

var (
	ErrPayloadTooLarge = errors.New("contract payload too large")
	ErrInvalidJSON     = errors.New("invalid contract JSON")
	ErrInvalidContract = errors.New("invalid contract value")
)

// FieldError names one safe wire-contract violation.
type FieldError struct {
	Field   string
	Problem string
}

func (e *FieldError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Problem)
}

func (e *FieldError) Unwrap() error { return ErrInvalidContract }

func invalid(field, problem string) error {
	return &FieldError{Field: field, Problem: problem}
}

func decodeStrict(data []byte, limit int, target any) error {
	return decodeBounded(data, limit, target, true)
}

func decodeCommandInput(data []byte, target any) error {
	if err := decodeStrict(data, MaxCommandJSONBytes, target); err != nil {
		return err
	}
	return requireTopLevelJSONMembers(data, "causation_id")
}

func decodeOutput(data []byte, limit int, target any) error {
	return decodeBounded(data, limit, target, false)
}

func decodeBounded(data []byte, limit int, target any, rejectUnknownFields bool) error {
	if len(data) > limit {
		return fmt.Errorf("%w: got %d bytes, limit %d", ErrPayloadTooLarge, len(data), limit)
	}
	if err := validateNoDuplicateJSONKeys(data); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	if rejectUnknownFields {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: multiple JSON values", ErrInvalidJSON)
		}
		return fmt.Errorf("%w: trailing content: %v", ErrInvalidJSON, err)
	}
	return nil
}

// validateNoDuplicateJSONKeys walks the complete JSON token stream before a
// typed decode. encoding/json otherwise accepts duplicate object members and
// silently lets the last value win, which makes signatures, request hashes,
// and audit interpretation ambiguous. A fresh key set is used for every object
// so duplicates are rejected recursively rather than only at the envelope.
func validateNoDuplicateJSONKeys(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("JSON must be valid UTF-8")
	}
	if err := validateJSONSurrogatePairs(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 1); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values beginning with %v", token)
		}
		return fmt.Errorf("trailing content: %w", err)
	}
	return nil
}

func validateJSONSurrogatePairs(data []byte) error {
	inString := false
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(data) {
				continue
			}
			if data[index+1] != 'u' {
				index++
				continue
			}
			first, ok := decodeHexQuad(data, index+2)
			if !ok {
				continue
			}
			if first >= 0xdc00 && first <= 0xdfff {
				return errors.New("JSON contains an unpaired low surrogate escape")
			}
			if first < 0xd800 || first > 0xdbff {
				index += 5
				continue
			}
			if index+11 >= len(data) || data[index+6] != '\\' || data[index+7] != 'u' {
				return errors.New("JSON contains an unpaired high surrogate escape")
			}
			second, paired := decodeHexQuad(data, index+8)
			if !paired || second < 0xdc00 || second > 0xdfff {
				return errors.New("JSON contains an unpaired high surrogate escape")
			}
			index += 11
		}
	}
	return nil
}

func decodeHexQuad(data []byte, start int) (uint16, bool) {
	if start+4 > len(data) {
		return 0, false
	}
	var value uint16
	for _, character := range data[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value += uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value += uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		if number, ok := token.(json.Number); ok {
			return validateJSONNumber(number)
		}
		return nil
	}
	if depth > maxJSONNestingDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONNestingDepth)
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate object member %q", key)
			}
			keys[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil {
			return closeErr
		}
		if closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil {
			return closeErr
		}
		if closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func validateJSONNumber(value json.Number) error {
	number, err := strconv.ParseFloat(value.String(), 64)
	if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
		return fmt.Errorf("JSON number %q is not a finite binary64 value", value)
	}
	if math.Trunc(number) == number && (number < 0 || number > float64(domain.MaxCanonicalInteger)) {
		return fmt.Errorf(
			"JSON integer %q is outside the interoperable range 0..%d",
			value,
			domain.MaxCanonicalInteger,
		)
	}
	return nil
}

func requireTopLevelJSONMembers(data []byte, required ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return fmt.Errorf("%w: top-level value must be an object", ErrInvalidJSON)
	}
	found := make(map[string]bool, len(required))
	for decoder.More() {
		keyToken, keyErr := decoder.Token()
		if keyErr != nil {
			return fmt.Errorf("%w: %v", ErrInvalidJSON, keyErr)
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("%w: object member name is not a string", ErrInvalidJSON)
		}
		for _, member := range required {
			if key == member {
				found[member] = true
			}
		}
		if err := walkJSONValue(decoder, 2); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	for _, member := range required {
		if !found[member] {
			return invalid(member, "is a required JSON member")
		}
	}
	return nil
}

func requireNestedJSONMembers(data []byte, object string, required ...string) error {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	raw, present := envelope[object]
	if !present {
		return invalid(object, "is a required JSON member")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return invalid(object, "must be a JSON object")
	}
	for _, member := range required {
		if _, present := members[member]; !present {
			return invalid(object+"."+member, "is a required JSON member")
		}
	}
	return nil
}

func validateRequiredID(field string, id interface{ IsZero() bool }) error {
	if id.IsZero() {
		return invalid(field, "is required")
	}
	return nil
}

func validateVersion(field string, version domain.Version) error {
	if version.IsZero() {
		return invalid(field, "must be a positive aggregate version")
	}
	return nil
}

func validateInitialVersion(field string, version domain.Version) error {
	if version.Uint64() != domain.InitialVersion().Uint64() {
		return invalid(field, "must equal initial aggregate version 1")
	}
	return nil
}

func validateAdvancedVersion(field string, version domain.Version) error {
	if version.Uint64() <= domain.InitialVersion().Uint64() {
		return invalid(field, "must be later than initial aggregate version 1")
	}
	return nil
}

func validateLiteral(field, actual, expected string) error {
	if actual != expected {
		return invalid(field, fmt.Sprintf("must equal %q", expected))
	}
	return nil
}

func validateToken(field, value string, maximum int) error {
	if value == "" {
		return invalid(field, "is required")
	}
	if len(value) > maximum || !utf8.ValidString(value) {
		return invalid(field, fmt.Sprintf("must be valid UTF-8 no longer than %d bytes", maximum))
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return invalid(field, "must not contain whitespace or control characters")
		}
	}
	return nil
}

func validateText(field, value string, maximum int, required bool) error {
	if value == "" {
		if required {
			return invalid(field, "is required")
		}
		return nil
	}
	if len(value) > maximum || !utf8.ValidString(value) {
		return invalid(field, fmt.Sprintf("must be valid UTF-8 no longer than %d bytes", maximum))
	}
	if strings.TrimSpace(value) != value {
		return invalid(field, "must not have leading or trailing whitespace")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return invalid(field, "must not contain control characters")
		}
	}
	return nil
}

func validateRawJSONObject(field string, data json.RawMessage) error {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return invalid(field, "is required")
	}
	if err := validateNoDuplicateJSONKeys(data); err != nil {
		return invalid(field, err.Error())
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
		return invalid(field, "must be a JSON object")
	}
	return nil
}

func validateDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return invalid("deadline", "is required")
	}
	_, offset := deadline.Zone()
	if offset != 0 {
		return invalid("deadline", "must use UTC")
	}
	return nil
}

func validateIdempotencyKey(key string) error {
	if _, err := domain.NewIdempotencyKey(key); err != nil {
		return invalid("idempotency_key", err.Error())
	}
	return nil
}

func validateOperation(actual, expected string) error {
	operation, err := domain.NewOperationName(actual)
	if err != nil {
		return invalid("operation", err.Error())
	}
	if operation.String() != expected {
		return invalid("operation", fmt.Sprintf("must equal %q", expected))
	}
	return nil
}

func validateSHA256Hex(field, value string) error {
	if len(value) != 64 {
		return invalid(field, "must be a lowercase SHA-256 hex digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || strings.ToLower(value) != value {
		return invalid(field, "must be a lowercase SHA-256 hex digest")
	}
	return nil
}

func validateBase64URL(field, value string, maximumDecoded int) error {
	if value == "" {
		return invalid(field, "is required")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximumDecoded {
		return invalid(field, fmt.Sprintf("must be unpadded base64url encoding 1..%d bytes", maximumDecoded))
	}
	return nil
}

func normalizeCapabilities(field string, values []string) ([]string, error) {
	if len(values) == 0 || len(values) > maxCapabilityCount {
		return nil, invalid(field, fmt.Sprintf("must contain 1..%d capabilities", maxCapabilityCount))
	}
	normalized := append([]string(nil), values...)
	for index, capability := range normalized {
		if err := validateCapability(fmt.Sprintf("%s[%d]", field, index), capability); err != nil {
			return nil, err
		}
	}
	slices.Sort(normalized)
	for index := 1; index < len(normalized); index++ {
		if normalized[index-1] == normalized[index] {
			return nil, invalid(field, fmt.Sprintf("contains duplicate capability %q", normalized[index]))
		}
	}
	return normalized, nil
}

func validateCapability(field, value string) error {
	if len(value) == 0 || len(value) > maxCapabilityBytes {
		return invalid(field, fmt.Sprintf("must be 1..%d bytes", maxCapabilityBytes))
	}
	for _, character := range value {
		valid := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == ':' || character == '.' || character == '_' || character == '-'
		if !valid {
			return invalid(field, "must use lowercase capability-token characters")
		}
	}
	return nil
}

func validateCursor(field, cursor string) error {
	return validateToken(field, cursor, maxCursorBytes)
}

func validateAggregateID(kind domain.AggregateKind, value string) error {
	var err error
	switch kind {
	case domain.AggregateKindInstallation:
		_, err = domain.ParseInstallationID(value)
	case domain.AggregateKindWorkspace:
		_, err = domain.ParseWorkspaceID(value)
	case domain.AggregateKindPrincipal:
		_, err = domain.ParsePrincipalID(value)
	case domain.AggregateKindDevice:
		_, err = domain.ParseDeviceID(value)
	case domain.AggregateKindMembership:
		_, err = domain.ParseMembershipID(value)
	case domain.AggregateKindActor:
		_, err = domain.ParseActorID(value)
	case domain.AggregateKindActorDelegation:
		_, err = domain.ParseActorDelegationID(value)
	case domain.AggregateKindActorSession:
		_, err = domain.ParseActorSessionID(value)
	case domain.AggregateKindGrant:
		_, err = domain.ParseGrantID(value)
	case domain.AggregateKindInvitation:
		_, err = domain.ParseInvitationID(value)
	default:
		return invalid("aggregate.type", "is not a supported aggregate kind")
	}
	if err != nil {
		return invalid("aggregate.id", err.Error())
	}
	return nil
}
