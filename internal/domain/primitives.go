package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// MaxCanonicalInteger is the largest integer exactly representable by every
// I-JSON consumer. Domain values carried by Blackbird's JSON/JCS contracts
// must not exceed it, even when their Go representation is wider.
const MaxCanonicalInteger uint64 = 1<<53 - 1

const IdentifierKindAuthorityEpoch IdentifierKind = "authority_epoch"

type authorityEpochMarker struct{}

func (authorityEpochMarker) identifierKind() IdentifierKind { return IdentifierKindAuthorityEpoch }

// AuthorityEpoch is an opaque, globally nonrepeating authority generation.
// Only equality is meaningful: UUID timestamp bits do not define epoch order.
type AuthorityEpoch struct{ typedID[authorityEpochMarker] }

func ParseAuthorityEpoch(text string) (AuthorityEpoch, error) {
	epoch, err := parseTypedID[authorityEpochMarker](text)
	return AuthorityEpoch{typedID: epoch}, err
}

func NewAuthorityEpoch() (AuthorityEpoch, error) {
	epoch, err := newTypedID[authorityEpochMarker]()
	return AuthorityEpoch{typedID: epoch}, err
}

func (epoch AuthorityEpoch) Equal(other AuthorityEpoch) bool { return epoch == other }

var (
	ErrInvalidVersion  = errors.New("invalid aggregate version")
	ErrVersionOverflow = errors.New("aggregate version overflow")
)

// Version is one aggregate's monotonic logical revision. Version zero is
// always invalid; a newly created aggregate starts at InitialVersion().
type Version struct {
	value uint64
}

func NewVersion(value uint64) (Version, error) {
	if value == 0 || value > MaxCanonicalInteger {
		return Version{}, ErrInvalidVersion
	}
	return Version{value: value}, nil
}

func ParseVersion(text string) (Version, error) {
	if text == "" || text[0] == '+' || text[0] == '-' || (len(text) > 1 && text[0] == '0') {
		return Version{}, ErrInvalidVersion
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, text)
	}
	return NewVersion(value)
}

func InitialVersion() Version { return Version{value: 1} }

func (version Version) IsZero() bool { return version.value == 0 }

func (version Version) Valid() bool {
	return version.value > 0 && version.value <= MaxCanonicalInteger
}

func (version Version) Uint64() uint64 { return version.value }

func (version Version) String() string {
	if !version.Valid() {
		return ""
	}
	return strconv.FormatUint(version.value, 10)
}

func (version Version) Next() (Version, error) {
	if !version.Valid() {
		return Version{}, ErrInvalidVersion
	}
	if version.value == MaxCanonicalInteger {
		return Version{}, ErrVersionOverflow
	}
	return Version{value: version.value + 1}, nil
}

func (version Version) MarshalText() ([]byte, error) {
	if !version.Valid() {
		return nil, ErrInvalidVersion
	}
	return []byte(version.String()), nil
}

func (version *Version) UnmarshalText(text []byte) error {
	if version == nil {
		return ErrInvalidVersion
	}
	parsed, err := ParseVersion(string(text))
	if err != nil {
		return err
	}
	*version = parsed
	return nil
}

func (version Version) MarshalJSON() ([]byte, error) {
	if !version.Valid() {
		return nil, ErrInvalidVersion
	}
	return strconv.AppendUint(nil, version.value, 10), nil
}

func (version *Version) UnmarshalJSON(data []byte) error {
	if version == nil {
		return ErrInvalidVersion
	}
	var value uint64
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidVersion, data)
	}
	parsed, err := NewVersion(value)
	if err != nil {
		return err
	}
	*version = parsed
	return nil
}
