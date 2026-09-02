package domain

// MaxCanonicalInteger is the largest integer exactly representable by every
// I-JSON consumer.
const MaxCanonicalInteger uint64 = 1<<53 - 1

const IdentifierKindAuthorityEpoch IdentifierKind = "authority_epoch"

type authorityEpochMarker struct{}

func (authorityEpochMarker) identifierKind() IdentifierKind { return IdentifierKindAuthorityEpoch }

// AuthorityEpoch is an opaque, globally nonrepeating authority generation.
type AuthorityEpoch struct{ typedID[authorityEpochMarker] }

func ParseAuthorityEpoch(text string) (AuthorityEpoch, error) {
	epoch, err := parseTypedID[authorityEpochMarker](text)
	return AuthorityEpoch{typedID: epoch}, err
}
