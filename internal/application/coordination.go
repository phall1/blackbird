// Package application defines Blackbird's local coordination contracts.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	MaxCanonicalInteger            uint64 = domain.MaxCanonicalInteger
	MaxQueryPageSize                      = 256
	MaxQueryPayloadBytes                  = 256 * 1024
	MaxCoordinationConsumerIDBytes        = 64
)

type Digest [sha256.Size]byte

func DigestBytes(value []byte) Digest { return sha256.Sum256(value) }
func (digest Digest) IsZero() bool    { return digest == Digest{} }

var (
	ErrInvalidCoordination     = errors.New("invalid coordination contract")
	ErrCoordinationUnsupported = errors.New("coordination storage is unsupported")
)

func cloneOptional[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func validQueryJSONObject(value []byte) bool {
	if len(value) == 0 || len(value) > MaxQueryPayloadBytes || !json.Valid(value) {
		return false
	}
	trimmed := strings.TrimSpace(string(value))
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
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

// W2 durable coordination contracts.
const (
	MaxMessageRecipients   = 256
	MaxMessageSubjectBytes = 512
	MaxMessageBodyBytes    = 256 * 1024
	MaxLeaseSelectors      = 256
	MaxLeaseSelectorBytes  = 4096
	MaxLeaseTTL            = 24 * time.Hour
	MaxLeaseLifetime       = 7 * 24 * time.Hour
)

type RecipientKind string

const (
	RecipientTo  RecipientKind = "to"
	RecipientCc  RecipientKind = "cc"
	RecipientBcc RecipientKind = "bcc"
)

type Recipient struct {
	actor domain.ActorID
	kind  RecipientKind
}

func NewRecipient(actor domain.ActorID, kind RecipientKind) (Recipient, error) {
	if actor.IsZero() || kind != RecipientTo && kind != RecipientCc && kind != RecipientBcc {
		return Recipient{}, ErrInvalidCoordination
	}
	return Recipient{actor: actor, kind: kind}, nil
}

func (recipient Recipient) ActorID() domain.ActorID { return recipient.actor }
func (recipient Recipient) Kind() RecipientKind     { return recipient.kind }

// MaxConversationSlugBytes bounds the caller-supplied alternate key. It is the
// same bound as an agent name because a slug is the same kind of thing: a short
// stable handle a person or a model types, not a payload.
const MaxConversationSlugBytes = 128

type OpenConversationParams struct {
	ConversationID  domain.ConversationID
	WorkspaceID     domain.WorkspaceID
	RunID           domain.RunID
	OpenedBy        domain.ActorID
	OpenedBySession domain.ActorSessionID
	Topic           string
	// Slug is an optional caller-supplied alternate key, unique per workspace.
	// Opening a slug that already exists returns that conversation instead of
	// minting a second one: without it, an agent that reopens "the auth
	// refactor" after a compaction gets a fresh UUID and a fresh thread, and
	// every reply its teammates already wrote stays in the thread it can no
	// longer name. The UUID remains the conversation's identity; the slug only
	// addresses it, which is why a reused open returns an ID that differs from
	// the one the caller proposed -- that difference is how a caller tells a
	// reuse from a create without a second field to keep in step.
	Slug string
}

type Conversation struct {
	id        domain.ConversationID
	workspace domain.WorkspaceID
	run       domain.RunID
	openedBy  domain.ActorID
	topic     string
	slug      string
	openedAt  time.Time
}

func NewConversation(params OpenConversationParams, openedAt time.Time) (Conversation, error) {
	if params.ConversationID.IsZero() || params.WorkspaceID.IsZero() || params.RunID.IsZero() ||
		params.OpenedBy.IsZero() || params.OpenedBySession.IsZero() || !validOpaqueText(params.Topic, 512) ||
		!ValidConversationSlug(params.Slug) || openedAt.IsZero() {
		return Conversation{}, ErrInvalidCoordination
	}
	return Conversation{id: params.ConversationID, workspace: params.WorkspaceID, run: params.RunID,
		openedBy: params.OpenedBy, topic: params.Topic, slug: params.Slug, openedAt: openedAt.UTC()}, nil
}

// ValidConversationSlug accepts the empty slug, which means "no alternate key"
// and leaves conversation_open minting a fresh thread per call as it always did.
func ValidConversationSlug(slug string) bool {
	return slug == "" || validOpaqueText(slug, MaxConversationSlugBytes)
}

func (conversation Conversation) ID() domain.ConversationID       { return conversation.id }
func (conversation Conversation) WorkspaceID() domain.WorkspaceID { return conversation.workspace }
func (conversation Conversation) RunID() domain.RunID             { return conversation.run }
func (conversation Conversation) OpenedBy() domain.ActorID        { return conversation.openedBy }
func (conversation Conversation) Topic() string                   { return conversation.topic }
func (conversation Conversation) Slug() string                    { return conversation.slug }
func (conversation Conversation) OpenedAt() time.Time             { return conversation.openedAt }

type SendMessageParams struct {
	MessageID               domain.MessageID
	ConversationID          domain.ConversationID
	WorkspaceID             domain.WorkspaceID
	Author                  domain.ActorID
	AuthorSession           domain.ActorSessionID
	Subject                 string
	Body                    string
	Recipients              []Recipient
	ReplyTo                 *domain.MessageID
	AcknowledgementRequired bool
}

type Delivery struct {
	recipient               Recipient
	acknowledgementRequired bool
	availableAt             *time.Time
	readAt                  *time.Time
	acknowledgedAt          *time.Time
}

func NewDeliveryView(recipient Recipient, acknowledgementRequired bool, availableAt, readAt, acknowledgedAt *time.Time) (Delivery, error) {
	if recipient.actor.IsZero() || recipient.kind != RecipientTo && recipient.kind != RecipientCc && recipient.kind != RecipientBcc {
		return Delivery{}, ErrInvalidCoordination
	}
	return Delivery{recipient: recipient, acknowledgementRequired: acknowledgementRequired,
		availableAt: cloneOptional(availableAt), readAt: cloneOptional(readAt), acknowledgedAt: cloneOptional(acknowledgedAt)}, nil
}

func (delivery Delivery) Recipient() Recipient           { return delivery.recipient }
func (delivery Delivery) AcknowledgementRequired() bool  { return delivery.acknowledgementRequired }
func (delivery Delivery) AvailableAt() (time.Time, bool) { return optionalTime(delivery.availableAt) }
func (delivery Delivery) ReadAt() (time.Time, bool)      { return optionalTime(delivery.readAt) }
func (delivery Delivery) AcknowledgedAt() (time.Time, bool) {
	return optionalTime(delivery.acknowledgedAt)
}

func optionalTime(value *time.Time) (time.Time, bool) {
	if value == nil {
		return time.Time{}, false
	}
	return *value, true
}

type Message struct {
	id           domain.MessageID
	conversation domain.ConversationID
	workspace    domain.WorkspaceID
	author       domain.ActorID
	subject      string
	body         string
	digest       Digest
	replyTo      *domain.MessageID
	sentAt       time.Time
	position     uint64
	deliveries   []Delivery
}

type MessageViewParams struct {
	MessageID      domain.MessageID
	ConversationID domain.ConversationID
	WorkspaceID    domain.WorkspaceID
	Author         domain.ActorID
	Subject        string
	Body           string
	ReplyTo        *domain.MessageID
	SentAt         time.Time
	Position       uint64
	Deliveries     []Delivery
}

func NewMessageView(params MessageViewParams) (Message, error) {
	if params.MessageID.IsZero() || params.ConversationID.IsZero() || params.WorkspaceID.IsZero() || params.Author.IsZero() ||
		len(params.Subject) == 0 || len(params.Subject) > MaxMessageSubjectBytes || !utf8.ValidString(params.Subject) ||
		len(params.Body) == 0 || len(params.Body) > MaxMessageBodyBytes || !utf8.ValidString(params.Body) ||
		params.SentAt.IsZero() || params.Position == 0 || len(params.Deliveries) == 0 || len(params.Deliveries) > MaxMessageRecipients {
		return Message{}, ErrInvalidCoordination
	}
	if params.ReplyTo != nil && params.ReplyTo.IsZero() {
		return Message{}, ErrInvalidCoordination
	}
	deliveries := append([]Delivery(nil), params.Deliveries...)
	return Message{id: params.MessageID, conversation: params.ConversationID, workspace: params.WorkspaceID,
		author: params.Author, subject: params.Subject, body: params.Body, digest: DigestBytes([]byte(params.Body)),
		replyTo: cloneOptional(params.ReplyTo), sentAt: params.SentAt.UTC(), position: params.Position, deliveries: deliveries}, nil
}

func ValidateSendMessage(params SendMessageParams) error {
	if params.MessageID.IsZero() || params.ConversationID.IsZero() || params.WorkspaceID.IsZero() || params.Author.IsZero() ||
		params.AuthorSession.IsZero() || len(params.Subject) == 0 || len(params.Subject) > MaxMessageSubjectBytes ||
		!utf8.ValidString(params.Subject) || len(params.Body) == 0 || len(params.Body) > MaxMessageBodyBytes ||
		!utf8.ValidString(params.Body) || len(params.Recipients) == 0 || len(params.Recipients) > MaxMessageRecipients ||
		params.ReplyTo != nil && params.ReplyTo.IsZero() {
		return ErrInvalidCoordination
	}
	seen := make(map[domain.ActorID]struct{}, len(params.Recipients))
	for _, recipient := range params.Recipients {
		if recipient.actor.IsZero() || recipient.kind != RecipientTo && recipient.kind != RecipientCc && recipient.kind != RecipientBcc {
			return ErrInvalidCoordination
		}
		if _, duplicate := seen[recipient.actor]; duplicate {
			return ErrInvalidCoordination
		}
		seen[recipient.actor] = struct{}{}
	}
	return nil
}

func (message Message) ID() domain.MessageID                  { return message.id }
func (message Message) ConversationID() domain.ConversationID { return message.conversation }
func (message Message) WorkspaceID() domain.WorkspaceID       { return message.workspace }
func (message Message) Author() domain.ActorID                { return message.author }
func (message Message) Subject() string                       { return message.subject }
func (message Message) Body() string                          { return message.body }
func (message Message) Digest() Digest                        { return message.digest }
func (message Message) ReplyTo() *domain.MessageID            { return cloneOptional(message.replyTo) }
func (message Message) SentAt() time.Time                     { return message.sentAt }
func (message Message) Position() uint64                      { return message.position }
func (message Message) Deliveries() []Delivery                { return append([]Delivery(nil), message.deliveries...) }

type CoordinationPage struct {
	messages []Message
	next     uint64
	hasMore  bool
}

func NewCoordinationPage(messages []Message, next uint64, hasMore bool) (CoordinationPage, error) {
	if len(messages) > MaxQueryPageSize {
		return CoordinationPage{}, ErrInvalidCoordination
	}
	return CoordinationPage{messages: append([]Message(nil), messages...), next: next, hasMore: hasMore}, nil
}
func (page CoordinationPage) Messages() []Message { return append([]Message(nil), page.messages...) }
func (page CoordinationPage) NextCursor() uint64  { return page.next }
func (page CoordinationPage) HasMore() bool       { return page.hasMore }

// CoordinationEventCursor is an opaque, authenticated continuation token.
// Callers may persist and return it but must not interpret its contents.
type CoordinationEventCursor struct{ value string }

func NewCoordinationEventCursor(value string) (CoordinationEventCursor, error) {
	if !validOpaqueText(value, 1024) {
		return CoordinationEventCursor{}, ErrInvalidCoordination
	}
	return CoordinationEventCursor{value: value}, nil
}

func (cursor CoordinationEventCursor) String() string { return cursor.value }
func (cursor CoordinationEventCursor) IsZero() bool   { return cursor.value == "" }

type CoordinationEventType string

const (
	CoordinationEventMessageAvailable    CoordinationEventType = "message.available"
	CoordinationEventMessageRead         CoordinationEventType = "message.read"
	CoordinationEventMessageAcknowledged CoordinationEventType = "message.acknowledged"
	CoordinationEventLeaseAcquired       CoordinationEventType = "lease.acquired"
	CoordinationEventLeaseRenewed        CoordinationEventType = "lease.renewed"
	CoordinationEventLeaseReleased       CoordinationEventType = "lease.released"
)

func (kind CoordinationEventType) Valid() bool {
	switch kind {
	case CoordinationEventMessageAvailable, CoordinationEventMessageRead,
		CoordinationEventMessageAcknowledged, CoordinationEventLeaseAcquired,
		CoordinationEventLeaseRenewed, CoordinationEventLeaseReleased:
		return true
	default:
		return false
	}
}

type CoordinationEvent struct {
	position   uint64
	workspace  domain.WorkspaceID
	actor      domain.ActorID
	eventType  CoordinationEventType
	subjectID  string
	occurredAt time.Time
	payload    []byte
}

type CoordinationEventParams struct {
	Position   uint64
	Workspace  domain.WorkspaceID
	Actor      domain.ActorID
	EventType  CoordinationEventType
	SubjectID  string
	OccurredAt time.Time
	Payload    []byte
}

func NewCoordinationEvent(params CoordinationEventParams) (CoordinationEvent, error) {
	if params.Position == 0 || params.Position > MaxCanonicalInteger || params.Workspace.IsZero() ||
		params.Actor.IsZero() || !params.EventType.Valid() || !validOpaqueText(params.SubjectID, 256) ||
		params.OccurredAt.IsZero() || !validQueryJSONObject(params.Payload) {
		return CoordinationEvent{}, ErrInvalidCoordination
	}
	return CoordinationEvent{position: params.Position, workspace: params.Workspace, actor: params.Actor,
		eventType: params.EventType, subjectID: params.SubjectID, occurredAt: params.OccurredAt.UTC(),
		payload: append([]byte(nil), params.Payload...)}, nil
}

func (event CoordinationEvent) Position() uint64                { return event.position }
func (event CoordinationEvent) WorkspaceID() domain.WorkspaceID { return event.workspace }

// ActorID is the actor that caused a recipient- or workspace-visible fact.
// Legacy actor-visible rows retain their original audience actor.
func (event CoordinationEvent) ActorID() domain.ActorID          { return event.actor }
func (event CoordinationEvent) EventType() CoordinationEventType { return event.eventType }
func (event CoordinationEvent) SubjectID() string                { return event.subjectID }
func (event CoordinationEvent) OccurredAt() time.Time            { return event.occurredAt }
func (event CoordinationEvent) Payload() []byte                  { return append([]byte(nil), event.payload...) }

type CoordinationConsumerID string

func NewCoordinationConsumerID(value string) (CoordinationConsumerID, error) {
	if value == "" || len(value) > MaxCoordinationConsumerIDBytes {
		return "", ErrInvalidCoordination
	}
	for _, character := range value {
		if character > unicode.MaxASCII || !unicode.IsLetter(character) && !unicode.IsDigit(character) && !strings.ContainsRune("._-", character) {
			return "", ErrInvalidCoordination
		}
	}
	return CoordinationConsumerID(value), nil
}

func (id CoordinationConsumerID) String() string { return string(id) }

// CoordinationEventsQuery uses either an explicit cursor or the committed
// position of one named consumer. The two modes are deliberately exclusive.
type CoordinationEventsQuery struct {
	workspace domain.WorkspaceID
	actor     domain.ActorID
	after     CoordinationEventCursor
	consumer  CoordinationConsumerID
	limit     uint16
}

func NewCoordinationEventsQuery(workspace domain.WorkspaceID, actor domain.ActorID,
	after CoordinationEventCursor, limit uint16) (CoordinationEventsQuery, error) {
	return newCoordinationEventsQuery(workspace, actor, after, "", limit)
}

func NewCoordinationConsumerEventsQuery(workspace domain.WorkspaceID, actor domain.ActorID,
	consumer CoordinationConsumerID, limit uint16) (CoordinationEventsQuery, error) {
	return newCoordinationEventsQuery(workspace, actor, CoordinationEventCursor{}, consumer, limit)
}

func newCoordinationEventsQuery(workspace domain.WorkspaceID, actor domain.ActorID, after CoordinationEventCursor,
	consumer CoordinationConsumerID, limit uint16) (CoordinationEventsQuery, error) {
	if workspace.IsZero() || actor.IsZero() || limit == 0 || limit > MaxQueryPageSize ||
		(!after.IsZero() && consumer != "") {
		return CoordinationEventsQuery{}, ErrInvalidCoordination
	}
	return CoordinationEventsQuery{workspace: workspace, actor: actor, after: after, consumer: consumer, limit: limit}, nil
}

func (query CoordinationEventsQuery) WorkspaceID() domain.WorkspaceID      { return query.workspace }
func (query CoordinationEventsQuery) ActorID() domain.ActorID              { return query.actor }
func (query CoordinationEventsQuery) AfterCursor() CoordinationEventCursor { return query.after }
func (query CoordinationEventsQuery) ConsumerID() CoordinationConsumerID   { return query.consumer }
func (query CoordinationEventsQuery) Limit() uint16                        { return query.limit }

type CoordinationConsumerCommit struct {
	workspace domain.WorkspaceID
	actor     domain.ActorID
	consumer  CoordinationConsumerID
	cursor    CoordinationEventCursor
}

func NewCoordinationConsumerCommit(workspace domain.WorkspaceID, actor domain.ActorID,
	consumer CoordinationConsumerID, cursor CoordinationEventCursor) (CoordinationConsumerCommit, error) {
	if workspace.IsZero() || actor.IsZero() || consumer == "" || cursor.IsZero() {
		return CoordinationConsumerCommit{}, ErrInvalidCoordination
	}
	return CoordinationConsumerCommit{workspace: workspace, actor: actor, consumer: consumer, cursor: cursor}, nil
}

func (commit CoordinationConsumerCommit) WorkspaceID() domain.WorkspaceID    { return commit.workspace }
func (commit CoordinationConsumerCommit) ActorID() domain.ActorID            { return commit.actor }
func (commit CoordinationConsumerCommit) ConsumerID() CoordinationConsumerID { return commit.consumer }
func (commit CoordinationConsumerCommit) Cursor() CoordinationEventCursor    { return commit.cursor }

type CoordinationEventsPage struct {
	events       []CoordinationEvent
	eventCursors []CoordinationEventCursor
	next         CoordinationEventCursor
	hasMore      bool
}

func NewCoordinationEventsPage(events []CoordinationEvent, eventCursors []CoordinationEventCursor,
	next CoordinationEventCursor, hasMore bool) (CoordinationEventsPage, error) {
	if next.IsZero() || len(events) > MaxQueryPageSize || len(events) != len(eventCursors) {
		return CoordinationEventsPage{}, ErrInvalidCoordination
	}
	cloned := append([]CoordinationEvent(nil), events...)
	for index := range cloned {
		if cloned[index].position == 0 || eventCursors[index].IsZero() || index > 0 && cloned[index-1].position >= cloned[index].position {
			return CoordinationEventsPage{}, ErrInvalidCoordination
		}
		cloned[index].payload = append([]byte(nil), cloned[index].payload...)
	}
	return CoordinationEventsPage{events: cloned, eventCursors: append([]CoordinationEventCursor(nil), eventCursors...),
		next: next, hasMore: hasMore}, nil
}

func (page CoordinationEventsPage) Events() []CoordinationEvent {
	result := append([]CoordinationEvent(nil), page.events...)
	for index := range result {
		result[index].payload = append([]byte(nil), result[index].payload...)
	}
	return result
}
func (page CoordinationEventsPage) EventCursors() []CoordinationEventCursor {
	return append([]CoordinationEventCursor(nil), page.eventCursors...)
}
func (page CoordinationEventsPage) NextCursor() CoordinationEventCursor { return page.next }
func (page CoordinationEventsPage) HasMore() bool                       { return page.hasMore }

type InboxQuery struct {
	WorkspaceID domain.WorkspaceID
	Recipient   domain.ActorID
	After       uint64
	Limit       uint16
	UnreadOnly  bool
}
type ThreadQuery struct {
	WorkspaceID    domain.WorkspaceID
	ConversationID domain.ConversationID
	Viewer         domain.ActorID
	After          uint64
	Limit          uint16
}

type DeliveryFactKind string

const (
	DeliveryAvailable    DeliveryFactKind = "available"
	DeliveryRead         DeliveryFactKind = "read"
	DeliveryAcknowledged DeliveryFactKind = "acknowledged"
)

type RecordDeliveryFactParams struct {
	WorkspaceID    domain.WorkspaceID
	MessageID      domain.MessageID
	Recipient      domain.ActorID
	ActorSessionID *domain.ActorSessionID
	Kind           DeliveryFactKind
	MessageDigest  Digest
}

type LeaseSelectorKind string

const (
	LeaseSelectorExact   LeaseSelectorKind = "exact"
	LeaseSelectorSubtree LeaseSelectorKind = "subtree"
)

type LeaseSelector struct {
	kind  LeaseSelectorKind
	value string
}

func NewLeaseSelector(kind LeaseSelectorKind, value string) (LeaseSelector, error) {
	if kind != LeaseSelectorExact && kind != LeaseSelectorSubtree || value == "" || len(value) > MaxLeaseSelectorBytes ||
		!utf8.ValidString(value) || strings.Contains(value, "\\") || path.IsAbs(value) || !norm.NFC.IsNormalString(value) {
		return LeaseSelector{}, ErrInvalidCoordination
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsRune(segment, 0) {
			return LeaseSelector{}, ErrInvalidCoordination
		}
	}
	if path.Clean(value) != value {
		return LeaseSelector{}, ErrInvalidCoordination
	}
	return LeaseSelector{kind: kind, value: value}, nil
}
func (selector LeaseSelector) Kind() LeaseSelectorKind { return selector.kind }
func (selector LeaseSelector) Path() string            { return selector.value }
func (selector LeaseSelector) Key() string             { return string(selector.kind) + ":" + selector.value }
func LeaseSelectorsOverlap(left, right LeaseSelector) bool {
	if left.value == right.value {
		return true
	}
	return left.kind == LeaseSelectorSubtree && strings.HasPrefix(right.value, left.value+"/") ||
		right.kind == LeaseSelectorSubtree && strings.HasPrefix(left.value, right.value+"/")
}

// LeaseSelectorCovers reports whether outer protects everything inner does.
// Overlap is symmetric and only says two selectors touch; supersession needs
// containment, because retiring a prior lease that the new one does not fully
// cover silently drops paths its holder still believes it has reserved. An
// exact selector covers only the identical exact selector: it does not protect
// the subtree a same-path subtree selector does.
func LeaseSelectorCovers(outer, inner LeaseSelector) bool {
	if outer.kind == LeaseSelectorSubtree {
		return outer.value == inner.value || strings.HasPrefix(inner.value, outer.value+"/")
	}
	return inner.kind == LeaseSelectorExact && outer.value == inner.value
}

type LeaseMode string

const (
	LeaseShared    LeaseMode = "shared"
	LeaseExclusive LeaseMode = "exclusive"
)

type Fence struct {
	conflictKey string
	counter     uint64
}

func NewFence(key string, counter uint64) (Fence, error) {
	if !validOpaqueText(key, MaxLeaseSelectorBytes+16) || counter == 0 || counter > MaxCanonicalInteger {
		return Fence{}, ErrInvalidCoordination
	}
	return Fence{conflictKey: key, counter: counter}, nil
}
func (fence Fence) ConflictKey() string { return fence.conflictKey }
func (fence Fence) Counter() uint64     { return fence.counter }

type AcquireLeaseParams struct {
	LeaseID        domain.LeaseID
	WorkspaceID    domain.WorkspaceID
	Holder         domain.ActorID
	HolderSession  domain.ActorSessionID
	AuthorityEpoch domain.AuthorityEpoch
	Mode           LeaseMode
	Selectors      []LeaseSelector
	TTL            time.Duration
}
type Lease struct {
	id            domain.LeaseID
	workspace     domain.WorkspaceID
	holder        domain.ActorID
	holderSession domain.ActorSessionID
	epoch         domain.AuthorityEpoch
	mode          LeaseMode
	selectors     []LeaseSelector
	fences        []Fence
	acquiredAt    time.Time
	expiresAt     time.Time
	releasedAt    *time.Time
}
type LeaseViewParams struct {
	LeaseID        domain.LeaseID
	WorkspaceID    domain.WorkspaceID
	Holder         domain.ActorID
	HolderSession  domain.ActorSessionID
	AuthorityEpoch domain.AuthorityEpoch
	Mode           LeaseMode
	Selectors      []LeaseSelector
	Fences         []Fence
	AcquiredAt     time.Time
	ExpiresAt      time.Time
	ReleasedAt     *time.Time
}

func NewLeaseView(params LeaseViewParams) (Lease, error) {
	if params.LeaseID.IsZero() || params.WorkspaceID.IsZero() || params.Holder.IsZero() || params.HolderSession.IsZero() ||
		params.AuthorityEpoch.IsZero() || params.Mode != LeaseShared && params.Mode != LeaseExclusive ||
		len(params.Selectors) == 0 || len(params.Selectors) > MaxLeaseSelectors || params.AcquiredAt.IsZero() ||
		!params.ExpiresAt.After(params.AcquiredAt) {
		return Lease{}, ErrInvalidCoordination
	}
	return Lease{id: params.LeaseID, workspace: params.WorkspaceID, holder: params.Holder, holderSession: params.HolderSession,
		epoch: params.AuthorityEpoch, mode: params.Mode, selectors: append([]LeaseSelector(nil), params.Selectors...),
		fences: append([]Fence(nil), params.Fences...), acquiredAt: params.AcquiredAt.UTC(), expiresAt: params.ExpiresAt.UTC(),
		releasedAt: cloneOptional(params.ReleasedAt)}, nil
}
func ValidateAcquireLease(params AcquireLeaseParams) error {
	if params.LeaseID.IsZero() || params.WorkspaceID.IsZero() || params.Holder.IsZero() || params.HolderSession.IsZero() ||
		params.AuthorityEpoch.IsZero() || params.Mode != LeaseShared && params.Mode != LeaseExclusive ||
		params.TTL <= 0 || params.TTL > MaxLeaseTTL || len(params.Selectors) == 0 || len(params.Selectors) > MaxLeaseSelectors {
		return ErrInvalidCoordination
	}
	total := 0
	seen := make(map[string]struct{}, len(params.Selectors))
	for index, selector := range params.Selectors {
		if selector.value == "" || selector.kind != LeaseSelectorExact && selector.kind != LeaseSelectorSubtree {
			return ErrInvalidCoordination
		}
		total += len(selector.Key())
		if _, duplicate := seen[selector.Key()]; duplicate {
			return ErrInvalidCoordination
		}
		seen[selector.Key()] = struct{}{}
		for prior := 0; prior < index; prior++ {
			if LeaseSelectorsOverlap(params.Selectors[prior], selector) {
				return ErrInvalidCoordination
			}
		}
	}
	if total > MaxLeaseSelectorBytes {
		return ErrInvalidCoordination
	}
	return nil
}
func (lease Lease) ID() domain.LeaseID                    { return lease.id }
func (lease Lease) WorkspaceID() domain.WorkspaceID       { return lease.workspace }
func (lease Lease) Holder() domain.ActorID                { return lease.holder }
func (lease Lease) HolderSession() domain.ActorSessionID  { return lease.holderSession }
func (lease Lease) AuthorityEpoch() domain.AuthorityEpoch { return lease.epoch }
func (lease Lease) Mode() LeaseMode                       { return lease.mode }
func (lease Lease) Selectors() []LeaseSelector {
	return append([]LeaseSelector(nil), lease.selectors...)
}
func (lease Lease) Fences() []Fence               { return append([]Fence(nil), lease.fences...) }
func (lease Lease) AcquiredAt() time.Time         { return lease.acquiredAt }
func (lease Lease) ExpiresAt() time.Time          { return lease.expiresAt }
func (lease Lease) ReleasedAt() (time.Time, bool) { return optionalTime(lease.releasedAt) }

type ChangeLeaseParams struct {
	LeaseID        domain.LeaseID
	HolderSession  domain.ActorSessionID
	AuthorityEpoch domain.AuthorityEpoch
	Fences         []Fence
	TTL            time.Duration
}

type CoordinationStore interface {
	OpenConversation(context.Context, OpenConversationParams) (Conversation, error)
	SendMessage(context.Context, SendMessageParams) (Message, error)
	Inbox(context.Context, InboxQuery) (CoordinationPage, error)
	Thread(context.Context, ThreadQuery) (CoordinationPage, error)
	RecordDeliveryFact(context.Context, RecordDeliveryFactParams) (Delivery, error)
	AcquireLease(context.Context, AcquireLeaseParams) (Lease, error)
	RenewLease(context.Context, ChangeLeaseParams) (Lease, error)
	ReleaseLease(context.Context, ChangeLeaseParams) (Lease, error)
	ValidateFence(context.Context, domain.LeaseID, domain.AuthorityEpoch, []Fence) error
	SyncCoordinationEvents(context.Context, CoordinationEventsQuery) (CoordinationEventsPage, error)
	CommitCoordinationConsumer(context.Context, CoordinationConsumerCommit) error
}

const (
	MaxCoordinationKeyBytes  = 4096
	MaxCoordinationNameBytes = 128
)

// WorkReferenceObserver reads provider-owned work without making Blackbird an
// authority over its fields.
type WorkReferenceObserver interface {
	ObserveWorkReference(context.Context, string, string) (WorkReference, error)
}

type WorkReference struct {
	Provider        string                  `json:"provider"`
	Project         string                  `json:"project"`
	ObjectID        string                  `json:"object_id"`
	ObservedVersion string                  `json:"observed_version"`
	ObservedAt      time.Time               `json:"observed_at"`
	Fields          WorkReferenceFields     `json:"fields"`
	Provenance      WorkReferenceProvenance `json:"provenance"`
}

type WorkReferenceFields struct {
	Title        string                    `json:"title"`
	IssueType    string                    `json:"issue_type"`
	Status       string                    `json:"status"`
	Priority     int                       `json:"priority"`
	Assignee     string                    `json:"assignee,omitempty"`
	Dependencies []WorkReferenceDependency `json:"dependencies"`
}

type WorkReferenceDependency struct {
	ObjectID string `json:"object_id"`
	Type     string `json:"type"`
	Status   string `json:"status"`
}

type WorkReferenceProvenance struct {
	Provider      string   `json:"provider"`
	Version       string   `json:"version"`
	Build         string   `json:"build"`
	Branch        string   `json:"branch"`
	SchemaVersion int      `json:"schema_version"`
	Capabilities  []string `json:"capabilities"`
	Executable    string   `json:"executable"`
	BinarySHA256  string   `json:"binary_sha256"`
}

type LocalAgentSession struct {
	ProjectKey     string
	AgentName      string
	WorkspaceID    domain.WorkspaceID
	RunID          domain.RunID
	ActorID        domain.ActorID
	ActorSessionID domain.ActorSessionID
	AuthorityEpoch domain.AuthorityEpoch
	StartedAt      time.Time
	LastSeenAt     time.Time
}

type ActiveAgent struct {
	Name       string
	ActorID    domain.ActorID
	SessionID  domain.ActorSessionID
	StartedAt  time.Time
	LastSeenAt time.Time
}

// LocalCoordinationStore resolves ergonomic local names and bearer tokens to
// the UUID-level durable coordination contracts above.
type LocalCoordinationStore interface {
	CoordinationStore
	GetVisibleMessage(context.Context, domain.WorkspaceID, domain.ActorID, domain.MessageID) (Message, error)
	RegisterLocalAgent(context.Context, string, string, string) (LocalAgentSession, string, error)
	AuthenticateLocalAgent(context.Context, string) (LocalAgentSession, error)
	LocalAgentSnapshot(context.Context, LocalAgentSession) (LocalAgentSnapshot, error)
	ListActiveLocalAgents(context.Context, LocalAgentSession) ([]ActiveAgent, error)
	ResolveLocalAgentNames(context.Context, LocalAgentSession, []string) ([]domain.ActorID, error)
	// LocalAgentReservations answers "who holds this path, in what mode, and
	// for how much longer" for the caller's own workspace. The same question
	// the loopback admin surface answers, reachable by the agent the answer is
	// for: an agent refused a lease could otherwise only be told that it lost,
	// never to whom, and the operator's CLI was the only way to find out.
	//
	// The query's ProjectKey is ignored and replaced with the session's, so
	// this can never read across into another workspace. Everything else --
	// path overlap on separator boundaries, the derived state, the
	// server-computed ExpiresInMS -- is the admin query's, unchanged.
	LocalAgentReservations(context.Context, LocalAgentSession, AdminReservationsQuery) (AdminReservationsPage, error)
	// AwaitCoordination parks the caller until the path it wants is free, mail
	// arrives for it, or the budget runs out, and says which. See
	// CoordinationWaitRequest for why a bounded server-side wait is the only
	// shape of this that a model on the far side of MCP can actually use.
	AwaitCoordination(context.Context, LocalAgentSession, CoordinationWaitRequest) (CoordinationWaitResult, error)
}
