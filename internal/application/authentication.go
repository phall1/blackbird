package application

import (
	"context"
	"time"

	"github.com/phall1/blackbird/internal/domain"
)

// AuthenticationLookupParams are the transport-verified identity fields of one
// protected ingress. Identifier fields are metadata verified by the transport
// edge; they are never caller-overridable request values.
type AuthenticationLookupParams struct {
	PrincipalID           domain.PrincipalID
	DeviceID              *domain.DeviceID
	ActorSessionID        *domain.ActorSessionID
	CredentialFingerprint domain.CredentialDigest
	RequiredAudience      domain.CredentialAudience
	AuthorityEpoch        domain.AuthorityEpoch
}

// AuthenticationLookup is the opaque, validated identity a transport presents
// for store-side authentication resolution. At least one of the device or
// actor-session identities must be present.
type AuthenticationLookup struct {
	principal             domain.PrincipalID
	device                domain.DeviceID
	hasDevice             bool
	actorSession          domain.ActorSessionID
	hasActorSession       bool
	credentialFingerprint domain.CredentialDigest
	requiredAudience      domain.CredentialAudience
	authorityEpoch        domain.AuthorityEpoch
}

// NewAuthenticationLookup validates and seals a transport identity lookup.
func NewAuthenticationLookup(params AuthenticationLookupParams) (AuthenticationLookup, error) {
	if params.PrincipalID.IsZero() || params.RequiredAudience.String() == "" || params.AuthorityEpoch.IsZero() ||
		params.DeviceID == nil && params.ActorSessionID == nil {
		return AuthenticationLookup{}, ErrInvalidApplicationContract
	}
	lookup := AuthenticationLookup{
		principal: params.PrincipalID, requiredAudience: params.RequiredAudience,
		authorityEpoch: params.AuthorityEpoch,
	}
	if params.DeviceID != nil {
		if params.DeviceID.IsZero() || params.CredentialFingerprint.IsZero() {
			return AuthenticationLookup{}, ErrInvalidApplicationContract
		}
		lookup.device, lookup.hasDevice = *params.DeviceID, true
		lookup.credentialFingerprint = params.CredentialFingerprint
	} else if !params.CredentialFingerprint.IsZero() {
		return AuthenticationLookup{}, ErrInvalidApplicationContract
	}
	if params.ActorSessionID != nil {
		if params.ActorSessionID.IsZero() {
			return AuthenticationLookup{}, ErrInvalidApplicationContract
		}
		lookup.actorSession, lookup.hasActorSession = *params.ActorSessionID, true
	}
	return lookup, nil
}

func (lookup AuthenticationLookup) PrincipalID() domain.PrincipalID { return lookup.principal }
func (lookup AuthenticationLookup) DeviceID() (domain.DeviceID, bool) {
	return lookup.device, lookup.hasDevice
}
func (lookup AuthenticationLookup) ActorSessionID() (domain.ActorSessionID, bool) {
	return lookup.actorSession, lookup.hasActorSession
}
func (lookup AuthenticationLookup) CredentialFingerprint() domain.CredentialDigest {
	return lookup.credentialFingerprint
}
func (lookup AuthenticationLookup) RequiredAudience() domain.CredentialAudience {
	return lookup.requiredAudience
}
func (lookup AuthenticationLookup) AuthorityEpoch() domain.AuthorityEpoch {
	return lookup.authorityEpoch
}

// AuthenticationStateParams are the durable identity snapshot fields produced
// by an atomic store-side authentication resolution.
type AuthenticationStateParams struct {
	Principal         domain.PrincipalState
	Device            *domain.DeviceState
	ActorSession      *domain.ActorSessionState
	SourceAuthorityID domain.AuthorityID
	VerifiedAt        time.Time
}

// AuthenticationState is the immutable, atomically verified identity snapshot
// behind one authenticated ingress. Every bound identity in the snapshot was
// present, active, unexpired, and at its durable revision when the snapshot was
// read.
type AuthenticationState struct {
	principal         domain.PrincipalState
	device            *domain.DeviceState
	actorSession      *domain.ActorSessionState
	sourceAuthorityID domain.AuthorityID
	verifiedAt        time.Time
}

// NewAuthenticationState validates and seals a resolved authentication
// snapshot. Principal ownership of the device and actor-session identities is
// required when either is present.
func NewAuthenticationState(params AuthenticationStateParams) (AuthenticationState, error) {
	if params.Principal.IsZero() || params.SourceAuthorityID.IsZero() || params.VerifiedAt.IsZero() {
		return AuthenticationState{}, ErrInvalidApplicationContract
	}
	if params.Device != nil {
		if params.Device.IsZero() || params.Device.PrincipalID() != params.Principal.ID() {
			return AuthenticationState{}, ErrInvalidApplicationContract
		}
	}
	if params.ActorSession != nil {
		if params.ActorSession.IsZero() || params.ActorSession.Binding().PrincipalID() != params.Principal.ID() {
			return AuthenticationState{}, ErrInvalidApplicationContract
		}
	}
	return AuthenticationState{
		principal: params.Principal, device: params.Device, actorSession: params.ActorSession,
		sourceAuthorityID: params.SourceAuthorityID, verifiedAt: params.VerifiedAt.UTC(),
	}, nil
}

func (state AuthenticationState) Principal() domain.PrincipalState { return state.principal }
func (state AuthenticationState) Device() (*domain.DeviceState, bool) {
	return state.device, state.device != nil
}
func (state AuthenticationState) ActorSession() (*domain.ActorSessionState, bool) {
	return state.actorSession, state.actorSession != nil
}
func (state AuthenticationState) SourceAuthorityID() domain.AuthorityID {
	return state.sourceAuthorityID
}
func (state AuthenticationState) VerifiedAt() time.Time { return state.verifiedAt }

// AuthenticationStateResolver resolves a transport-verified identity lookup
// against durable store state in one atomic read. It returns an
// AuthenticationState only when every bound identity is present, active,
// unexpired, at its bound revision, and the actor-session audience matches the
// required ingress audience.
type AuthenticationStateResolver interface {
	ResolveAuthentication(context.Context, AuthenticationLookup) (AuthenticationState, error)
}
