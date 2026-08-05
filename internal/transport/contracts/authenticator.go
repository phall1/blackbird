package contracts

import (
	"context"
	"errors"
	"fmt"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

// VerifiedIngressParams are the transport-verified identity facts extracted
// from one protected ingress. Every identifier here is channel-derived and
// never a caller-overridable request value.
type VerifiedIngressParams struct {
	PrincipalID           domain.PrincipalID
	DeviceID              *domain.DeviceID
	CredentialFingerprint domain.CredentialDigest
	ActorSessionID        *domain.ActorSessionID
	AuthorityEpoch        domain.AuthorityEpoch
	ChannelBinding        ChannelBindingDigest
}

// VerifiedIngress is the sealed, transport-verified identity bundle presented
// on one ingress. Its zero value is invalid; only this package can create a
// valid value, so transports cannot manufacture trusted identity claims.
type VerifiedIngress struct {
	principalID           domain.PrincipalID
	deviceID              domain.DeviceID
	hasDevice             bool
	credentialFingerprint domain.CredentialDigest
	actorSessionID        domain.ActorSessionID
	hasActorSession       bool
	authorityEpoch        domain.AuthorityEpoch
	channelBinding        ChannelBindingDigest
}

// NewVerifiedIngress seals a transport-verified identity bundle. A device
// identity requires its credential fingerprint; a fingerprint without a device
// identity is rejected. The channel binding must be nonzero proof-bound
// material.
func NewVerifiedIngress(params VerifiedIngressParams) (VerifiedIngress, error) {
	if params.PrincipalID.IsZero() || params.AuthorityEpoch.IsZero() ||
		params.ChannelBinding.String() == "" {
		return VerifiedIngress{}, invalid("verified_ingress", "contains incomplete verified identity")
	}
	ingress := VerifiedIngress{
		principalID: params.PrincipalID, authorityEpoch: params.AuthorityEpoch,
		channelBinding: params.ChannelBinding,
	}
	if params.DeviceID != nil {
		if params.DeviceID.IsZero() || params.CredentialFingerprint.IsZero() {
			return VerifiedIngress{}, invalid("verified_ingress", "device identity requires a nonzero credential fingerprint")
		}
		ingress.deviceID, ingress.hasDevice = *params.DeviceID, true
		ingress.credentialFingerprint = params.CredentialFingerprint
	} else if !params.CredentialFingerprint.IsZero() {
		return VerifiedIngress{}, invalid("verified_ingress", "credential fingerprint requires a device identity")
	}
	if params.ActorSessionID != nil {
		if params.ActorSessionID.IsZero() {
			return VerifiedIngress{}, invalid("verified_ingress", "contains a zero actor session identity")
		}
		ingress.actorSessionID, ingress.hasActorSession = *params.ActorSessionID, true
	}
	return ingress, nil
}

func (ingress VerifiedIngress) Valid() bool {
	_, err := NewVerifiedIngress(VerifiedIngressParams{
		PrincipalID: ingress.principalID,
		DeviceID:    ingress.devicePointer(), CredentialFingerprint: ingress.credentialFingerprint,
		ActorSessionID: ingress.sessionPointer(), AuthorityEpoch: ingress.authorityEpoch,
		ChannelBinding: ingress.channelBinding,
	})
	return err == nil
}

func (ingress VerifiedIngress) devicePointer() *domain.DeviceID {
	if !ingress.hasDevice {
		return nil
	}
	device := ingress.deviceID
	return &device
}

func (ingress VerifiedIngress) sessionPointer() *domain.ActorSessionID {
	if !ingress.hasActorSession {
		return nil
	}
	session := ingress.actorSessionID
	return &session
}

func (ingress VerifiedIngress) PrincipalID() domain.PrincipalID { return ingress.principalID }

func (ingress VerifiedIngress) DeviceID() (domain.DeviceID, bool) {
	return ingress.deviceID, ingress.hasDevice
}

func (ingress VerifiedIngress) CredentialFingerprint() domain.CredentialDigest {
	return ingress.credentialFingerprint
}

func (ingress VerifiedIngress) ActorSessionID() (domain.ActorSessionID, bool) {
	return ingress.actorSessionID, ingress.hasActorSession
}

func (ingress VerifiedIngress) AuthorityEpoch() domain.AuthorityEpoch {
	return ingress.authorityEpoch
}

func (ingress VerifiedIngress) ChannelBinding() ChannelBindingDigest {
	return ingress.channelBinding
}

// ProductionAuthenticator resolves a transport-verified ingress against
// durable store state and seals the result as AuthenticationEvidence. The
// resolver is the atomic store-side authority; this component never trusts a
// request-derived identity it did not observe resolved.
type ProductionAuthenticator struct {
	resolver application.AuthenticationStateResolver
	audience AuthenticationAudience
}

// NewProductionAuthenticator requires a resolver and the exact resource-server
// audience this ingress validates. The audience is never inferred from a
// request target or operation body.
func NewProductionAuthenticator(
	resolver application.AuthenticationStateResolver,
	audience AuthenticationAudience,
) (*ProductionAuthenticator, error) {
	if resolver == nil || audience.String() == "" {
		return nil, application.ErrInvalidApplicationContract
	}
	return &ProductionAuthenticator{resolver: resolver, audience: audience}, nil
}

// Authenticate resolves the verified ingress identity in one atomic read and
// returns sealed evidence carrying the ingress channel binding and audience.
// A safe failure is a typed ErrorDTO with the transport request ID; an
// internal failure returns an error and no failure DTO. The operation names
// the denied capability when authorization fails.
func (authenticator *ProductionAuthenticator) Authenticate(
	ctx context.Context,
	ingress VerifiedIngress,
	operation string,
	requestID string,
) (AuthenticationEvidence, *ErrorDTO, error) {
	if err := ctx.Err(); err != nil {
		return AuthenticationEvidence{}, nil, err
	}
	if authenticator == nil || authenticator.resolver == nil {
		return AuthenticationEvidence{}, nil, application.ErrInvalidApplicationContract
	}
	if !ingress.Valid() {
		return AuthenticationEvidence{}, nil, application.ErrInvalidApplicationContract
	}
	audience, err := domain.NewCredentialAudience(authenticator.audience.String())
	if err != nil {
		return AuthenticationEvidence{}, nil, fmt.Errorf("derive authentication lookup audience: %w", err)
	}
	params := application.AuthenticationLookupParams{
		PrincipalID: ingress.PrincipalID(), CredentialFingerprint: ingress.CredentialFingerprint(),
		RequiredAudience: audience, AuthorityEpoch: ingress.AuthorityEpoch(),
	}
	if device, present := ingress.DeviceID(); present {
		deviceID := device
		params.DeviceID = &deviceID
	}
	if session, present := ingress.ActorSessionID(); present {
		sessionID := session
		params.ActorSessionID = &sessionID
	}
	lookup, err := application.NewAuthenticationLookup(params)
	if err != nil {
		return AuthenticationEvidence{}, nil, err
	}
	state, resolveErr := authenticator.resolver.ResolveAuthentication(ctx, lookup)
	if resolveErr != nil {
		var rejection *domain.CommandError
		if errors.As(resolveErr, &rejection) {
			failure, mappingErr := authenticationFailure(requestID, operation, ingress, rejection)
			return AuthenticationEvidence{}, failure, mappingErr
		}
		return AuthenticationEvidence{}, nil, resolveErr
	}
	evidence, evidenceErr := authenticationEvidence(state, ingress, authenticator.audience)
	if evidenceErr != nil {
		return AuthenticationEvidence{}, nil, evidenceErr
	}
	return evidence, nil, nil
}

func authenticationEvidence(
	state application.AuthenticationState,
	ingress VerifiedIngress,
	audience AuthenticationAudience,
) (AuthenticationEvidence, error) {
	provenance, err := NewAuthenticationAuditProvenance(state.SourceAuthorityID(), nil)
	if err != nil {
		return AuthenticationEvidence{}, err
	}
	params := AuthenticationEvidenceParams{
		PrincipalID: state.Principal().ID(), PrincipalRevision: state.Principal().Version(),
		ChannelBinding: ingress.ChannelBinding(), Audience: audience,
		AuditProvenance: provenance, VerifiedAt: state.VerifiedAt(),
	}
	if device, present := state.Device(); present {
		deviceID := device.ID()
		params.DeviceID = &deviceID
		params.DeviceRevision = device.Version()
		params.DeviceTrustRevision = device.TrustRevision()
		params.DeviceRevocationRevision = device.RevocationRevision()
		params.CredentialFingerprint = ingress.CredentialFingerprint()
	}
	if session, present := state.ActorSession(); present {
		sessionID := session.ID()
		params.ActorSessionID = &sessionID
		params.ActorSessionRevision = session.Version()
		params.GrantRevisions = session.Binding().GrantRevisions()
	}
	return NewAuthenticationEvidence(params)
}

func authenticationFailure(
	requestID string,
	operation string,
	ingress VerifiedIngress,
	rejection *domain.CommandError,
) (*ErrorDTO, error) {
	var message string
	details := ErrorDetailsDTO{}
	switch rejection.Code() {
	case domain.ErrorCodeUnauthenticated:
		message, details.Recovery = "Authentication is required.", RecoveryReauthenticate
	case domain.ErrorCodeSessionExpired:
		message, details.Recovery = "The actor session is no longer active.", RecoveryResumeSession
	case domain.ErrorCodeForbidden, domain.ErrorCodeCapabilityRequired:
		message = "The presented identity is not authorized for this operation."
		details.DeniedCapability = operation
		details.ResourceScope = failureResourceScope(ingress)
	default:
		return nil, rejection
	}
	failure := &ErrorDTO{
		Schema: SchemaError, RequestID: requestID, Code: rejection.Code(),
		Category: rejection.Category(), Message: message, Retryable: rejection.Retryable(),
		Details: details,
	}
	if err := failure.Validate(); err != nil {
		return nil, fmt.Errorf("map authentication failure: %w", err)
	}
	return failure, nil
}

func failureResourceScope(ingress VerifiedIngress) *ResourceScopeDTO {
	if session, present := ingress.ActorSessionID(); present {
		return &ResourceScopeDTO{Type: domain.AggregateKindActorSession, ID: session.String()}
	}
	if device, present := ingress.DeviceID(); present {
		return &ResourceScopeDTO{Type: domain.AggregateKindDevice, ID: device.String()}
	}
	return &ResourceScopeDTO{Type: domain.AggregateKindPrincipal, ID: ingress.PrincipalID().String()}
}
