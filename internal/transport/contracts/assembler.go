package contracts

import (
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

// CommandPolicySource yields the current authorization policy for an authority
// scope. The revision and digest are composition-level facts owned by the
// production policy registry and never by the caller.
type CommandPolicySource interface {
	CurrentPolicy(domain.AuthorityScope) (domain.PolicyRevision, application.Digest, error)
}

// W0CommandAssembler derives the authenticated command context shared by every
// W0 command: the transport-verified authentication request, the current
// policy preparation bound to that authentication, and the audit request
// context. Per-operation command specs and canonical hash views are assembled
// by the application handler on top of this context.
type W0CommandAssembler struct {
	policy CommandPolicySource
}

// NewW0CommandAssembler requires the production policy source for every scope
// a command may touch. A nil policy source fails closed.
func NewW0CommandAssembler(policy CommandPolicySource) (*W0CommandAssembler, error) {
	if policy == nil {
		return nil, application.ErrInvalidApplicationContract
	}
	return &W0CommandAssembler{policy: policy}, nil
}

// AuthenticationRequest seals verified evidence into the authentication request
// for one command operation and scope. The evidence's channel binding,
// audience, grant revisions, device, and actor session are preserved exactly.
func (assembler *W0CommandAssembler) AuthenticationRequest(
	evidence AuthenticationEvidence,
	operation application.CommandOperation,
	scope domain.AuthorityScope,
) (application.AuthenticationRequest, error) {
	if assembler == nil || !evidence.Valid() || scope.IsZero() {
		return application.AuthenticationRequest{}, application.ErrInvalidApplicationContract
	}
	provenance, err := application.NewAuditProvenanceEvidence(
		evidence.AuditProvenance().SourceAuthorityID(), auditEnvelopeID(evidence),
	)
	if err != nil {
		return application.AuthenticationRequest{}, err
	}
	audience, err := domain.NewCredentialAudience(evidence.Audience().String())
	if err != nil {
		return application.AuthenticationRequest{}, err
	}
	params := application.AuthenticationRequestParams{
		Operation: operation, Scope: scope, PrincipalID: evidence.PrincipalID(),
		PrincipalRevision: evidence.PrincipalRevision(), GrantRevisions: evidence.GrantRevisions(),
		ChannelBinding: application.Digest(evidence.ChannelBindingDigest().Bytes()),
		Audience:       audience, AuditProvenance: provenance, VerifiedAt: evidence.VerifiedAt(),
	}
	if device, present := evidence.DeviceID(); present {
		deviceID := device
		params.DeviceID = &deviceID
		params.DeviceRevision, params.DeviceTrustRevision, params.DeviceRevokeRevision =
			deviceEvidenceRevisions(evidence)
		params.CredentialFingerprint = evidenceCredentialFingerprint(evidence)
	}
	if session, present := evidence.ActorSessionID(); present {
		sessionID := session
		params.ActorSessionID = &sessionID
		params.ActorSessionRevision = evidenceActorSessionRevision(evidence)
	}
	return application.NewAuthenticationRequest(params)
}

// PolicyPreparationRequest resolves the current policy for the authenticated
// scope and binds it to the authentication request.
func (assembler *W0CommandAssembler) PolicyPreparationRequest(
	authentication application.AuthenticationRequest,
) (application.PolicyPreparationRequest, error) {
	if assembler == nil || assembler.policy == nil {
		return application.PolicyPreparationRequest{}, application.ErrInvalidApplicationContract
	}
	revision, digest, err := assembler.policy.CurrentPolicy(authentication.Scope())
	if err != nil {
		return application.PolicyPreparationRequest{}, err
	}
	return application.NewPolicyPreparationRequest(authentication, revision, digest)
}

// AuditRequestContext seals transport request metadata into the audit context.
// The server-received instant is supplied by the transport edge; no client
// clock is trusted.
func (assembler *W0CommandAssembler) AuditRequestContext(
	requestID string,
	traceID string,
	serverReceived time.Time,
) (application.AuditRequestContext, error) {
	if assembler == nil {
		return application.AuditRequestContext{}, application.ErrInvalidApplicationContract
	}
	return application.NewAuditRequestContext(requestID, traceID, serverReceived, nil)
}

func auditEnvelopeID(evidence AuthenticationEvidence) *string {
	if envelope, present := evidence.AuditProvenance().FederationEnvelopeID(); present {
		return &envelope
	}
	return nil
}

func deviceEvidenceRevisions(
	evidence AuthenticationEvidence,
) (domain.Version, domain.Version, domain.Version) {
	revision, _ := evidence.DeviceRevision()
	trust, _ := evidence.DeviceTrustRevision()
	revocation, _ := evidence.DeviceRevocationRevision()
	return revision, trust, revocation
}

func evidenceCredentialFingerprint(evidence AuthenticationEvidence) domain.CredentialDigest {
	fingerprint, _ := evidence.CredentialFingerprint()
	return fingerprint
}

func evidenceActorSessionRevision(evidence AuthenticationEvidence) domain.Version {
	revision, _ := evidence.ActorSessionRevision()
	return revision
}
