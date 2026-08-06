package contracts

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

type stubCommandPolicySource struct {
	revision domain.PolicyRevision
	digest   application.Digest
	err      error
	scopes   []domain.AuthorityScope
}

func (source *stubCommandPolicySource) CurrentPolicy(scope domain.AuthorityScope) (domain.PolicyRevision, application.Digest, error) {
	source.scopes = append(source.scopes, scope)
	if source.err != nil {
		return domain.PolicyRevision{}, application.Digest{}, source.err
	}
	return source.revision, source.digest, nil
}

func assemblerEvidence(t *testing.T, fixture authenticationFixture) AuthenticationEvidence {
	t.Helper()
	resolver := &stubAuthenticationResolver{state: resolvedSessionState(t, fixture)}
	authenticator := newProductionAuthenticator(t, resolver, fixture.audience)
	evidence, failure, err := authenticator.Authenticate(context.Background(), sessionIngress(t, fixture), testOperation, "req_assembler")
	if err != nil || failure != nil || !evidence.Valid() {
		t.Fatalf("authenticate evidence=%v failure=%v err=%v", evidence, failure, err)
	}
	return evidence
}

func deviceOnlyAssemblerEvidence(t *testing.T, fixture authenticationFixture) AuthenticationEvidence {
	t.Helper()
	resolver := &stubAuthenticationResolver{state: resolvedDeviceState(t, fixture)}
	authenticator := newProductionAuthenticator(t, resolver, fixture.audience)
	evidence, failure, err := authenticator.Authenticate(context.Background(), deviceIngress(t, fixture), testOperation, "req_assembler_device")
	if err != nil || failure != nil || !evidence.Valid() {
		t.Fatalf("authenticate device evidence=%v failure=%v err=%v", evidence, failure, err)
	}
	return evidence
}

func newW0CommandAssembler(t *testing.T, source CommandPolicySource) *W0CommandAssembler {
	t.Helper()
	assembler, err := NewW0CommandAssembler(source)
	if err != nil {
		t.Fatal(err)
	}
	return assembler
}

func TestW0CommandAssemblerSealsAuthenticationRequest(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	scope, err := domain.WorkspaceScope(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	assembler := newW0CommandAssembler(t, &stubCommandPolicySource{})

	request, err := assembler.AuthenticationRequest(
		assemblerEvidence(t, fixture), application.CommandCreateWorkspace, scope,
	)
	if err != nil {
		t.Fatalf("AuthenticationRequest: %v", err)
	}
	if request.Operation() != application.CommandCreateWorkspace || request.Scope() != scope ||
		request.PrincipalID() != fixture.principal.ID() ||
		request.PrincipalRevision() != fixture.principal.Version() {
		t.Fatalf("command identity context mismatch: operation=%s scope=%v principal=%s@%d",
			request.Operation(), request.Scope(), request.PrincipalID(), request.PrincipalRevision().Uint64())
	}
	deviceID, deviceRevision, deviceTrust, deviceRevoke, fingerprint, hasDevice := request.Device()
	if !hasDevice || deviceID != fixture.device.ID() || deviceRevision != fixture.device.Version() ||
		deviceTrust != fixture.device.TrustRevision() || deviceRevoke != fixture.device.RevocationRevision() ||
		fingerprint != fixture.spki {
		t.Fatalf("device authentication context mismatch: id=%s/%v rev=%v trust=%v revoke=%v fp=%x",
			deviceID, hasDevice, deviceRevision, deviceTrust, deviceRevoke, fingerprint)
	}
	sessionID, sessionRevision, hasSession := request.ActorSession()
	if !hasSession || sessionID != fixture.session.ID() || sessionRevision != fixture.session.Version() {
		t.Fatalf("actor session authentication context mismatch: id=%s/%v rev=%v", sessionID, hasSession, sessionRevision)
	}
	grants := request.GrantRevisions()
	if len(grants) != 1 || grants[0] != fixture.grant {
		t.Fatalf("grant revisions=%v, want %v", grants, []domain.AggregateRef{fixture.grant})
	}
	wantBinding := application.Digest(fixture.channelBinding.Bytes())
	if request.ChannelBinding() != wantBinding {
		t.Fatalf("channel binding=%s, want %x", request.ChannelBinding(), wantBinding)
	}
	if request.Audience() != fixture.sessionAudience {
		t.Fatalf("audience=%s, want %s", request.Audience(), fixture.sessionAudience)
	}
	if request.AuditProvenance().SourceAuthorityID() != fixture.authority {
		t.Fatalf("audit provenance authority=%s, want %s",
			request.AuditProvenance().SourceAuthorityID(), fixture.authority)
	}
	if !request.VerifiedAt().Equal(fixture.verifiedAt) {
		t.Fatalf("verified at=%s, want %s", request.VerifiedAt(), fixture.verifiedAt)
	}
}

func TestW0CommandAssemblerSealsDeviceOnlyAuthenticationRequest(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	scope, err := domain.WorkspaceScope(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	assembler := newW0CommandAssembler(t, &stubCommandPolicySource{})

	request, err := assembler.AuthenticationRequest(
		deviceOnlyAssemblerEvidence(t, fixture), application.CommandCreateWorkspace, scope,
	)
	if err != nil {
		t.Fatalf("AuthenticationRequest: %v", err)
	}
	deviceID, _, _, _, fingerprint, hasDevice := request.Device()
	if !hasDevice || deviceID != fixture.device.ID() || fingerprint != fixture.spki {
		t.Fatalf("device authentication context mismatch: id=%s/%v fp=%x", deviceID, hasDevice, fingerprint)
	}
	session, _, hasSession := request.ActorSession()
	if hasSession || !session.IsZero() {
		t.Fatalf("device-only authentication unexpectedly carries session %s", session)
	}
}

func TestW0CommandAssemblerResolvesCurrentPolicy(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	scope, err := domain.WorkspaceScope(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	policyRevision, err := domain.NewPolicyRevision("policy:assembler-test:v1")
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := application.Digest(sha256.Sum256([]byte("assembler policy digest")))
	source := &stubCommandPolicySource{revision: policyRevision, digest: policyDigest}
	assembler := newW0CommandAssembler(t, source)

	authentication, err := assembler.AuthenticationRequest(
		assemblerEvidence(t, fixture), application.CommandCreateWorkspace, scope,
	)
	if err != nil {
		t.Fatalf("AuthenticationRequest: %v", err)
	}
	policy, err := assembler.PolicyPreparationRequest(authentication)
	if err != nil {
		t.Fatalf("PolicyPreparationRequest: %v", err)
	}
	if len(source.scopes) != 1 || source.scopes[0] != scope {
		t.Fatalf("policy lookup scopes=%v, want %v", source.scopes, []domain.AuthorityScope{scope})
	}
	if policy.PolicyRevision() != policyRevision || policy.PolicyDigest() != policyDigest {
		t.Fatalf("policy=%s/%x, want %s/%x", policy.PolicyRevision(), policy.PolicyDigest(), policyRevision, policyDigest)
	}
	if policy.Operation() != application.CommandCreateWorkspace || policy.PrincipalID() != fixture.principal.ID() ||
		policy.ChannelBinding() != application.Digest(fixture.channelBinding.Bytes()) ||
		policy.Audience() != fixture.sessionAudience || !policy.VerifiedAt().Equal(fixture.verifiedAt) {
		t.Fatalf("policy did not preserve authenticated context: %+v", policy)
	}
	if session, present := policy.ActorSession(); !present || session != fixture.session.ID() {
		t.Fatalf("policy actor session=%s/%v, want %s", session, present, fixture.session.ID())
	}
}

func TestW0CommandAssemblerSealsAuditContext(t *testing.T) {
	assembler := newW0CommandAssembler(t, &stubCommandPolicySource{})
	receivedAt := time.Now().UTC().Truncate(time.Microsecond)

	audit, err := assembler.AuditRequestContext("req_assembler_audit", "trace_assembler_audit", receivedAt)
	if err != nil {
		t.Fatalf("AuditRequestContext: %v", err)
	}
	if audit.RequestID() != "req_assembler_audit" || audit.TraceID() != "trace_assembler_audit" ||
		!audit.ServerReceivedAt().Equal(receivedAt) {
		t.Fatalf("audit context=%+v, want request=%s trace=%s received=%s",
			audit, "req_assembler_audit", "trace_assembler_audit", receivedAt)
	}
	if clientAt, present := audit.AuthenticatedClientAt(); present || !clientAt.IsZero() {
		t.Fatalf("audit context unexpectedly carries client time %s/%v", clientAt, present)
	}
}

func TestW0CommandAssemblerRejectsInvalidInputs(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	scope, err := domain.WorkspaceScope(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	evidence := assemblerEvidence(t, fixture)
	assembler := newW0CommandAssembler(t, &stubCommandPolicySource{})

	if request, err := assembler.AuthenticationRequest(AuthenticationEvidence{}, application.CommandCreateWorkspace, scope); !errors.Is(err, application.ErrInvalidApplicationContract) || request.Operation() != "" {
		t.Fatalf("zero evidence request=%+v err=%v, want invalid contract", request, err)
	}
	if request, err := assembler.AuthenticationRequest(evidence, application.CommandCreateWorkspace, domain.AuthorityScope{}); !errors.Is(err, application.ErrInvalidApplicationContract) || request.Operation() != "" {
		t.Fatalf("zero scope request=%+v err=%v, want invalid contract", request, err)
	}
	if request, err := assembler.AuthenticationRequest(evidence, application.CommandOperation("no.such.operation.v1"), scope); !errors.Is(err, application.ErrInvalidApplicationContract) || request.Operation() != "" {
		t.Fatalf("unknown operation request=%+v err=%v, want invalid contract", request, err)
	}
	if audit, err := assembler.AuditRequestContext("", "trace", time.Now()); !errors.Is(err, application.ErrInvalidApplicationContract) || audit.RequestID() != "" {
		t.Fatalf("empty request id audit=%+v err=%v, want invalid contract", audit, err)
	}
	if audit, err := assembler.AuditRequestContext("req", "trace", time.Time{}); !errors.Is(err, application.ErrInvalidApplicationContract) || audit.RequestID() != "" {
		t.Fatalf("zero received-at audit=%+v err=%v, want invalid contract", audit, err)
	}
}

func TestW0CommandAssemblerForwardsPolicyFailures(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	scope, err := domain.WorkspaceScope(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	source := &stubCommandPolicySource{err: errors.New("policy registry unavailable")}
	assembler := newW0CommandAssembler(t, source)
	authentication, err := assembler.AuthenticationRequest(assemblerEvidence(t, fixture), application.CommandCreateWorkspace, scope)
	if err != nil {
		t.Fatalf("AuthenticationRequest: %v", err)
	}
	if policy, err := assembler.PolicyPreparationRequest(authentication); err == nil || policy.PolicyRevision().String() != "" {
		t.Fatalf("policy failure policy=%+v err=%v, want error only", policy, err)
	}
}

func TestNewW0CommandAssemblerRejectsNilPolicy(t *testing.T) {
	if assembler, err := NewW0CommandAssembler(nil); err == nil || assembler != nil {
		t.Fatalf("nil policy source accepted: assembler=%v err=%v", assembler, err)
	}
	var nilAssembler *W0CommandAssembler
	if _, err := nilAssembler.AuthenticationRequest(AuthenticationEvidence{}, application.CommandCreateWorkspace, domain.AuthorityScope{}); !errors.Is(err, application.ErrInvalidApplicationContract) {
		t.Fatalf("nil assembler err=%v, want invalid contract", err)
	}
}
