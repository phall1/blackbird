package contracts

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const testOperation = "context.get.v1"

type stubAuthenticationResolver struct {
	state   application.AuthenticationState
	err     error
	lookups []application.AuthenticationLookup
}

func (resolver *stubAuthenticationResolver) ResolveAuthentication(
	ctx context.Context,
	lookup application.AuthenticationLookup,
) (application.AuthenticationState, error) {
	if err := ctx.Err(); err != nil {
		return application.AuthenticationState{}, err
	}
	resolver.lookups = append(resolver.lookups, lookup)
	if resolver.err != nil {
		return application.AuthenticationState{}, resolver.err
	}
	return resolver.state, nil
}

type authenticationFixture struct {
	audience        AuthenticationAudience
	channelBinding  ChannelBindingDigest
	authority       domain.AuthorityID
	epoch           domain.AuthorityEpoch
	installation    domain.InstallationID
	workspace       domain.WorkspaceID
	principal       domain.PrincipalState
	device          domain.DeviceState
	spki            domain.CredentialDigest
	session         domain.ActorSessionState
	sessionAudience domain.CredentialAudience
	grant           domain.AggregateRef
	verifiedAt      time.Time
}

func newAuthenticationFixture(t *testing.T) authenticationFixture {
	t.Helper()
	installation, err := domain.ParseInstallationID("01b8e094-9888-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := domain.ParseAuthorityID("01b8e094-9888-7000-8000-000000000003")
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := domain.NewAuthorityEpoch()
	if err != nil {
		t.Fatal(err)
	}
	principalID, err := domain.ParsePrincipalID("01b8e094-9888-7000-8000-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	displayName, err := domain.NewDisplayName("authenticator workload")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := domain.NewPublicKeyReference("keyref:authenticator-workload")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := domain.RehydratePrincipal(domain.PrincipalRehydrationParams{
		ID: principalID, InstallationID: installation, Kind: domain.PrincipalKindWorkload,
		DisplayName: displayName, PublicKeyReference: publicKey,
		Status: domain.PrincipalActive, Version: domain.InitialVersion(),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifiedAt := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	spki, err := domain.NewCredentialDigest(sha256.Sum256([]byte("authenticator sealed spki")))
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := domain.ParseDeviceID("01b8e094-9888-7000-8000-000000000014")
	if err != nil {
		t.Fatal(err)
	}
	deviceName, err := domain.NewDisplayName("authenticator device")
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := domain.NewPublicKeyReference("keyref:authenticator-device")
	if err != nil {
		t.Fatal(err)
	}
	deviceCredential, err := domain.NewDeviceCredentialBinding(
		deviceKey, spki, domain.FingerprintCommand([]byte("authenticator device transcript")),
	)
	if err != nil {
		t.Fatal(err)
	}
	deviceVersion, err := domain.NewVersion(3)
	if err != nil {
		t.Fatal(err)
	}
	deviceTrust, err := domain.NewVersion(2)
	if err != nil {
		t.Fatal(err)
	}
	device, err := domain.RehydrateDevice(domain.DeviceRehydrationParams{
		ID: deviceID, InstallationID: installation, PrincipalID: principal.ID(),
		DisplayName: deviceName, PublicKeyReference: deviceKey, Status: domain.DeviceTrusted,
		Version: deviceVersion, TrustRevision: deviceTrust, RevocationRevision: domain.InitialVersion(),
		CredentialBinding: deviceCredential, CredentialActivatedAt: verifiedAt.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	session, sessionGrant := newAuthenticatorSession(t, authenticationFixture{
		installation: installation, authority: authority, epoch: epoch, principal: principal,
		device: device, verifiedAt: verifiedAt,
	})
	audience, err := NewAuthenticationAudience("blackbird-test-ingress")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewChannelBindingDigest(strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	return authenticationFixture{
		audience: audience, channelBinding: binding, authority: authority, epoch: epoch,
		installation: installation, workspace: session.Binding().WorkspaceID(),
		principal: principal, device: device, spki: spki, session: session,
		sessionAudience: session.PresentationCredential().Audience(), grant: sessionGrant,
		verifiedAt: verifiedAt,
	}
}

func newAuthenticatorSession(
	t *testing.T,
	base authenticationFixture,
) (domain.ActorSessionState, domain.AggregateRef) {
	t.Helper()
	workspace, err := domain.ParseWorkspaceID("01b8e094-9888-7000-8000-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	membershipID, err := domain.ParseMembershipID("01b8e094-9888-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	actorID, err := domain.ParseActorID("01b8e094-9888-7000-8000-000000000012")
	if err != nil {
		t.Fatal(err)
	}
	delegationID, err := domain.ParseActorDelegationID("01b8e094-9888-7000-8000-000000000013")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.ParseActorSessionID("01b8e094-9888-7000-8000-00000000001f")
	if err != nil {
		t.Fatal(err)
	}
	clientInstance, err := domain.ParseClientInstanceID("01b8e094-9888-7000-8000-000000000020")
	if err != nil {
		t.Fatal(err)
	}
	grantID, err := domain.ParseGrantID("01b8e094-9888-7000-8000-000000000021")
	if err != nil {
		t.Fatal(err)
	}
	grantRef, err := domain.NewAggregateRef(grantID, domain.InitialVersion())
	if err != nil {
		t.Fatal(err)
	}
	membershipRef, err := domain.NewAggregateRef(membershipID, domain.InitialVersion())
	if err != nil {
		t.Fatal(err)
	}
	delegationRef, err := domain.NewAggregateRef(delegationID, domain.InitialVersion())
	if err != nil {
		t.Fatal(err)
	}
	deviceRef, err := domain.NewAggregateRef(base.device.ID(), base.device.Version())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := domain.NewPolicyRevision("policy:production-authenticator:v1")
	if err != nil {
		t.Fatal(err)
	}
	assurance, err := domain.NewAssuranceClass("production-authenticator-strong")
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := base.verifiedAt.Add(-time.Hour)
	sessionAudience, err := domain.NewCredentialAudience("blackbird-test-ingress")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := domain.NewSessionBinding(
		base.authority, base.epoch, workspace, base.principal.ID(), actorID,
		membershipRef, delegationRef, &deviceRef, base.device.TrustRevision(),
		[]domain.AggregateRef{grantRef}, policy, assurance, issuedAt, base.verifiedAt.Add(8*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := domain.NewCapabilitySet(domain.WorkspaceOwnerCapability())
	if err != nil {
		t.Fatal(err)
	}
	clientMetadata, err := domain.NewClientMetadata("authenticator-agent", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	presentationDigest, err := domain.NewCredentialDigest(sha256.Sum256([]byte("authenticator presentation")))
	if err != nil {
		t.Fatal(err)
	}
	presentationReference, err := domain.NewCredentialReference("credential-ref:authenticator-session")
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := domain.NewPresentationCredentialBinding(
		presentationDigest, presentationReference, sessionAudience, domain.PresentationCredentialVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	sessionVersion, err := domain.NewVersion(4)
	if err != nil {
		t.Fatal(err)
	}
	session, err := domain.RehydrateActorSession(domain.ActorSessionRehydrationParams{
		ID: sessionID, ClientInstanceID: clientInstance, ClientMetadata: clientMetadata,
		Status: domain.ActorSessionActive, Version: sessionVersion, Binding: binding,
		Capabilities: capabilities, PresentationCredential: presentation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return session, grantRef
}

func resolvedSessionState(t *testing.T, fixture authenticationFixture) application.AuthenticationState {
	t.Helper()
	state, err := application.NewAuthenticationState(application.AuthenticationStateParams{
		Principal: fixture.principal, Device: &fixture.device, ActorSession: &fixture.session,
		SourceAuthorityID: fixture.authority, VerifiedAt: fixture.verifiedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func resolvedDeviceState(t *testing.T, fixture authenticationFixture) application.AuthenticationState {
	t.Helper()
	state, err := application.NewAuthenticationState(application.AuthenticationStateParams{
		Principal: fixture.principal, Device: &fixture.device,
		SourceAuthorityID: fixture.authority, VerifiedAt: fixture.verifiedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func sessionIngress(t *testing.T, fixture authenticationFixture) VerifiedIngress {
	t.Helper()
	deviceID := fixture.device.ID()
	sessionID := fixture.session.ID()
	ingress, err := NewVerifiedIngress(VerifiedIngressParams{
		PrincipalID: fixture.principal.ID(), DeviceID: &deviceID,
		CredentialFingerprint: fixture.spki, ActorSessionID: &sessionID,
		AuthorityEpoch: fixture.epoch, ChannelBinding: fixture.channelBinding,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ingress
}

func deviceIngress(t *testing.T, fixture authenticationFixture) VerifiedIngress {
	t.Helper()
	deviceID := fixture.device.ID()
	ingress, err := NewVerifiedIngress(VerifiedIngressParams{
		PrincipalID: fixture.principal.ID(), DeviceID: &deviceID,
		CredentialFingerprint: fixture.spki,
		AuthorityEpoch:        fixture.epoch, ChannelBinding: fixture.channelBinding,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ingress
}

func newProductionAuthenticator(
	t *testing.T,
	resolver application.AuthenticationStateResolver,
	audience AuthenticationAudience,
) *ProductionAuthenticator {
	t.Helper()
	authenticator, err := NewProductionAuthenticator(resolver, audience)
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

func TestProductionAuthenticatorSealsSessionAndDeviceEvidence(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	resolver := &stubAuthenticationResolver{state: resolvedSessionState(t, fixture)}
	authenticator := newProductionAuthenticator(t, resolver, fixture.audience)

	evidence, failure, err := authenticator.Authenticate(context.Background(), sessionIngress(t, fixture), testOperation, "req_authenticator_session")
	if err != nil || failure != nil || !evidence.Valid() {
		t.Fatalf("authenticate session ingress: evidence=%v failure=%v err=%v", evidence, failure, err)
	}
	if evidence.PrincipalID() != fixture.principal.ID() ||
		evidence.PrincipalRevision() != fixture.principal.Version() {
		t.Fatalf("principal evidence=%s@%d, want %s@%d", evidence.PrincipalID(), evidence.PrincipalRevision().Uint64(),
			fixture.principal.ID(), fixture.principal.Version().Uint64())
	}
	deviceID, hasDevice := evidence.DeviceID()
	deviceRevision, hasDeviceRevision := evidence.DeviceRevision()
	deviceTrust, hasDeviceTrust := evidence.DeviceTrustRevision()
	deviceRevocation, hasDeviceRevocation := evidence.DeviceRevocationRevision()
	fingerprint, hasFingerprint := evidence.CredentialFingerprint()
	if !hasDevice || deviceID != fixture.device.ID() || !hasDeviceRevision ||
		deviceRevision != fixture.device.Version() || !hasDeviceTrust ||
		deviceTrust != fixture.device.TrustRevision() || !hasDeviceRevocation ||
		deviceRevocation != fixture.device.RevocationRevision() || !hasFingerprint ||
		fingerprint != fixture.spki {
		t.Fatalf("device evidence tuple mismatch: id=%s/%v rev=%v/%v trust=%v/%v revoke=%v/%v fp=%x/%v",
			deviceID, hasDevice, deviceRevision, hasDeviceRevision, deviceTrust, hasDeviceTrust,
			deviceRevocation, hasDeviceRevocation, fingerprint, hasFingerprint)
	}
	sessionID, hasSession := evidence.ActorSessionID()
	sessionRevision, hasSessionRevision := evidence.ActorSessionRevision()
	if !hasSession || sessionID != fixture.session.ID() || !hasSessionRevision ||
		sessionRevision != fixture.session.Version() {
		t.Fatalf("actor session evidence tuple mismatch: id=%s/%v rev=%v/%v",
			sessionID, hasSession, sessionRevision, hasSessionRevision)
	}
	bound := fixture.session.Binding().GrantRevisions()
	sealed := evidence.GrantRevisions()
	if len(bound) != len(sealed) || len(sealed) != 1 || sealed[0] != fixture.grant {
		t.Fatalf("grant revisions=%v, want %v", sealed, bound)
	}
	if evidence.ChannelBindingDigest() != fixture.channelBinding || evidence.Audience() != fixture.audience {
		t.Fatalf("ingress binding/audience not preserved: binding=%s audience=%s",
			evidence.ChannelBindingDigest(), evidence.Audience())
	}
	if evidence.AuditProvenance().SourceAuthorityID() != fixture.authority {
		t.Fatalf("audit provenance authority=%s, want %s",
			evidence.AuditProvenance().SourceAuthorityID(), fixture.authority)
	}
	if !evidence.VerifiedAt().Equal(fixture.verifiedAt) {
		t.Fatalf("verified at=%s, want %s", evidence.VerifiedAt(), fixture.verifiedAt)
	}
}

func TestProductionAuthenticatorSealsDeviceOnlyEvidence(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	resolver := &stubAuthenticationResolver{state: resolvedDeviceState(t, fixture)}
	authenticator := newProductionAuthenticator(t, resolver, fixture.audience)

	evidence, failure, err := authenticator.Authenticate(context.Background(), deviceIngress(t, fixture), testOperation, "req_authenticator_device")
	if err != nil || failure != nil || !evidence.Valid() {
		t.Fatalf("authenticate device ingress: evidence=%v failure=%v err=%v", evidence, failure, err)
	}
	if device, present := evidence.DeviceID(); !present || device != fixture.device.ID() {
		t.Fatalf("device evidence=%s present=%v, want %s", device, present, fixture.device.ID())
	}
	if fingerprint, present := evidence.CredentialFingerprint(); !present || fingerprint != fixture.spki {
		t.Fatalf("credential fingerprint=%x present=%v, want %x", fingerprint, present, fixture.spki)
	}
	if session, present := evidence.ActorSessionID(); present || !session.IsZero() {
		t.Fatalf("device evidence unexpectedly carries actor session %s", session)
	}
}

func TestProductionAuthenticatorForwardsLookupIdentity(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	resolver := &stubAuthenticationResolver{state: resolvedSessionState(t, fixture)}
	authenticator := newProductionAuthenticator(t, resolver, fixture.audience)

	if _, _, err := authenticator.Authenticate(context.Background(), sessionIngress(t, fixture), testOperation, "req_authenticator_lookup"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(resolver.lookups) != 1 {
		t.Fatalf("resolver lookups=%d, want 1", len(resolver.lookups))
	}
	lookup := resolver.lookups[0]
	if lookup.PrincipalID() != fixture.principal.ID() {
		t.Fatalf("lookup principal=%s, want %s", lookup.PrincipalID(), fixture.principal.ID())
	}
	deviceID, hasDevice := lookup.DeviceID()
	if !hasDevice || deviceID != fixture.device.ID() {
		t.Fatalf("lookup device=%s/%v, want %s", deviceID, hasDevice, fixture.device.ID())
	}
	if lookup.CredentialFingerprint() != fixture.spki {
		t.Fatalf("lookup fingerprint=%x, want %x", lookup.CredentialFingerprint(), fixture.spki)
	}
	sessionID, hasSession := lookup.ActorSessionID()
	if !hasSession || sessionID != fixture.session.ID() {
		t.Fatalf("lookup session=%s/%v, want %s", sessionID, hasSession, fixture.session.ID())
	}
	if lookup.RequiredAudience() != fixture.sessionAudience {
		t.Fatalf("lookup audience=%s, want %s", lookup.RequiredAudience(), fixture.sessionAudience)
	}
	if lookup.AuthorityEpoch() != fixture.epoch {
		t.Fatalf("lookup epoch=%s, want %s", lookup.AuthorityEpoch(), fixture.epoch)
	}
}

func TestProductionAuthenticatorMapsSafeAuthenticationRejections(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	requestID := "req_authenticator_rejection"
	deviceIngress := deviceIngress(t, fixture)
	sessionIngress := sessionIngress(t, fixture)

	for _, test := range []struct {
		name    string
		code    domain.ErrorCode
		ingress VerifiedIngress
		verify  func(*testing.T, *ErrorDTO)
	}{
		{
			name: "unauthenticated device credential", code: domain.ErrorCodeUnauthenticated, ingress: deviceIngress,
			verify: func(t *testing.T, failure *ErrorDTO) {
				t.Helper()
				if failure.Category != domain.ErrorCategoryAuthentication ||
					failure.Retryable || failure.Details.Recovery != RecoveryReauthenticate ||
					failure.Message == "" || failure.RequestID != requestID {
					t.Fatalf("unauthenticated failure=%v", failure)
				}
			},
		},
		{
			name: "expired session", code: domain.ErrorCodeSessionExpired, ingress: sessionIngress,
			verify: func(t *testing.T, failure *ErrorDTO) {
				t.Helper()
				if failure.Category != domain.ErrorCategoryAuthentication ||
					failure.Retryable || failure.Details.Recovery != RecoveryResumeSession {
					t.Fatalf("expired failure=%v", failure)
				}
			},
		},
		{
			name: "forbidden device", code: domain.ErrorCodeForbidden, ingress: deviceIngress,
			verify: func(t *testing.T, failure *ErrorDTO) {
				t.Helper()
				if failure.Category != domain.ErrorCategoryAuthorization ||
					failure.Details.DeniedCapability != testOperation ||
					failure.Details.ResourceScope == nil ||
					failure.Details.ResourceScope.Type != domain.AggregateKindDevice ||
					failure.Details.ResourceScope.ID != fixture.device.ID().String() {
					t.Fatalf("forbidden device failure=%v", failure)
				}
			},
		},
		{
			name: "capability required session", code: domain.ErrorCodeCapabilityRequired, ingress: sessionIngress,
			verify: func(t *testing.T, failure *ErrorDTO) {
				t.Helper()
				if failure.Category != domain.ErrorCategoryAuthorization ||
					failure.Details.DeniedCapability != testOperation ||
					failure.Details.ResourceScope == nil ||
					failure.Details.ResourceScope.Type != domain.AggregateKindActorSession ||
					failure.Details.ResourceScope.ID != fixture.session.ID().String() {
					t.Fatalf("capability session failure=%v", failure)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rejection, constructionErr := domain.NewCommandError(test.code, "rejected by the resolver", nil)
			if constructionErr != nil {
				t.Fatal(constructionErr)
			}
			resolver := &stubAuthenticationResolver{err: rejection}
			authenticator := newProductionAuthenticator(t, resolver, fixture.audience)
			evidence, failure, err := authenticator.Authenticate(context.Background(), test.ingress, testOperation, requestID)
			if err != nil || evidence.Valid() || failure == nil {
				t.Fatalf("authenticate evidence=%v failure=%v err=%v", evidence, failure, err)
			}
			if failure.Validate() != nil {
				t.Fatalf("mapped failure is not a valid contract: %v", failure)
			}
			test.verify(t, failure)
		})
	}

	t.Run("unknown code becomes internal", func(t *testing.T) {
		rejection, constructionErr := domain.NewCommandError(domain.ErrorCodeBackpressure, "capacity constrained", nil)
		if constructionErr != nil {
			t.Fatal(constructionErr)
		}
		resolver := &stubAuthenticationResolver{err: rejection}
		authenticator := newProductionAuthenticator(t, resolver, fixture.audience)
		evidence, failure, err := authenticator.Authenticate(context.Background(), deviceIngress, testOperation, requestID)
		if evidence.Valid() || failure != nil || err == nil {
			t.Fatalf("unknown rejection evidence=%v failure=%v err=%v, want internal error only", evidence, failure, err)
		}
	})
}

func TestProductionAuthenticatorForwardsInternalResolutionErrors(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	resolver := &stubAuthenticationResolver{err: errors.New("storage unavailable")}
	authenticator := newProductionAuthenticator(t, resolver, fixture.audience)
	evidence, failure, err := authenticator.Authenticate(context.Background(), deviceIngress(t, fixture), testOperation, "req_authenticator_internal")
	if evidence.Valid() || failure != nil || err == nil {
		t.Fatalf("internal error evidence=%v failure=%v err=%v, want error only", evidence, failure, err)
	}
}

func TestProductionAuthenticatorRejectsCanceledContext(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	resolver := &stubAuthenticationResolver{state: resolvedDeviceState(t, fixture)}
	authenticator := newProductionAuthenticator(t, resolver, fixture.audience)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	evidence, failure, err := authenticator.Authenticate(ctx, deviceIngress(t, fixture), testOperation, "req_authenticator_canceled")
	if evidence.Valid() || failure != nil || err == nil || len(resolver.lookups) != 0 {
		t.Fatalf("canceled authenticate evidence=%v failure=%v err=%v lookups=%d",
			evidence, failure, err, len(resolver.lookups))
	}
}

func TestNewVerifiedIngressRejectsIncompleteIdentity(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	deviceID := fixture.device.ID()
	sessionID := fixture.session.ID()
	valid := VerifiedIngressParams{
		PrincipalID: fixture.principal.ID(), DeviceID: &deviceID,
		CredentialFingerprint: fixture.spki, ActorSessionID: &sessionID,
		AuthorityEpoch: fixture.epoch, ChannelBinding: fixture.channelBinding,
	}
	zeroDevice := domain.DeviceID{}
	zeroSession := domain.ActorSessionID{}
	for _, test := range []struct {
		name string
		edit func(*VerifiedIngressParams)
	}{
		{name: "zero principal", edit: func(params *VerifiedIngressParams) { params.PrincipalID = domain.PrincipalID{} }},
		{name: "zero epoch", edit: func(params *VerifiedIngressParams) { params.AuthorityEpoch = domain.AuthorityEpoch{} }},
		{name: "zero channel binding", edit: func(params *VerifiedIngressParams) { params.ChannelBinding = ChannelBindingDigest{} }},
		{name: "zero device", edit: func(params *VerifiedIngressParams) { params.DeviceID = &zeroDevice }},
		{name: "device without fingerprint", edit: func(params *VerifiedIngressParams) { params.CredentialFingerprint = domain.CredentialDigest{} }},
		{name: "fingerprint without device", edit: func(params *VerifiedIngressParams) {
			params.DeviceID = nil
		}},
		{name: "zero session", edit: func(params *VerifiedIngressParams) { params.ActorSessionID = &zeroSession }},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := valid
			test.edit(&params)
			if _, err := NewVerifiedIngress(params); err == nil {
				t.Fatalf("NewVerifiedIngress(%+v) succeeded, want rejection", params)
			}
		})
	}
	if _, err := NewVerifiedIngress(valid); err != nil {
		t.Fatalf("NewVerifiedIngress(valid) rejected: %v", err)
	}
}

func TestNewProductionAuthenticatorRejectsMissingDependencies(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	if _, err := NewProductionAuthenticator(nil, fixture.audience); err == nil {
		t.Fatal("nil resolver accepted")
	}
	authenticator, err := NewProductionAuthenticator(&stubAuthenticationResolver{}, AuthenticationAudience{})
	if err == nil || authenticator != nil {
		t.Fatalf("empty audience accepted: authenticator=%v err=%v", authenticator, err)
	}
}
