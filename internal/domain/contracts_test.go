package domain

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func mustVersion(t *testing.T, value uint64) Version {
	t.Helper()
	version, err := NewVersion(value)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestAggregateExpectationsSeparateCreateFromUpdate(t *testing.T) {
	workspace, _ := ParseWorkspaceID(validUUIDV7)
	absent, err := ExpectAggregateAbsent(workspace)
	if err != nil || absent.Kind() != ExpectationMustNotExist {
		t.Fatalf("absent = %#v, %v", absent, err)
	}
	if _, hasVersion := absent.Version(); hasVersion {
		t.Fatal("create-nonexistence unexpectedly carries a version")
	}
	expected, err := ExpectAggregateVersion(workspace, mustVersion(t, 9))
	if err != nil || expected.Kind() != ExpectationExpectedVersion {
		t.Fatalf("expected = %#v, %v", expected, err)
	}
	if version, ok := expected.Version(); !ok || version.Uint64() != 9 {
		t.Fatalf("version = %v, %v", version, ok)
	}
}

func TestCanonicalIdempotencyScopeHasExactAuthorityIndependentIdentity(t *testing.T) {
	workspace, _ := ParseWorkspaceID(validUUIDV7)
	principal, _ := ParsePrincipalID(validUUIDV7)
	client, _ := ParseClientInstanceID(validUUIDV7)
	operation, _ := NewOperationName("session.start")
	key, _ := NewIdempotencyKey("retry-1")

	scope, err := NewIdempotencyScope(workspace, principal, client, operation, key)
	if err != nil {
		t.Fatal(err)
	}
	if scope.WorkspaceID() != workspace || scope.PrincipalID() != principal ||
		scope.ClientInstanceID() != client || scope.Operation() != operation || scope.Key() != key {
		t.Fatalf("scope lost identity: %#v", scope)
	}

	typeOfScope := reflect.TypeFor[IdempotencyScope]()
	fields := map[string]bool{}
	for index := range typeOfScope.NumField() {
		fields[typeOfScope.Field(index).Name] = true
	}
	for _, forbidden := range []string{"authority", "authorityID", "epoch", "authorityEpoch"} {
		if fields[forbidden] {
			t.Fatalf("idempotency uniqueness unexpectedly contains %q", forbidden)
		}
	}
}

func TestProvisioningScopeIsSeparateAndPurposeBound(t *testing.T) {
	installation, _ := ParseInstallationID(validUUIDV7)
	authorityScope, _ := InstallationScope(installation)
	operation, _ := NewOperationName("installation.bootstrap.v1")
	key, _ := NewIdempotencyKey("bootstrap-1")
	fingerprint := FingerprintCommand([]byte("signed transcript"))
	scope, err := NewProvisioningIdempotencyScope(authorityScope, fingerprint, operation, key)
	if err != nil || scope.TranscriptFingerprint() != fingerprint {
		t.Fatalf("scope = %#v, %v", scope, err)
	}
	if _, err := NewProvisioningIdempotencyScope(authorityScope, CommandFingerprint{}, operation, key); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("zero transcript error = %v", err)
	}
	workspace, _ := ParseWorkspaceID("01b8e094-9888-7000-8000-000000000002")
	workspaceScope, _ := WorkspaceScope(workspace)
	if _, err := NewProvisioningIdempotencyScope(workspaceScope, fingerprint, operation, key); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("workspace bootstrap scope error = %v", err)
	}
}

func TestCatalogedAtomicCommitSets(t *testing.T) {
	principal, _ := ParsePrincipalID(validUUIDV7)
	device, _ := ParseDeviceID("01b8e094-9888-7000-8000-000000000002")
	grant, _ := ParseGrantID("01b8e094-9888-7000-8000-000000000003")
	invitation, _ := ParseInvitationID("01b8e094-9888-7000-8000-000000000004")
	bootstrap, err := BootstrapInstallationCommitSet(principal, device, grant, invitation, InitialVersion())
	if err != nil || bootstrap.Kind() != CommitSetBootstrapInstallation || len(bootstrap.Expectations()) != 4 {
		t.Fatalf("bootstrap = %#v, %v", bootstrap, err)
	}
	expectations := bootstrap.Expectations()
	expectations[0] = AggregateExpectation{}
	if bootstrap.Expectations()[0].Target().IsZero() {
		t.Fatal("commit-set expectations leaked mutable slice storage")
	}

	workspace, _ := ParseWorkspaceID("01b8e094-9888-7000-8000-000000000005")
	membership, _ := ParseMembershipID("01b8e094-9888-7000-8000-000000000006")
	created, err := CreateWorkspaceOwnerCommitSet(workspace, membership, principal, InitialVersion())
	if err != nil || created.Kind() != CommitSetCreateWorkspaceOwner || len(created.Expectations()) != 3 {
		t.Fatalf("workspace commit = %#v, %v", created, err)
	}
}

func TestSessionBindingCapturesExactSecuritySnapshot(t *testing.T) {
	authority, _ := ParseAuthorityID(validUUIDV7)
	epoch, _ := ParseAuthorityEpoch("01b8e094-9888-7000-8000-000000000002")
	workspace, _ := ParseWorkspaceID("01b8e094-9888-7000-8000-000000000003")
	principal, _ := ParsePrincipalID("01b8e094-9888-7000-8000-000000000004")
	actor, _ := ParseActorID("01b8e094-9888-7000-8000-000000000005")
	membership, _ := ParseMembershipID("01b8e094-9888-7000-8000-000000000006")
	delegation, _ := ParseActorDelegationID("01b8e094-9888-7000-8000-000000000007")
	device, _ := ParseDeviceID("01b8e094-9888-7000-8000-000000000008")
	grant, _ := ParseGrantID("01b8e094-9888-7000-8000-000000000009")
	grantTwo, _ := ParseGrantID("01b8e094-9888-7000-8000-00000000000a")
	membershipRef, _ := NewAggregateRef(membership, mustVersion(t, 4))
	delegationRef, _ := NewAggregateRef(delegation, mustVersion(t, 5))
	deviceRef, _ := NewAggregateRef(device, mustVersion(t, 6))
	grantRef, _ := NewAggregateRef(grant, mustVersion(t, 7))
	grantTwoRef, _ := NewAggregateRef(grantTwo, mustVersion(t, 8))
	policy, _ := NewPolicyRevision("organization-policy:sha256:abc")
	assurance, _ := NewAssuranceClass("strong-factor")
	issuedAt := time.Date(2026, 8, 4, 12, 0, 0, 0, time.FixedZone("source", -4*60*60))
	expiresAt := issuedAt.Add(8 * time.Hour)
	grants := []AggregateRef{grantRef}

	binding, err := NewSessionBinding(
		authority, epoch, workspace, principal, actor,
		membershipRef, delegationRef, &deviceRef, mustVersion(t, 8), grants,
		policy, assurance, issuedAt, expiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	grants[0] = AggregateRef{}
	if binding.AuthorityID() != authority || !binding.AuthorityEpoch().Equal(epoch) ||
		binding.PolicyRevision() != policy || binding.AssuranceClass() != assurance ||
		binding.IssuedAt().Location() != time.UTC || binding.AbsoluteExpiry().Location() != time.UTC ||
		binding.GrantRevisions()[0] != grantRef {
		t.Fatalf("incomplete or mutable binding: %#v", binding)
	}

	if _, err := NewSessionBinding(
		authority, epoch, workspace, principal, actor,
		membershipRef, delegationRef, nil, Version{}, []AggregateRef{grantRef, grantRef},
		policy, assurance, issuedAt, expiresAt,
	); !errors.Is(err, ErrInvalidSessionBinding) {
		t.Fatalf("duplicate grant error = %v", err)
	}
	if _, err := NewSessionBinding(
		authority, epoch, workspace, principal, actor,
		membershipRef, delegationRef, nil, Version{}, nil,
		policy, assurance, expiresAt, issuedAt,
	); !errors.Is(err, ErrInvalidSessionBinding) {
		t.Fatalf("invalid lifetime error = %v", err)
	}
	if _, err := NewSessionBinding(
		authority, epoch, workspace, principal, actor,
		membershipRef, delegationRef, nil, Version{}, nil,
		policy, assurance, issuedAt, issuedAt.Add(MaxActorSessionLifetime),
	); err != nil {
		t.Fatalf("exact maximum lifetime error = %v", err)
	}
	if _, err := NewSessionBinding(
		authority, epoch, workspace, principal, actor,
		membershipRef, delegationRef, nil, Version{}, nil,
		policy, assurance, issuedAt, issuedAt.Add(MaxActorSessionLifetime+time.Nanosecond),
	); !errors.Is(err, ErrInvalidSessionBinding) {
		t.Fatalf("over maximum lifetime error = %v", err)
	}
	ordered, err := NewSessionBinding(
		authority, epoch, workspace, principal, actor,
		membershipRef, delegationRef, nil, Version{}, []AggregateRef{grantTwoRef, grantRef},
		policy, assurance, issuedAt, expiresAt,
	)
	if err != nil || ordered.GrantRevisions()[0] != grantRef || ordered.GrantRevisions()[1] != grantTwoRef {
		t.Fatalf("grant revisions are not canonical: %#v, %v", ordered.GrantRevisions(), err)
	}
	tooMany := make([]AggregateRef, MaxSessionGrantRevisions+1)
	for index := range tooMany {
		grantID, parseErr := ParseGrantID(identityUUID(1000 + index))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		tooMany[index], parseErr = NewAggregateRef(grantID, InitialVersion())
		if parseErr != nil {
			t.Fatal(parseErr)
		}
	}
	if _, err := NewSessionBinding(
		authority, epoch, workspace, principal, actor,
		membershipRef, delegationRef, nil, Version{}, tooMany,
		policy, assurance, issuedAt, expiresAt,
	); !errors.Is(err, ErrInvalidSessionBinding) {
		t.Fatalf("unbounded grants error = %v", err)
	}
}
