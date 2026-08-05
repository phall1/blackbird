package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

func loadCommandReadSet(ctx context.Context, tx pgx.Tx, spec application.CommandSpec, admitted bool) ([]application.IdentityState, []domain.CeremonyChallenge, error) {
	plan := spec.Guards()
	targets := make(map[domain.AggregateTarget]struct{})
	expected := make(map[domain.AggregateTarget]domain.Version)
	if admitted {
		for _, group := range [][]domain.AggregateRef{plan.Authorization(), plan.References()} {
			for _, ref := range group {
				targets[ref.Target()] = struct{}{}
				expected[ref.Target()] = ref.Version()
			}
		}
		for _, mutation := range plan.Mutations() {
			if mutation.Kind() == domain.ExpectationExpectedVersion {
				targets[mutation.Target()] = struct{}{}
				expected[mutation.Target()], _ = mutation.Version()
			}
		}
	} else {
		for _, target := range plan.DisclosureTargets() {
			targets[target] = struct{}{}
		}
	}
	ordered := make([]domain.AggregateTarget, 0, len(targets))
	for target := range targets {
		ordered = append(ordered, target)
	}
	slices.SortFunc(ordered, func(a, b domain.AggregateTarget) int { return strings.Compare(a.String(), b.String()) })
	states := make([]application.IdentityState, 0, len(ordered))
	for _, target := range ordered {
		state, err := loadIdentityState(ctx, tx, target, true)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, commandReferenceConflict("declared command reference is absent")
		}
		if err != nil {
			return nil, nil, fmt.Errorf("load PostgreSQL %s: %w", target.String(), err)
		}
		if version, present := expected[target]; present && state.Version() != version {
			return nil, nil, commandReferenceConflict("declared command reference version changed")
		}
		states = append(states, state)
	}
	if admitted {
		for _, mutation := range plan.Mutations() {
			if mutation.Kind() != domain.ExpectationMustNotExist {
				continue
			}
			present, err := identityStateExists(ctx, tx, mutation.Target())
			if err != nil {
				return nil, nil, err
			}
			if present {
				return nil, nil, commandReferenceConflict("command create target already exists")
			}
		}
		for _, claim := range plan.Ceremonies() {
			if claim.Kind() == application.CeremonyReserveAbsent {
				var count int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM ceremony_challenges WHERE ceremony_id=$1", claim.ID().String()).Scan(&count); err != nil {
					return nil, nil, err
				}
				if count != 0 {
					return nil, nil, commandReferenceConflict("ceremony identifier already exists")
				}
			}
		}
	}
	var ceremonies []domain.CeremonyChallenge
	if admitted {
		for _, claim := range plan.Ceremonies() {
			if claim.Kind() != application.CeremonyConsumeStandalone {
				continue
			}
			challenge, err := loadCeremony(ctx, tx, claim.ID().String(), true)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil, commandReferenceConflict("ceremony is absent")
			}
			if err != nil {
				return nil, nil, err
			}
			ceremonies = append(ceremonies, challenge)
		}
	}
	return states, ceremonies, nil
}

func stateTable(kind domain.AggregateKind) (string, string, error) {
	switch kind {
	case domain.AggregateKindInvitation:
		return "installation_invitations", "invitation_id", nil
	case domain.AggregateKindPrincipal:
		return "principals", "principal_id", nil
	case domain.AggregateKindDevice:
		return "device_registrations", "device_id", nil
	case domain.AggregateKindGrant:
		return "grants", "grant_id", nil
	case domain.AggregateKindWorkspace:
		return "workspaces", "workspace_id", nil
	case domain.AggregateKindMembership:
		return "workspace_memberships", "membership_id", nil
	case domain.AggregateKindActor:
		return "actors", "actor_id", nil
	case domain.AggregateKindActorDelegation:
		return "actor_delegations", "delegation_id", nil
	case domain.AggregateKindActorSession:
		return "actor_sessions", "session_id", nil
	default:
		return "", "", application.ErrInvalidCommandContext
	}
}

func identityStateExists(ctx context.Context, tx pgx.Tx, target domain.AggregateTarget) (bool, error) {
	table, column, err := stateTable(target.Kind())
	if err != nil {
		return false, err
	}
	var present bool
	err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE "+column+"=$1)", target.ID()).Scan(&present)
	return present, err
}

func loadIdentityState(ctx context.Context, tx pgx.Tx, target domain.AggregateTarget, lock bool) (application.IdentityState, error) {
	var value any
	var err error
	suffix := ""
	if lock {
		suffix = " FOR SHARE"
	}
	switch target.Kind() {
	case domain.AggregateKindInvitation:
		value, err = loadInvitationState(ctx, tx, target.ID(), suffix)
	case domain.AggregateKindPrincipal:
		value, err = loadPrincipalState(ctx, tx, target.ID(), suffix)
	case domain.AggregateKindDevice:
		value, err = loadDeviceState(ctx, tx, target.ID(), suffix)
	case domain.AggregateKindGrant:
		value, err = loadGrantState(ctx, tx, target.ID(), suffix)
	case domain.AggregateKindWorkspace:
		value, err = loadWorkspaceState(ctx, tx, target.ID(), suffix)
	case domain.AggregateKindMembership:
		value, err = loadMembershipState(ctx, tx, target.ID(), suffix)
	case domain.AggregateKindActor:
		value, err = loadActorState(ctx, tx, target.ID(), suffix)
	case domain.AggregateKindActorDelegation:
		value, err = loadDelegationState(ctx, tx, target.ID(), suffix)
	case domain.AggregateKindActorSession:
		value, err = loadActorSessionState(ctx, tx, target.ID(), suffix)
	default:
		err = application.ErrInvalidCommandContext
	}
	if err != nil {
		return application.IdentityState{}, err
	}
	return application.NewIdentityState(value)
}

func loadInvitationState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.InstallationInvitationState, error) {
	var invitationID, installationID, key, generation, status string
	var verifier []byte
	var failures uint8
	var expires int64
	var version uint64
	err := tx.QueryRow(ctx, `SELECT invitation_id::text,installation_id::text,installation_public_key_reference,invitation_verifier,bootstrap_generation_id::text,status,failed_attempts,expires_at_us,version FROM installation_invitations WHERE invitation_id=$1`+suffix, id).Scan(&invitationID, &installationID, &key, &verifier, &generation, &status, &failures, &expires, &version)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	iid, err := domain.ParseInvitationID(invitationID)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	installation, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	public, err := domain.NewPublicKeyReference(key)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	bootstrap, err := domain.ParseBootstrapGenerationID(generation)
	if err != nil {
		return domain.InstallationInvitationState{}, err
	}
	if len(verifier) != sha256.Size {
		return domain.InstallationInvitationState{}, application.ErrInvalidCommandContext
	}
	var fp domain.CommandFingerprint
	copy(fp[:], verifier)
	return domain.RehydrateInstallationInvitation(domain.InstallationInvitationRehydrationParams{ID: iid, InstallationID: installation, InstallationPublicKey: public, InvitationVerifier: fp, BootstrapGenerationID: bootstrap, ExpiresAt: microsTime(expires), FailedAttempts: failures, Status: domain.InstallationInvitationStatus(status), Version: mustVersion(version)})
}

func loadPrincipalState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.PrincipalState, error) {
	var principalID, installationID, kind, display, status string
	var public sql.NullString
	var version uint64
	err := tx.QueryRow(ctx, `SELECT principal_id::text,installation_id::text,kind,display_name,public_key_reference,status,version FROM principals WHERE principal_id=$1`+suffix, id).Scan(&principalID, &installationID, &kind, &display, &public, &status, &version)
	if err != nil {
		return domain.PrincipalState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.PrincipalState{}, err
	}
	iid, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.PrincipalState{}, err
	}
	name, err := domain.NewDisplayName(display)
	if err != nil {
		return domain.PrincipalState{}, err
	}
	var key domain.PublicKeyReference
	if public.Valid {
		key, err = domain.NewPublicKeyReference(public.String)
		if err != nil {
			return domain.PrincipalState{}, err
		}
	}
	return domain.RehydratePrincipal(domain.PrincipalRehydrationParams{ID: pid, InstallationID: iid, Kind: domain.PrincipalKind(kind), DisplayName: name, PublicKeyReference: key, Status: domain.PrincipalStatus(status), Version: mustVersion(version)})
}

func decodeCapabilities(raw []byte) (domain.CapabilitySet, error) {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return domain.CapabilitySet{}, err
	}
	caps := make([]domain.Capability, len(values))
	for i, text := range values {
		value, err := domain.NewCapability(text)
		if err != nil {
			return domain.CapabilitySet{}, err
		}
		caps[i] = value
	}
	return domain.NewCapabilitySet(caps...)
}
func capabilitiesJSON(set domain.CapabilitySet) ([]byte, error) {
	values := set.Values()
	text := make([]string, len(values))
	for i := range values {
		text[i] = values[i].String()
	}
	return json.Marshal(text)
}

func loadGrantState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.GrantState, error) {
	var grantID, installationID, principalID, status string
	var workspace sql.NullString
	var capabilities []byte
	var version uint64
	err := tx.QueryRow(ctx, `SELECT grant_id::text,installation_id::text,workspace_id::text,principal_id::text,capabilities_json,status,version FROM grants WHERE grant_id=$1`+suffix, id).Scan(&grantID, &installationID, &workspace, &principalID, &capabilities, &status, &version)
	if err != nil {
		return domain.GrantState{}, err
	}
	gid, err := domain.ParseGrantID(grantID)
	if err != nil {
		return domain.GrantState{}, err
	}
	iid, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.GrantState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.GrantState{}, err
	}
	var wid domain.WorkspaceID
	if workspace.Valid {
		wid, err = domain.ParseWorkspaceID(workspace.String)
		if err != nil {
			return domain.GrantState{}, err
		}
	}
	set, err := decodeCapabilities(capabilities)
	if err != nil {
		return domain.GrantState{}, err
	}
	return domain.RehydrateGrant(domain.GrantRehydrationParams{ID: gid, InstallationID: iid, WorkspaceID: wid, PrincipalID: pid, Status: domain.GrantStatus(status), Version: mustVersion(version), Capabilities: set})
}

func loadWorkspaceState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.WorkspaceState, error) {
	var workspaceID, installationID, authorityID, epoch, aliasText, discoveryText, policyText, status string
	var version uint64
	err := tx.QueryRow(ctx, `SELECT workspace_id::text,installation_id::text,home_authority_id::text,authority_epoch::text,alias,discovery_locator,policy_revision,status,version FROM workspaces WHERE workspace_id=$1`+suffix, id).Scan(&workspaceID, &installationID, &authorityID, &epoch, &aliasText, &discoveryText, &policyText, &status, &version)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	iid, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	aid, err := domain.ParseAuthorityID(authorityID)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	authorityEpoch, err := domain.ParseAuthorityEpoch(epoch)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	alias, err := domain.NewWorkspaceAlias(aliasText)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	discovery, err := domain.NewDiscoveryLocator(discoveryText)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	policy, err := domain.NewPolicyRevision(policyText)
	if err != nil {
		return domain.WorkspaceState{}, err
	}
	return domain.RehydrateWorkspace(domain.WorkspaceRehydrationParams{ID: wid, InstallationID: iid, AuthorityID: aid, AuthorityEpoch: authorityEpoch, Alias: alias, DiscoveryLocator: discovery, PolicyRevision: policy, Status: domain.WorkspaceStatus(status), Version: mustVersion(version)})
}

func loadMembershipState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.MembershipState, error) {
	var membershipID, workspaceID, principalID, status string
	var capabilities []byte
	var version uint64
	err := tx.QueryRow(ctx, `SELECT membership_id::text,workspace_id::text,principal_id::text,capabilities_json,status,version FROM workspace_memberships WHERE membership_id=$1`+suffix, id).Scan(&membershipID, &workspaceID, &principalID, &capabilities, &status, &version)
	if err != nil {
		return domain.MembershipState{}, err
	}
	mid, err := domain.ParseMembershipID(membershipID)
	if err != nil {
		return domain.MembershipState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.MembershipState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.MembershipState{}, err
	}
	set, err := decodeCapabilities(capabilities)
	if err != nil {
		return domain.MembershipState{}, err
	}
	ceremony, err := loadOptionalCeremonyByOwner(ctx, tx, domain.CeremonyPurposeMembershipAcceptance, "membership_id", membershipID)
	if err != nil {
		return domain.MembershipState{}, err
	}
	return domain.RehydrateMembership(domain.MembershipRehydrationParams{ID: mid, WorkspaceID: wid, PrincipalID: pid, Status: domain.MembershipStatus(status), Version: mustVersion(version), Capabilities: set, AcceptanceChallenge: ceremony})
}

func loadActorState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.ActorState, error) {
	var actorID, workspaceID, kind, display, status string
	var version uint64
	err := tx.QueryRow(ctx, `SELECT actor_id::text,workspace_id::text,kind,display_name,status,version FROM actors WHERE actor_id=$1`+suffix, id).Scan(&actorID, &workspaceID, &kind, &display, &status, &version)
	if err != nil {
		return domain.ActorState{}, err
	}
	aid, err := domain.ParseActorID(actorID)
	if err != nil {
		return domain.ActorState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.ActorState{}, err
	}
	name, err := domain.NewDisplayName(display)
	if err != nil {
		return domain.ActorState{}, err
	}
	profile, err := domain.NewActorProfile(name)
	if err != nil {
		return domain.ActorState{}, err
	}
	return domain.RehydrateActor(domain.ActorRehydrationParams{ID: aid, WorkspaceID: wid, Kind: domain.ActorKind(kind), Profile: profile, Status: domain.ActorStatus(status), Version: mustVersion(version)})
}

func loadDelegationState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.ActorDelegationState, error) {
	var delegationID, workspaceID, principalID, actorID, membershipID, status string
	var capabilities []byte
	var version uint64
	err := tx.QueryRow(ctx, `SELECT delegation_id::text,workspace_id::text,principal_id::text,actor_id::text,membership_id::text,capabilities_json,status,version FROM actor_delegations WHERE delegation_id=$1`+suffix, id).Scan(&delegationID, &workspaceID, &principalID, &actorID, &membershipID, &capabilities, &status, &version)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	did, err := domain.ParseActorDelegationID(delegationID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	aid, err := domain.ParseActorID(actorID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	mid, err := domain.ParseMembershipID(membershipID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	set, err := decodeCapabilities(capabilities)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	ceremony, err := loadOptionalCeremonyByOwner(ctx, tx, domain.CeremonyPurposeDelegationActivation, "delegation_id", delegationID)
	if err != nil {
		return domain.ActorDelegationState{}, err
	}
	return domain.RehydrateActorDelegation(domain.ActorDelegationRehydrationParams{ID: did, WorkspaceID: wid, PrincipalID: pid, ActorID: aid, MembershipID: mid, Status: domain.DelegationStatus(status), Version: mustVersion(version), Capabilities: set, ActivationChallenge: ceremony})
}

func loadDeviceState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.DeviceState, error) {
	var deviceID, installationID, principalID, display, key, status string
	var algorithm, retiringAlgorithm, retiringKey sql.NullString
	var spki, transcript, retiringSPKI, retiringTranscript, rotationTranscript []byte
	var activatedAt, retiringExpires, rotatedAt, revokedAt sql.NullInt64
	var trust, revocation, version uint64
	err := tx.QueryRow(ctx, `SELECT device_id::text,installation_id::text,principal_id::text,display_name,credential_algorithm,public_key_reference,spki_fingerprint,transcript_fingerprint,trust_revision,revocation_revision,credential_activated_at_us,retiring_credential_algorithm,retiring_public_key_reference,retiring_spki_fingerprint,retiring_transcript_fingerprint,retiring_credential_expires_at_us,rotation_transcript_fingerprint,rotated_at_us,revoked_at_us,status,version FROM device_registrations WHERE device_id=$1`+suffix, id).Scan(&deviceID, &installationID, &principalID, &display, &algorithm, &key, &spki, &transcript, &trust, &revocation, &activatedAt, &retiringAlgorithm, &retiringKey, &retiringSPKI, &retiringTranscript, &retiringExpires, &rotationTranscript, &rotatedAt, &revokedAt, &status, &version)
	if err != nil {
		return domain.DeviceState{}, err
	}
	did, err := domain.ParseDeviceID(deviceID)
	if err != nil {
		return domain.DeviceState{}, err
	}
	iid, err := domain.ParseInstallationID(installationID)
	if err != nil {
		return domain.DeviceState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.DeviceState{}, err
	}
	name, err := domain.NewDisplayName(display)
	if err != nil {
		return domain.DeviceState{}, err
	}
	public, err := domain.NewPublicKeyReference(key)
	if err != nil {
		return domain.DeviceState{}, err
	}
	ceremony, err := loadOptionalCeremonyByOwner(ctx, tx, domain.CeremonyPurposeDevicePairing, "device_id", deviceID)
	if err != nil {
		return domain.DeviceState{}, err
	}
	credential, err := decodeDeviceCredential(algorithm, key, spki, transcript)
	if err != nil {
		return domain.DeviceState{}, err
	}
	retiring, err := decodeDeviceCredential(retiringAlgorithm, retiringKey.String, retiringSPKI, retiringTranscript)
	if err != nil {
		return domain.DeviceState{}, err
	}
	var rotation domain.CommandFingerprint
	if len(rotationTranscript) != 0 {
		if len(rotationTranscript) != sha256.Size {
			return domain.DeviceState{}, application.ErrInvalidCommandContext
		}
		copy(rotation[:], rotationTranscript)
	}
	return domain.RehydrateDevice(domain.DeviceRehydrationParams{ID: did, InstallationID: iid, PrincipalID: pid, DisplayName: name, PublicKeyReference: public, Status: domain.DeviceStatus(status), Version: mustVersion(version), TrustRevision: mustVersion(trust), RevocationRevision: mustVersion(revocation), PairingChallenge: ceremony, CredentialBinding: credential, CredentialActivatedAt: nullableMicrosTime(activatedAt), RetiringCredential: retiring, RetiringCredentialExpiresAt: nullableMicrosTime(retiringExpires), RotationTranscriptFingerprint: rotation, RotatedAt: nullableMicrosTime(rotatedAt), RevokedAt: nullableMicrosTime(revokedAt)})
}

func decodeDeviceCredential(algorithm sql.NullString, key string, spki, transcript []byte) (domain.DeviceCredentialBinding, error) {
	if !algorithm.Valid {
		if len(spki) != 0 || len(transcript) != 0 {
			return domain.DeviceCredentialBinding{}, application.ErrInvalidCommandContext
		}
		return domain.DeviceCredentialBinding{}, nil
	}
	if algorithm.String != domain.DeviceCredentialAlgorithm || len(spki) != sha256.Size || len(transcript) != sha256.Size {
		return domain.DeviceCredentialBinding{}, application.ErrInvalidCommandContext
	}
	public, err := domain.NewPublicKeyReference(key)
	if err != nil {
		return domain.DeviceCredentialBinding{}, err
	}
	var digestArray [sha256.Size]byte
	copy(digestArray[:], spki)
	digest, err := domain.NewCredentialDigest(digestArray)
	if err != nil {
		return domain.DeviceCredentialBinding{}, err
	}
	var fp domain.CommandFingerprint
	copy(fp[:], transcript)
	return domain.NewDeviceCredentialBinding(public, digest, fp)
}
func nullableMicrosTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return microsTime(value.Int64)
}

func loadCeremony(ctx context.Context, tx pgx.Tx, id string, lock bool) (domain.CeremonyChallenge, error) {
	return loadCeremonyWithStatus(ctx, tx, id, "", lock)
}
func loadOptionalCeremonyByOwner(ctx context.Context, tx pgx.Tx, purpose domain.CeremonyPurpose, column, id string) (domain.CeremonyChallenge, error) {
	var ceremonyID string
	err := tx.QueryRow(ctx, "SELECT ceremony_id::text FROM ceremony_challenges WHERE purpose=$1 AND "+column+"=$2", string(purpose), id).Scan(&ceremonyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.CeremonyChallenge{}, nil
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	return loadCeremony(ctx, tx, ceremonyID, false)
}
func loadCeremonyWithStatus(ctx context.Context, tx pgx.Tx, id string, historical domain.CeremonyStatus, lock bool) (domain.CeremonyChallenge, error) {
	var ceremonyID, purpose, status string
	var proof []byte
	var expires int64
	var installation, workspace, principal, membership, actor, delegation, device sql.NullString
	suffix := ""
	if lock {
		suffix = " FOR SHARE"
	}
	err := tx.QueryRow(ctx, `SELECT ceremony_id::text,purpose,proof_fingerprint,installation_id::text,workspace_id::text,principal_id::text,membership_id::text,actor_id::text,delegation_id::text,device_id::text,status,expires_at_us FROM ceremony_challenges WHERE ceremony_id=$1`+suffix, id).Scan(&ceremonyID, &purpose, &proof, &installation, &workspace, &principal, &membership, &actor, &delegation, &device, &status, &expires)
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if len(proof) != sha256.Size {
		return domain.CeremonyChallenge{}, application.ErrInvalidCommandContext
	}
	params := domain.CeremonyChallengeRehydrationParams{Purpose: domain.CeremonyPurpose(purpose), Status: domain.CeremonyStatus(status), ExpiresAt: microsTime(expires)}
	if historical != "" {
		params.Status = historical
	}
	params.ID, err = domain.ParseCeremonyID(ceremonyID)
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	copy(params.ProofDigest[:], proof)
	if installation.Valid {
		params.InstallationID, err = domain.ParseInstallationID(installation.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if workspace.Valid {
		params.WorkspaceID, err = domain.ParseWorkspaceID(workspace.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if principal.Valid {
		params.PrincipalID, err = domain.ParsePrincipalID(principal.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if membership.Valid {
		params.MembershipID, err = domain.ParseMembershipID(membership.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if actor.Valid {
		params.ActorID, err = domain.ParseActorID(actor.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if delegation.Valid {
		params.DelegationID, err = domain.ParseActorDelegationID(delegation.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	if device.Valid {
		params.DeviceID, err = domain.ParseDeviceID(device.String)
	}
	if err != nil {
		return domain.CeremonyChallenge{}, err
	}
	return domain.RehydrateCeremonyChallenge(params)
}

func loadActorSessionState(ctx context.Context, tx pgx.Tx, id, suffix string) (domain.ActorSessionState, error) {
	var sessionID, authorityID, epoch, workspaceID, principalID, actorID, delegationID, membershipID string
	var clientID, clientName, clientVersion, policyText, assuranceText, credentialRef, credentialAudience, status string
	var capabilities, credentialDigest []byte
	var deviceID sql.NullString
	var delegationVersion, membershipVersion, version uint64
	var deviceVersion, deviceTrust sql.NullInt64
	var credentialVersion uint16
	var issued, expires int64
	err := tx.QueryRow(ctx, `SELECT session_id::text,authority_id::text,authority_epoch::text,workspace_id::text,
		principal_id::text,actor_id::text,delegation_id::text,delegation_version,membership_id::text,membership_version,
		device_id::text,device_version,device_trust_revision,client_instance_id::text,client_name,client_version,
		capabilities_json,policy_revision,assurance_class,presentation_credential_reference,presentation_credential_digest,
		presentation_credential_audience,presentation_credential_version,status,issued_at_us,expires_at_us,version
		FROM actor_sessions WHERE session_id=$1`+suffix, id).Scan(&sessionID, &authorityID, &epoch, &workspaceID,
		&principalID, &actorID, &delegationID, &delegationVersion, &membershipID, &membershipVersion, &deviceID,
		&deviceVersion, &deviceTrust, &clientID, &clientName, &clientVersion, &capabilities, &policyText, &assuranceText,
		&credentialRef, &credentialDigest, &credentialAudience, &credentialVersion, &status, &issued, &expires, &version)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	sid, err := domain.ParseActorSessionID(sessionID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	authority, err := domain.ParseAuthorityID(authorityID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	authorityEpoch, err := domain.ParseAuthorityEpoch(epoch)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	wid, err := domain.ParseWorkspaceID(workspaceID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	pid, err := domain.ParsePrincipalID(principalID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	aid, err := domain.ParseActorID(actorID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	did, err := domain.ParseActorDelegationID(delegationID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	mid, err := domain.ParseMembershipID(membershipID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	delegationRef, err := domain.NewAggregateRef(did, mustVersion(delegationVersion))
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	membershipRef, err := domain.NewAggregateRef(mid, mustVersion(membershipVersion))
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	var deviceRef *domain.AggregateRef
	var trust domain.Version
	if deviceID.Valid {
		parsed, parseErr := domain.ParseDeviceID(deviceID.String)
		if parseErr != nil {
			return domain.ActorSessionState{}, parseErr
		}
		ref, refErr := domain.NewAggregateRef(parsed, mustVersion(uint64(deviceVersion.Int64)))
		if refErr != nil {
			return domain.ActorSessionState{}, refErr
		}
		deviceRef, trust = &ref, mustVersion(uint64(deviceTrust.Int64))
	}
	rows, err := tx.Query(ctx, `SELECT grant_id::text,grant_version FROM actor_session_grant_revisions WHERE session_id=$1 ORDER BY grant_id FOR SHARE`, sessionID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	defer rows.Close()
	var grants []domain.AggregateRef
	for rows.Next() {
		var grantID string
		var grantVersion uint64
		if err := rows.Scan(&grantID, &grantVersion); err != nil {
			return domain.ActorSessionState{}, err
		}
		gid, err := domain.ParseGrantID(grantID)
		if err != nil {
			return domain.ActorSessionState{}, err
		}
		ref, err := domain.NewAggregateRef(gid, mustVersion(grantVersion))
		if err != nil {
			return domain.ActorSessionState{}, err
		}
		grants = append(grants, ref)
	}
	if err := rows.Err(); err != nil {
		return domain.ActorSessionState{}, err
	}
	policy, err := domain.NewPolicyRevision(policyText)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	assurance, err := domain.NewAssuranceClass(assuranceText)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	binding, err := domain.NewSessionBinding(authority, authorityEpoch, wid, pid, aid, membershipRef, delegationRef, deviceRef, trust, grants, policy, assurance, microsTime(issued), microsTime(expires))
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	cid, err := domain.ParseClientInstanceID(clientID)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	metadata, err := domain.NewClientMetadata(clientName, clientVersion)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	set, err := decodeCapabilities(capabilities)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	if len(credentialDigest) != sha256.Size {
		return domain.ActorSessionState{}, application.ErrInvalidCommandContext
	}
	var digestArray [sha256.Size]byte
	copy(digestArray[:], credentialDigest)
	digest, err := domain.NewCredentialDigest(digestArray)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	reference, err := domain.NewCredentialReference(credentialRef)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	audience, err := domain.NewCredentialAudience(credentialAudience)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	presentation, err := domain.NewPresentationCredentialBinding(digest, reference, audience, credentialVersion)
	if err != nil {
		return domain.ActorSessionState{}, err
	}
	return domain.RehydrateActorSession(domain.ActorSessionRehydrationParams{ID: sid, ClientInstanceID: cid, ClientMetadata: metadata,
		Status: domain.ActorSessionStatus(status), Version: mustVersion(version), Binding: binding, Capabilities: set, PresentationCredential: presentation})
}
