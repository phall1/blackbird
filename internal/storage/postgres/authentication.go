package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

// ResolveAuthentication atomically verifies a transport identity lookup against
// durable store state in a single repeatable-read transaction.
func (store *Store) ResolveAuthentication(ctx context.Context, lookup application.AuthenticationLookup) (application.AuthenticationState, error) {
	if err := ctx.Err(); err != nil {
		return application.AuthenticationState{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return application.AuthenticationState{}, fmt.Errorf("begin PostgreSQL authentication resolution: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	return resolveAuthenticationState(ctx, tx, lookup)
}

func resolveAuthenticationState(ctx context.Context, tx pgx.Tx, lookup application.AuthenticationLookup) (application.AuthenticationState, error) {
	var serverMicros int64
	if err := tx.QueryRow(ctx, `SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint`).Scan(&serverMicros); err != nil {
		return application.AuthenticationState{}, fmt.Errorf("read PostgreSQL authentication server time: %w", err)
	}
	verifiedAt := microsTime(serverMicros)

	principal, err := loadPrincipalState(ctx, tx, lookup.PrincipalID().String(), "")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "principal is not registered")
		}
		return application.AuthenticationState{}, fmt.Errorf("read PostgreSQL authentication principal: %w", err)
	}
	if principal.Status() != domain.PrincipalActive {
		return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "principal is not active")
	}

	var device *domain.DeviceState
	if deviceID, hasDevice := lookup.DeviceID(); hasDevice {
		loaded, loadErr := loadDeviceState(ctx, tx, deviceID.String(), "")
		if loadErr != nil {
			if errors.Is(loadErr, pgx.ErrNoRows) {
				return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "device is not registered")
			}
			return application.AuthenticationState{}, fmt.Errorf("read PostgreSQL authentication device: %w", loadErr)
		}
		if loaded.PrincipalID() != principal.ID() {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "device does not belong to the principal")
		}
		if loaded.Status() != domain.DeviceTrusted {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeForbidden, "device is not trusted")
		}
		if !loaded.AcceptsCredential(lookup.CredentialFingerprint(), verifiedAt) {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "device credential was rejected")
		}
		device = &loaded
	}

	var session *domain.ActorSessionState
	if sessionID, hasSession := lookup.ActorSessionID(); hasSession {
		loaded, loadErr := loadActorSessionState(ctx, tx, sessionID.String(), "")
		if loadErr != nil {
			if errors.Is(loadErr, pgx.ErrNoRows) {
				return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "actor session is not registered")
			}
			return application.AuthenticationState{}, fmt.Errorf("read PostgreSQL authentication actor session: %w", loadErr)
		}
		binding := loaded.Binding()
		if binding.PrincipalID() != principal.ID() {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "actor session does not belong to the principal")
		}
		if binding.AuthorityEpoch() != lookup.AuthorityEpoch() {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "actor session authority epoch does not match")
		}
		if loaded.Status() != domain.ActorSessionActive {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeUnauthenticated, "actor session is not active")
		}
		if !verifiedAt.Before(binding.AbsoluteExpiry()) {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeSessionExpired, "actor session has expired")
		}
		if loaded.PresentationCredential().Audience() != lookup.RequiredAudience() {
			return application.AuthenticationState{}, queryError(domain.ErrorCodeForbidden, "presentation audience does not match the ingress audience")
		}
		for _, grant := range binding.GrantRevisions() {
			if currencyErr := verifyGrantCurrency(ctx, tx, grant, verifiedAt); currencyErr != nil {
				return application.AuthenticationState{}, currencyErr
			}
		}
		session = &loaded
	}

	var sourceAuthority domain.AuthorityID
	if session != nil {
		sourceAuthority = session.Binding().AuthorityID()
	} else {
		authority, authorityErr := loadInstallationAuthority(ctx, tx, principal.InstallationID(), lookup.AuthorityEpoch())
		if authorityErr != nil {
			return application.AuthenticationState{}, authorityErr
		}
		sourceAuthority = authority
	}

	state, stateErr := application.NewAuthenticationState(application.AuthenticationStateParams{
		Principal: principal, Device: device, ActorSession: session,
		SourceAuthorityID: sourceAuthority, VerifiedAt: verifiedAt,
	})
	if stateErr != nil {
		return application.AuthenticationState{}, stateErr
	}
	return state, nil
}

func verifyGrantCurrency(ctx context.Context, tx pgx.Tx, bound domain.AggregateRef, verifiedAt time.Time) error {
	var status string
	var current uint64
	var expires *int64
	err := tx.QueryRow(ctx, `SELECT status, version, expires_at_us FROM grants WHERE grant_id = $1`,
		bound.Target().ID()).Scan(&status, &current, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return queryError(domain.ErrorCodeForbidden, "grant authorization is no longer current")
	}
	if err != nil {
		return fmt.Errorf("read PostgreSQL authentication grant revision: %w", err)
	}
	if status != "active" || current != bound.Version().Uint64() ||
		expires != nil && *expires <= timeMicros(verifiedAt) {
		return queryError(domain.ErrorCodeForbidden, "grant authorization is no longer current")
	}
	return nil
}

func loadInstallationAuthority(ctx context.Context, tx pgx.Tx, installation domain.InstallationID,
	epoch domain.AuthorityEpoch) (domain.AuthorityID, error) {
	var authorityText string
	err := tx.QueryRow(ctx, `SELECT authority_id::text FROM authority_streams
		WHERE scope_kind = 'installation' AND scope_id = $1 AND authority_epoch = $2`,
		installation.String(), epoch.String()).Scan(&authorityText)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AuthorityID{}, queryError(domain.ErrorCodeUnauthenticated, "installation authority epoch is not current")
	}
	if err != nil {
		return domain.AuthorityID{}, fmt.Errorf("read PostgreSQL authentication installation authority: %w", err)
	}
	authority, authorityErr := domain.ParseAuthorityID(authorityText)
	if authorityErr != nil {
		return domain.AuthorityID{}, application.ErrInvalidQuery
	}
	return authority, nil
}
