package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/integration/localsecurity"
	"github.com/phall1/blackbird/internal/transport/contracts"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
	mcptransport "github.com/phall1/blackbird/internal/transport/mcp"
)

const (
	productionAudience   = "blackbird.local"
	productionPolicy     = "blackbird-local-v1"
	recoveryCapsuleKeyID = "blackbird-local-recovery-v1"
	recoveryCredentialID = "recovery-signing-key"
	productionAssurance  = "local-credential"
)

type productionStore interface {
	Storage
	application.UnitOfWork
	application.QueryStore
	application.AuthenticationStateResolver
}

// NewProductionDaemon constructs the complete source-built daemon. Test-only
// lifecycle seams remain on NewDaemon; callers of this constructor always get
// durable stores and the real application, authentication, and transport graph.
func NewProductionDaemon(build BuildInfo, config Config) (*Daemon, error) {
	if config.Storage == StorageSQLite {
		path, err := filepath.Abs(config.SQLitePath)
		if err != nil {
			return nil, fmt.Errorf("resolve SQLite path: %w", err)
		}
		config.SQLitePath = filepath.Clean(path)
	}
	return NewDaemon(build, config, Dependencies{Compose: composeProduction})
}

func composeProduction(_ context.Context, storage Storage) (HandlerBundle, error) {
	store, ok := storage.(productionStore)
	if !ok {
		return HandlerBundle{}, errors.New("production storage does not implement the application ports")
	}

	checkpointIDs := productionCheckpointIDs{}
	queries, err := application.NewQueryService(store, checkpointIDs)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose query service: %w", err)
	}

	vault := localsecurity.NewOSCredentialVault()
	recoveryReference, err := localsecurity.InstallationCredentialReference(recoveryCredentialID)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose recovery credential: %w", err)
	}
	recoveryReferences := map[string]localsecurity.CredentialReference{recoveryCapsuleKeyID: recoveryReference}
	authenticationRegistry := localsecurity.NewAuthenticationRegistry()
	policyRegistry := localsecurity.NewPolicyRegistry()
	assurance, err := domain.NewAssuranceClass(productionAssurance)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose assurance class: %w", err)
	}
	security, err := localsecurity.NewProductionOrchestrationAdapters(
		vault, recoveryReferences, authenticationRegistry, policyRegistry, assurance, domain.MaxActorSessionLifetime,
	)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose local security: %w", err)
	}

	proofKeys, err := localsecurity.NewProofPublicKeyRegistry(vault, nil, nil)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose proof keys: %w", err)
	}
	proofs, err := localsecurity.NewCryptographicProofVerifier(
		localsecurity.NewPairingInvitationRegistry(rand.Reader, time.Now),
		proofKeys,
		localsecurity.NewProofChallengeRegistry(time.Now),
	)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose proof verifier: %w", err)
	}

	policies, err := newProductionPolicies(policyRegistry)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose policy source: %w", err)
	}
	orchestration, err := application.NewOrchestrationService(application.OrchestrationDependencies{
		UnitOfWork:          store,
		Authentication:      registeringAuthentication{registry: authenticationRegistry, next: security.Authentication},
		Policy:              security.Policy,
		LockedAuthorization: security.LockedAuthorization,
		ReplayDisclosure:    security.ReplayDisclosure,
		DenialPolicy:        security.DenialPolicy,
		SignerLookup:        security.SignerLookup,
		EffectPlanner:       security.EffectPlanner,
		BootstrapProofs:     proofs,
		CeremonyProofs:      proofs,
		PairingRedemptions:  proofs,
		Presentations:       security.Presentations,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose orchestration service: %w", err)
	}
	assembler, err := contracts.NewW0CommandAssembler(policies)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose command assembler: %w", err)
	}
	applicationHandler, err := contracts.NewApplicationHandler(
		queries, orchestration, assembler, security.SignerLookup, recoveryCapsuleKeyID, time.Now,
	)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose application handler: %w", err)
	}
	handler := productionW0Handler{ApplicationHandler: applicationHandler}

	audience, err := contracts.NewAuthenticationAudience(productionAudience)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose authentication audience: %w", err)
	}
	authenticator, err := contracts.NewProductionAuthenticator(store, audience)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose authenticator: %w", err)
	}
	ingress := productionIngressAuthenticator{authenticator: authenticator}
	httpHandler, err := httptransport.NewHandler(httptransport.Dependencies{
		Authenticator:         httpIngressAuthenticator{ingress},
		InstallationBootstrap: handler, PrincipalRegister: handler,
		DevicePairingBegin: handler, DevicePair: handler, WorkspaceCreate: handler,
		WorkspaceMemberInvite: handler, WorkspaceMembershipAccept: handler,
		ActorCreate: handler, ActorDelegationPropose: handler, ActorDelegationActivate: handler,
		SessionStart: handler, WorkRefObserve: handler, ObjectiveAndWorkCreate: handler,
		ObjectiveActivate: handler, RunPlanWithBindings: handler, RunJoin: handler, RunStart: handler,
		ContextGet: handler, EventsSync: handler,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose HTTP transport: %w", err)
	}
	coordination := localCoordinationStore(storage)
	localHTTPHandler, err := httptransport.NewLocalHandler(httptransport.LocalDependencies{Coordination: coordination})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose local HTTP transport: %w", err)
	}
	httpMux := http.NewServeMux()
	httpMux.Handle("/api/v1/local/", localHTTPHandler)
	httpMux.Handle("/", httpHandler)
	mcpServer, err := mcptransport.NewServer(mcptransport.Dependencies{
		Authenticator: mcpIngressAuthenticator{ingress}, CurrentSession: productionCurrentSession{},
		Coordination:          coordination,
		InstallationBootstrap: handler, PrincipalRegister: handler,
		DevicePairingBegin: handler, DevicePair: handler, WorkspaceCreate: handler,
		WorkspaceMemberInvite: handler, WorkspaceMembershipAccept: handler,
		ActorCreate: handler, ActorDelegationPropose: handler, ActorDelegationActivate: handler,
		SessionStart: handler, WorkRefObserve: handler, ObjectiveAndWorkCreate: handler,
		ObjectiveActivate: handler, RunPlanWithBindings: handler, RunJoin: handler, RunStart: handler,
		ContextGet: handler, EventsSync: handler,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose MCP transport: %w", err)
	}
	return HandlerBundle{HTTP: httpMux, MCP: mcpServer.HTTPHandler(nil)}, nil
}

func localCoordinationStore(storage Storage) application.LocalCoordinationStore {
	store, _ := storage.(application.LocalCoordinationStore)
	return store
}

type productionCheckpointIDs struct{}

func (productionCheckpointIDs) NewCheckpointID() (application.CheckpointID, error) {
	id, err := domain.NewCeremonyID()
	if err != nil {
		return application.CheckpointID{}, err
	}
	return application.NewCheckpointID(id.String())
}

type productionPolicies struct {
	mu       sync.Mutex
	registry *localsecurity.PolicyRegistry
	revision domain.PolicyRevision
	digest   application.Digest
}

func newProductionPolicies(registry *localsecurity.PolicyRegistry) (*productionPolicies, error) {
	revision, err := domain.NewPolicyRevision(productionPolicy)
	if err != nil {
		return nil, err
	}
	return &productionPolicies{
		registry: registry,
		revision: revision,
		digest:   application.Digest(sha256.Sum256([]byte("blackbird-policy/v1\x00" + productionPolicy))),
	}, nil
}

func (policies *productionPolicies) CurrentPolicy(scope domain.AuthorityScope) (domain.PolicyRevision, application.Digest, error) {
	if policies == nil || policies.registry == nil || scope.IsZero() {
		return domain.PolicyRevision{}, application.Digest{}, application.ErrInvalidApplicationContract
	}
	policies.mu.Lock()
	defer policies.mu.Unlock()
	if err := policies.registry.Register(scope, policies.revision, policies.digest); err != nil {
		return domain.PolicyRevision{}, application.Digest{}, err
	}
	return policies.revision, policies.digest, nil
}

type registeringAuthentication struct {
	registry *localsecurity.AuthenticationRegistry
	next     application.AuthenticationPreparer
}

func (authentication registeringAuthentication) PrepareAuthentication(
	ctx context.Context,
	request application.AuthenticationRequest,
) (application.AuthenticationDecision, error) {
	if authentication.registry == nil || authentication.next == nil {
		return application.AuthenticationDecision{}, application.ErrInvalidApplicationContract
	}
	if err := authentication.registry.Register(request); err != nil {
		return application.AuthenticationDecision{}, err
	}
	defer func() { _ = authentication.registry.Revoke(request) }()
	return authentication.next.PrepareAuthentication(ctx, request)
}

type verifiedIngressContextKey struct{}

type productionIngressAuthenticator struct {
	authenticator *contracts.ProductionAuthenticator
}

func (auth productionIngressAuthenticator) authenticate(
	ctx context.Context,
	operation string,
	requestID string,
) (contracts.AuthenticationEvidence, *contracts.ErrorDTO, error) {
	ingress, ok := ctx.Value(verifiedIngressContextKey{}).(contracts.VerifiedIngress)
	if !ok || !ingress.Valid() {
		failure := unauthenticated(requestID)
		return contracts.AuthenticationEvidence{}, &failure, nil
	}
	return auth.authenticator.Authenticate(ctx, ingress, operation, requestID)
}

type httpIngressAuthenticator struct{ productionIngressAuthenticator }

func (auth httpIngressAuthenticator) Authenticate(
	ctx context.Context,
	_ *http.Request,
	operation string,
	requestID string,
) (contracts.AuthenticationEvidence, *contracts.ErrorDTO, error) {
	return auth.authenticate(ctx, operation, requestID)
}

type mcpIngressAuthenticator struct{ productionIngressAuthenticator }

func (auth mcpIngressAuthenticator) Authenticate(
	ctx context.Context,
	operation string,
	requestID string,
) (contracts.AuthenticationEvidence, *contracts.ErrorDTO, error) {
	return auth.authenticate(ctx, operation, requestID)
}

type productionCurrentSession struct{}

func (productionCurrentSession) CurrentActorSession(
	_ context.Context,
	evidence contracts.AuthenticationEvidence,
	requestID string,
) (domain.ActorSessionID, *contracts.ErrorDTO, error) {
	if session, ok := evidence.ActorSessionID(); ok {
		return session, nil, nil
	}
	failure := unauthenticated(requestID)
	return domain.ActorSessionID{}, &failure, nil
}

func unauthenticated(requestID string) contracts.ErrorDTO {
	return contracts.ErrorDTO{
		Schema: contracts.SchemaError, RequestID: requestID,
		Code: domain.ErrorCodeUnauthenticated, Category: domain.ErrorCategoryAuthentication,
		Message: "Authentication is required.",
		Details: contracts.ErrorDetailsDTO{Recovery: contracts.RecoveryReauthenticate},
	}
}

// productionW0Handler promotes the application-backed handlers already present
// in the contract package. Proof-bearing W0 ceremonies stay closed until their
// transport can supply verified proof material; they never synthesize success.
type productionW0Handler struct{ *contracts.ApplicationHandler }

func (productionW0Handler) unavailable() error { return application.ErrInvalidApplicationContract }

func (handler productionW0Handler) HandleInstallationBootstrap(context.Context, contracts.AuthenticationEvidence, contracts.InstallationBootstrapRequestDTO) (contracts.InstallationBootstrapResultDTO, *contracts.ErrorDTO, error) {
	return contracts.InstallationBootstrapResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandlePrincipalRegister(context.Context, contracts.AuthenticationEvidence, contracts.PrincipalRegisterRequestDTO) (contracts.PrincipalRegisterResultDTO, *contracts.ErrorDTO, error) {
	return contracts.PrincipalRegisterResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandleDevicePairingBegin(context.Context, contracts.AuthenticationEvidence, contracts.DevicePairingBeginRequestDTO) (contracts.DevicePairingBeginResultDTO, *contracts.ErrorDTO, error) {
	return contracts.DevicePairingBeginResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandleDevicePair(context.Context, contracts.AuthenticationEvidence, contracts.DevicePairRequestDTO) (contracts.DevicePairResultDTO, *contracts.ErrorDTO, error) {
	return contracts.DevicePairResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandleWorkspaceMemberInvite(context.Context, contracts.AuthenticationEvidence, contracts.WorkspaceMemberInviteRequestDTO) (contracts.WorkspaceMemberInviteResultDTO, *contracts.ErrorDTO, error) {
	return contracts.WorkspaceMemberInviteResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandleWorkspaceMembershipAccept(context.Context, contracts.AuthenticationEvidence, contracts.WorkspaceMembershipAcceptRequestDTO) (contracts.WorkspaceMembershipAcceptResultDTO, *contracts.ErrorDTO, error) {
	return contracts.WorkspaceMembershipAcceptResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandleActorCreate(context.Context, contracts.AuthenticationEvidence, contracts.ActorCreateRequestDTO) (contracts.ActorCreateResultDTO, *contracts.ErrorDTO, error) {
	return contracts.ActorCreateResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandleActorDelegationPropose(context.Context, contracts.AuthenticationEvidence, contracts.ActorDelegationProposeRequestDTO) (contracts.ActorDelegationProposeResultDTO, *contracts.ErrorDTO, error) {
	return contracts.ActorDelegationProposeResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandleActorDelegationActivate(context.Context, contracts.AuthenticationEvidence, contracts.ActorDelegationActivateRequestDTO) (contracts.ActorDelegationActivateResultDTO, *contracts.ErrorDTO, error) {
	return contracts.ActorDelegationActivateResultDTO{}, nil, handler.unavailable()
}
func (handler productionW0Handler) HandleSessionStart(context.Context, contracts.AuthenticationEvidence, contracts.SessionStartRequestDTO) (contracts.SessionStartResultDTO, *contracts.ErrorDTO, error) {
	return contracts.SessionStartResultDTO{}, nil, handler.unavailable()
}
