package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
	"github.com/phall1/blackbird/internal/integration/localsecurity"
	"github.com/phall1/blackbird/internal/transport/contracts"
	httptransport "github.com/phall1/blackbird/internal/transport/http"
	mcptransport "github.com/phall1/blackbird/internal/transport/mcp"
	"github.com/phall1/blackbird/internal/transport/metrics"
)

const (
	productionAudience   = "blackbird.local"
	productionPolicy     = "blackbird-local-v1"
	recoveryCapsuleKeyID = "blackbird-local-recovery-v1"
	recoveryCredentialID = "recovery-signing-key"
	productionAssurance  = "local-credential"

	// mcpSessionTimeout bounds how long an idle MCP session survives without a
	// client request. It is long enough to outlast a thinking agent and short
	// enough that an abandoned session is reclaimed within one work break.
	//
	// It is idle time, not request time: blackbird_wait holds one request open
	// for up to application.MaxCoordinationWait while it parks an agent behind a
	// reservation. That is why the ingress server sets no write timeout -- one
	// shorter than the wait ceiling would cut every long poll off mid-answer,
	// and the agent would read a coordination feature as a broken daemon.
	mcpSessionTimeout = 30 * time.Minute
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
	if config.StateDir != "" {
		path, err := filepath.Abs(config.StateDir)
		if err != nil {
			return nil, fmt.Errorf("resolve state directory: %w", err)
		}
		config.StateDir = filepath.Clean(path)
	}
	logger, severity, err := NewLeveledLogger(config, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("runtime configuration: %w", err)
	}
	return NewDaemon(build, config, Dependencies{
		Logger:      logger,
		LogSeverity: severity,
		Compose:     composeProduction(build.Normalize(), config, logger),
	})
}

// composeProduction closes over build identity and process configuration so the
// admin and health surfaces can describe the daemon without reaching back into
// the process for facts the composition root already holds.
func composeProduction(build BuildInfo, config Config, logger *slog.Logger) Composer {
	return func(ctx context.Context, storage Storage) (HandlerBundle, error) {
		return composeProductionBundle(ctx, build, config, logger, storage)
	}
}

func composeProductionBundle(
	_ context.Context,
	build BuildInfo,
	config Config,
	logger *slog.Logger,
	storage Storage,
) (HandlerBundle, error) {
	store, ok := storage.(productionStore)
	if !ok {
		return HandlerBundle{}, errors.New("production storage does not implement the application ports")
	}
	telemetry := metrics.New()

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
		Logger:                logger,
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
	localHTTPHandler, err := httptransport.NewLocalHandler(httptransport.LocalDependencies{
		Coordination: coordination, Logger: logger,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose local HTTP transport: %w", err)
	}
	admin, ok := storage.(application.LocalAdminStore)
	if !ok {
		return HandlerBundle{}, errors.New("production storage does not implement the local admin projections")
	}
	token, err := newAdminToken()
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("mint admin token: %w", err)
	}
	started := time.Now().UTC()
	adminHTTPHandler, err := httptransport.NewAdminHandler(httptransport.AdminDependencies{
		Admin: admin, Token: httptransport.NewAdminTokenDigest(token), Metrics: telemetry,
		Identity: httptransport.LocalIdentity{
			Version: build.Version, Commit: build.Commit, BuiltAt: build.BuiltAt,
			PID: os.Getpid(), StartedAt: started,
			HTTPAddress: config.HTTPAddress, MCPAddress: config.MCPAddress,
		},
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose admin HTTP transport: %w", err)
	}
	healthHandler, err := httptransport.NewHealthHandler(httptransport.HealthDependencies{
		Readiness: admin, Version: build.Version,
	})
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose health HTTP transport: %w", err)
	}
	handshake, err := newAdminHandshakeWorker(config.StateDir, token, config.HTTPAddress, build.Version, started, logger)
	if err != nil {
		return HandlerBundle{}, fmt.Errorf("compose admin handshake: %w", err)
	}
	// Method-and-path patterns and the longer admin prefix both beat the "/"
	// catch-all under net/http precedence, so registration order is immaterial.
	httpMux := http.NewServeMux()
	httpMux.Handle("GET "+httptransport.PathHealth, healthHandler)
	httpMux.Handle("GET "+httptransport.PathReady, healthHandler)
	httpMux.Handle(httptransport.PathLocalAdmin, adminHTTPHandler)
	httpMux.Handle("/api/v1/local/", localHTTPHandler)
	httpMux.Handle("/", httpHandler)
	mcpServer, err := mcptransport.NewServer(mcptransport.Dependencies{
		Logger:        logger,
		Metrics:       telemetry,
		Authenticator: mcpIngressAuthenticator{ingress}, CurrentSession: productionCurrentSession{},
		// The W0/W1 plane stays off MCP: nothing on this transport can attach a
		// verified ingress credential, so those tools could only answer
		// UNAUTHENTICATED while spending most of every client's tool-list budget.
		// They keep their full HTTP surface, where the credential travels.
		ExposeIdentityPlane:   false,
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
	logger.Info("ingress composed",
		slog.String("admin_path", httptransport.PathLocalAdmin),
		slog.String("health_path", httptransport.PathHealth),
		slog.String("readiness_path", httptransport.PathReady))
	return HandlerBundle{
		HTTP:    telemetry.WrapHTTP(httpMux, httptransport.PathLocalCoordinationEventsStream),
		Workers: []Worker{handshake},
		// Without a session timeout the SDK never closes an idle session, so a
		// crashed agent or a killed terminal leaks its map entry and goroutines
		// for the daemon's lifetime.
		MCP: mcpServer.HTTPHandler(&sdkmcp.StreamableHTTPOptions{SessionTimeout: mcpSessionTimeout}),
	}, nil
}

// SetBoundHTTPAddress replaces the configured address with the one the HTTP
// listener actually bound. Composition runs before the bind, so the worker is
// built from the request; runtime supplies the result before Start, which is
// the only value a client can dial when the configuration asks for port 0.
func (worker *adminHandshakeWorker) SetBoundHTTPAddress(address string) {
	if address == "" {
		return
	}
	worker.handshake.HTTPAddress = address
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

type authenticationRegistry interface {
	Register(application.AuthenticationRequest) error
	Revoke(application.AuthenticationRequest) error
}

type registeringAuthentication struct {
	registry authenticationRegistry
	next     application.AuthenticationPreparer
}

func (authentication registeringAuthentication) PrepareAuthentication(
	ctx context.Context,
	request application.AuthenticationRequest,
) (decision application.AuthenticationDecision, err error) {
	if authentication.registry == nil || authentication.next == nil {
		return application.AuthenticationDecision{}, application.ErrInvalidApplicationContract
	}
	if err := authentication.registry.Register(request); err != nil {
		return application.AuthenticationDecision{}, err
	}
	defer func() {
		if revokeErr := authentication.registry.Revoke(request); revokeErr != nil {
			err = errors.Join(err, fmt.Errorf("revoke authentication registration: %w", revokeErr))
		}
	}()
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
