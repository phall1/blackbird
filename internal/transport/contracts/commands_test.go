package contracts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

// workspaceCreateDispatcherStub records the assembled request and returns a
// configured execution so the handler's full assembly surface is observable
// without the application OrchestrationService.
type workspaceCreateDispatcherStub struct {
	request *application.CreateWorkspaceRequest
	exec    application.CommandExecution
	err     error
}

func (stub *workspaceCreateDispatcherStub) CreateWorkspace(_ context.Context, request application.CreateWorkspaceRequest) (application.CommandExecution, error) {
	copyOfRequest := request
	stub.request = &copyOfRequest
	return stub.exec, stub.err
}

func (stub *workspaceCreateDispatcherStub) BootstrapInstallation(context.Context, application.BootstrapInstallationRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) RegisterPrincipal(context.Context, application.RegisterPrincipalRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) InviteWorkspaceMember(context.Context, application.InviteWorkspaceMemberRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) AcceptWorkspaceMembership(context.Context, application.AcceptWorkspaceMembershipRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) CreateActor(context.Context, application.CreateActorRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) ProposeActorDelegation(context.Context, application.ProposeActorDelegationRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) ActivateActorDelegation(context.Context, application.ActivateActorDelegationRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) BeginDevicePairing(context.Context, application.BeginDevicePairingRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) PairDevice(context.Context, application.PairDeviceRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}
func (stub *workspaceCreateDispatcherStub) StartActorSession(context.Context, application.StartActorSessionRequest) (application.CommandExecution, error) {
	panic("unexpected command dispatch")
}

type commandTestQueryStore struct{}

func (commandTestQueryStore) GetContext(context.Context, application.ContextGetQuery) (application.ContextPage, error) {
	panic("unexpected query")
}
func (commandTestQueryStore) SyncEvents(context.Context, application.EventsSyncQuery) (application.EventsPage, error) {
	panic("unexpected query")
}

type commandTestCheckpointSource struct{}

func (commandTestCheckpointSource) NewCheckpointID() (application.CheckpointID, error) {
	return application.NewCheckpointID("checkpoint-test-1")
}

type commandTestCapsuleSigner struct {
	keyID   string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func (signer commandTestCapsuleSigner) KeyID() string { return signer.keyID }
func (signer commandTestCapsuleSigner) Ed25519PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), signer.public...)
}
func (signer commandTestCapsuleSigner) SignRecoveryCapsule(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, message), nil
}

type commandTestSignerLookup struct{ signer commandTestCapsuleSigner }

func (lookup commandTestSignerLookup) PrepareRecoveryCapsuleSigner(_ context.Context, keyID string) (application.PreparedRecoveryCapsuleSigner, error) {
	if keyID != lookup.signer.keyID {
		return nil, application.ErrInvalidApplicationContract
	}
	return lookup.signer, nil
}

func workspaceCreateTestDTO(t *testing.T, fixture authenticationFixture) WorkspaceCreateRequestDTO {
	t.Helper()
	commandID, err := domain.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	correlation, err := domain.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	clientInstance, err := domain.NewClientInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	membershipID, err := domain.NewMembershipID()
	if err != nil {
		t.Fatal(err)
	}
	grantID, err := domain.ParseGrantID(fixture.grant.Target().ID())
	if err != nil {
		t.Fatal(err)
	}
	return WorkspaceCreateRequestDTO{
		CommandMetadataDTO: CommandMetadataDTO{
			Schema: SchemaWorkspaceCreateCommand, RequestID: "req_workspace_create",
			CommandID: commandID, Operation: OperationWorkspaceCreate,
			IdempotencyKey: "workspace-create-test-key", AuthorityID: fixture.authority,
			AuthorityEpoch: fixture.epoch, Deadline: time.Now().UTC().Add(time.Hour),
			CorrelationID: correlation,
		},
		ClientInstanceID: clientInstance,
		ExpectedVersions: WorkspaceCreateExpectedVersionsDTO{
			OwnerPrincipal:    fixture.principal.Version(),
			InstallationGrant: fixture.grant.Version(),
		},
		Body: WorkspaceCreateBodyDTO{
			InstallationID:      fixture.installation,
			WorkspaceID:         fixture.workspace,
			OwnerPrincipalID:    fixture.principal.ID(),
			InstallationGrantID: grantID,
			OwnerMembershipID:   membershipID,
			Alias:               "team-workspace",
			DiscoveryLocator:    "workspace://team-workspace",
			PolicyRevision:      "policy:workspace-create:v1",
			OwnerCapabilities:   []string{"membership:admin", "workspace:owner"},
		},
	}
}

func newWorkspaceCreateTestHandler(t *testing.T, fixture authenticationFixture, dispatcher *workspaceCreateDispatcherStub) (*ApplicationHandler, WorkspaceCreateRequestDTO) {
	t.Helper()
	queries, err := application.NewQueryService(commandTestQueryStore{}, commandTestCheckpointSource{})
	if err != nil {
		t.Fatal(err)
	}
	policyRevision, err := domain.NewPolicyRevision("policy:workspace-create:v1")
	if err != nil {
		t.Fatal(err)
	}
	assembler := newW0CommandAssembler(t, &stubCommandPolicySource{
		revision: policyRevision, digest: application.DigestBytes([]byte("workspace create policy")),
	})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signers := commandTestSignerLookup{signer: commandTestCapsuleSigner{
		keyID: "ed25519:test-capsule-key", private: private, public: public,
	}}
	now := time.Now().UTC()
	handler, err := NewApplicationHandler(
		queries, dispatcher, assembler, signers, "ed25519:test-capsule-key",
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	return handler, workspaceCreateTestDTO(t, fixture)
}

func TestHandleWorkspaceCreateAssemblesAndDispatches(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := &workspaceCreateDispatcherStub{}
	handler, dto := newWorkspaceCreateTestHandler(t, fixture, dispatcher)
	rejection, err := domain.NewCommandError(domain.ErrorCodeIdempotencyKeyReused, "idempotency key reused", nil)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.exec, err = application.RejectedCommandExecution(rejection)
	if err != nil {
		t.Fatal(err)
	}

	result, failure, err := handler.HandleWorkspaceCreate(context.Background(), evidence, dto)
	if err != nil {
		t.Fatalf("HandleWorkspaceCreate error=%v", err)
	}
	if failure == nil || failure.Code != domain.ErrorCodeIdempotencyKeyReused {
		t.Fatalf("failure=%+v, want IDEMPOTENCY_KEY_REUSED", failure)
	}
	if result.Schema != "" {
		t.Fatalf("rejected execution must not produce a result, got %+v", result)
	}
	request := dispatcher.request
	if request == nil {
		t.Fatal("dispatcher was never invoked")
	}

	scope, err := domain.WorkspaceScope(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if request.Spec.CommandOperation() != application.CommandCreateWorkspace {
		t.Fatalf("spec operation=%s, want %s", request.Spec.CommandOperation(), application.CommandCreateWorkspace)
	}
	if request.Spec.Scope() != scope {
		t.Fatalf("spec scope=%v, want %v", request.Spec.Scope(), scope)
	}
	if request.Spec.AuthorityID() != fixture.authority || request.Spec.RequestedEpoch() != fixture.epoch {
		t.Fatalf("spec authority=%s@%s, want %s@%s",
			request.Spec.AuthorityID(), request.Spec.RequestedEpoch(), fixture.authority, fixture.epoch)
	}
	if request.Spec.Authorship().PrincipalID() != fixture.principal.ID() {
		t.Fatalf("spec authorship principal=%s, want %s",
			request.Spec.Authorship().PrincipalID(), fixture.principal.ID())
	}
	fingerprint, err := application.NewProductionCanonicalCodec().HashCommand(request.HashView)
	if err != nil || fingerprint != request.Spec.RequestFingerprint() {
		t.Fatalf("hash-view fingerprint=%x error=%v does not match spec fingerprint=%x",
			fingerprint, err, request.Spec.RequestFingerprint())
	}
	if request.Authentication.Operation() != application.CommandCreateWorkspace || request.Authentication.Scope() != scope {
		t.Fatalf("authentication=%s@%v, want %s@%v",
			request.Authentication.Operation(), request.Authentication.Scope(), application.CommandCreateWorkspace, scope)
	}
	if request.Policy.Operation() != application.CommandCreateWorkspace || request.Policy.Scope() != scope {
		t.Fatalf("policy=%s@%v, want %s@%v",
			request.Policy.Operation(), request.Policy.Scope(), application.CommandCreateWorkspace, scope)
	}
	if request.Audit.RequestID() != dto.RequestID || request.Audit.TraceID() != dto.RequestID {
		t.Fatalf("audit request=%s trace=%s, want %s", request.Audit.RequestID(), request.Audit.TraceID(), dto.RequestID)
	}
	if request.OwnerID != fixture.principal.ID() || request.WorkspaceID != fixture.workspace ||
		request.InstallationGrantID.String() != fixture.grant.Target().ID() ||
		request.OwnerMembershipID != dto.Body.OwnerMembershipID {
		t.Fatalf("command identity owner=%s workspace=%s grant=%s membership=%s",
			request.OwnerID, request.WorkspaceID, request.InstallationGrantID, request.OwnerMembershipID)
	}
	if request.Alias.String() != dto.Body.Alias || request.DiscoveryLocator.String() != dto.Body.DiscoveryLocator {
		t.Fatalf("alias=%q locator=%q, want %q/%q",
			request.Alias.String(), request.DiscoveryLocator.String(), dto.Body.Alias, dto.Body.DiscoveryLocator)
	}
	if !request.OwnerCapabilities.Contains(domain.WorkspaceOwnerCapability()) ||
		!request.OwnerCapabilities.Contains(domain.MembershipAdminCapability()) {
		t.Fatalf("owner capabilities=%v missing workspace:owner or membership:admin", request.OwnerCapabilities)
	}
	if failure.RequestID != dto.RequestID || failure.Details.IdempotencyKey != dto.IdempotencyKey ||
		failure.Details.DomainConflict != domain.ConflictIdempotency {
		t.Fatalf("failure mapping=%+v, want request=%s key=%s conflict=IdempotencyConflict",
			failure, dto.RequestID, dto.IdempotencyKey)
	}
}

func TestHandleWorkspaceCreateForbiddenMapsDeniedCapabilityAndScope(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := &workspaceCreateDispatcherStub{}
	handler, dto := newWorkspaceCreateTestHandler(t, fixture, dispatcher)
	rejection, err := domain.NewCommandError(domain.ErrorCodeForbidden, "identity lacks workspace create capability", nil)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.exec, err = application.RejectedCommandExecution(rejection)
	if err != nil {
		t.Fatal(err)
	}

	_, failure, err := handler.HandleWorkspaceCreate(context.Background(), evidence, dto)
	if err != nil {
		t.Fatalf("HandleWorkspaceCreate error=%v", err)
	}
	if failure == nil || failure.Code != domain.ErrorCodeForbidden {
		t.Fatalf("failure=%+v, want FORBIDDEN", failure)
	}
	if failure.Details.DeniedCapability != "workspace:create" {
		t.Fatalf("denied capability=%q, want workspace:create", failure.Details.DeniedCapability)
	}
	if failure.Details.ResourceScope == nil || failure.Details.ResourceScope.Type != domain.AggregateKindWorkspace ||
		failure.Details.ResourceScope.ID != fixture.workspace.String() {
		t.Fatalf("resource scope=%+v, want workspace %s", failure.Details.ResourceScope, fixture.workspace)
	}
}

func TestHandleWorkspaceCreateMapsCapacityRejections(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := &workspaceCreateDispatcherStub{}
	handler, dto := newWorkspaceCreateTestHandler(t, fixture, dispatcher)
	rejection, err := domain.NewCommandError(domain.ErrorCodeBackpressure, "capacity constrained", nil)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.exec, err = application.RejectedCommandExecution(rejection)
	if err != nil {
		t.Fatal(err)
	}

	_, failure, err := handler.HandleWorkspaceCreate(context.Background(), evidence, dto)
	if err != nil {
		t.Fatalf("HandleWorkspaceCreate error=%v", err)
	}
	if failure == nil || failure.Code != domain.ErrorCodeBackpressure {
		t.Fatalf("failure=%+v, want BACKPRESSURE", failure)
	}
	if failure.Details.Recovery != RecoveryRetryAfterDelay || failure.RetryAfterMS == nil ||
		*failure.RetryAfterMS != commandRetryAfterMS {
		t.Fatalf("backpressure recovery=%s delay=%v, want retry_after_delay/%d",
			failure.Details.Recovery, failure.RetryAfterMS, commandRetryAfterMS)
	}
}

func TestHandleWorkspaceCreateUnderivableRejectionSurfacesInternal(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := &workspaceCreateDispatcherStub{}
	handler, dto := newWorkspaceCreateTestHandler(t, fixture, dispatcher)
	execution, err := application.RejectedCommandExecution(domain.ErrStaleVersion)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.exec = execution

	_, failure, err := handler.HandleWorkspaceCreate(context.Background(), evidence, dto)
	if err == nil || failure != nil {
		t.Fatalf("stale-version evidence must surface internally, got failure=%v err=%v", failure, err)
	}
}

func TestHandleWorkspaceCreateDispatchErrorSurfaces(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := &workspaceCreateDispatcherStub{err: errors.New("storage unavailable")}
	handler, dto := newWorkspaceCreateTestHandler(t, fixture, dispatcher)

	_, failure, err := handler.HandleWorkspaceCreate(context.Background(), evidence, dto)
	if err == nil || failure != nil {
		t.Fatalf("dispatch failure must surface, got failure=%v err=%v", failure, err)
	}
}

func TestHandleWorkspaceCreateRejectsInvalidRequest(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dispatcher := &workspaceCreateDispatcherStub{}
	handler, dto := newWorkspaceCreateTestHandler(t, fixture, dispatcher)
	dto.Body.Alias = ""

	_, failure, err := handler.HandleWorkspaceCreate(context.Background(), evidence, dto)
	if !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
		t.Fatalf("invalid request must fail closed, got failure=%v err=%v", failure, err)
	}
	if dispatcher.request != nil {
		t.Fatal("invalid request must not reach the dispatcher")
	}
}

func TestHandleWorkspaceCreateFailsClosedWithoutDependencies(t *testing.T) {
	fixture := newAuthenticationFixture(t)
	evidence := assemblerEvidence(t, fixture)
	dto := workspaceCreateTestDTO(t, fixture)

	var nilHandler *ApplicationHandler
	if _, failure, err := nilHandler.HandleWorkspaceCreate(context.Background(), evidence, dto); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
		t.Fatalf("nil handler err=%v failure=%v, want invalid contract", err, failure)
	}
	empty := &ApplicationHandler{}
	if _, failure, err := empty.HandleWorkspaceCreate(context.Background(), evidence, dto); !errors.Is(err, application.ErrInvalidApplicationContract) || failure != nil {
		t.Fatalf("empty handler err=%v failure=%v, want invalid contract", err, failure)
	}
}
