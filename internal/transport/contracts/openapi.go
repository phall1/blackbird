package contracts

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/application"
	"github.com/phall1/blackbird/internal/domain"
)

const (
	OpenAPITitle   = "Blackbird Product API"
	OpenAPIVersion = "1.0.0-w0"
)

type schema = map[string]any

type apiOperation struct {
	Path      string
	Operation string
	Request   string
	Response  string
	Type      reflect.Type
	Output    reflect.Type
}

var productAPIOperations = []apiOperation{
	{"/api/v1/commands/installation.bootstrap", OperationInstallationBootstrap, "InstallationBootstrapRequest", "InstallationBootstrapResult", reflect.TypeFor[InstallationBootstrapRequestDTO](), reflect.TypeFor[InstallationBootstrapResultDTO]()},
	{"/api/v1/commands/principal.register", OperationPrincipalRegister, "PrincipalRegisterRequest", "PrincipalRegisterResult", reflect.TypeFor[PrincipalRegisterRequestDTO](), reflect.TypeFor[PrincipalRegisterResultDTO]()},
	{"/api/v1/commands/pairing.challenge.issue", OperationDevicePairingBegin, "DevicePairingBeginRequest", "DevicePairingBeginResult", reflect.TypeFor[DevicePairingBeginRequestDTO](), reflect.TypeFor[DevicePairingBeginResultDTO]()},
	{"/api/v1/commands/pairing.challenge.redeem", OperationDevicePair, "DevicePairRequest", "DevicePairResult", reflect.TypeFor[DevicePairRequestDTO](), reflect.TypeFor[DevicePairResultDTO]()},
	{"/api/v1/commands/workspace.create", OperationWorkspaceCreate, "WorkspaceCreateRequest", "WorkspaceCreateResult", reflect.TypeFor[WorkspaceCreateRequestDTO](), reflect.TypeFor[WorkspaceCreateResultDTO]()},
	{"/api/v1/commands/workspace_member.invite", OperationWorkspaceMemberInvite, "WorkspaceMemberInviteRequest", "WorkspaceMemberInviteResult", reflect.TypeFor[WorkspaceMemberInviteRequestDTO](), reflect.TypeFor[WorkspaceMemberInviteResultDTO]()},
	{"/api/v1/commands/workspace_membership.accept", OperationWorkspaceMembershipAccept, "WorkspaceMembershipAcceptRequest", "WorkspaceMembershipAcceptResult", reflect.TypeFor[WorkspaceMembershipAcceptRequestDTO](), reflect.TypeFor[WorkspaceMembershipAcceptResultDTO]()},
	{"/api/v1/commands/actor.create", OperationActorCreate, "ActorCreateRequest", "ActorCreateResult", reflect.TypeFor[ActorCreateRequestDTO](), reflect.TypeFor[ActorCreateResultDTO]()},
	{"/api/v1/commands/actor_delegation.propose", OperationActorDelegationPropose, "ActorDelegationProposeRequest", "ActorDelegationProposeResult", reflect.TypeFor[ActorDelegationProposeRequestDTO](), reflect.TypeFor[ActorDelegationProposeResultDTO]()},
	{"/api/v1/commands/actor_delegation.activate", OperationActorDelegationActivate, "ActorDelegationActivateRequest", "ActorDelegationActivateResult", reflect.TypeFor[ActorDelegationActivateRequestDTO](), reflect.TypeFor[ActorDelegationActivateResultDTO]()},
	{"/api/v1/commands/session.start", OperationSessionStart, "SessionStartRequest", "SessionStartResult", reflect.TypeFor[SessionStartRequestDTO](), reflect.TypeFor[SessionStartResultDTO]()},
	{"/api/v1/commands/work_ref.observe", OperationWorkRefObserve, "WorkRefObserveRequest", "WorkRefObserveResult", reflect.TypeFor[WorkRefObserveRequestDTO](), reflect.TypeFor[WorkRefObserveResultDTO]()},
	{"/api/v1/commands/objective_and_work.create", OperationObjectiveAndWorkCreate, "ObjectiveAndWorkCreateRequest", "ObjectiveAndWorkCreateResult", reflect.TypeFor[ObjectiveAndWorkCreateRequestDTO](), reflect.TypeFor[ObjectiveAndWorkCreateResultDTO]()},
	{"/api/v1/commands/objective.activate", OperationObjectiveActivate, "ObjectiveActivateRequest", "ObjectiveActivateResult", reflect.TypeFor[ObjectiveActivateRequestDTO](), reflect.TypeFor[ObjectiveActivateResultDTO]()},
	{"/api/v1/commands/run.plan_with_bindings", OperationRunPlanWithBindings, "RunPlanWithBindingsRequest", "RunPlanWithBindingsResult", reflect.TypeFor[RunPlanWithBindingsRequestDTO](), reflect.TypeFor[RunPlanWithBindingsResultDTO]()},
	{"/api/v1/commands/run_participation.join", OperationRunJoin, "RunJoinRequest", "RunJoinResult", reflect.TypeFor[RunJoinRequestDTO](), reflect.TypeFor[RunJoinResultDTO]()},
	{"/api/v1/commands/run.start", OperationRunStart, "RunStartRequest", "RunStartResult", reflect.TypeFor[RunStartRequestDTO](), reflect.TypeFor[RunStartResultDTO]()},
	{"/api/v1/queries/context.get", OperationContextGet, "ContextGetRequest", "ContextPage", reflect.TypeFor[ContextGetRequestDTO](), reflect.TypeFor[ContextPageDTO]()},
	{"/api/v1/queries/events.sync", OperationEventsSync, "EventsSyncRequest", "EventPage", reflect.TypeFor[EventsSyncRequestDTO](), reflect.TypeFor[EventPageDTO]()},
}

// httpStatusByErrorCode is the single mapping from a typed error code to the
// HTTP status that reports it. The OpenAPI document and the HTTP transport both
// read it through HTTPStatusForErrorCode, because a second copy drifts silently:
// a new code or a changed status lands in one table, and the published document
// then describes an API the daemon does not serve.
var httpStatusByErrorCode = map[domain.ErrorCode]int{
	domain.ErrorCodeInvalidArgument:       http.StatusBadRequest,
	domain.ErrorCodeCursorInvalid:         http.StatusBadRequest,
	domain.ErrorCodeCursorScopeMismatch:   http.StatusBadRequest,
	domain.ErrorCodeUnauthenticated:       http.StatusUnauthorized,
	domain.ErrorCodeSessionExpired:        http.StatusUnauthorized,
	domain.ErrorCodeForbidden:             http.StatusForbidden,
	domain.ErrorCodeCapabilityRequired:    http.StatusForbidden,
	domain.ErrorCodeNotFound:              http.StatusNotFound,
	domain.ErrorCodeStaleVersion:          http.StatusConflict,
	domain.ErrorCodeStateConflict:         http.StatusConflict,
	domain.ErrorCodeIdempotencyKeyReused:  http.StatusConflict,
	domain.ErrorCodeCommandIDReused:       http.StatusConflict,
	domain.ErrorCodeCommandInProgress:     http.StatusConflict,
	domain.ErrorCodeLeaseConflict:         http.StatusConflict,
	domain.ErrorCodeLeaseExpired:          http.StatusConflict,
	domain.ErrorCodeFenceRejected:         http.StatusConflict,
	domain.ErrorCodeCursorExpired:         http.StatusGone,
	domain.ErrorCodeInvalidSchema:         http.StatusUnprocessableEntity,
	domain.ErrorCodeRateLimited:           http.StatusTooManyRequests,
	domain.ErrorCodeInternal:              http.StatusInternalServerError,
	domain.ErrorCodeBackpressure:          http.StatusServiceUnavailable,
	domain.ErrorCodeDependencyUnavailable: http.StatusServiceUnavailable,
	domain.ErrorCodeDeadlineExceeded:      http.StatusGatewayTimeout,
}

// HTTPStatusForErrorCode reports the HTTP status a typed error code is served
// with. An unmapped code answers 500, which is the only safe reading: a code
// this table does not know is not one a client should be told to retry, redeem,
// or re-read on the strength of a more specific status.
func HTTPStatusForErrorCode(code domain.ErrorCode) int {
	if status, mapped := httpStatusByErrorCode[code]; mapped {
		return status
	}
	return http.StatusInternalServerError
}

// The document repeats the status set three ways — as the response keys of every
// operation, as the x-blackbird-error-statuses matrix, and as the Problem
// status enum — so all three are projected from the one table above.
var errorStatusCodes = distinctErrorStatusCodes()

var errorStatuses = errorStatusStrings()

var errorStatusByCode = errorStatusMatrix()

func distinctErrorStatusCodes() []int {
	seen := map[int]struct{}{}
	statuses := make([]int, 0, len(httpStatusByErrorCode))
	for _, status := range httpStatusByErrorCode {
		if _, duplicate := seen[status]; duplicate {
			continue
		}
		seen[status] = struct{}{}
		statuses = append(statuses, status)
	}
	sort.Ints(statuses)
	return statuses
}

func errorStatusStrings() []string {
	statuses := make([]string, 0, len(errorStatusCodes))
	for _, status := range errorStatusCodes {
		statuses = append(statuses, strconv.Itoa(status))
	}
	return statuses
}

func errorStatusMatrix() schema {
	matrix := make(schema, len(httpStatusByErrorCode))
	for code, status := range httpStatusByErrorCode {
		matrix[string(code)] = status
	}
	return matrix
}

// ProductOpenAPI31 returns the canonical deterministic OpenAPI 3.1 document.
// Its component schemas are generated from the concrete DTO field/tag graph;
// contract-specific constraints are layered on that graph below.
func ProductOpenAPI31() ([]byte, error) {
	components, err := contractSchemas()
	if err != nil {
		return nil, err
	}
	paths := schema{}
	for _, operation := range productAPIOperations {
		responses := schema{
			"200": response("Successful operation", "application/json", operation.Response),
		}
		for _, status := range errorStatuses {
			responses[status] = response("RFC 9457 problem details", "application/problem+json", "Problem")
		}
		paths[operation.Path] = schema{"post": schema{
			"operationId": operation.Operation,
			"summary":     operation.Operation,
			"requestBody": schema{
				"required": true,
				"content":  schema{"application/json": schema{"schema": ref(operation.Request)}},
			},
			"responses": responses,
		}}
	}
	document := schema{
		"openapi":                    "3.1.0",
		"jsonSchemaDialect":          "https://json-schema.org/draft/2020-12/schema",
		"info":                       schema{"title": OpenAPITitle, "version": OpenAPIVersion},
		"paths":                      paths,
		"components":                 schema{"schemas": components},
		"x-blackbird-error-statuses": errorStatusByCode,
	}
	return json.MarshalIndent(document, "", "  ")
}

// JSONSchemas202012 returns standalone deterministic JSON Schema documents for
// every public HTTP request, success, and RFC 9457 error component.
func JSONSchemas202012() (map[string][]byte, error) {
	components, err := contractSchemas()
	if err != nil {
		return nil, err
	}
	result := make(map[string][]byte, len(components))
	for name, component := range components {
		definitions := standaloneDefinitions(components)
		document := schema{
			"$schema":     "https://json-schema.org/draft/2020-12/schema",
			"$id":         "https://blackbird.local/schemas/" + name + ".json",
			"$defs":       definitions,
			"$ref":        "#/$defs/" + name,
			"title":       name,
			"description": component.(schema)["description"],
		}
		encoded, marshalErr := json.MarshalIndent(document, "", "  ")
		if marshalErr != nil {
			return nil, marshalErr
		}
		result[name] = encoded
	}
	return result, nil
}

func standaloneDefinitions(components schema) schema {
	encoded, err := json.Marshal(components)
	if err != nil {
		panic(err)
	}
	var definitions schema
	if err := json.Unmarshal(encoded, &definitions); err != nil {
		panic(err)
	}
	rewriteComponentRefs(definitions)
	return definitions
}

func rewriteComponentRefs(value any) {
	switch typed := value.(type) {
	case map[string]any:
		if reference, ok := typed["$ref"].(string); ok {
			typed["$ref"] = strings.Replace(reference, "#/components/schemas/", "#/$defs/", 1)
		}
		for _, child := range typed {
			rewriteComponentRefs(child)
		}
	case []any:
		for _, child := range typed {
			rewriteComponentRefs(child)
		}
	}
}

func response(description, mediaType, component string) schema {
	return schema{"description": description, "content": schema{mediaType: schema{"schema": ref(component)}}}
}

func ref(name string) schema { return schema{"$ref": "#/components/schemas/" + name} }

type schemaBuilder struct {
	components schema
	names      map[reflect.Type]string
}

func contractSchemas() (schema, error) {
	builder := &schemaBuilder{components: schema{}, names: map[reflect.Type]string{}}
	for _, operation := range productAPIOperations {
		builder.names[operation.Type] = operation.Request
		builder.names[operation.Output] = operation.Response
	}
	builder.names[reflect.TypeFor[ErrorDTO]()] = "BlackbirdError"
	for _, operation := range productAPIOperations {
		builder.add(operation.Type)
		builder.add(operation.Output)
	}
	builder.add(reflect.TypeFor[ErrorDTO]())
	for _, operation := range productAPIOperations {
		applyRootContract(builder.components[operation.Request].(schema), operation.Type, operation.Operation)
		applyRootContract(builder.components[operation.Response].(schema), operation.Output, operation.Operation)
	}
	applyProblemSchema(builder.components)
	return builder.components, nil
}

func (builder *schemaBuilder) add(valueType reflect.Type) schema {
	if valueType.Kind() == reflect.Pointer {
		return schema{"oneOf": []any{builder.add(valueType.Elem()), schema{"type": "null"}}}
	}
	if valueType == reflect.TypeFor[time.Time]() {
		return schema{"type": "string", "format": "date-time"}
	}
	if valueType == reflect.TypeFor[json.RawMessage]() {
		return schema{"type": "object", "additionalProperties": true}
	}
	if primitive := primitiveSchema(valueType); primitive != nil {
		return primitive
	}
	if valueType.Kind() == reflect.Slice || valueType.Kind() == reflect.Array {
		return schema{"type": "array", "items": builder.add(valueType.Elem())}
	}
	if valueType.Kind() != reflect.Struct {
		panic(fmt.Sprintf("unsupported contract schema type %v", valueType))
	}
	name := builder.names[valueType]
	if name == "" {
		name = strings.TrimSuffix(valueType.Name(), "DTO")
		builder.names[valueType] = name
	}
	if _, exists := builder.components[name]; exists {
		return ref(name)
	}
	object := schema{"type": "object", "additionalProperties": false, "properties": schema{}, "required": []string{}, "description": "Generated from Go DTO " + valueType.Name() + "."}
	builder.components[name] = object
	properties := object["properties"].(schema)
	required := object["required"].([]string)
	for index := range valueType.NumField() {
		field := valueType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		if field.Anonymous && field.Tag.Get("json") == "" {
			embedded := builder.objectFields(field.Type)
			for key, value := range embedded.properties {
				properties[key] = value
			}
			required = append(required, embedded.required...)
			continue
		}
		jsonName, options := jsonField(field)
		if jsonName == "-" {
			continue
		}
		properties[jsonName] = builder.add(field.Type)
		if !options["omitempty"] {
			required = append(required, jsonName)
		}
	}
	sort.Strings(required)
	object["required"] = required
	applyTypeContract(object, valueType)
	return ref(name)
}

type reflectedFields struct {
	properties schema
	required   []string
}

func (builder *schemaBuilder) objectFields(valueType reflect.Type) reflectedFields {
	builder.add(valueType)
	name := builder.names[valueType]
	object := builder.components[name].(schema)
	return reflectedFields{object["properties"].(schema), append([]string(nil), object["required"].([]string)...)}
}

func primitiveSchema(valueType reflect.Type) schema {
	if valueType.PkgPath() == "github.com/phall1/blackbird/internal/transport/contracts" &&
		(valueType.Name() == "CeremonyIDDTO" || valueType.Name() == "ContextCheckpointIDDTO") {
		return uuidSchema()
	}
	if valueType.PkgPath() == "github.com/phall1/blackbird/internal/domain" {
		switch valueType.Name() {
		case "Version", "StreamPosition":
			return schema{"type": "integer", "minimum": 1, "maximum": domain.MaxCanonicalInteger}
		case "AuthorityEpoch":
			return uuidSchema()
		}
		if strings.HasSuffix(valueType.Name(), "ID") {
			return uuidSchema()
		}
	}
	switch valueType.Kind() {
	case reflect.String:
		return schema{"type": "string"}
	case reflect.Bool:
		return schema{"type": "boolean"}
	case reflect.Uint8:
		return schema{"type": "integer", "minimum": 0, "maximum": uint64(1<<8 - 1)}
	case reflect.Uint16:
		return schema{"type": "integer", "minimum": 0, "maximum": uint64(1<<16 - 1)}
	case reflect.Uint32:
		return schema{"type": "integer", "minimum": 0, "maximum": uint64(1<<32 - 1)}
	case reflect.Uint, reflect.Uint64:
		return schema{"type": "integer", "minimum": 0, "maximum": domain.MaxCanonicalInteger}
	default:
		return nil
	}
}

func uuidSchema() schema {
	return schema{"type": "string", "format": "uuid", "pattern": `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`}
}

func jsonField(field reflect.StructField) (string, map[string]bool) {
	tag := strings.Split(field.Tag.Get("json"), ",")
	name := tag[0]
	if name == "" {
		name = field.Name
	}
	options := map[string]bool{}
	for _, option := range tag[1:] {
		options[option] = true
	}
	return name, options
}

func applyTypeContract(object schema, valueType reflect.Type) {
	properties := object["properties"].(schema)
	for name, raw := range properties {
		property := raw.(schema)
		applyNamedProperty(name, property)
	}
	switch valueType.Name() {
	case "BootstrapPrincipalDTO", "PrincipalRegisterBodyDTO", "PrincipalRegisteredPayloadDTO":
		setEnum(properties, "kind", PrincipalKindHuman, PrincipalKindWorkload, PrincipalKindService)
	case "ActorCreateBodyDTO", "ActorCreatedPayloadDTO":
		setEnum(properties, "kind", ActorKindHuman, ActorKindAgent, ActorKindAutomation, ActorKindService)
	case "ApprovedPairingTranscriptRefDTO":
		setConst(properties, "protocol", PairingProtocolV1)
	case "SessionStartBodyDTO":
		setEnum(properties, "start_authority_kind", "trusted_device", "one_use_handoff")
	case "ContextDeltaDTO":
		setConst(properties, "schema", SchemaContextDelta)
		setEnum(properties, "delta_type", "upsert", "remove", "invalidate")
	case "ContextCheckpointDTO":
		setConst(properties, "schema", SchemaContextCheckpoint)
	case "IssuedCeremonyDTO":
		setEnum(properties, "purpose", "membership_acceptance", "delegation_activation", "device_pairing", "actor_session_start")
	case "LeaseHolderDTO":
		setEnum(properties, "selector_kind", string(application.LeaseSelectorExact), string(application.LeaseSelectorSubtree))
	case "ErrorDTO":
		applyErrorContract(object)
	case "EmptyExtensionsDTO":
		object["additionalProperties"] = true
	}
}

func applyNamedProperty(name string, property schema) {
	target := dereferenceNullable(property)
	switch name {
	case "request_id":
		stringBounds(target, 1, maxRequestIDBytes)
	case "idempotency_key":
		stringBounds(target, 1, 128)
	case "event_cursor", "cursor", "after_cursor", "next_cursor", "head_cursor", "through_cursor":
		stringBounds(target, 1, maxCursorBytes)
	case "display_name", "alias":
		stringBounds(target, 1, maxDisplayNameBytes)
	case "objective_title", "work_unit_title":
		stringBounds(target, 1, maxObjectiveTitleBytes)
	case "acceptance_criteria":
		stringBounds(target, 1, maxAcceptanceCriteriaBytes)
	case "provider_namespace", "provider_object_id", "provider_locator", "provider_version":
		stringBounds(target, 1, maxOpaqueProviderValueBytes)
	case "previous_provider_version":
		stringBounds(target, 0, maxOpaqueProviderValueBytes)
	case "role":
		stringBounds(target, 1, maxRunRoleBytes)
	case "participants", "bindings", "participations":
		target["minItems"], target["maxItems"] = 1, domain.MaxRunParticipants
	case "selected_fields":
		target["type"] = "object"
		target["additionalProperties"] = true
	case "discovery_locator":
		stringBounds(target, 0, maxDiscoveryLocatorBytes)
	case "public_key_reference":
		stringBounds(target, 0, 512)
	case "public_key_spki":
		stringBounds(target, 2, 1366)
		target["pattern"] = `^[A-Za-z0-9_-]+$`
	case "transcript_hash", "proof_hash":
		target["minLength"], target["maxLength"] = 64, 64
		target["pattern"] = `^[0-9a-f]{64}$`
	case "capabilities", "owner_capabilities", "capability_ceiling", "effective_capabilities":
		target["minItems"], target["maxItems"], target["uniqueItems"] = 1, maxCapabilityCount, true
		target["items"] = schema{"type": "string", "minLength": 1, "maxLength": maxCapabilityBytes, "pattern": `^[a-z0-9:._-]+$`}
	case "grants", "grant_revisions":
		target["maxItems"], target["uniqueItems"] = maxGrantReferenceCount, true
	case "emitted_event_ids":
		target["minItems"], target["maxItems"], target["uniqueItems"] = 1, maxEventIDCount, true
	case "events", "deltas":
		target["maxItems"] = maxSyncPageCount
	case "limit":
		target["minimum"], target["maximum"] = 1, maxSyncPageCount
	case "retry_after_ms":
		target["minimum"], target["maximum"] = 1, MaxRetryAfterMS
	case "expires_in_ms":
		target["minimum"], target["maximum"] = 1, MaxLeaseExpiresInMS
	case "selector_path":
		stringBounds(target, 1, maxLeaseSelectorPathBytes)
	case "conflict_key":
		stringBounds(target, 1, maxFenceConflictKeyBytes)
	case "expected_counter", "supplied_counter":
		target["minimum"] = 1
	case "message", "detail":
		stringBounds(target, 1, 512)
	case "field":
		stringBounds(target, 1, 256)
	case "code":
		stringBounds(target, 1, 64)
	case "dependency":
		stringBounds(target, 0, 128)
	case "current_state", "state":
		stringBounds(target, 1, 64)
	case "transition_ref":
		stringBounds(target, 0, 256)
	case "event_type":
		stringBounds(target, 1, 256)
	case "event_version", "projection_version":
		target["minimum"] = 1
	}
}

func dereferenceNullable(property schema) schema {
	oneOf, ok := property["oneOf"].([]any)
	if !ok || len(oneOf) == 0 {
		return property
	}
	return oneOf[0].(schema)
}

func stringBounds(property schema, minimum, maximum int) {
	property["minLength"], property["maxLength"] = minimum, maximum
}

func setConst(properties schema, name string, value any) {
	properties[name].(schema)["const"] = value
}

func setEnum(properties schema, name string, values ...string) {
	items := make([]any, len(values))
	for index, value := range values {
		items[index] = value
	}
	properties[name].(schema)["enum"] = items
}

func applyRootContract(object schema, valueType reflect.Type, operation string) {
	properties := object["properties"].(schema)
	if _, present := properties["operation"]; present {
		setConst(properties, "operation", operation)
	}
	if schemaValue := schemaLiteral(valueType); schemaValue != "" {
		setConst(properties, "schema", schemaValue)
	}
	if emitted, present := properties["emitted_event_ids"]; present {
		minimum, maximum := expectedEventCountRange(operation)
		emitted.(schema)["minItems"], emitted.(schema)["maxItems"] = minimum, maximum
	}
}

func schemaLiteral(valueType reflect.Type) string {
	switch valueType {
	case reflect.TypeFor[InstallationBootstrapRequestDTO]():
		return SchemaInstallationBootstrapCommand
	case reflect.TypeFor[PrincipalRegisterRequestDTO]():
		return SchemaPrincipalRegisterCommand
	case reflect.TypeFor[DevicePairingBeginRequestDTO]():
		return SchemaDevicePairingBeginCommand
	case reflect.TypeFor[DevicePairRequestDTO]():
		return SchemaDevicePairCommand
	case reflect.TypeFor[WorkspaceCreateRequestDTO]():
		return SchemaWorkspaceCreateCommand
	case reflect.TypeFor[WorkspaceMemberInviteRequestDTO]():
		return SchemaWorkspaceMemberInviteCommand
	case reflect.TypeFor[WorkspaceMembershipAcceptRequestDTO]():
		return SchemaWorkspaceMembershipAcceptCommand
	case reflect.TypeFor[ActorCreateRequestDTO]():
		return SchemaActorCreateCommand
	case reflect.TypeFor[ActorDelegationProposeRequestDTO]():
		return SchemaActorDelegationProposeCommand
	case reflect.TypeFor[ActorDelegationActivateRequestDTO]():
		return SchemaActorDelegationActivateCommand
	case reflect.TypeFor[SessionStartRequestDTO]():
		return SchemaSessionStartCommand
	case reflect.TypeFor[WorkRefObserveRequestDTO]():
		return SchemaWorkRefObserveCommand
	case reflect.TypeFor[ObjectiveAndWorkCreateRequestDTO]():
		return SchemaObjectiveAndWorkCreateCommand
	case reflect.TypeFor[ObjectiveActivateRequestDTO]():
		return SchemaObjectiveActivateCommand
	case reflect.TypeFor[RunPlanWithBindingsRequestDTO]():
		return SchemaRunPlanWithBindingsCommand
	case reflect.TypeFor[RunJoinRequestDTO]():
		return SchemaRunJoinCommand
	case reflect.TypeFor[RunStartRequestDTO]():
		return SchemaRunStartCommand
	case reflect.TypeFor[ContextGetRequestDTO]():
		return SchemaContextGetRequest
	case reflect.TypeFor[EventsSyncRequestDTO]():
		return SchemaEventsSyncRequest
	case reflect.TypeFor[ContextPageDTO]():
		return SchemaContextPage
	case reflect.TypeFor[EventPageDTO]():
		return SchemaEventPage
	default:
		if strings.HasSuffix(valueType.Name(), "ResultDTO") {
			return SchemaCommandResult
		}
		return ""
	}
}

func expectedEventCountRange(operation string) (int, int) {
	switch operation {
	case OperationInstallationBootstrap, OperationWorkspaceCreate:
		return 3, 3
	case OperationObjectiveAndWorkCreate:
		return 2, 2
	case OperationRunPlanWithBindings:
		return 1, maxEventIDCount
	default:
		return 1, 1
	}
}

func applyErrorContract(object schema) {
	properties := object["properties"].(schema)
	setConst(properties, "schema", SchemaError)
	setEnum(properties, "code",
		"INVALID_ARGUMENT", "INVALID_SCHEMA", "UNAUTHENTICATED", "SESSION_EXPIRED", "FORBIDDEN",
		"CAPABILITY_REQUIRED", "NOT_FOUND", "STALE_VERSION", "STATE_CONFLICT", "IDEMPOTENCY_KEY_REUSED",
		"COMMAND_ID_REUSED", "COMMAND_IN_PROGRESS", "LEASE_CONFLICT", "LEASE_EXPIRED", "FENCE_REJECTED",
		"CURSOR_INVALID", "CURSOR_SCOPE_MISMATCH", "CURSOR_EXPIRED", "RATE_LIMITED", "BACKPRESSURE",
		"DEPENDENCY_UNAVAILABLE", "DEADLINE_EXCEEDED", "INTERNAL")
	setEnum(properties, "category", "validation", "authentication", "authorization", "lookup", "conflict", "contention", "cursor", "capacity", "dependency", "timeout", "internal")
}

func applyProblemSchema(components schema) {
	errorSchema := components["BlackbirdError"].(schema)
	properties := schema{}
	for name, value := range errorSchema["properties"].(schema) {
		properties[name] = value
	}
	properties["type"] = schema{"type": "string", "format": "uri", "pattern": `^https://blackbird\.local/problems/[A-Z_]+$`}
	properties["title"] = schema{"type": "string", "minLength": 1, "maxLength": 64}
	statusEnum := make([]any, 0, len(errorStatusCodes))
	for _, status := range errorStatusCodes {
		statusEnum = append(statusEnum, status)
	}
	properties["status"] = schema{"type": "integer", "enum": statusEnum}
	properties["detail"] = schema{"type": "string", "minLength": 1, "maxLength": 512}
	required := append([]string(nil), errorSchema["required"].([]string)...)
	required = append(required, "type", "title", "status", "detail")
	sort.Strings(required)
	components["Problem"] = schema{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
		"required":             required,
		"description":          "RFC 9457 problem details with the complete Blackbird typed error envelope.",
	}
}
