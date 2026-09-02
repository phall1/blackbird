package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/phall1/blackbird/internal/domain"
)

const productOpenAPIGoldenSHA256 = "dd32f749ae40ff34d6d4b1934fcc1fb7a7a00f7115ac617fe8787c7da90a8c0b"

func TestProductOpenAPI31IsDeterministicAndComplete(t *testing.T) {
	t.Parallel()
	first, err := ProductOpenAPI31()
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProductOpenAPI31()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("ProductOpenAPI31() is nondeterministic")
	}
	if digest := fmt.Sprintf("%x", sha256.Sum256(first)); digest != productOpenAPIGoldenSHA256 {
		t.Fatalf("ProductOpenAPI31() golden digest = %s, want %s", digest, productOpenAPIGoldenSHA256)
	}
	var document map[string]any
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatalf("generated OpenAPI is not JSON: %v", err)
	}
	if document["openapi"] != "3.1.0" || document["jsonSchemaDialect"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("OpenAPI dialect metadata = %#v", document)
	}
	if got := document["x-blackbird-error-statuses"].(map[string]any); len(got) != len(errorStatusByCode) || got["INVALID_SCHEMA"] != float64(422) || got["DEPENDENCY_UNAVAILABLE"] != float64(503) {
		t.Fatalf("error status matrix = %#v", got)
	}
	paths := document["paths"].(map[string]any)
	if len(paths) != 19 {
		t.Fatalf("path count = %d, want 19", len(paths))
	}
	for _, operation := range productAPIOperations {
		post := paths[operation.Path].(map[string]any)["post"].(map[string]any)
		if post["operationId"] != operation.Operation {
			t.Fatalf("%s operationId = %v", operation.Path, post["operationId"])
		}
		responses := post["responses"].(map[string]any)
		wantStatuses := append([]string{"200"}, errorStatuses...)
		sort.Strings(wantStatuses)
		gotStatuses := make([]string, 0, len(responses))
		for status := range responses {
			gotStatuses = append(gotStatuses, status)
		}
		sort.Strings(gotStatuses)
		if !reflect.DeepEqual(gotStatuses, wantStatuses) {
			t.Fatalf("%s statuses = %v, want %v", operation.Path, gotStatuses, wantStatuses)
		}
	}
}

func TestProductOpenAPI31TypeScriptGeneration(t *testing.T) {
	if os.Getenv("BLACKBIRD_OPENAPI_CLIENT_TEST") != "1" {
		t.Skip("set BLACKBIRD_OPENAPI_CLIENT_TEST=1 to run the external client generator")
	}
	document, err := ProductOpenAPI31()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	input := filepath.Join(directory, "product-v1.json")
	output := filepath.Join(directory, "product-v1.d.ts")
	if err := os.WriteFile(input, document, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("npx", "--yes", "openapi-typescript@7.13.0", input, "--output", output)
	if generated, err := command.CombinedOutput(); err != nil {
		t.Fatalf("openapi-typescript failed: %v\n%s", err, generated)
	}
	types, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range productAPIOperations {
		if !bytes.Contains(types, []byte(operation.Operation)) {
			t.Fatalf("generated client types omit operation %s", operation.Operation)
		}
	}
}

func TestGeneratedSchemasMatchGoDTOFieldsAndRequiredness(t *testing.T) {
	t.Parallel()
	components, err := contractSchemas()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range productAPIOperations {
		assertSchemaMatchesDTO(t, components, operation.Request, operation.Type)
		assertSchemaMatchesDTO(t, components, operation.Response, operation.Output)
	}
	assertSchemaMatchesDTO(t, components, "BlackbirdError", reflect.TypeFor[ErrorDTO]())
}

func TestInputSchemasAreClosedAndConstrained(t *testing.T) {
	t.Parallel()
	components, err := contractSchemas()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range productAPIOperations {
		walkClosedSchema(t, components, operation.Request, map[string]bool{})
	}
	context := components["ContextGetRequest"].(schema)["properties"].(schema)
	if limit := context["limit"].(schema); limit["minimum"] != 1 || limit["maximum"] != maxContextDeltaCount {
		t.Fatalf("context limit bounds = %#v", limit)
	}
	workspace := components["WorkspaceCreateBody"].(schema)["properties"].(schema)
	if alias := workspace["alias"].(schema); alias["maxLength"] != maxDisplayNameBytes {
		t.Fatalf("alias constraints = %#v", alias)
	}
	metadata := components["CommandMetadata"].(schema)["properties"].(schema)
	if deadline := metadata["deadline"].(schema); deadline["format"] != "date-time" {
		t.Fatalf("deadline schema = %#v", deadline)
	}
	identifier := components["WorkspaceCreateBody"].(schema)["properties"].(schema)["workspace_id"].(schema)
	if identifier["format"] != "uuid" || !strings.Contains(identifier["pattern"].(string), "-7") {
		t.Fatalf("workspace identifier schema = %#v", identifier)
	}
}

func TestStandaloneJSONSchemasAreDeterministic(t *testing.T) {
	t.Parallel()
	first, err := JSONSchemas202012()
	if err != nil {
		t.Fatal(err)
	}
	second, err := JSONSchemas202012()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(first) != len(second) {
		t.Fatalf("schema counts = %d and %d", len(first), len(second))
	}
	for name, document := range first {
		if !bytes.Equal(document, second[name]) {
			t.Fatalf("schema %s is nondeterministic", name)
		}
		var decoded map[string]any
		if err := json.Unmarshal(document, &decoded); err != nil {
			t.Fatalf("schema %s is not JSON: %v", name, err)
		}
		if decoded["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("schema %s dialect = %v", name, decoded["$schema"])
		}
		if bytes.Contains(document, []byte("#/components/schemas/")) {
			t.Fatalf("standalone schema %s contains an OpenAPI-only reference", name)
		}
	}
}

func TestCoordinationEvidenceSchemasAreConstrained(t *testing.T) {
	t.Parallel()
	components, err := contractSchemas()
	if err != nil {
		t.Fatal(err)
	}
	details := components["ErrorDetails"].(schema)["properties"].(schema)
	for _, name := range []string{"lease_holder", "expired_lease", "fence_conflict"} {
		if _, described := details[name]; !described {
			t.Fatalf("error details omit %s evidence", name)
		}
	}
	holder := components["LeaseHolder"].(schema)["properties"].(schema)
	if expiry := holder["expires_in_ms"].(schema); expiry["minimum"] != 1 || expiry["maximum"] != MaxLeaseExpiresInMS {
		t.Fatalf("holder expiry bounds = %#v", expiry)
	}
	if kind := holder["selector_kind"].(schema); !reflect.DeepEqual(kind["enum"], []any{"exact", "subtree"}) {
		t.Fatalf("holder selector kind = %#v", kind)
	}
	if selector := holder["selector_path"].(schema); selector["minLength"] != 1 || selector["maxLength"] != maxLeaseSelectorPathBytes {
		t.Fatalf("holder selector path bounds = %#v", selector)
	}
	fence := components["FenceConflict"].(schema)["properties"].(schema)
	if key := fence["conflict_key"].(schema); key["minLength"] != 1 || key["maxLength"] != maxFenceConflictKeyBytes {
		t.Fatalf("fence conflict key bounds = %#v", key)
	}
	for _, name := range []string{"expected_counter", "supplied_counter"} {
		if counter := fence[name].(schema); counter["minimum"] != 1 || counter["maximum"] != domain.MaxCanonicalInteger {
			t.Fatalf("fence %s bounds = %#v", name, counter)
		}
	}
}

func assertSchemaMatchesDTO(t *testing.T, components schema, name string, valueType reflect.Type) {
	t.Helper()
	wantProperties, wantRequired := dtoJSONShape(valueType)
	object := components[name].(schema)
	properties := object["properties"].(schema)
	gotProperties := make([]string, 0, len(properties))
	for field := range properties {
		gotProperties = append(gotProperties, field)
	}
	sort.Strings(gotProperties)
	if !reflect.DeepEqual(gotProperties, wantProperties) {
		t.Fatalf("%s properties = %v, want DTO fields %v", name, gotProperties, wantProperties)
	}
	gotRequired := append([]string(nil), object["required"].([]string)...)
	sort.Strings(gotRequired)
	if !reflect.DeepEqual(gotRequired, wantRequired) {
		t.Fatalf("%s required = %v, want DTO-required %v", name, gotRequired, wantRequired)
	}
}

func dtoJSONShape(valueType reflect.Type) ([]string, []string) {
	properties := []string{}
	required := []string{}
	for index := range valueType.NumField() {
		field := valueType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		if field.Anonymous && field.Tag.Get("json") == "" {
			embeddedProperties, embeddedRequired := dtoJSONShape(field.Type)
			properties = append(properties, embeddedProperties...)
			required = append(required, embeddedRequired...)
			continue
		}
		name, options := jsonField(field)
		if name == "-" {
			continue
		}
		properties = append(properties, name)
		if !options["omitempty"] {
			required = append(required, name)
		}
	}
	sort.Strings(properties)
	sort.Strings(required)
	return properties, required
}

func walkClosedSchema(t *testing.T, components schema, name string, seen map[string]bool) {
	t.Helper()
	if seen[name] {
		return
	}
	seen[name] = true
	object := components[name].(schema)
	if object["type"] == "object" && object["additionalProperties"] != false && name != "EmptyExtensions" {
		t.Fatalf("input component %s is not closed", name)
	}
	for _, raw := range object["properties"].(schema) {
		walkRefs(t, components, raw.(schema), seen)
	}
}

func walkRefs(t *testing.T, components schema, value schema, seen map[string]bool) {
	t.Helper()
	if reference, ok := value["$ref"].(string); ok {
		walkClosedSchema(t, components, strings.TrimPrefix(reference, "#/components/schemas/"), seen)
	}
	if items, ok := value["items"].(schema); ok {
		walkRefs(t, components, items, seen)
	}
	if alternatives, ok := value["oneOf"].([]any); ok {
		for _, alternative := range alternatives {
			walkRefs(t, components, alternative.(schema), seen)
		}
	}
}
