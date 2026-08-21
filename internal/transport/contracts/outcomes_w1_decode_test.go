package contracts

import (
	"testing"

	"github.com/phall1/blackbird/internal/domain"
)

// The work-plane result decoders had no coverage for the same reason the W0
// ones did not: outcomes_w1_test.go builds valid results and calls Validate()
// on them directly, which skips decodeCommandResult entirely. Validate() is
// only half of what a caller reaches — the decoder also bounds the payload and
// demands an explicit idempotent_replay member, and neither was exercised.

func validObjectiveActivateResult(t *testing.T) ObjectiveActivateResultDTO {
	t.Helper()
	workspaceID, err := domain.NewWorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
	objectiveID, err := domain.NewObjectiveID()
	if err != nil {
		t.Fatal(err)
	}
	return ObjectiveActivateResultDTO{
		CommandResultMetadataDTO: w1TestResultMetadata(t, OperationObjectiveActivate, 1),
		Resource: ObjectiveActivateResourceDTO{
			WorkspaceID: workspaceID, ObjectiveID: objectiveID,
			ObjectiveState: string(domain.ObjectiveActive),
			// Activation always supersedes the version the objective was
			// created at, so the contract requires an advanced version.
			ResourceVersion: w1TestAdvancedVersion(t),
		},
	}
}

// w1ResultDecoders pairs each work-plane result decoder with a valid result.
func w1ResultDecoders() map[string]struct {
	decode func([]byte) error
	valid  func(*testing.T) any
} {
	return map[string]struct {
		decode func([]byte) error
		valid  func(*testing.T) any
	}{
		"work ref observe": {
			decode: func(data []byte) error { _, err := DecodeWorkRefObserveResult(data); return err },
			valid:  func(t *testing.T) any { return validWorkRefObserveResult(t) },
		},
		"objective and work create": {
			decode: func(data []byte) error { _, err := DecodeObjectiveAndWorkCreateResult(data); return err },
			valid:  func(t *testing.T) any { return validObjectiveAndWorkCreateResult(t) },
		},
		"objective activate": {
			decode: func(data []byte) error { _, err := DecodeObjectiveActivateResult(data); return err },
			valid:  func(t *testing.T) any { return validObjectiveActivateResult(t) },
		},
		"run plan with bindings": {
			decode: func(data []byte) error { _, err := DecodeRunPlanWithBindingsResult(data); return err },
			valid:  func(t *testing.T) any { return validRunPlanWithBindingsResult(t) },
		},
		"run join": {
			decode: func(data []byte) error { _, err := DecodeRunJoinResult(data); return err },
			valid:  func(t *testing.T) any { return validRunJoinResult(t) },
		},
		"run start": {
			decode: func(data []byte) error { _, err := DecodeRunStartResult(data); return err },
			valid:  func(t *testing.T) any { return validRunStartResult(t) },
		},
	}
}

// TestW1ResultDecodersAdmitWellFormedResults reaches each decoder with the
// result its own operation produces.
func TestW1ResultDecodersAdmitWellFormedResults(t *testing.T) {
	t.Parallel()

	for name, decoder := range w1ResultDecoders() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := decoder.decode(mustMarshal(t, decoder.valid(t))); err != nil {
				t.Fatalf("a well-formed result was rejected: %v", err)
			}
		})
	}
}

// TestW1ResultDecodersRequireAnExplicitIdempotentReplay is the contract a Go
// zero value cannot carry: absent and false decode identically, but they mean
// "the daemon did not say" and "this was a first execution". A caller that
// reads a replay as a fresh execution acts twice on one command.
func TestW1ResultDecodersRequireAnExplicitIdempotentReplay(t *testing.T) {
	t.Parallel()

	for name, decoder := range w1ResultDecoders() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded := mustMarshal(t, decoder.valid(t))
			if err := decoder.decode(encoded); err != nil {
				t.Fatalf("a well-formed result was rejected: %v", err)
			}
			if err := decoder.decode(mustRemoveJSONField(t, encoded, `,"idempotent_replay":false`)); err == nil {
				t.Fatal("decode() accepted a result with no idempotent_replay member")
			}
		})
	}
}

// TestW1ResultDecodersTolerateUnknownMembers pins a deliberate asymmetry that
// is otherwise invisible. Requests decode through decodeCommandInput, which
// sets DisallowUnknownFields: inbound data is untrusted, so an unrecognised
// member is refused. Results decode through decodeOutput, which does not:
// a result comes from the daemon, and refusing unknown members would strand
// every older client the moment a newer daemon adds a field.
//
// This is asserted rather than assumed because a later "tighten the decoders"
// change would look like a strict improvement and would silently break forward
// compatibility for shipped clients.
func TestW1ResultDecodersTolerateUnknownMembers(t *testing.T) {
	t.Parallel()

	for name, decoder := range w1ResultDecoders() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			extended := addTopLevelJSONField(mustMarshal(t, decoder.valid(t)), `"field_from_a_newer_daemon":true`)
			if err := decoder.decode(extended); err != nil {
				t.Fatalf("an unknown member broke forward compatibility: %v", err)
			}
		})
	}
}

// TestW1ResultDecodersRejectMalformedJSON covers what the result decoders do
// still refuse. Tolerating unknown members is not tolerating an ambiguous or
// truncated document: a duplicate key makes the value that wins arbitrary, and
// a second JSON value after the result makes the payload's meaning ambiguous.
func TestW1ResultDecodersRejectMalformedJSON(t *testing.T) {
	t.Parallel()

	for name, decoder := range w1ResultDecoders() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded := mustMarshal(t, decoder.valid(t))
			cases := map[string][]byte{
				"not an object":  []byte(`["not","an","object"]`),
				"truncated":      encoded[:len(encoded)/2],
				"empty":          nil,
				"trailing value": append(append([]byte(nil), encoded...), []byte(`{"second":true}`)...),
				"duplicate key":  addTopLevelJSONField(encoded, `"schema":"`+SchemaCommandResult+`"`),
				"oversize":       append(append([]byte(nil), encoded...), make([]byte, MaxOutcomeJSONBytes)...),
			}
			for caseName, data := range cases {
				if err := decoder.decode(data); err == nil {
					t.Fatalf("%s: decode() error = nil, want a rejection", caseName)
				}
			}
		})
	}
}

// TestObjectiveActivateResultRequiresAnAdvancedVersion covers the one binding
// this result has that its siblings do not. Activation mutates an objective
// that already exists, so reporting the initial version would describe a
// resource that was never activated at all.
func TestObjectiveActivateResultRequiresAnAdvancedVersion(t *testing.T) {
	t.Parallel()

	initial := validObjectiveActivateResult(t)
	initial.Resource.ResourceVersion = domain.InitialVersion()
	rejects(t, "initial version", initial.Validate(), "resource.resource_version")

	wrongState := validObjectiveActivateResult(t)
	wrongState.Resource.ObjectiveState = string(domain.ObjectiveDraft)
	rejects(t, "draft state", wrongState.Validate(), "resource.objective_state")
}

// TestDecodeObjectiveActivateRequestAdmitsAndRejects reaches the last work-plane
// request decoder. Its fixture lives beside the handler tests, which call
// Values() directly and never encode.
func TestDecodeObjectiveActivateRequestAdmitsAndRejects(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)

	decoded, err := DecodeObjectiveActivateRequest(mustMarshal(t, objectiveActivateTestDTO(t, fixture)))
	if err != nil {
		t.Fatalf("DecodeObjectiveActivateRequest() error = %v", err)
	}
	if decoded.Operation != OperationObjectiveActivate {
		t.Fatalf("operation = %q, want %q", decoded.Operation, OperationObjectiveActivate)
	}

	wrongOperation := objectiveActivateTestDTO(t, fixture)
	wrongOperation.Operation = OperationRunStart
	if _, err := DecodeObjectiveActivateRequest(mustMarshal(t, wrongOperation)); err == nil {
		t.Fatal("an operation naming another command was accepted")
	}

	wrongSchema := objectiveActivateTestDTO(t, fixture)
	wrongSchema.Schema = SchemaRunStartCommand
	if _, err := DecodeObjectiveActivateRequest(mustMarshal(t, wrongSchema)); err == nil {
		t.Fatal("a schema naming another command was accepted")
	}
}
