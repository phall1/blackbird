package architecturetest

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/phall1/blackbird"

var outwardLayers = map[string]bool{
	"storage":     true,
	"integration": true,
	"transport":   true,
}

var allowedInternalLayers = map[string]bool{
	"adminapi":         true,
	"domain":           true,
	"application":      true,
	"storage":          true,
	"integration":      true,
	"transport":        true,
	"runtime":          true,
	"install":          true,
	"cli":              true,
	"architecturetest": true,
}

// applicationPlaneRank orders the planes inside internal/application.
//
// Layer is the first path segment under internal/, so "application may import
// only domain and itself" says nothing at all about coordination and telemetry:
// both are layer "application", and Go's import-cycle rule is the only thing
// standing between them. A cycle is not a direction. This map states the
// direction the code already runs in.
//
// It is the ordering ADR-0001 decided -- "coordination is the product;
// telemetry is a projection against it" -- and the one the tree implements:
// coordination imports nothing but domain, and telemetry imports coordination
// for the contracts it attributes observations against. Forbidding every
// sibling edge would have needed an exception on its first day. An allowed-edge
// list would have recorded that one edge without saying which way the next one
// must run. A rank says why, and answers for pairs that do not exist yet.
//
// Given a plane's rank:
//
//   - A plane may import a strictly lower-ranked plane, and itself.
//   - A plane may never import a higher-ranked one. That is the inversion
//     ADR-0001 turns on: coordination must not know telemetry exists, or a
//     failing observation acquires a route into a lease write.
//   - Equal ranks are declared peers -- independent, and forbidden from
//     importing each other in either direction. Give one a rank when a real
//     edge appears, rather than discovering the direction from whichever
//     import someone wrote first.
//
// The numbers are an ordering, not a schedule and not a count. Inserting a
// plane between two existing ones means renumbering, which is the point: the
// direction has to be restated deliberately.
var applicationPlaneRank = map[string]int{
	"coordination": 0,
	"telemetry":    1,
}

// TestDeclaredLayersAllExist keeps the allow-list from rotting in the direction
// the import rules cannot see. A new top-level directory under internal/ fails
// loudly because it is undeclared, but a deleted one leaves an entry that
// silently authorizes a layer nobody can import — and the next reader takes the
// list as a description of the tree. Derive the layers from the tree instead of
// trusting the list: internal/companion outlived its own deletion here.
func TestDeclaredLayersAllExist(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	for layer := range allowedInternalLayers {
		info, err := os.Stat(filepath.Join(root, "internal", layer))
		if err != nil || !info.IsDir() {
			t.Errorf("allowedInternalLayers declares %q, but internal/%s is not a directory", layer, layer)
		}
	}
}

// TestDeclaredApplicationPlanesMatchTree holds applicationPlaneRank to the tree
// in both directions, for the reason TestDeclaredLayersAllExist exists. A
// declared plane whose directory is gone keeps authorizing edges nobody can
// write, and reads as a description of a tree that no longer has it. A new
// sub-package that nobody declared would inherit the application layer's rules
// and none of the ordering -- which is exactly the hole this file closes, so it
// must not reopen by default.
//
// It also fails a package placed directly in internal/application: the layer
// root is a namespace, not a package, because a plane-less package has no rank
// and therefore no statable direction against anything.
func TestDeclaredApplicationPlanesMatchTree(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	applicationDir := filepath.Join(root, "internal", "application")

	for plane := range applicationPlaneRank {
		info, err := os.Stat(filepath.Join(applicationDir, plane))
		if err != nil || !info.IsDir() {
			t.Errorf("applicationPlaneRank declares %q, but internal/application/%s is not a directory",
				plane, plane)
		}
	}

	entries, err := os.ReadDir(applicationDir)
	if err != nil {
		t.Fatalf("read internal/application: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() {
			if filepath.Ext(name) == ".go" {
				t.Errorf("internal/application/%s sits at the layer root, which holds no packages: move it into "+
					"a plane declared in applicationPlaneRank (%s). A plane-less package has no rank, so no "+
					"import to or from it has a stated direction",
					name, applicationPlaneOrdering(applicationPlaneRank))
			}
			continue
		}
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" {
			continue
		}
		if _, declared := applicationPlaneRank[name]; !declared {
			t.Errorf("internal/application/%s is an undeclared application plane: add it to applicationPlaneRank "+
				"with a rank that states its direction against %s -- strictly higher than every plane it may "+
				"import, strictly lower than every plane that may import it, equal only to planes it must not "+
				"exchange imports with at all",
				name, applicationPlaneOrdering(applicationPlaneRank))
		}
	}
}

func TestProductionImportBoundaries(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	standard := standardLibrary(t, root)
	fileSet := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		importer, known := layerFor(filepath.ToSlash(filepath.Dir(relative)))
		if !known {
			t.Errorf("%s: undeclared internal layer %q", relative, importer)
			return nil
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: decode import: %w", relative, err)
			}
			if forbiddenImport(importPath) {
				position := fileSet.Position(imported.Pos())
				t.Errorf("%s: forbidden legacy or proof import %q", position, importPath)
				continue
			}
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			if err := validateImport(importer, importPath, standard); err != nil {
				position := fileSet.Position(imported.Pos())
				t.Errorf("%s: %v", position, err)
				continue
			}
			if err := validatePackageImport(filepath.ToSlash(filepath.Dir(relative)), importPath); err != nil {
				position := fileSet.Position(imported.Pos())
				t.Errorf("%s: %v", position, err)
				continue
			}
			if err := validateApplicationPlaneImport(
				filepath.ToSlash(filepath.Dir(relative)), importPath, applicationPlaneRank); err != nil {
				position := fileSet.Position(imported.Pos())
				t.Errorf("%s: %v", position, err)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("scan production imports: %v", err)
	}
}

func TestModuleGraphAndPackageSourcesAvoidProofAndLegacyTrees(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	forbiddenRoots := []string{
		filepath.Join(filepath.Dir(root), "spikes", "go-stack"),
		filepath.Join(filepath.Dir(root), "src", "mcp_agent_mail"),
	}

	modules := commandJSON[moduleRecord](t, root, "go", "list", "-m", "-json", "all")
	for _, module := range modules {
		checkModuleRecord(t, root, forbiddenRoots, module)
	}

	packages := commandJSON[packageRecord](t, root, "go", "list", "-deps", "-test", "-json", "./...")
	for _, pkg := range packages {
		if forbiddenImport(pkg.ImportPath) {
			t.Errorf("resolved forbidden package import %q", pkg.ImportPath)
		}
		checkSourceDirectory(t, root, forbiddenRoots, pkg.Dir)
		if pkg.Module != nil {
			checkModuleRecord(t, root, forbiddenRoots, *pkg.Module)
		}
	}

	edits := commandJSON[goModEdit](t, root, "go", "mod", "edit", "-json")
	if len(edits) != 1 {
		t.Fatalf("go mod edit returned %d documents, want 1", len(edits))
	}
	for _, replacement := range edits[0].Replace {
		if forbiddenImport(replacement.New.Path) {
			t.Errorf("go.mod replacement points at forbidden module %q", replacement.New.Path)
		}
		if replacement.New.Version == "" {
			checkSourceDirectory(t, root, forbiddenRoots, replacement.New.Path)
		}
	}
}

func TestBoundaryPolicyExamples(t *testing.T) {
	t.Parallel()

	standard := map[string]bool{"context": true, "fmt": true}
	tests := []struct {
		name       string
		importer   string
		importPath string
		wantError  bool
	}{
		{name: "domain standard library", importer: "domain", importPath: "context"},
		{name: "domain same layer", importer: "domain", importPath: modulePath + "/internal/domain/identity"},
		{name: "domain external", importer: "domain", importPath: "example.com/id", wantError: true},
		{name: "domain application", importer: "domain", importPath: modulePath + "/internal/application", wantError: true},
		{name: "application domain", importer: "application", importPath: modulePath + "/internal/domain"},
		{name: "application same layer", importer: "application", importPath: modulePath + "/internal/application/ports"},
		{name: "application storage", importer: "application", importPath: modulePath + "/internal/storage/sqlite", wantError: true},
		{name: "storage application", importer: "storage", importPath: modulePath + "/internal/application"},
		{name: "storage integration", importer: "storage", importPath: modulePath + "/internal/integration/phux", wantError: true},
		{name: "storage runtime", importer: "storage", importPath: modulePath + "/internal/runtime", wantError: true},
		{name: "transport admin API", importer: "transport", importPath: modulePath + "/internal/adminapi"},
		{name: "runtime transport", importer: "runtime", importPath: modulePath + "/internal/transport/http"},
		{name: "install same layer", importer: "install", importPath: modulePath + "/internal/install/probe"},
		{name: "install domain", importer: "install", importPath: modulePath + "/internal/domain", wantError: true},
		{name: "install application", importer: "install", importPath: modulePath + "/internal/application", wantError: true},
		{name: "cli install", importer: "cli", importPath: modulePath + "/internal/install"},
		{name: "cli same layer", importer: "cli", importPath: modulePath + "/internal/cli/render"},
		{name: "cli admin API", importer: "cli", importPath: modulePath + "/internal/adminapi"},
		{name: "cli domain", importer: "cli", importPath: modulePath + "/internal/domain", wantError: true},
		{name: "cli application", importer: "cli", importPath: modulePath + "/internal/application", wantError: true},
		{name: "cli runtime", importer: "cli", importPath: modulePath + "/internal/runtime", wantError: true},
		{name: "cli storage", importer: "cli", importPath: modulePath + "/internal/storage/sqlite", wantError: true},
		{name: "cli transport", importer: "cli", importPath: modulePath + "/internal/transport/http", wantError: true},
		{name: "cmd assembles cli", importer: "cmd", importPath: modulePath + "/internal/cli"},
		{name: "unknown assembles storage", importer: "other", importPath: modulePath + "/internal/storage/sqlite", wantError: true},
		{name: "undeclared internal import", importer: "runtime", importPath: modulePath + "/internal/experimental", wantError: true},
		{name: "spike forbidden", importer: "runtime", importPath: "github.com/phall1/blackmail/spikes/go-stack/internal/application", wantError: true},
		{name: "legacy forbidden", importer: "runtime", importPath: "github.com/phall1/blackmail/src/mcp_agent_mail", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateImport(test.importer, test.importPath, standard)
			if (err != nil) != test.wantError {
				t.Fatalf("validateImport(%q, %q) error = %v, wantError=%t", test.importer, test.importPath, err, test.wantError)
			}
		})
	}

	layerTests := []struct {
		directory string
		wantLayer string
		wantKnown bool
	}{
		{directory: "internal/adminapi", wantLayer: "adminapi", wantKnown: true},
		{directory: "internal/domain/identity", wantLayer: "domain", wantKnown: true},
		{directory: "internal/architecturetest", wantLayer: "architecturetest", wantKnown: true},
		{directory: "internal/experimental", wantLayer: "experimental", wantKnown: false},
		{directory: "cmd/blackbird", wantLayer: "cmd", wantKnown: true},
	}
	for _, test := range layerTests {
		gotLayer, gotKnown := layerFor(test.directory)
		if gotLayer != test.wantLayer || gotKnown != test.wantKnown {
			t.Errorf("layerFor(%q) = (%q, %t), want (%q, %t)", test.directory, gotLayer, gotKnown, test.wantLayer, test.wantKnown)
		}
	}

	packageTests := []struct {
		name       string
		importer   string
		importPath string
		wantError  bool
	}{
		{name: "sqlite same package", importer: "internal/storage/sqlite", importPath: modulePath + "/internal/storage/sqlite/internal"},
		{name: "sqlite postgres", importer: "internal/storage/sqlite", importPath: modulePath + "/internal/storage/postgres", wantError: true},
		{name: "sqlite child postgres", importer: "internal/storage/sqlite/codec", importPath: modulePath + "/internal/storage/postgres", wantError: true},
		{name: "sqlite postgres child", importer: "internal/storage/sqlite", importPath: modulePath + "/internal/storage/postgres/codec", wantError: true},
		{name: "sqlite similarly named package", importer: "internal/storage/sqlite", importPath: modulePath + "/internal/storage/postgresql"},
		{name: "similarly named importer", importer: "internal/storage/sqlite2", importPath: modulePath + "/internal/storage/postgres"},
		{name: "other storage adapter postgres", importer: "internal/storage/memory", importPath: modulePath + "/internal/storage/postgres"},
	}
	for _, test := range packageTests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePackageImport(test.importer, test.importPath)
			if (err != nil) != test.wantError {
				t.Fatalf("validatePackageImport(%q, %q) error = %v, wantError=%t",
					test.importer, test.importPath, err, test.wantError)
			}
		})
	}
}

func TestApplicationPlanePolicyExamples(t *testing.T) {
	t.Parallel()

	// A fixture rather than applicationPlaneRank, so these cases keep asserting
	// the rule when the real planes change, and so the peer case is reachable
	// without inventing a directory.
	ranks := map[string]int{"coordination": 0, "telemetry": 1, "ledger": 1, "reporting": 2}
	const application = modulePath + "/internal/application"

	tests := []struct {
		name       string
		importer   string
		importPath string
		wantError  bool
	}{
		{name: "higher imports lower", importer: "internal/application/telemetry", importPath: application + "/coordination"},
		{name: "lower imports higher", importer: "internal/application/coordination", importPath: application + "/telemetry", wantError: true},
		{name: "skips a rank downward", importer: "internal/application/reporting", importPath: application + "/coordination"},
		{name: "skips a rank upward", importer: "internal/application/coordination", importPath: application + "/reporting", wantError: true},
		{name: "own plane", importer: "internal/application/telemetry", importPath: application + "/telemetry"},
		{name: "own plane child", importer: "internal/application/telemetry", importPath: application + "/telemetry/sink"},
		{name: "nested importer downward", importer: "internal/application/telemetry/sink", importPath: application + "/coordination"},
		{name: "nested importer upward", importer: "internal/application/coordination/ports", importPath: application + "/telemetry", wantError: true},
		{name: "child of a lower plane", importer: "internal/application/telemetry", importPath: application + "/coordination/ports"},
		{name: "child of a higher plane", importer: "internal/application/coordination", importPath: application + "/telemetry/sink", wantError: true},
		{name: "declared peers", importer: "internal/application/telemetry", importPath: application + "/ledger", wantError: true},
		{name: "declared peers reversed", importer: "internal/application/ledger", importPath: application + "/telemetry", wantError: true},
		{name: "undeclared importer plane", importer: "internal/application/experimental", importPath: application + "/coordination", wantError: true},
		{name: "undeclared imported plane", importer: "internal/application/telemetry", importPath: application + "/experimental", wantError: true},
		{name: "layer root importer", importer: "internal/application", importPath: application + "/coordination", wantError: true},
		{name: "layer root import path", importer: "internal/application/telemetry", importPath: application, wantError: true},
		{name: "domain import", importer: "internal/application/telemetry", importPath: modulePath + "/internal/domain"},
		{name: "external import", importer: "internal/application/coordination", importPath: "golang.org/x/text/unicode/norm"},
		{name: "outward importer reads a plane", importer: "internal/storage/sqlite", importPath: application + "/telemetry"},
		{name: "runtime assembles both planes", importer: "internal/runtime", importPath: application + "/coordination"},
		{name: "similarly named importer layer", importer: "internal/applicationtest/telemetry", importPath: application + "/telemetry"},
		{name: "similarly named imported layer", importer: "internal/application/coordination", importPath: modulePath + "/internal/applicationtest/telemetry"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateApplicationPlaneImport(test.importer, test.importPath, ranks)
			if (err != nil) != test.wantError {
				t.Fatalf("validateApplicationPlaneImport(%q, %q) error = %v, wantError=%t",
					test.importer, test.importPath, err, test.wantError)
			}
		})
	}

	if got := applicationPlaneOrdering(ranks); got != "coordination(0) < ledger(1) = telemetry(1) < reporting(2)" {
		t.Errorf("applicationPlaneOrdering(...) = %q", got)
	}
}

func validateImport(importer, importPath string, standard map[string]bool) error {
	if forbiddenImport(importPath) {
		return fmt.Errorf("forbidden legacy or proof import %q", importPath)
	}

	imported := importedLayer(importPath)
	if strings.HasPrefix(importPath, modulePath+"/internal/") && !allowedInternalLayers[imported] {
		return fmt.Errorf("import uses undeclared internal layer %q", imported)
	}
	if importer == "domain" && imported != "domain" && !standard[importPath] {
		return fmt.Errorf("domain must use the standard library only; found %q", importPath)
	}
	if imported == "" {
		return nil
	}

	switch importer {
	case "domain":
		if imported != "domain" {
			return fmt.Errorf("domain cannot import %s", imported)
		}
	case "application":
		if imported != "domain" && imported != "application" {
			return fmt.Errorf("application may import only its own layer and domain among Blackbird packages; found %s", imported)
		}
	case "adminapi":
		if imported != "adminapi" {
			return fmt.Errorf("adminapi may import only itself among Blackbird packages; found %s", imported)
		}
	case "storage", "integration", "transport":
		if imported != "adminapi" && imported != "domain" && imported != "application" && imported != importer {
			return fmt.Errorf("%s may import inward layers or itself; found %s", importer, imported)
		}
	case "install":
		if imported != "install" {
			return fmt.Errorf("install may import only its own layer among Blackbird packages; found %s", imported)
		}
	case "cli":
		if imported != "adminapi" && imported != "cli" && imported != "install" {
			return fmt.Errorf("cli may import only adminapi, its own layer, and install among Blackbird packages; found %s", imported)
		}
	default:
		if outwardLayers[imported] && importer != "runtime" && importer != "cmd" {
			return fmt.Errorf("only runtime or cmd may assemble outward layer %s", imported)
		}
	}

	return nil
}

func validatePackageImport(importer, importPath string) error {
	const (
		sqlite   = "internal/storage/sqlite"
		postgres = modulePath + "/internal/storage/postgres"
	)
	fromSQLite := importer == sqlite || strings.HasPrefix(importer, sqlite+"/")
	toPostgres := importPath == postgres || strings.HasPrefix(importPath, postgres+"/")
	if fromSQLite && toPostgres {
		return fmt.Errorf("sqlite cannot import the postgres adapter")
	}
	return nil
}

// validateApplicationPlaneImport enforces the direction declared in ranks for
// imports that both start and end inside internal/application. Every other edge
// is somebody else's rule: validateImport already governs what may reach the
// application layer from outside it, and what the layer may reach.
func validateApplicationPlaneImport(importerDir, importPath string, ranks map[string]int) error {
	importer, fromApplication := applicationPlane(importerDir)
	if !fromApplication {
		return nil
	}
	imported, toApplication := importedApplicationPlane(importPath)
	if !toApplication || imported == importer {
		return nil
	}

	ordering := applicationPlaneOrdering(ranks)
	if importer == "" || imported == "" {
		return fmt.Errorf("internal/application holds no packages of its own, only planes (%s): "+
			"an edge between the layer root and %q has no direction to check. Move the root package into the "+
			"plane that owns it", ordering, importPath)
	}

	importerRank, importerDeclared := ranks[importer]
	if !importerDeclared {
		return fmt.Errorf("undeclared application plane %q: declare it in applicationPlaneRank (%s) before it "+
			"imports %q, so the direction is a decision rather than whatever the first import happened to be",
			importer, ordering, imported)
	}
	importedRank, importedDeclared := ranks[imported]
	if !importedDeclared {
		return fmt.Errorf("plane %q imports undeclared application plane %q: declare %q in applicationPlaneRank "+
			"(%s) with a rank strictly below %q, or this edge has no stated direction",
			importer, imported, imported, ordering, importer)
	}

	switch {
	case importedRank < importerRank:
		return nil
	case importedRank == importerRank:
		return fmt.Errorf("illegal application plane edge %s -> %s: the two are declared peers at rank %d (%s), "+
			"which means neither may import the other, in either direction. Decide the direction by giving one a "+
			"lower rank in applicationPlaneRank -- the importable one goes lower -- or move the shared contract "+
			"down into a plane below both",
			importer, imported, importerRank, ordering)
	default:
		return fmt.Errorf("illegal application plane edge %s -> %s: application planes are strictly ordered "+
			"(%s) and imports may only run downward, from a higher plane to a lower one. The arrow points the "+
			"other way here: %s may import %s, never the reverse. Invert the dependency -- move the shared "+
			"contract down into %s and have %s depend on it -- rather than adding an exception",
			importer, imported, ordering, imported, importer, importer, imported)
	}
}

// applicationPlane names the plane owning a directory relative to the module
// root. It reports false outside internal/application, and an empty plane for
// the layer's own root directory.
func applicationPlane(relativeDir string) (string, bool) {
	parts := strings.Split(strings.Trim(relativeDir, "/"), "/")
	if len(parts) < 2 || parts[0] != "internal" || parts[1] != "application" {
		return "", false
	}
	if len(parts) == 2 {
		return "", true
	}
	return parts[2], true
}

// importedApplicationPlane names the plane an import path resolves to, matching
// on whole path segments so a similarly named layer is not mistaken for one.
func importedApplicationPlane(importPath string) (string, bool) {
	const prefix = modulePath + "/internal/application"
	if importPath == prefix {
		return "", true
	}
	if !strings.HasPrefix(importPath, prefix+"/") {
		return "", false
	}
	return strings.Split(strings.TrimPrefix(importPath, prefix+"/"), "/")[0], true
}

// applicationPlaneOrdering renders the declared order for a failure message,
// because a boundary error that names a violation without naming the intended
// direction leaves the reader to guess which side to change.
func applicationPlaneOrdering(ranks map[string]int) string {
	planes := make([]string, 0, len(ranks))
	for plane := range ranks {
		planes = append(planes, plane)
	}
	slices.SortFunc(planes, func(left, right string) int {
		return cmp.Or(cmp.Compare(ranks[left], ranks[right]), cmp.Compare(left, right))
	})

	var ordering strings.Builder
	for index, plane := range planes {
		if index > 0 {
			separator := " < "
			if ranks[plane] == ranks[planes[index-1]] {
				separator = " = "
			}
			ordering.WriteString(separator)
		}
		fmt.Fprintf(&ordering, "%s(%d)", plane, ranks[plane])
	}
	return ordering.String()
}

func forbiddenImport(importPath string) bool {
	return strings.Contains(importPath, "/spikes/go-stack") || strings.Contains(importPath, "/src/mcp_agent_mail")
}

func importedLayer(importPath string) string {
	const internalPrefix = modulePath + "/internal/"
	if strings.HasPrefix(importPath, internalPrefix) {
		return strings.Split(strings.TrimPrefix(importPath, internalPrefix), "/")[0]
	}
	if strings.HasPrefix(importPath, modulePath+"/cmd/") {
		return "cmd"
	}
	return ""
}

func layerFor(relativeDir string) (string, bool) {
	parts := strings.Split(strings.Trim(relativeDir, "/"), "/")
	if len(parts) == 0 {
		return "other", true
	}
	if parts[0] == "cmd" {
		return "cmd", true
	}
	if len(parts) >= 2 && parts[0] == "internal" {
		return parts[1], allowedInternalLayers[parts[1]]
	}
	return "other", true
}

type moduleRecord struct {
	Path    string
	Dir     string
	GoMod   string
	Replace *moduleRecord
}

type packageRecord struct {
	ImportPath string
	Dir        string
	Module     *moduleRecord
}

type moduleVersion struct {
	Path    string
	Version string
}

type goModEdit struct {
	Replace []struct {
		Old moduleVersion
		New moduleVersion
	}
}

func commandJSON[T any](t *testing.T, directory string, name string, args ...string) []T {
	t.Helper()

	command := exec.Command(name, args...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		t.Fatalf("run %s %s: %v", name, strings.Join(args, " "), err)
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	var records []T
	for {
		var record T
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			return records
		} else if err != nil {
			t.Fatalf("decode %s %s output: %v", name, strings.Join(args, " "), err)
		}
		records = append(records, record)
	}
}

func checkModuleRecord(t *testing.T, root string, forbiddenRoots []string, module moduleRecord) {
	t.Helper()

	if forbiddenImport(module.Path) {
		t.Errorf("resolved forbidden module %q", module.Path)
	}
	checkSourceDirectory(t, root, forbiddenRoots, module.Dir)
	checkSourceDirectory(t, root, forbiddenRoots, module.GoMod)
	if module.Replace != nil {
		checkModuleRecord(t, root, forbiddenRoots, *module.Replace)
	}
}

func checkSourceDirectory(t *testing.T, root string, forbiddenRoots []string, source string) {
	t.Helper()
	if source == "" {
		return
	}

	resolved := source
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(root, resolved)
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		t.Errorf("resolve source path %q: %v", source, err)
		return
	}
	if evaluated, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = evaluated
	}

	for _, forbiddenRoot := range forbiddenRoots {
		forbiddenAbsolute, err := filepath.Abs(forbiddenRoot)
		if err != nil {
			t.Errorf("resolve forbidden source root %q: %v", forbiddenRoot, err)
			continue
		}
		if evaluated, err := filepath.EvalSymlinks(forbiddenAbsolute); err == nil {
			forbiddenAbsolute = evaluated
		}
		relative, err := filepath.Rel(forbiddenAbsolute, absolute)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			t.Errorf("resolved source %q is inside forbidden tree %q", absolute, forbiddenAbsolute)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	return root
}

func standardLibrary(t *testing.T, root string) map[string]bool {
	t.Helper()

	command := exec.Command("go", "list", "std")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list standard library: %v", err)
	}

	standard := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		standard[scanner.Text()] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read standard-library list: %v", err)
	}
	return standard
}
