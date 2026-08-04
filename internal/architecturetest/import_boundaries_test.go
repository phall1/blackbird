package architecturetest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	"domain":           true,
	"application":      true,
	"storage":          true,
	"integration":      true,
	"transport":        true,
	"runtime":          true,
	"architecturetest": true,
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
		{name: "runtime transport", importer: "runtime", importPath: modulePath + "/internal/transport/http"},
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
	case "storage", "integration", "transport":
		if imported != "domain" && imported != "application" && imported != importer {
			return fmt.Errorf("%s may import inward layers or itself; found %s", importer, imported)
		}
	default:
		if outwardLayers[imported] && importer != "runtime" && importer != "cmd" {
			return fmt.Errorf("only runtime or cmd may assemble outward layer %s", imported)
		}
	}

	return nil
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
