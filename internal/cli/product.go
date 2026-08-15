package cli

import (
	"context"
	"strings"

	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

// InstallCmd installs the per-user service, the unattended updater, and the MCP
// client entries. The rendered line preserves the pre-0.4 output exactly.
type InstallCmd struct{}

type installReport struct {
	ServicePath  string   `json:"service_path"`
	UpdaterPaths []string `json:"updater_paths"`
	Clients      []string `json:"clients"`
}

func (cmd *InstallCmd) Run(ctx context.Context, console *Console) error {
	manager, err := console.product()
	if err != nil {
		return err
	}
	result, err := manager.Install(ctx)
	if err != nil {
		return fault(ExitError, err, "install")
	}
	return console.present(newView(installReport{
		ServicePath:  result.ServicePath,
		UpdaterPaths: result.UpdaterPaths,
		Clients:      result.Clients,
	}, drawInstall))
}

func drawInstall(doc *render.Document, report installReport) {
	doc.Linef(render.RolePlain, "installed service=%s updater=%s clients=%s",
		report.ServicePath, joinOrNone(report.UpdaterPaths), joinOrNone(report.Clients))
}

// UpdateCmd upgrades through Homebrew and converges the service definition.
type UpdateCmd struct{}

type updateReport struct {
	Changed           bool   `json:"changed"`
	Before            string `json:"before"`
	After             string `json:"after"`
	DefinitionSkipped bool   `json:"definition_skipped,omitempty"`
}

func (cmd *UpdateCmd) Run(ctx context.Context, console *Console) error {
	manager, err := console.product()
	if err != nil {
		return err
	}
	result, err := manager.Update(ctx)
	if err != nil {
		return fault(ExitError, err, "update")
	}
	return console.present(newView(updateReport{
		Changed:           result.Changed,
		Before:            result.Before,
		After:             result.After,
		DefinitionSkipped: result.DefinitionSkipped,
	}, drawUpdate))
}

func drawUpdate(doc *render.Document, report updateReport) {
	doc.Linef(render.RolePlain, "updated changed=%t before=%q after=%q",
		report.Changed, report.Before, report.After)
}

// UninstallCmd stops and removes the service and updater. Data is retained.
type UninstallCmd struct{}

type uninstallReport struct {
	ServicePath  string   `json:"service_path"`
	UpdaterPaths []string `json:"updater_paths"`
	Data         string   `json:"data"`
}

func (cmd *UninstallCmd) Run(ctx context.Context, console *Console) error {
	manager, err := console.product()
	if err != nil {
		return err
	}
	result, err := manager.Uninstall(ctx)
	if err != nil {
		return fault(ExitError, err, "uninstall")
	}
	return console.present(newView(uninstallReport{
		ServicePath:  result.ServicePath,
		UpdaterPaths: result.UpdaterPaths,
		Data:         "retained",
	}, drawUninstall))
}

func drawUninstall(doc *render.Document, report uninstallReport) {
	doc.Linef(render.RolePlain, "uninstalled service=%s updater=%s data=%s",
		report.ServicePath, joinOrNone(report.UpdaterPaths), report.Data)
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ",")
}

// serviceFacts parses the installer's status line into its key=value pairs.
// Manager.Status is the single source of truth for installation state; parsing
// it here keeps status and doctor from re-deriving facts the installer owns.
func serviceFacts(line string) map[string]string {
	facts := make(map[string]string)
	var lastKey string
	starts := factKeyOffsets(line)
	for index, start := range starts {
		end := len(line)
		if index+1 < len(starts) {
			end = starts[index+1]
		}
		key, value, found := strings.Cut(strings.TrimRight(line[start:end], " "), "=")
		if !found {
			continue
		}
		if _, seen := facts[key]; seen && lastKey != "" {
			key = lastKey + "_" + key
		}
		facts[key] = value
		lastKey = key
	}
	return facts
}

// factKeyOffsets reports where each key=value pair begins. A value runs to the
// next key, not to the next space: splitting on spaces truncates a path that
// contains one and drops the parenthetical in "stopped (inactive)".
func factKeyOffsets(line string) []int {
	var starts []int
	for index := 0; index < len(line); index++ {
		if index > 0 && line[index-1] != ' ' {
			continue
		}
		width := factKeyWidth(line[index:])
		if width == 0 {
			continue
		}
		starts = append(starts, index)
		index += width
	}
	return starts
}

// factKeyWidth returns the length of the key at the head of text, or zero when
// text does not begin with one. A key is a run of unreserved characters
// terminated by "=".
func factKeyWidth(text string) int {
	for index := 0; index < len(text); index++ {
		char := text[index]
		if char == '=' {
			return index
		}
		lower := char >= 'a' && char <= 'z'
		upper := char >= 'A' && char <= 'Z'
		digit := char >= '0' && char <= '9'
		if !lower && !upper && !digit && char != '_' && char != '-' && char != '.' {
			return 0
		}
	}
	return 0
}

func serviceDefinitionState(facts map[string]string) string {
	state, ok := facts["definition"]
	if !ok {
		return install.DefinitionAbsent
	}
	return state
}
