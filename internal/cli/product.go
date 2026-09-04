package cli

import (
	"context"
	"strings"

	"github.com/phall1/blackbird/internal/cli/render"
	"github.com/phall1/blackbird/internal/install"
)

// InstallCmd installs the per-user service, the unattended updater, and the MCP
// client entries. The rendered line preserves the pre-0.4 output exactly.
type InstallCmd struct {
	// Peer and PeerAllow record a PREFERENCE rather than decorating this run's
	// service definition. `blackbird update` regenerates the argv, so a flag
	// written only into the unit file is dropped by the next unattended
	// upgrade; recording it means the installed service and the operator's
	// intention cannot drift apart.
	//
	// Omitting the flags on a later install leaves the recorded preference
	// alone: install is run again for many reasons, and silently switching
	// peering off during one of them is the failure this is built to avoid.
	// --no-peer is how it is turned off.
	Peer        *bool    `name:"peer" negatable:"" help:"Record that the installed service serves peer routes on this machine's tailnet address. --no-peer turns it off; omitted leaves the recorded preference alone."`
	PeerAddress string   `name:"peer-address" placeholder:"HOST:PORT" help:"Tailnet address for the installed service's peer listener. Defaults to this machine's tailnet address on the HTTP port."`
	PeerAllow   []string `name:"peer-allow" placeholder:"NAME" help:"Peer the installed service admits, by tailnet stable node id (preferred) or machine name. Repeatable, and required with --peer."`
}

type installReport struct {
	ServicePath    string   `json:"service_path"`
	UpdaterPaths   []string `json:"updater_paths"`
	Clients        []string `json:"clients"`
	UpdaterSkipped string   `json:"updater_skipped,omitempty"`
	Peering        string   `json:"peering"`
	PeerAllowed    []string `json:"peer_allowed,omitempty"`
}

func (cmd *InstallCmd) Run(ctx context.Context, console *Console) error {
	manager, err := console.product()
	if err != nil {
		return err
	}
	preference, err := cmd.peering(console, manager)
	if err != nil {
		return err
	}
	result, err := manager.Install(ctx)
	if err != nil {
		return fault(ExitError, err, "install")
	}
	report := installReport{
		ServicePath:    result.ServicePath,
		UpdaterPaths:   result.UpdaterPaths,
		Clients:        result.Clients,
		UpdaterSkipped: result.UpdaterSkipped,
		Peering:        "off",
	}
	if preference.Enabled {
		report.Peering = "on"
		report.PeerAllowed = preference.Allowed
	}
	return console.present(newView(report, drawInstall))
}

// peering reconciles the flags with what is already recorded, and writes the
// result BEFORE the install converges the service definition, so the unit file
// this run produces is the one the preference describes.
func (cmd *InstallCmd) peering(console *Console, manager ProductPort) (install.Peering, error) {
	existing, err := manager.Peering()
	if err != nil {
		return install.Peering{}, fault(ExitError, err, "install")
	}
	// Nothing said means nothing changed. An install run to repair a client
	// entry must not switch off a capability the operator turned on last week.
	if cmd.Peer == nil && cmd.PeerAddress == "" && len(cmd.PeerAllow) == 0 {
		return existing, nil
	}
	// Naming peers without saying --peer is taken as asking for peering: an
	// operator who typed an allow-list wants one, and refusing on a technicality
	// would be the daemon's flag rule imported where it helps nobody. Saying
	// --no-peer alongside them is the contradiction, and SetPeering refuses it.
	enabled := len(cmd.PeerAllow) != 0 || cmd.PeerAddress != ""
	if cmd.Peer != nil {
		enabled = *cmd.Peer
	}
	wanted := install.Peering{Enabled: enabled, Address: cmd.PeerAddress, Allowed: cmd.PeerAllow}
	if enabled && len(wanted.Allowed) == 0 {
		// Carrying the recorded list forward lets `--peer --peer-address=...`
		// change one thing without restating the fleet.
		wanted.Allowed = existing.Allowed
	}
	if err := manager.SetPeering(wanted); err != nil {
		return install.Peering{}, fault(ExitUsage, err, "install")
	}
	return wanted, nil
}

func drawInstall(doc *render.Document, report installReport) {
	doc.Linef(render.RolePlain, "installed service=%s updater=%s clients=%s",
		report.ServicePath, joinOrNone(report.UpdaterPaths), joinOrNone(report.Clients))
	// An install that silently scheduled nothing is how a machine ends up
	// believing it updates itself, so say so on the successful path.
	if report.UpdaterSkipped != "" {
		doc.Linef(render.RoleMuted, "  no unattended updater: %s; update with the tool you installed with",
			report.UpdaterSkipped)
	}
	// Peering is the one thing install writes that opens a network surface, so
	// it is stated on the successful path rather than left to be discovered.
	// The OFF case is silent on purpose: it is the default, it is what every
	// existing install prints, and a line saying so on every run would be noise
	// that trains an operator to skip the line that matters.
	if report.Peering == "on" {
		doc.Linef(render.RolePlain, "  peering on, admitting %s", joinOrNone(report.PeerAllowed))
	}
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
