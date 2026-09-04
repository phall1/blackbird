package cli

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
)

// Globals are the flags every command accepts. Kong flattens the anonymous
// embedding into the root node, so both "blackbird --json status" and
// "blackbird status --json" parse to the same value.
type Globals struct {
	JSON    bool   `env:"BLACKBIRD_JSON" help:"Emit machine-readable JSON instead of a rendered report."`
	Color   string `enum:"auto,always,never" default:"auto" env:"BLACKBIRD_COLOR" help:"Colorize output."`
	NoColor bool   `name:"no-color" help:"Disable color. Overrides --color."`
	ASCII   bool   `name:"ascii" help:"Draw with ASCII only, no box or status glyphs."`
	Width   int    `name:"width" placeholder:"COLUMNS" help:"Render at this width instead of probing the terminal."`
	Verbose int    `short:"v" type:"counter" help:"Increase detail. Repeat for more."`
	DB      string `name:"db" placeholder:"PATH" default:"${db_default}" env:"BLACKBIRD_DB" help:"Absolute path to the Blackbird SQLite database."`
	Address string `name:"address" placeholder:"HOST:PORT" env:"BLACKBIRD_ADDRESS" help:"Contact the daemon here instead of at the address in its handshake record. The service listens on ${address_default} unless it was started elsewhere."`
	Version bool   `name:"version" help:"Print build identity and exit."`
}

// AfterApply runs once, on the application node, after every flag is applied.
// It expands a leading ~/ itself rather than using Kong's path mapper, because
// that mapper makes a relative path absolute against the working directory —
// the exact mechanism that used to migrate a database into whatever directory
// the user happened to stand in.
func (globals *Globals) AfterApply() error {
	if _, err := render.ParseColorChoice(globals.Color); err != nil {
		return fmt.Errorf("--color: %w", err)
	}
	if globals.Width < 0 {
		return fmt.Errorf("--width must not be negative; got %d", globals.Width)
	}
	if err := validateAddress(globals.Address); err != nil {
		return err
	}
	if globals.DB == "" {
		return nil
	}
	expanded, err := expandHome(globals.DB)
	if err != nil {
		return fmt.Errorf("resolve --db: %w", err)
	}
	if !filepath.IsAbs(expanded) {
		return fmt.Errorf("--db must be an absolute path; got %q", globals.DB)
	}
	globals.DB = filepath.Clean(expanded)
	return nil
}

// AddressSetter is an AdminPort that can be pointed at an address after the
// flags are parsed. The client is constructed before Kong runs, so without this
// hand-off --address and $BLACKBIRD_ADDRESS would render in --help and change
// nothing at all.
type AddressSetter interface {
	SetAddress(address string)
}

// applyAddress is the whole wiring of --address: an empty value leaves the
// handshake record authoritative, and any other value overrides it, which is
// the only escape hatch when that record names an address no daemon answers on.
func applyAddress(admin AdminPort, address string) {
	if address == "" {
		return
	}
	if setter, ok := admin.(AddressSetter); ok {
		setter.SetAddress(address)
	}
}

// validateAddress rejects a value the client could only fail on later, so the
// user reads the flag's name rather than a transport error from three layers in.
func validateAddress(address string) error {
	if address == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("--address must be HOST:PORT; got %q", address)
	}
	if host == "" || port == "" {
		return fmt.Errorf("--address must name both a host and a port; got %q", address)
	}
	// Every admin request carries the daemon's bearer token, so a non-loopback
	// host would send the credential off the machine. The daemon's own loopback
	// gate protects the server, not the client.
	if !loopbackHost(host) {
		return fmt.Errorf("--address must be a loopback host; got %q", host)
	}
	return nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if err != nil {
		return false
	}
	return address.IsLoopback()
}

func (globals *Globals) colorChoice() render.ColorChoice {
	if globals.NoColor {
		return render.ColorNever
	}
	choice, err := render.ParseColorChoice(globals.Color)
	if err != nil {
		return render.ColorAuto
	}
	return choice
}

func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~"+string(os.PathSeparator)) {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

// defaultDatabasePath mirrors the installer's data directory exactly. There is
// no relative fallback anywhere in the tree.
func defaultDatabasePath(lookup render.Env) string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if data, ok := lookup("XDG_DATA_HOME"); ok && filepath.IsAbs(data) {
		return filepath.Join(data, "blackbird", "blackbird.db")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "blackbird", "blackbird.db")
}

// Console is the resolved output environment handed to every command. It holds
// no context: the parse context binds one separately so a command receives it
// as a parameter instead of carrying it in a struct.
type Console struct {
	Deps    Dependencies
	Globals *Globals
	Out     io.Writer
	Err     io.Writer
	Style   render.Style
}

func (console *Console) target() render.Target {
	return render.Target{Out: console.Out, Err: console.Err, Style: console.Style, JSON: console.Globals.JSON}
}

func (console *Console) present(view render.View) error {
	if err := render.Present(console.target(), view); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func (console *Console) watch(view render.View) error {
	if err := render.WatchFrame(console.target(), view); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

func (console *Console) now() time.Time {
	if console.Deps.Now == nil {
		return time.Now()
	}
	return console.Deps.Now()
}

func (console *Console) databasePath() (string, error) {
	if console.Globals.DB == "" {
		return "", withRemedy(unavailableFault(nil, "no database path is configured"),
			"pass --db=PATH or set BLACKBIRD_DB")
	}
	return console.Globals.DB, nil
}

func (console *Console) admin() (AdminPort, error) {
	if console.Deps.Admin == nil {
		return nil, withRemedy(unavailableFault(nil, "no daemon client is available"),
			"run \"blackbird status\" to check the daemon")
	}
	return console.Deps.Admin, nil
}

// peerCost is the fleet view's outbound port. Unlike every other port here it
// never reports "unavailable": the default client is part of this binary, needs
// no daemon on this machine to construct, and an operator who named a peer has
// already said what they want contacted.
func (console *Console) peerCost() PeerCostPort {
	if console.Deps.Peers != nil {
		return console.Deps.Peers
	}
	return newPeerCostClient()
}

func (console *Console) store() (StorePort, error) {
	if console.Deps.Store == nil {
		return nil, unavailableFault(nil, "no database reader is available")
	}
	return console.Deps.Store, nil
}

func (console *Console) product() (ProductPort, error) {
	if console.Deps.Product == nil {
		return nil, unavailableFault(nil, "no installation manager is available")
	}
	return console.Deps.Product, nil
}

func (console *Console) logs() (LogPort, error) {
	if console.Deps.Logs == nil {
		return nil, unavailableFault(nil, "no log source is available")
	}
	return console.Deps.Logs, nil
}

// resultView pairs a machine payload with the function that draws its human
// projection, so no command can ship one without the other.
type resultView[T any] struct {
	render.Of[T]
	draw func(doc *render.Document, value T)
}

func (view resultView[T]) Describe(doc *render.Document) { view.draw(doc, view.Value) }

func newView[T any](value T, draw func(doc *render.Document, value T)) resultView[T] {
	return resultView[T]{Of: render.Of[T]{Value: value}, draw: draw}
}
