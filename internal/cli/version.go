package cli

import (
	"github.com/phall1/blackbird/internal/cli/render"
)

// VersionCmd prints build identity. The rendered line is frozen by the release
// workflow, which asserts the exact output of "blackbird --version" against the
// version, commit, and build timestamp it just compiled in.
type VersionCmd struct{}

func (cmd *VersionCmd) Run(console *Console) error {
	return presentBuild(console)
}

func presentBuild(console *Console) error {
	return console.present(newView(console.Deps.Build, drawBuild))
}

func drawBuild(doc *render.Document, build BuildInfo) {
	doc.Linef(render.RolePlain, "blackbird version=%s commit=%s built_at=%s",
		build.Version, build.Commit, build.BuiltAt)
}
