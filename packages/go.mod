// The plugin packages contain no Go source, but `npm ci` vendors third-party
// packages that do (flatted ships a Go implementation under node_modules).
// Without this nested module those files join the root module, so `go build
// ./...`, `go vet ./...`, and the coverage total all change depending on
// whether a developer has installed the Node dependencies. Declaring the
// subtree as its own module keeps the root module's package set identical in
// CI and on every workstation.
module github.com/phall1/blackbird/packages

go 1.26.4
