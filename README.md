# Blackbird

This directory is the production Go module for Blackbird.

The current scaffold establishes process lifecycle, build identity, and
architecture-boundary enforcement. It intentionally does not yet implement or
claim product behavior. The daemon runs until its context is cancelled and
then exits cleanly.

## Development

```sh
go test ./...
go vet ./...
go build ./...
```

Build metadata can be supplied with linker flags targeting `main.version`,
`main.commit`, and `main.builtAt`. Unset fields use explicit development
values.
