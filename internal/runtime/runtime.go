// Package runtime owns process-level composition and lifecycle.
package runtime

import "context"

const (
	developmentVersion = "dev"
	unknownBuildValue  = "unknown"
)

// BuildInfo identifies the executable without implying product capabilities.
type BuildInfo struct {
	Version string
	Commit  string
	BuiltAt string
}

// Normalize replaces omitted build fields with stable development values.
func (info BuildInfo) Normalize() BuildInfo {
	if info.Version == "" {
		info.Version = developmentVersion
	}
	if info.Commit == "" {
		info.Commit = unknownBuildValue
	}
	if info.BuiltAt == "" {
		info.BuiltAt = unknownBuildValue
	}

	return info
}

// Daemon is the process-lifetime shell. Product components are composed here
// as their implementation slices land.
type Daemon struct {
	build BuildInfo
}

// New returns a daemon with deterministic build identity defaults.
func New(build BuildInfo) *Daemon {
	return &Daemon{build: build.Normalize()}
}

// BuildInfo returns the daemon's normalized build identity.
func (daemon *Daemon) BuildInfo() BuildInfo {
	return daemon.build
}

// Run blocks until cancellation. Context cancellation is a graceful stop.
func (daemon *Daemon) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
