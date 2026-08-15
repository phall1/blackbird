// Package termwidth probes the terminal's column count. It is the one piece of
// the rendering path that must ask the kernel, so it lives behind a build tag
// and is injected into render rather than imported by it.
package termwidth
