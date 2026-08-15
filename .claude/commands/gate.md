---
description: Run Blackbird's full quality gate and interpret any failure
argument-hint: "[optional: path or package to focus on]"
allowed-tools: Bash, Read, Grep, Glob
---

Run the repository's quality gate and report the result honestly.

```sh
make check
```

That is `lint vet test-race coverage build vuln`. It takes several minutes on a
cold cache — run it in the background and report when it finishes rather than
truncating it.

## Interpreting the result

- **`golangci-lint` findings.** The config is `default: all` with a deliberate
  disable list. Fix the finding. Do not disable a linter or add `//nolint` to
  make it pass.
- **Coverage.** `make coverage` and CI both fail below **61.0%**; the repo
  sits at 61.8%. The floors are deliberately identical, so a green local
  coverage step does mean a green CI gate — but still read the actual total
  rather than trusting the exit code:
  `go tool cover -func=/tmp/blackbird-coverage.out | tail -1`
  If it is below 61.0%, treat the gate as FAILED and say so. If you raise
  coverage substantially, ratchet both floors together and leave some slack.
- **`go mod tidy -diff` failure.** Run `go mod tidy` and commit the result.
- **Architecture test failure.** Delegate to the `boundary-auditor` agent.
- **Race or shuffle failure.** The suite runs `-race -shuffle=on` and CI repeats
  it with `-count=3`. A failure that appears intermittently is a real
  order-dependence or data race, not flakiness to retry away. Two known shapes
  have already been fixed and are worth recognising: a test that reads a
  wall-clock bucket and then does slow setup can straddle the boundary, and a
  `t.Parallel()` test with an absolute `context.WithTimeout` can blow its budget
  purely from machine load, because `go test ./...` runs package binaries
  concurrently. Establish which it is before changing anything — reproduce with
  the reported `-shuffle` seed, and check whether the same seed passes on the
  commit before your work.

$ARGUMENTS

If a focus path was given, additionally run the narrow checks for it
(`go test -race ./<pkg>/...`) and report those separately.

Report exactly which steps passed, which failed, and the coverage number. Do
not describe the gate as passing unless `make check` exited zero **and** total
coverage is at or above 61.0%.
