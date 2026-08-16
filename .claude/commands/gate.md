---
description: Run Blackbird's full quality gate and interpret any failure
argument-hint: "[optional: path or package to focus on]"
allowed-tools: Bash, Read, Grep, Glob
---

Run the repository's quality gate and report the result honestly.

```sh
make check
```

Read the target list from the Makefile rather than assuming it
(`grep '^check:' Makefile`). It takes several minutes on a cold cache — run it
in the background and report when it finishes rather than truncating it.

## Interpreting the result

- **`golangci-lint` findings.** The config is `default: all` with a deliberate
  disable list. Fix the finding. Do not disable a linter or add `//nolint` to
  make it pass.
- **Coverage.** Never quote a floor from memory. Read the two that exist and
  the total the tree actually measures:
  ```sh
  grep COVERAGE_FLOOR Makefile
  grep -A3 'coverage floor' .github/workflows/ci.yml
  go tool cover -func=/tmp/blackbird-coverage.out | tail -1
  ```
  The floors are deliberately identical, so a green local coverage step means a
  green CI gate — but if your two greps disagree, report that divergence as the
  finding before anything else. Below the floor, treat the gate as FAILED and
  say so. If you raise coverage substantially, ratchet both floors together and
  leave slack.
- **`go mod tidy -diff` failure.** Run `go mod tidy` and commit the result.
- **Architecture test failure.** Delegate to the `boundary-auditor` agent.
- **`vuln` failure naming only standard-library packages.** Read the "Fixed in"
  line before suspecting your own work. A toolchain one patch release behind
  turns this gate red with no code change; the fix is bumping the pin
  everywhere it appears, not touching the code the trace happens to name.
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

Before blaming the branch for any failure, establish whether it is
pre-existing: run the same check on the merge base in a scratch worktree
(`git worktree add <tmp> <merge-base>`). "This already failed before my work" is
a materially different report from "I broke this", and only one of them is
honest without that check.

Report exactly which steps passed, which failed, and the coverage number you
measured. Do not describe the gate as passing unless `make check` exited zero
**and** the measured total is at or above the floor you read.
