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
- **Coverage.** `make coverage` fails below 58.8%, but **CI fails below 59.2%**
  and the repo currently sits at exactly 59.2%. A green local coverage step
  therefore does not mean CI is green. Read the actual total:
  `go tool cover -func=/tmp/blackbird-coverage.out | tail -1`
  If it is below 59.2%, treat the gate as FAILED and say so.
- **`go mod tidy -diff` failure.** Run `go mod tidy` and commit the result.
- **Architecture test failure.** Delegate to the `boundary-auditor` agent.
- **Race or shuffle failure.** The suite runs `-race -shuffle=on` and CI repeats
  it with `-count=3`. A failure that appears intermittently is a real
  order-dependence or data race, not flakiness to retry away.

$ARGUMENTS

If a focus path was given, additionally run the narrow checks for it
(`go test -race ./<pkg>/...`) and report those separately.

Report exactly which steps passed, which failed, and the coverage number. Do
not describe the gate as passing unless `make check` exited zero **and** total
coverage is at or above 59.2%.
