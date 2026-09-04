.PHONY: format lint lint-fix vet test test-race test-stress coverage build vuln check hooks worktree daemon

GO ?= go
GOLANGCI_LINT ?= golangci-lint
PREK ?= uvx prek
GOVULNCHECK_VERSION ?= v1.6.0
BLACKBIRD_DB ?= $(HOME)/.local/share/blackbird/blackbird.db
COVERAGE_FLOOR ?= 80.0

# TEST_TIMEOUT is per package binary, and it is stated rather than left to go
# test's 10-minute default because the storage package sits close to it. The
# SQLite driver is pure Go, so a race-instrumented migration ladder plus the
# backup and coordination suites run for minutes; on a loaded workstation the
# package crossed 600s and failed on the clock while every assertion passed.
# A timeout that only fires on a busy machine is a flake, not a gate. This
# value must stay in step with the one in the CI workflow's race step.
TEST_TIMEOUT ?= 30m

format:
	$(GOLANGCI_LINT) fmt

lint:
	$(GOLANGCI_LINT) config verify
	$(GOLANGCI_LINT) run

lint-fix:
	$(GOLANGCI_LINT) run --fix
	$(GOLANGCI_LINT) fmt

vet:
	$(GO) vet ./...

test:
	$(GO) test -timeout $(TEST_TIMEOUT) -shuffle=on ./...

test-race:
	$(GO) test -timeout $(TEST_TIMEOUT) -race -shuffle=on ./...

test-stress:
	$(GO) test -timeout $(TEST_TIMEOUT) -shuffle=on -count=3 ./...

coverage:
	$(GO) test -timeout $(TEST_TIMEOUT) -covermode=atomic -coverprofile=/tmp/blackbird-coverage.out ./...
	$(GO) tool cover -func=/tmp/blackbird-coverage.out | tail -1
	@total="$$( $(GO) tool cover -func=/tmp/blackbird-coverage.out | awk '/^total:/ {gsub("%", "", $$3); print $$3}' )"; \
	awk -v total="$$total" -v floor="$(COVERAGE_FLOOR)" 'BEGIN { if (total + 0 < floor + 0) { printf "coverage %.1f%% is below %.1f%%\n", total, floor; exit 1 } }'

build:
	$(GO) mod verify
	$(GO) mod tidy -diff
	CGO_ENABLED=0 $(GO) build -trimpath ./...
	$(GO) test -run='^$$' ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

check: lint vet test-race coverage build vuln

# prek installs into .git/hooks, which git ignores entirely whenever
# core.hooksPath points somewhere else -- `bd init` sets it to .beads/hooks. A
# hook that is installed but never run is worse than a missing one, because the
# gate reads as present, so verify the install instead of assuming it.
hooks:
	$(PREK) install --hook-type pre-commit --hook-type pre-push
	@path="$$(git config --get core.hooksPath || true)"; \
	if [ -n "$$path" ] && ! grep -q prek "$$path/pre-commit" 2>/dev/null; then \
		echo "make hooks: core.hooksPath is $$path, so git will NOT run the hooks just installed in .git/hooks." >&2; \
		echo "  chain them from $$path/pre-commit, or: git config --unset core.hooksPath" >&2; \
		exit 1; \
	fi
	@echo "hooks installed and reachable by git"

# One writer, one worktree. Parallel agents sharing a checkout share an index:
# staging is repository-wide, so a second writer's `git add` takes whatever the
# first is holding, and that has already shipped a main that did not compile.
# Reservations cannot prevent it, because the daemon never sees a commit.
#
# Hooks and config live in the shared git directory, so a new worktree inherits
# them and needs no `make hooks` of its own.
WORKTREE_ROOT ?= $(HOME)/.local/state/blackbird/worktrees
worktree:
	@test -n "$(NAME)" || { echo "usage: make worktree NAME=<what-you-are-doing>" >&2; exit 2; }
	@mkdir -p "$(WORKTREE_ROOT)"
	git worktree add -b agent/$(NAME) "$(WORKTREE_ROOT)/$(NAME)"
	@echo
	@echo "worktree: $(WORKTREE_ROOT)/$(NAME)   branch: agent/$(NAME)"
	@echo "register with Blackbird under the repository, not the worktree:"
	@echo "  project_key = $$(git worktree list --porcelain | sed -n '1s/^worktree //p')"
	@echo "remove it when done:  git worktree remove $(WORKTREE_ROOT)/$(NAME)"

# Run the coordination daemon this repository's agents coordinate through.
# HTTP on 127.0.0.1:8080, MCP on 127.0.0.1:8081.
daemon:
	mkdir -p $(dir $(BLACKBIRD_DB))
	$(GO) run ./cmd/blackbird daemon --sqlite-path=$(BLACKBIRD_DB)
