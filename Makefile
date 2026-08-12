.PHONY: format lint lint-fix vet test test-race test-stress coverage build vuln check hooks

GO ?= go
GOLANGCI_LINT ?= golangci-lint
PREK ?= uvx prek
GOVULNCHECK_VERSION ?= v1.6.0
COVERAGE_FLOOR ?= 59.2

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
	$(GO) test -shuffle=on ./...

test-race:
	$(GO) test -race -shuffle=on ./...

test-stress:
	$(GO) test -shuffle=on -count=3 ./...

coverage:
	$(GO) test -covermode=atomic -coverprofile=/tmp/blackbird-coverage.out ./...
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

hooks:
	$(PREK) install --hook-type pre-commit --hook-type pre-push
