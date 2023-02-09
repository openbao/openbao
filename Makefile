REPO_DIR := $(shell basename $(CURDIR))
PLUGIN_NAME := $(shell command ls cmd/)

.PHONY: default
default: dev

.PHONY: dev
dev:
	CGO_ENABLED=0 go build -o bin/$(PLUGIN_NAME) cmd/$(PLUGIN_NAME)/main.go

.PHONY: bootstrap
bootstrap:
	@echo "Downloading tools ..."
	@go generate -tags tools tools/tools.go
	# This should only ever be performed once, so we lean on the cmd/ directory
	# to indicate whether this has already been done.
	@if [ "$(PLUGIN_NAME)" != "$(REPO_DIR)" ]; then \
		echo "Renaming cmd/$(PLUGIN_NAME) to cmd/$(REPO_DIR) ..."; \
		mv cmd/$(PLUGIN_NAME) to cmd/$(REPO_DIR); \
		echo "Renaming Go module to github.com/hashicorp/$(REPO_DIR) ..."; \
        go mod edit -module github.com/hashicorp/$(REPO_DIR); \
	fi

.PHONY: test
test: fmtcheck
	CGO_ENABLED=0 go test -v ./... $(TESTARGS) -timeout=20m

.PHONY: testacc
testacc: fmtcheck
	CGO_ENABLED=0 VAULT_ACC=1 go test -v ./... $(TESTARGS) -timeout=20m

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofumpt -l -w .