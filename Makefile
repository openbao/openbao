# Determine this Makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

DOCKER_CMD?=docker

TEST?=$$(go list ./... github.com/openbao/openbao/api/v2/... github.com/openbao/openbao/sdk/v2/... | grep -v /vendor/ | grep -v /integ)
TEST_TIMEOUT?=45m
EXTENDED_TEST_TIMEOUT=60m
INTEG_TEST_TIMEOUT=120m
GO_MODS?=$$(find . -name go.mod -not -path ./tools/go.mod | xargs -L 1 dirname)
SED?=$(shell command -v gsed || command -v sed)

GO_VERSION_MIN=$$(cat $(CURDIR)/.go-version)
PROTOC_VERSION=34.0
CGO_ENABLED?=0

default: dev

# bin generates the equivalent of releasable binaries for OpenBao
bin: prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS) ui' sh -c "'$(CURDIR)/scripts/build.sh'"

bin-plugin: prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS) ui' sh -c "'$(CURDIR)/scripts/build.sh' plugin"

# dev creates binaries for testing OpenBao locally. These are put
# into ./bin/ as well as $GOPATH/bin
dev: prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' OPENBAO_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
dev-ui: assetcheck prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS) ui' OPENBAO_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
dev-dynamic: prep
	@CGO_ENABLED=1 BUILD_TAGS='$(BUILD_TAGS)' OPENBAO_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

# *-mem variants will enable memory profiling which will write snapshots of heap usage
# to $TMP/vaultprof every 5 minutes. These can be analyzed using `$ go tool pprof <profile_file>`.
# Note that any build can have profiling added via: `$ BUILD_TAGS=memprofiler make ...`
dev-mem: BUILD_TAGS+=memprofiler
dev-mem: dev
dev-ui-mem: BUILD_TAGS+=memprofiler
dev-ui-mem: assetcheck dev-ui
dev-dynamic-mem: BUILD_TAGS+=memprofiler
dev-dynamic-mem: dev-dynamic

dev-tlsdebug: BUILD_TAGS+=tlsdebug
dev-tlsdebug: dev

# Creates a Docker image by adding the compiled linux/amd64 binary found in ./bin.
# The resulting image is tagged "openbao:dev".
docker-dev: prep
	$(DOCKER_CMD) build --build-arg VERSION=$(GO_VERSION_MIN) --build-arg BUILD_TAGS="$(BUILD_TAGS)" -f scripts/docker/Dockerfile -t openbao:dev .

docker-dev-ui: prep
	$(DOCKER_CMD) build --build-arg VERSION=$(GO_VERSION_MIN) --build-arg BUILD_TAGS="$(BUILD_TAGS)" -f scripts/docker/Dockerfile.ui -t openbao:dev-ui .

# test runs the unit tests and vets the code
test: prep
	@CGO_ENABLED=$(CGO_ENABLED) \
	BAO_ADDR= \
	BAO_TOKEN= \
	BAO_DEV_ROOT_TOKEN_ID= \
	BAO_ACC= \
	go test -tags='$(BUILD_TAGS)' $(TEST) $(TESTARGS) -timeout=$(TEST_TIMEOUT) -parallel=20

testcompile: prep
	@for pkg in $(TEST) ; do \
		go test -v -c -tags='$(BUILD_TAGS)' $$pkg -parallel=4 ; \
	done

# testacc runs acceptance tests
testacc: prep
	@if [ "$(TEST)" = "./..." ]; then \
		echo "ERROR: Set TEST to a specific package"; \
		exit 1; \
	fi
	BAO_ACC=1 go test -tags='$(BUILD_TAGS)' $(TEST) -v $(TESTARGS) -timeout=$(EXTENDED_TEST_TIMEOUT)

# testrace runs the race checker
testrace: prep
	@CGO_ENABLED=1 \
	BAO_ADDR= \
	BAO_TOKEN= \
	BAO_DEV_ROOT_TOKEN_ID= \
	BAO_ACC= \
	go test -tags='$(BUILD_TAGS)' -race $(TEST) $(TESTARGS) -timeout=$(EXTENDED_TEST_TIMEOUT) -parallel=20

cover:
	./scripts/coverage.sh --html

# vet runs the Go source code static analysis tool `vet` to find
# any common errors.
.PHONY: vet
vet:
	@for dir in $(GO_MODS); do \
		cd $$dir && go vet ./...; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Vet found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi; \
		cd $(CURDIR); \
	done

# deprecations runs staticcheck tool to look for deprecations. Checks entire code to see if it
# has deprecated function, variable, constant or field
.PHONY: deprecations
deprecations: LINT_FLAGS += "-c=$(CURDIR)/.golangci.deprecations.yml"
deprecations: lint

# lint-new runs golangci-lint on the current commit
.PHONY: lint-new
lint-new: LINT_FLAGS += "-n"
lint-new: lint

# lint runs golangci-lint, it is more comprehensive than vet, but louder
.PHONY: lint
lint:
	@for dir in $(GO_MODS); do \
		cd $$dir && go tool -modfile=$(realpath tools/go.mod) golangci-lint run $(LINT_FLAGS); if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Lint found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi; \
		cd $(CURDIR); \
	done

# n.b.: prep used to depend on fmtcheck, but since fmtcheck is
# now run as a pre-commit hook (and there's little value in
# making every build run the formatter), we've removed that
# dependency.
prep:
	@if [ -d .git/hooks ]; then cp .hooks/* .git/hooks/; fi

# bootstrap the build by downloading additional tools that may be used by devs
#
# Grep for tools that include a "." to select only those defined in tools/go.mod
# and exclude standard ones.
bootstrap:
	@for tool in $$(go tool -modfile=tools/go.mod | grep \\.); do \
		go install -modfile=tools/go.mod "$$tool"; \
	done

static-assets-dir:
	@mkdir -p ./internal/http/web_ui

install-ui-dependencies:
	@echo "--> Installing JavaScript assets"
	@cd ui && pnpm install

test-ember: install-ui-dependencies
	@echo "--> Running ember tests"
	@cd ui && pnpm test

check-openbao-in-path:
	@OPENBAO_BIN=$$(command -v bao) || { echo "bao command not found"; exit 1; }; \
		[ -x "$$OPENBAO_BIN" ] || { echo "$$OPENBAO_BIN not executable"; exit 1; }; \
		printf "Using OpenBao at %s:\n\$$ openbao version\n%s\n" "$$OPENBAO_BIN" "$$(bao version)"

ember-dist: install-ui-dependencies
	@echo "--> Building Ember application"
	@cd ui && pnpm build
	@rm -rf ui/if-you-need-to-delete-this-open-an-issue-async-disk-cache

ember-dist-dev: install-ui-dependencies
	@echo "--> Building Ember application"
	@cd ui && pnpm build:dev

static-dist: ember-dist
static-dist-dev: ember-dist-dev

proto: bootstrap
	@sh -c "'$(CURDIR)/scripts/protocversioncheck.sh' '$(PROTOC_VERSION)'"
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/logical/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/plugin/pb/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/helper/pluginutil/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/database/dbplugin/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/database/dbplugin/v5/proto/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/vault/tokens/token.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/vault/forwarding/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/physical/raft/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/builtin/logical/kv/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/builtin/logical/pki/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/helper/identity/mfa/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/helper/identity/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/helper/forwarding/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/helper/storagepacker/types.proto

	# No additional sed expressions should be added to this list. Going forward
	# we should just use the variable names chosen by protobuf. These are left
	# here for backwards compatibility, namely for SDK compilation.
	$(SED) -i -e 's/Id/ID/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' internal/vault/forwarding/request_forwarding_service.pb.go
	$(SED) -i -e 's/Idp/IDP/' -e 's/Url/URL/' -e 's/Id/ID/' -e 's/IDentity/Identity/' -e 's/EntityId/EntityID/' -e 's/Api/API/' -e 's/Qr/QR/' -e 's/Totp/TOTP/' -e 's/Mfa/MFA/' -e 's/Pingid/PingID/' -e 's/namespaceId/namespaceID/' -e 's/Ttl/TTL/' -e 's/BoundCidrs/BoundCIDRs/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' internal/helper/identity/types.pb.go internal/helper/identity/mfa/types.pb.go internal/helper/storagepacker/types.pb.go sdk/plugin/pb/backend.pb.go sdk/logical/identity.pb.go

.PHONY: fmtcheck
fmtcheck:
	./scripts/gofmtcheck.sh

.PHONY: fmt
fmt:
	go tool -modfile=tools/go.mod gofumpt -w .

semgrep:
	semgrep --include '*.go' -a -f tools/semgrep .

semgrep-ci:
	semgrep --error --include '*.go' -f tools/semgrep/ci .

docker-semgrep:
	$(DOCKER_CMD) run --rm --mount "type=bind,source=$(PWD),destination=/src,chown=true,relabel=shared" docker.io/returntocorp/semgrep:latest semgrep --include '*.go' -a -f tools/semgrep .

docker-semgrep-ci:
	$(DOCKER_CMD) run --rm --mount "type=bind,source=$(PWD),destination=/src,chown=true,relabel=shared" docker.io/returntocorp/semgrep:latest semgrep --error --include '*.go' -a -f tools/semgrep/ci .

assetcheck:
	@echo "==> Checking compiled UI assets..."
	@sh -c "'$(CURDIR)/scripts/assetcheck.sh'"

spellcheck:
	@echo "==> Spell checking website..."
	go tool -modfile=tools/go.mod misspell -w -source=text website/content

.PHONY: bin default prep test vet bootstrap fmt fmtcheck ember-dist ember-dist-dev static-dist static-dist-dev assetcheck check-openbao-in-path packages build build-ci semgrep semgrep-ci vet-godoctests ci-vet-godoctests

.NOTPARALLEL: ember-dist ember-dist-dev

.PHONY: openapi
openapi: dev
	@$(CURDIR)/scripts/gen_openapi.sh

.PHONY: vulncheck
vulncheck:
	go tool -modfile=tools/go.mod govulncheck -show verbose ./...
	go tool -modfile=tools/go.mod govulncheck -show verbose github.com/openbao/openbao/api/v2/...
	go tool -modfile=tools/go.mod govulncheck -show verbose github.com/openbao/openbao/sdk/v2/...

.PHONY: tidy-all
tidy-all:
	find . -name 'go.mod' -execdir go mod tidy \;

.PHONY: ci-tidy-all
ci-tidy-all:
	git diff --quiet
	find . -name 'go.mod' -execdir go mod tidy \;
	git diff --quiet || (echo -e "\n\nModified files:" && git status --short && echo -e "\n\nRun 'make tidy-all' locally and commit the changes.\n" && exit 1)

.PHONY: release-changelog
release-changelog: $(wildcard changelog/*.txt)
	@:$(if $(LAST_RELEASE),,$(error please set the LAST_RELEASE environment variable for changelog generation))
	@:$(if $(THIS_RELEASE),,$(error please set the THIS_RELEASE environment variable for changelog generation))
	go tool -modfile=tools/go.mod changelog-build -changelog-template changelog/changelog.tmpl -entries-dir changelog -git-dir . -note-template changelog/note.tmpl -last-release $(LAST_RELEASE) -this-release $(THIS_RELEASE)

.PHONY: goreleaser-check
goreleaser-check:
	goreleaser check -f goreleaser.hsm.yaml
	goreleaser check -f goreleaser.linux.yaml
	goreleaser check -f goreleaser.other.yaml

.PHONY: sync-deps
sync-deps:
	sh -c "'$(CURDIR)/scripts/sync-deps.sh'"

.PHONY: ci-sync-deps
ci-sync-deps: sync-deps
	git diff --quiet || (echo -e "\n\nModified files:" && git status --short && echo -e "\n\nRun 'make sync-deps' locally and commit the changes.\n" && exit 1)

.PHONY: bump-critical
bump-critical:
	go get github.com/golang-jwt/jwt/v4@latest
	go get github.com/golang-jwt/jwt/v5@latest
	go get github.com/ProtonMail/go-crypto@latest
	go get github.com/go-jose/go-jose/v4@latest
	go get github.com/caddyserver/certmagic@latest
	go get github.com/mholt/acmez/v3@latest
	go get github.com/google/cel-go@latest
	go get github.com/jackc/pgx/v5@latest
	go get github.com/hashicorp/cap@latest
	go get github.com/hashicorp/raft@latest
	go get github.com/tink-crypto/tink-go/v2@latest
	go get github.com/pquerna/otp@latest
	go get go.etcd.io/bbolt@latest
	go get google.golang.org/grpc@latest
	grep -o 'golang.org/x/[^ ]*' ./go.mod  | xargs -I{} go get '{}@latest'
	grep -o 'github.com/hashicorp/go-secure-stdlib/[^ ]*' ./go.mod  | xargs -I{} go get '{}@latest'
	grep -o 'github.com/openbao/go-kms-wrapping/[^ ]*' ./go.mod  | xargs -I{} go get '{}@latest'
	make sync-deps

.PHONY: tag-api
tag-api:
	@:$(if $(THIS_RELEASE),,$(error please set the THIS_RELEASE environment variable for API tagging))
	@:$(if $(ORIGIN),,$(error please set the ORIGIN environment variable for pushing API tags))
	git tag api/$(THIS_RELEASE)
	git tag api/auth/approle/$(THIS_RELEASE)
	git tag api/auth/jwt/$(THIS_RELEASE)
	git tag api/auth/kubernetes/$(THIS_RELEASE)
	git tag api/auth/ldap/$(THIS_RELEASE)
	git tag api/auth/userpass/$(THIS_RELEASE)
	git push $(ORIGIN) api/$(THIS_RELEASE)
	git push $(ORIGIN) api/auth/approle/$(THIS_RELEASE)
	git push $(ORIGIN) api/auth/jwt/$(THIS_RELEASE)
	git push $(ORIGIN) api/auth/kubernetes/$(THIS_RELEASE)
	git push $(ORIGIN) api/auth/ldap/$(THIS_RELEASE)
	git push $(ORIGIN) api/auth/userpass/$(THIS_RELEASE)

.PHONY: sync-deps-gkw
sync-deps-gkw:
	@:$(if $(GO_KMS_WRAPPING),,$(error please set the GO_KMS_WRAPPING environment variable to the go-kms-wrapping repository to update))
	sh -c "'$(CURDIR)/scripts/sync-deps-gkw.sh'"

.PHONY: tag-sdk
tag-sdk:
	@:$(if $(THIS_RELEASE),,$(error please set the THIS_RELEASE environment variable for API tagging))
	@:$(if $(ORIGIN),,$(error please set the ORIGIN environment variable for pushing API tags))
	git tag sdk/$(THIS_RELEASE)
	git push $(ORIGIN) sdk/$(THIS_RELEASE)
