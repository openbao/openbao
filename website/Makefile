NPM := $(shell which npm)
DOCKER?=docker

# For Podman, invoke via `make docker-start DOCKER=podman DOCKER_MOUNT_ARGS=,chown=true,relabel=shared`
DOCKER_MOUNT_ARGS?=

.PHONY: start, clean, deploy, serve, install, build-versioned

start: node_modules
	@$(NPM) run start

build: node_modules $(wildcard content/**/*.mdx) sidebars.ts sidebarsApi.ts
	@$(NPM) run build

serve: build
	@$(NPM) run serve

deploy: node_modules
	@$(NPM) run deploy

lint: node_modules $(wildcard content/**/*.mdx)
	@$(NPM) run lint

clean: node_modules
	@$(NPM) run clear
	@rm -rf versioned_* api-docs_versioned_* versions.json api-docs_versions.json

node_modules: package.json
	@$(NPM) install

install: node_modules

docker-start:
	$(DOCKER) build -t openbao-docs .
	$(DOCKER) run -p 3000:3000 --mount "type=bind,source=$(CURDIR),destination=/opt/docusaurus$(DOCKER_MOUNT_ARGS)" -it openbao-docs

# Versioned docs
GIT_REMOTE := $(shell git remote get-url origin)
DOCS_VERSIONS := $(shell grep -o '"2\..\.x"' docusaurus.config.ts | tr -d '["]')

build-versioned: node_modules $(addprefix versioned_docs/version-,$(DOCS_VERSIONS)) $(addprefix api-docs_versioned_docs/version-,$(DOCS_VERSIONS)) versions.json api-docs_versions.json
	VERSIONED_DOCS="true" $(NPM) run build

versioned_docs:
	@mkdir -p $@

versioned_sidebars:
	@mkdir -p $@

versioned_docs/version-%: node_modules | versioned_docs versioned_sidebars
	@git init $@
	@git -C $@ remote add origin $(GIT_REMOTE)
	@git -C $@ sparse-checkout set --no-cone website/content/docs sidebars.ts
	@git -C $@ pull --depth 1 origin $(subst versioned_docs/version-,release/,$@)
	@$(NPM) run docusaurus sidebar:json $@/website/sidebars.ts | tail -n+5 > $(subst _docs,_sidebars,$@)-sidebars.json
	@mv $@/website/content/docs/* $@/
	@rm -rf $@/website

versions.json:
	@echo -n $(DOCS_VERSIONS) | jq -Rs '. | split(" ")' > $@

api-docs_versioned_docs:
	@mkdir -p $@

api-docs_versioned_sidebars:
	@mkdir -p $@

api-docs_versioned_docs/version-%: node_modules | api-docs_versioned_docs api-docs_versioned_sidebars
	@git init $@
	@git -C $@ remote add origin $(GIT_REMOTE)
	@git -C $@ sparse-checkout set --no-cone website/content/api-docs sidebarsApi.ts
	@git -C $@ pull --depth 1 origin $(subst api-docs_versioned_docs/version-,release/,$@)
	@$(NPM) run docusaurus sidebar:json $@/website/sidebarsApi.ts | tail -n+5 > $(subst _docs,_sidebars,$@)-sidebars.json
	@mv $@/website/content/api-docs/* $@/
	@rm -rf $@/website

api-docs_versions.json:
	@echo -n $(DOCS_VERSIONS) | jq -Rs '. | split(" ")' > $@
