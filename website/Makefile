NPM := $(shell which npm)
DOCKER?=docker

# For Podman, invoke via `make docker-start DOCKER=podman DOCKER_MOUNT_ARGS=,chown=true,relabel=shared`
DOCKER_MOUNT_ARGS?=

.PHONY: start, clean, deploy, serve, install, build

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

node_modules: package.json
	@$(NPM) install

install: node_modules

docker-start:
	$(DOCKER) build -t openbao-docs .
	$(DOCKER) run -p 3000:3000 --mount "type=bind,source=$(CURDIR),destination=/opt/docusaurus$(DOCKER_MOUNT_ARGS)" -it openbao-docs
