NPM := $(shell which npm)

.PHONY: start, clean, deploy, serve, install

start: node_modules
	@$(NPM) run start

build: node_modules $(wildcard content/**/*.mdx) sidebars.ts sidebarsApi.ts
	@$(NPM) run build

serve: build
	@$(NPM) run serve

deploy: node_modules
	@$(NPM) run deploy

clean: node_modules
	@$(NPM) run clear

node_modules: package.json
	@$(NPM) install

install: node_modules
