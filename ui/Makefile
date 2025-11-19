.PHONY: frontend
frontend:
	yarn start

.PHONY: backend
backend:
	yarn openbao

.PHONY: test
test:
	yarn run test

.PHONY: check
check: test

.PHONY: lint
lint: bootstrap
	npm run lint:fix

.PHONY: bootstrap
bootstrap:
	command -v yarn || ( npm install -g yarn )
	yarn
