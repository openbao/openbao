.PHONY: frontend
frontend:
	pnpm start

.PHONY: backend
backend:
	pnpm openbao

.PHONY: test
test:
	pnpm run test

.PHONY: check
check: test

.PHONY: lint
lint: bootstrap
	pnpm run lint:fix

.PHONY: bootstrap
bootstrap:
	command -v npm || ( npm install -g pnpm )
	pnpm install -r
