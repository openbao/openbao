.PHONY: frontend
frontend:
	pnpm start

.PHONY: backend
backend:
	pnpm openbao

.PHONY: test
test:
	pnpm test

.PHONY: check
check: test

.PHONY: lint
lint: bootstrap
	pnpm lint:fix

.PHONY: bootstrap
bootstrap:
	pnpm install
