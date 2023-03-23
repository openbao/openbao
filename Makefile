TESTARGS  ?= '-test.v'
# kind cluster name
KIND_CLUSTER_NAME ?= vault-plugin-auth-kubernetes

# kind k8s version
KIND_K8S_VERSION ?= v1.26.2

.PHONY: default
default: dev

.PHONY: dev
dev:
	CGO_ENABLED=0 go build -o bin/vault-plugin-auth-kubernetes cmd/vault-plugin-auth-kubernetes/main.go

.PHONY: test
test: fmtcheck
	CGO_ENABLED=0 go test $(TESTARGS) -timeout=20m ./...

.PHONY: integration-test
integration-test:
	INTEGRATION_TESTS=true CGO_ENABLED=0 go test $(TESTARGS) -count=1 -timeout=20m github.com/hashicorp/vault-plugin-auth-kubernetes/integrationtest/...

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofumpt -w .

.PHONY: setup-kind
# create a kind cluster for running the integration tests locally
setup-kind:
	kind get clusters | grep --silent "^${KIND_CLUSTER_NAME}$$" || \
	kind create cluster \
		--image kindest/node:${KIND_K8S_VERSION} \
		--name ${KIND_CLUSTER_NAME}  \
		--config $(CURDIR)/integrationtest/kind/config.yaml
	kubectl config use-context kind-${KIND_CLUSTER_NAME}

.PHONY: delete-kind
# delete the kind cluster
delete-kind:
	kind delete cluster --name ${KIND_CLUSTER_NAME} || true

.PHONY: vault-image
vault-image:
	GOOS=linux make dev
	docker build -f integrationtest/vault/Dockerfile bin/ --tag=hashicorp/vault:dev

# Create Vault inside the cluster with a locally-built version of kubernetes auth.
.PHONY: setup-integration-test
setup-integration-test: teardown-integration-test vault-image
	kind --name ${KIND_CLUSTER_NAME} load docker-image hashicorp/vault:dev
	kubectl create namespace test
	helm install vault vault --repo https://helm.releases.hashicorp.com --version=0.23.0 \
		--wait --timeout=5m \
		--namespace=test \
		--set server.dev.enabled=true \
		--set server.image.tag=dev \
		--set server.image.pullPolicy=Never \
		--set server.logLevel=trace \
		--set injector.enabled=false \
		--set server.extraArgs="-dev-plugin-dir=/vault/plugin_directory"
	kubectl patch --namespace=test statefulset vault --patch-file integrationtest/vault/hostPortPatch.yaml
	kubectl apply --namespace=test -f integrationtest/vault/tokenReviewerServiceAccount.yaml
	kubectl apply -f integrationtest/vault/tokenReviewerBinding.yaml
	kubectl delete --namespace=test pod vault-0
	kubectl wait --namespace=test --for=condition=Ready --timeout=5m pod -l app.kubernetes.io/name=vault

.PHONY: teardown-integration-test
teardown-integration-test:
	helm uninstall vault --namespace=test || true
	kubectl delete --ignore-not-found namespace test
