# kind cluster name
KIND_CLUSTER_NAME?=vault-plugin-secrets-kubernetes

# kind k8s version
KIND_K8S_VERSION?=v1.23.6

PKG=github.com/hashicorp/vault-plugin-secrets-kubernetes
LDFLAGS?="-X '$(PKG).WALRollbackMinAge=10s'"

.PHONY: default
default: dev

# dev target sets WALRollbackMinAge to 10s instead of the default 10 minutes to speed up integration tests
.PHONY: dev
dev:
	CGO_ENABLED=0 go build -ldflags $(LDFLAGS) -o bin/vault-plugin-secrets-kubernetes cmd/vault-plugin-secrets-kubernetes/main.go

.PHONY: test
test: fmtcheck
	CGO_ENABLED=0 go test ./... $(TESTARGS) -timeout=20m

.PHONY: integration-test
integration-test:
	INTEGRATION_TESTS=true KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) CGO_ENABLED=0 go test github.com/hashicorp/vault-plugin-secrets-kubernetes/integrationtest/... $(TESTARGS) -count=1 -timeout=40m

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	gofumpt -l -w .

.PHONY: setup-kind
# create a kind cluster for running the acceptance tests locally
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
	GOOS=linux GOARCH=amd64 make dev
	docker build -f integrationtest/vault/Dockerfile bin/ --tag=hashicorp/vault:dev

# Create Vault inside the cluster with a locally-built version of kubernetes secrets.
.PHONY: setup-integration-test
setup-integration-test: teardown-integration-test vault-image
	kind --name ${KIND_CLUSTER_NAME} load docker-image hashicorp/vault:dev
	kubectl create namespace test
	helm install vault vault --repo https://helm.releases.hashicorp.com --version=0.19.0 \
		--wait --timeout=5m \
		--namespace=test \
		--set server.logLevel=debug \
		--set server.dev.enabled=true \
		--set server.image.tag=dev \
		--set server.image.pullPolicy=Never \
		--set injector.enabled=false \
		--set server.extraArgs="-dev-plugin-dir=/vault/plugin_directory"
	kubectl patch --namespace=test statefulset vault --patch-file integrationtest/vault/hostPortPatch.yaml
	kubectl apply --namespace=test -f integrationtest/vault/testRoles.yaml
	kubectl apply --namespace=test -f integrationtest/vault/testServiceAccounts.yaml
	kubectl apply --namespace=test -f integrationtest/vault/testBindings.yaml

	kubectl delete --namespace=test pod vault-0
	kubectl wait --namespace=test --for=condition=Ready --timeout=5m pod -l app.kubernetes.io/name=vault

.PHONY: teardown-integration-test
teardown-integration-test:
	helm uninstall vault --namespace=test || true
	kubectl delete --ignore-not-found namespace test
	# kubectl delete --ignore-not-found clusterrolebinding vault-crb
	# kubectl delete --ignore-not-found clusterrole k8s-clusterrole
	kubectl delete --ignore-not-found --namespace=test -f integrationtest/vault/testBindings.yaml
	kubectl delete --ignore-not-found --namespace=test -f integrationtest/vault/testServiceAccounts.yaml
	kubectl delete --ignore-not-found --namespace=test -f integrationtest/vault/testRoles.yaml
