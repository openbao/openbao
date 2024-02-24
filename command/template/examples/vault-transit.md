# Encryption Key Export Example

The [Vault Transit Secret Backend](https://www.vaultproject.io/docs/secrets/transit/index.html) allows you to export encryption keys to be used for local encrypt/decrypt operations when data is too large or latency is too high to be sent to Vault over the network. This example shows how you can leverage consul-template to trigger clients to automatically pull down an encryption key from Vault's Transit backend based on the version specified in Consul KV.

This method can help you act quickly in the event of a compromise by rotating the encryption key in Vault and triggering all clients to grab latest by updating the version in Consul KV.

## Template Example
```
{{ with printf "transit/export/encryption-key/%s/%s" ( key "named-key" ) ( key "vault-index" ) | secret }}{{ if .Data.keys }}Encryption Key Version {{ ( key "vault-index" ) }}: {{ index .Data.keys ( key "vault-index" ) }}{{ end }}{{ end }}
```

## Prerequisites

- Consul: `https://www.consul.io/downloads.html` or `https://releases.hashicorp.com/consul/`
- Vault: `https://www.vaultproject.io/downloads.html` or `https://releases.hashicorp.com/vault/`
- consul-template: `https://releases.hashicorp.com/consul-template/`
- Running Consul cluster: `consul agent -dev`
- Unsealed Vault cluster: `vault server -dev -dev-root-token-id=root`

## Step 1: Vault & Consul Configuration

Run the below script against a running Consul & unsealed Vault cluster. Assumes both Vault and Consul are reachable locally.

```
#!/bin/bash
set -e

VAULT_TOKEN=${VAULT_TOKEN:-"root"}
NAMED_KEY=${NAMED_KEY:-"example"}

echo "Setting env vars VAULT_TOKEN to '${VAULT_TOKEN}' and NAMED_KEY to '${NAMED_KEY}', these can be overridden."

POLICY_NAME=${NAMED_KEY}-policy
POLICY_PATH=${POLICY_NAME}.hcl

echo "Write ${POLICY_NAME} locally"
cat <<EOF >${POLICY_PATH}
# Allow renewal of leases for secrets
path "sys/renew/*" {
  capabilities = ["create"]
}

# Allow renewal of token leases
path "auth/token/renew/*" {
  capabilities = ["create"]
}

# Allow reading and listing of mounts
path "sys/mounts" {
  capabilities = ["list", "read"]
}

# Generic secret backend
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Transit backend
path "transit/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Policy can be created in the UI as well
vault policy-write ${POLICY_NAME} ${POLICY_PATH}

echo
echo "Generate auth token tied to ${POLICY_NAME} and place in .vault-token"
# CLI: `vault token-create -policy="${POLICY_NAME}"`
curl -s -X POST \
     -H "X-Vault-Token:${VAULT_TOKEN}" \
     http://127.0.0.1:8200/v1/auth/token/create \
     -d '{"policies":["'"${POLICY_NAME}"'"]}' | jq -r '.auth.client_token' > .vault-token
echo "You can login with the below token using the Token authentication provider"
echo "Token: $(cat .vault-token)"

echo
echo "Enable userpass authentication"
vault auth-enable userpass

echo
echo "Create userpass credentials using ${POLICY_NAME} policy"
vault write auth/userpass/users/$NAMED_KEY \
    password=${NAMED_KEY} \
    policies=${POLICY_NAME}
echo "You can login with the below credentials using the Userpass authentication provider (same policy as token above)"
echo "Username: ${NAMED_KEY}"
echo "Password: ${NAMED_KEY}"

echo
echo "Mount the Transit secret backend"
vault mount transit

echo
echo "Create exportable ${NAMED_KEY} named symmetric encryption key in the Transit secret backend"
# CLI: vault write -f transit/keys/${NAMED_KEY} exportable=true
curl -s -X POST \
     -H "X-Vault-Token:${VAULT_TOKEN}" \
     http://127.0.0.1:8200/v1/transit/keys/${NAMED_KEY} \
     -d '{"exportable":"true","type":"aes256-gcm96"}' | jq "."

echo
echo "Use the below command to read this encryption key locally, this is what consul-template will be calling later on."
echo "curl -s -X GET -H \"X-Vault-Token:${VAULT_TOKEN}\" http://127.0.0.1:8200/v1/transit/export/encryption-key/${NAMED_KEY} | jq \".\""

echo
echo "Or grab just the encryption key"

echo
echo "curl -s -X GET -H \"X-Vault-Token:${VAULT_TOKEN}\" http://127.0.0.1:8200/v1/transit/export/encryption-key/${NAMED_KEY} | jq -r '.data.keys.\"1\"'"

echo
echo "Add KVs to Consul that consul-template will leverage"
consul kv put named-key ${NAMED_KEY}
consul kv put vault-index 1

echo
echo "After running consul-template, you can rotate the encryption key in Vault UI or using the below cURL command"
echo "curl -s -X POST -H \"X-Vault-Token:${VAULT_TOKEN}\" http://127.0.0.1:8200/v1/transit/keys/${NAMED_KEY}/rotate | jq \".\""

echo
echo "Once the key has been rotated, change the 'vault-index' KV in the Consul UI or using the below CLI command to pull down the latest encryption key"
echo "e.g. 'consul kv put vault-index 2'"

echo
echo "Finished"
```

## Step 2: Encryption Key Export

Run the below script in the same location as above to see how consul-template leverages Vault & Consul to automatically rotate local encryption keys.

```
#!/bin/bash
set -e

NAME=example
KEY_NAME=${NAME}.key
TEMPLATE=${NAME}.ctmpl
SCRIPT=${NAME}.sh

cat <<EOF >${TEMPLATE}
{{ with printf "transit/export/encryption-key/%s/%s" ( key "named-key" ) ( key "vault-index" ) | secret }}{{ if .Data.keys }}Encryption Key Version {{ ( key "vault-index" ) }}: {{ index .Data.keys ( key "vault-index" ) }}{{ end }}{{ end }}
EOF

cat <<EOF >${SCRIPT}
#!/bin/bash
set -e

echo \$(cat ${KEY_NAME})
EOF

echo "Running consul-template"
echo "Add the -dry switch to the consul-template command for debugging"
VAULT_TOKEN=$(cat .vault-token)

consul-template \
  -template="${TEMPLATE}:${KEY_NAME}:/bin/bash ${SCRIPT}" \
  -vault-ssl-verify=false \
  -vault-renew-token=false \
  -vault-token=${VAULT_TOKEN}

echo "Finished"
```
