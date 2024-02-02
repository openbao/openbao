#!/usr/bin/env bats

# Environment Variables:
# Required:
# VAULT_PLUGIN_DIR  Location of the directory Vault should use to find all plugins.
#                   These plugins will need to be built for Linux.
#
# Optional:
# ===== Vault ===========================================
# VAULT_DOCKER_NAME  Name of the container to run Vault in
#                    Default: "vault-tests"
# VAULT_BIN          Location of the Vault binary. This is used to run queries against Vault.
#                    Default: "vault" (uses $PATH)
# VAULT_VERSION      Version of Vault to run in Docker
#                    Default: "latest"
# VAULT_TOKEN        The root token to use with Vault. These tests will not store the token
#                    in the local file system unlike the default behavior of a dev Vault server
#                    Default: "root-token"
# VAULT_PORT         The port number for Vault to run at. This is used to construct the
#                    $VAULT_ADDR environment variable. The IP address nor protocol are specified
#                    because it is assumed that http://127.0.0.1 will be used.
#                    Default: 8200
#
# ===== OpenLDAP ===========================================
# OPENLDAP_DOCKER_NAME    Name of the container to run OpenLDAP in
#                         Default: "openldap-tests"
# OPENLDAP_VERSION        Version of the OpenLDAP container to use
#                         Default: "latest"
# OPENLDAP_PORT_UNSECURE  The port number to expose OpenLDAP for unsecure communications
#                         Default: 389
# OPENLDAP_PORT_SECURE    The port number to expose OpenLDAP for secure communications
#                         Default: 636
#
# ===== Docker ===========================================
# DOCKER_NETWORK  Name of the docker network to create
#                 Default: "openldap-acceptance-tests-network"

# Required
vault_plugin_dir=${VAULT_PLUGIN_DIR}

# Optional
docker_network=${DOCKER_NETWORK:-"openldap-acceptance-tests-network"}

vault=${VAULT_BIN:-"vault"} # Uses $PATH

vault_docker_name=${VAULT_DOCKER_NAME:-"vault-tests"}
vault_version=${VAULT_VERSION:-"latest"}
vault_port=${VAULT_PORT:-"8200"}
vault_server_addr="127.0.0.1"
VAULT_ADDR="http://${vault_server_addr}:${vault_port}"
export VAULT_TOKEN=${VAULT_TOKEN:-"root-token"}

openldap_docker_name=${OPENLDAP_DOCKER_NAME:-"openldap-tests"}
openldap_version=${OPENLDAP_VERSION:-"latest"}
openldap_port_unsecure=${OPENLDAP_PORT_UNSECURE:-389}
openldap_port_secure=${OPENLDAP_PORT_SECURE:-636}
admin_password="2LearnVault"

creation_ldif='dn: cn={{.Username}},ou=users,dc=learn,dc=example
objectClass: person
objectClass: top
cn: learn
sn: learn-{{.Username | utf16le | base64}}
memberOf: cn=dev,ou=groups,dc=learn,dc=example
userPassword: {{.Password}}'

deletion_ldif='dn: cn={{.Username}},ou=users,dc=learn,dc=example
changetype: delete'

log() {
  printf "# $(date) - %s\n" "${1}" >&3
}

if [ "${vault_plugin_dir}" == "" ]; then
  log "No plugin directory specified"
  exit 1
fi

stop_container() {
  container_name="$1"

  if [ -z "${container_name}" ]; then
    log "Missing container name from stop_container call"
    exit 1
  fi

  run docker ps -q -f name="${container_name}"
  if [ "${output}" != "" ]; then
    log "Killing container ${container_name}..."
    docker kill "${container_name}"
    log "Container ${container_name} has stopped"
  fi
}

start_openldap() {
  # Taken from our Learn guide
  log "Starting OpenLDAP server..."

  docker run \
    --name ${openldap_docker_name} \
    --rm \
    --detach \
    --network "${docker_network}" \
    --env LDAP_ORGANISATION="learn" \
    --env LDAP_DOMAIN="learn.example" \
    --env LDAP_ADMIN_PASSWORD="${admin_password}" \
    -p ${openldap_port_unsecure}:${openldap_port_unsecure} \
    -p ${openldap_port_secure}:${openldap_port_secure} \
    osixia/openldap:${openldap_version}

  # Wait for the container to start up - this really should be a status check of some sort
  sleep 2

  log "Bootstrapping OpenLDAP data..."

  ldapadd -cxD "cn=admin,dc=learn,dc=example" -w "${admin_password}" -f "${BATS_TEST_DIRNAME}/create_entries.ldif"

  # Confirm user added
  ldapsearch -b "cn=alice,ou=users,dc=learn,dc=example" -D "cn=alice,ou=users,dc=learn,dc=example" -w "1LearnedVault"

  log "OpenLDAP server is running!"
}

start_vault() {
  log "Starting Vault with plugin directory [${vault_plugin_dir}]"

  docker run \
    --name "${vault_docker_name}" \
    --rm \
    --detach \
    --cap-add=IPC_LOCK \
    --network "${docker_network}" \
    -v "${vault_plugin_dir}:/vault/plugins" \
    -p ${vault_port}:8200 \
    -e VAULT_DEV_ROOT_TOKEN_ID="${VAULT_TOKEN}" \
    -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
    "vault:${vault_version}" \
    vault \
      server \
      -dev \
      -dev-plugin-dir /vault/plugins \
      -log-level=trace

  # Wait for Vault to become available
  log "Waiting for vault to become available..."
  run ${vault} status -address="${VAULT_ADDR}"
  while [ "$status" -ne 0 ]; do
    sleep 1
    run ${vault} status -address="${VAULT_ADDR}"
  done
  sleep 1
}

setup_file() {
  stop_container "${vault_docker_name}"
  stop_container "${openldap_docker_name}"

  if docker network ls -f "name=${docker_network}" | grep "${docker_network}"; then
    docker network remove "${docker_network}"
  fi

  docker network create "${docker_network}" --driver bridge

  start_openldap
  start_vault

  vault secrets enable -path openldap vault-plugin-secrets-openldap
}

teardown_file() {
  log "Tearing down containers..."
  stop_container "${vault_docker_name}"
  stop_container "${openldap_docker_name}"
  docker network remove "${docker_network}"
  log "Teardown complete"
}

setup() {
  vault write openldap/config binddn='cn=admin,dc=learn,dc=example' bindpass="${admin_password}" url="ldap://${openldap_docker_name}"
}

teardown() {
  vault delete openldap/config

  # Remove any roles that were created so they don't bleed over to other tests
  output=$(vault list -format=json openldap/role || true) # "or true" so it doesn't show an error if there are no roles

  roles=$(echo "${output}" | jq -r .[])
  for role in ${roles}; do
    vault delete "openldap/role/${role}" > /dev/null
  done
}

@test "Dynamic Secrets - Read/write role" {
  default_ttl=5
  max_ttl=10

  # Create role
  run vault write openldap/role/testrole creation_ldif="${creation_ldif}" deletion_ldif="${deletion_ldif}" default_ttl="${default_ttl}s" max_ttl="${max_ttl}s"
  [ ${status} -eq 0 ]

  # Read role and make sure it matches what we expect
  run vault read openldap/role/testrole -format=json
  [ ${status} -eq 0 ]
  expected='{
    "creation_ldif": "dn: cn={{.Username}},ou=users,dc=learn,dc=example\nobjectClass: person\nobjectClass: top\ncn: learn\nsn: learn-{{.Username | utf16le | base64}}\nmemberOf: cn=dev,ou=groups,dc=learn,dc=example\nuserPassword: {{.Password}}",
    "deletion_ldif": "dn: cn={{.Username}},ou=users,dc=learn,dc=example\nchangetype: delete",
    "rollback_ldif": "",
    "default_ttl": 5,
    "max_ttl": 10,
    "username_template": ""
  }'
  run jq --argjson a "${output}" --argjson b "${expected}" -n '$a.data == $b'
  [ ${status} -eq 0 ]
  [ "${output}" == "true" ]

  ## Delete the role and ensure that it and the creds endpoint isn't readable
  run vault delete openldap/role/testrole
  [ ${status} -eq 0 ]

  run vault read openldap/role/testrole
  [ ${status} -ne 0 ]

  run vault read openldap/creds/testrole
  [ ${status} -ne 0 ]
}

@test "Dynamic Secrets - List roles" {
  # Create a bunch of roles with different prefixes
  for id in $(seq -f "%02g" 0 10); do
    rolename="testrole${id}"
    run vault write "openldap/role/${rolename}" creation_ldif="${creation_ldif}" deletion_ldif="${deletion_ldif}" default_ttl="5s" max_ttl="10s"
    [ ${status} -eq 0 ]

    rolename="roletest${id}"
    run vault write "openldap/role/${rolename}" creation_ldif="${creation_ldif}" deletion_ldif="${deletion_ldif}" default_ttl="5s" max_ttl="10s"
    [ ${status} -eq 0 ]
  done

  # Test list
  run vault list -format=json openldap/role
  [ ${status} -eq 0 ]

  expected='[
    "roletest00",
    "roletest01",
    "roletest02",
    "roletest03",
    "roletest04",
    "roletest05",
    "roletest06",
    "roletest07",
    "roletest08",
    "roletest09",
    "roletest10",
    "testrole00",
    "testrole01",
    "testrole02",
    "testrole03",
    "testrole04",
    "testrole05",
    "testrole06",
    "testrole07",
    "testrole08",
    "testrole09",
    "testrole10"
  ]'
  run jq --argjson a "${output}" --argjson b "${expected}" -n '$a == $b'
  [ ${status} -eq 0 ]
  [ "${output}" == "true" ]
}

@test "Dynamic Secrets - Credential lifecycle without renewal" {
  default_ttl=10
  max_ttl=20

  # Create role
  run vault write openldap/role/testrole creation_ldif="${creation_ldif}" deletion_ldif="${deletion_ldif}" rollback_ldif="${deletion_ldif}" default_ttl="${default_ttl}s" max_ttl="${max_ttl}s"
  [ ${status} -eq 0 ]

  # Get credentials
  run vault read -format=json openldap/creds/testrole
  [ ${status} -eq 0 ]


  ## Assert all fields that should be there are there
  assertion=$(echo "${output}" | jq '.data | has("username")')
  [ "${assertion}" == "true" ]

  assertion=$(echo "${output}" | jq '.data | has("password")')
  [ "${assertion}" == "true" ]

  assertion=$(echo "${output}" | jq '.data | has("distinguished_names")')
  [ "${assertion}" == "true" ]

  ## Assert the fields are structured correctly
  username="$(echo "${output}" | jq -r '.data.username')"
  [[ "${username}" =~ ^v_token_testrole_[a-zA-Z0-9]{20}_[0-9]{10}$ ]]

  password="$(echo "${output}" | jq -r '.data.password')"
  [[ "${password}" =~ ^[a-zA-Z0-9]{64}$ ]]

  numDNs="$(echo "${output}" | jq -r '.data.distinguished_names | length')"
  [[ ${numDNs} -eq 1 ]]

  dn="$(echo "${output}" | jq -r '.data.distinguished_names[0]')"
  [[ "${dn}" =~ ^cn=${username},ou=users,dc=learn,dc=example$ ]]

  ## Assert the credentials work in OpenLDAP
  run ldapsearch -b "${dn}" -D "${dn}" -w "${password}"
  if [ ${status} -ne 0 ]; then
    log "FAILED!!!"
    sleep 30
    [ ${status} -ne 0 ]
  fi

  ## Assert the credentials no longer work after their TTL
  sleep $((default_ttl + 1))

  run ldapsearch -b "${dn}" -D "${dn}" -w "${password}"
  [ ${status} -ne 0 ]
}

@test "Dynamic Secrets - Credential lifecycle with renewal" {
  default_ttl=10
  max_ttl=20

  # Create role
  run vault write openldap/role/testrole creation_ldif="${creation_ldif}" deletion_ldif="${deletion_ldif}" default_ttl="${default_ttl}s" max_ttl="${max_ttl}s"
  [ ${status} -eq 0 ]

  # Get credentials
  log "Generating credentials..."
  run vault read -format=json openldap/creds/testrole
  [ ${status} -eq 0 ]

  lease_id=$(echo "${output}" | jq -r .lease_id)

  ## Assert all fields that should be there are there
  assertion=$(echo "${output}" | jq '.data | has("username")')
  [ "${assertion}" == "true" ]

  assertion=$(echo "${output}" | jq '.data | has("password")')
  [ "${assertion}" == "true" ]

  assertion=$(echo "${output}" | jq '.data | has("distinguished_names")')
  [ "${assertion}" == "true" ]

  ## Assert the fields are structured correctly
  username="$(echo "${output}" | jq -r '.data.username')"
  [[ "${username}" =~ ^v_token_testrole_[a-zA-Z0-9]{20}_[0-9]{10}$ ]]

  password="$(echo "${output}" | jq -r '.data.password')"
  [[ "${password}" =~ ^[a-zA-Z0-9]{64}$ ]]

  numDNs="$(echo "${output}" | jq -r '.data.distinguished_names | length')"
  [[ ${numDNs} -eq 1 ]]

  dn="$(echo "${output}" | jq -r '.data.distinguished_names[0]')"
  [[ "${dn}" =~ ^cn=${username},ou=users,dc=learn,dc=example$ ]]

  ## Assert the credentials work in OpenLDAP
  run ldapsearch -b "${dn}" -D "${dn}" -w "${password}"
  [ ${status} -eq 0 ]

  ## Wait until the credentials have been around for a detectable amount of time
  wait_until_dur=$((default_ttl - 2))

  log "Waiting for a couple of seconds..."
  while true; do
    run vault write -format=json sys/leases/lookup lease_id="${lease_id}"
    [ ${status} -eq 0 ]
    ttl=$(echo "${output}" | jq .data.ttl)
    if [ ${ttl} -le ${wait_until_dur} ]; then
      break
    fi
    sleep 1
  done

  before_renewal=$(gdate +%s)

  log "Renewing lease..."
  run vault lease renew "${lease_id}"
  [ ${status} -eq 0 ]

  sleep_time=$(($(gdate +%s) - before_renewal + 1))

  ## Wait until after the original TTL but less than the new TTL
  log "Sleeping until after original TTL (${sleep_time}s)..."
  sleep $((sleep_time))

  run ldapsearch -b "${dn}" -D "${dn}" -w "${password}"
  [ ${status} -eq 0 ]

  log "Sleeping until lease expires"
  while true; do
    run vault write -format=json sys/leases/lookup lease_id="${lease_id}"
    if [ ${status} -ne 0 ]; then
      break
    fi
    sleep 1
  done

  run ldapsearch -b "${dn}" -D "${dn}" -w "${password}"
  [ ${status} -ne 0 ]
}

@test "Dynamic Secrets - Useful error on creation failure" {
  default_ttl=10
  max_ttl=20

  bad_creation_ldif='dn: cn={{.Username}},ou=thisgroupdoesnotexist,dc=learn,dc=example
objectClass: person
objectClass: top
cn: learn
sn: learn-{{.Username | utf16le | base64}}
memberOf: cn=dev,ou=groups,dc=learn,dc=example
userPassword: {{.Password}}'

  # Create role
  run vault write openldap/role/testrole creation_ldif="${bad_creation_ldif}" deletion_ldif="${deletion_ldif}" rollback_ldif="${deletion_ldif}" default_ttl="${default_ttl}s" max_ttl="${max_ttl}s"
  [ ${status} -eq 0 ]

  # Get credentials
  run vault read -format=json openldap/creds/testrole
  [ ${status} -ne 0 ]
  [[ "${output}" == *"failed to create user" ]]

  # Optional assertion that makes sure both errors are included but if this becomes flaky it isn't the important error and can be removed
  [[ "${output}" == *"failed to roll back user" ]]

  ## Assert the credentials do *not* work in OpenLDAP
  run ldapsearch -b "${dn}" -D "${dn}" -w "${password}"
  [ ${status} -ne 0 ]
}
