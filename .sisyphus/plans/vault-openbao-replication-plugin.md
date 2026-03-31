# Plan: Vault-to-OpenBao Replication Plugin POC

## TL;DR

> **Summary**: External logical plugin that provides bidirectional sync of secrets, policies, and auth methods between HashiCorp Vault and OpenBao.
> **Deliverables**: Complete plugin source code with sync operations (secrets, policies, auth), configuration, and build instructions.
> **Effort**: Medium
> **Parallel**: YES - 3 waves
> **Critical Path**: Plugin scaffolding → Client implementations → Sync engine → API endpoints

## Context

### Original Request
User wants a POC plugin to replicate information (secrets, policies, auth methods) between HashiCorp Vault and OpenBao in two-way sync mode, implemented as an external plugin.

### Interview Summary
- **Scope**: KV secrets, ACL policies, auth methods (approle, LDAP, etc.)
- **Direction**: Two-way sync (bidirectional)
- **Type**: External plugin (not builtin)
- **Approach**: Trigger-based sync (not continuous polling for POC)

### Metis Review
- Identified need for proper error handling and rollback on sync failures
- Need to handle conflicts (which system wins?)
- External Vault connectivity needs secure token management

## Work Objectives

### Core Objective
Create a functional external plugin that can sync secrets, policies, and auth methods between HashiCorp Vault and OpenBao bidirectionally via API calls.

### Deliverables
1. Plugin source code (main.go, backend.go, sync.go, clients)
2. Configuration schema for mount options
3. Sync API endpoints (secrets, policies, auth, all, status)
4. Build instructions and Makefile

### Definition of Done
- [ ] Plugin compiles without errors
- [ ] Plugin registers with OpenBao successfully
- [ ] `POST /sync/secrets` reads from Vault, writes to OpenBao
- [ ] `POST /sync/policies` reads from Vault, writes to OpenBao  
- [ ] `POST /sync/auth` reads from Vault, writes to OpenBao
- [ ] `GET /sync/status` returns sync state
- [ ] Configuration accepts vault_addr, vault_token, sync_mode

### Must Have
- Implement logical.Backend interface
- Use hashicorp/go-plugin for external plugin communication
- Use OpenBao SDK (github.com/openbao/openbao/api/v2)
- Use HashiCorp Vault SDK for Vault connectivity
- Proper logging and error handling

### Must NOT Have
- Modify any OpenBao core code
- Hardcode credentials (must come from config)
- Implement complex conflict resolution (use "newest wins" for POC)
- Store secrets in plaintext (use existing Vault/OpenBao encryption)

## Verification Strategy

- **Test Decision**: tests-after
- **Framework**: Go testing + manual curl commands
- **QA Policy**: Every task has agent-executed scenarios
- **Evidence**: .sisyphus/evidence/task-{N}-{slug}.{ext}

## Execution Strategy

### Parallel Execution Waves

**Wave 1: Foundation** (tasks 1-3)
- Plugin scaffolding with main.go and go.mod
- logical.Backend interface implementation (stub)
- Configuration struct and initialization

**Wave 2: Clients** (tasks 4-6)
- Vault client implementation (read secrets, policies, auth)
- OpenBao client implementation (write secrets, policies, auth)
- Client factory/initialization

**Wave 3: Sync Engine** (tasks 7-9)
- Sync engine with bidirectional logic
- API endpoints for sync operations
- Status endpoint and error handling

**Wave 4: Polish** (tasks 10-12)
- Makefile and build instructions
- Documentation/README
- Test verification

### Dependency Matrix

| Task | Depends On | Blocks |
|------|------------|--------|
| 1. Plugin scaffold | - | 2, 3 |
| 2. Backend interface | 1 | 4, 5, 7 |
| 3. Config struct | 1 | 4, 5 |
| 4. Vault client | 2, 3 | 7 |
| 5. OpenBao client | 2, 3 | 7 |
| 6. Client factory | 4, 5 | 7 |
| 7. Sync engine | 4, 5, 6 | 8 |
| 8. API endpoints | 7 | 9 |
| 9. Status endpoint | 8 | 10 |
| 10. Makefile | 8 | - |
| 11. README | All above | - |
| 12. Verification | 10, 11 | - |

## TODOs

### Wave 1: Foundation

- [ ] 1. Create plugin scaffolding

  **What to do**: Create directory `plugins/vault-openbao-replicator/` with go.mod and main.go using hashicorp/go-plugin. Set up plugin entry point with GRPCBackendPlugin.
  
  **Must NOT do**: Don't implement actual sync logic yet - just scaffold.

  **Recommended Agent Profile**:
  - Category: `unspecified-low` — Simple file creation
  - Skills: [] — Not needed
  - Omitted: [] — Not needed

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: 2, 3 | Blocked By: -

  **References**:
  - Pattern: `/Users/javierlimon/Documents/git/openbao/sdk/plugin/plugin.go` — Plugin initialization pattern
  - Pattern: `/Users/javierlimon/Documents/git/openbao/plugins/database/postgresql/postgresql.go:1-30` — External plugin structure
  - External: https://www.vaultproject/docs/internals/plugins — Plugin architecture

  **Acceptance Criteria**:
  - [ ] Directory `plugins/vault-openbao-replicator/` exists
  - [ ] go.mod with dependencies: hashicorp/go-plugin, openbao/api/v2, hashicorp/vault/api
  - [ ] main.go uses plugin.Serve() with proper handshake config

  **QA Scenarios**:
  ```
  Scenario: Plugin compiles
    Tool: Bash
    Steps: cd plugins/vault-openbao-replicator && go build -o vault-openbao-replicator .
    Expected: Binary compiles without errors
    Evidence: .sisyphus/evidence/task-1-build.txt
  ```

  **Commit**: YES | Message: `feat(plugin): scaffold vault-openbao-replicator` | Files: plugins/vault-openbao-replicator/*


- [ ] 2. Implement logical.Backend interface

  **What to do**: Create backend.go implementing logical.Backend interface. Implement all required methods: Initialize, HandleRequest, SpecialPaths, System, Logger, HandleExistenceCheck, Cleanup, InvalidateKey, Setup, Type.

  **Must NOT do**: Don't implement actual sync logic - just return stub responses.

  **Recommended Agent Profile**:
  - Category: `unspecified-low` — Simple Go implementation
  - Skills: [] — Not needed

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: 4, 5, 7 | Blocked By: 1

  **References**:
  - Pattern: `/Users/javierlimon/Documents/git/openbao/builtin/logical/kv/backend.go:36-71` — Backend struct pattern
  - API/Type: `/Users/javierlimon/Documents/git/openbao/sdk/logical/logical.go:43-91` — Backend interface contract

  **Acceptance Criteria**:
  - [ ] Backend implements all 10 methods from logical.Backend
  - [ ] Type() returns TypeLogical
  - [ ] SpecialPaths() returns empty Paths for now

  **QA Scenarios**:
  ```
  Scenario: Backend compiles
    Tool: Bash
    Steps: cd plugins/vault-openbao-replicator && go build -o vault-openbao-replicator .
    Expected: Compiles without errors
    Evidence: .sisyphus/evidence/task-2-compile.txt
  ```

  **Commit**: NO | Message: - | Files: -


- [ ] 3. Define configuration struct

  **What to do**: Create config.go with configuration struct for plugin mount options: vault_addr, vault_token, openbao_addr, openbao_token, sync_interval, sync_mode.

  **Must NOT do**: Don't add validation - keep simple for POC.

  **Recommended Agent Profile**:
  - Category: `unspecified-low` — Simple struct definition

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: 4, 5 | Blocked By: 1

  **References**:
  - Pattern: `/Users/javierlimon/Documents/git/openbao/builtin/logical/kv/backend.go:73-90` — Config reading pattern

  **Acceptance Criteria**:
  - [ ] Config struct has all required fields
  - [ ] ParseConfig function extracts from BackendConfig.Config

  **Commit**: NO | Message: - | Files: -


### Wave 2: Clients

- [ ] 4. Implement Vault client (read operations)

  **What to do**: Create vault_client.go with Vault client that can:
  - List all secret engines (sysmounts)
  - Read KV secrets from each mount
  - List policies (sys/policies)
  - List auth methods (sys/auth)
  - Read specific secrets, policies, auth configs

  **Must NOT do**: Don't implement write operations - that's OpenBao client.

  **Recommended Agent Profile**:
  - Category: `unspecified-high` — Requires API knowledge

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 7 | Blocked By: 2, 3

  **References**:
  - API: https://pkg.go.dev/github.com/hashicorp/vault/api — Vault API client
  - Pattern: `/Users/javierlimon/Documents/git/openbao/api/client.go` — Similar client pattern

  **Acceptance Criteria**:
  - [ ] NewVaultClient(config) returns *api.Client
  - [ ] ListSecrets(ctx) returns map[mount]map[key]string
  - [ ] ListPolicies(ctx) returns []string
  - [ ] ListAuthMethods(ctx) returns map[string]MountConfigInput

  **QA Scenarios**:
  ```
  Scenario: Vault client initialized
    Tool: Bash
    Steps: go build passes
    Expected: No compile errors
    Evidence: .sisyphus/evidence/task-4-compile.txt
  ```

  **Commit**: NO | Message: - | Files: -


- [ ] 5. Implement OpenBao client (write operations)

  **What to do**: Create openbao_client.go with OpenBao client that can:
  - Write KV secrets to each mount
  - Create/update policies
  - Enable and configure auth methods
  - Use sys/storage for mounting if needed

  **Must NOT do**: Don't implement read operations - use Vault client for that.

  **Recommended Agent Profile**:
  - Category: `unspecified-high` — Requires API knowledge

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 7 | Blocked By: 2, 3

  **References**:
  - API: `/Users/javierlimon/Documents/git/openbao/api/client.go` — OpenBao API client
  - SDK: `/Users/javierlimon/Documents/git/openbao/sdk/v2/logical/` — Logical storage

  **Acceptance Criteria**:
  - [ ] NewOpenBaoClient(config) returns *api.Client
  - [ ] WriteSecret(ctx, mount, path, data) returns error
  - [ ] WritePolicy(ctx, name, policy) returns error
  - [ ] EnableAuthMethod(ctx, path, config) returns error

  **QA Scenarios**:
  ```
  Scenario: OpenBao client compiles
    Tool: Bash
    Steps: go build passes
    Expected: No compile errors
    Evidence: .sisyphus/evidence/task-5-compile.txt
  ```

  **Commit**: NO | Message: - | Files: -


- [ ] 6. Client factory

  **What to do**: Create client_factory.go that initializes both clients from config. Add to backend struct.

  **Must NOT do**: Don't change client implementations.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 7 | Blocked By: 4, 5

  **Acceptance Criteria**:
  - [ ] InitializeClients(ctx, config) returns (VaultClient, OpenBaoClient, error)
  - [ ] Clients attached to backend struct

  **Commit**: NO | Message: - | Files: -


### Wave 3: Sync Engine

- [ ] 7. Implement sync engine

  **What to do**: Create sync.go with core sync logic:
  - SyncSecrets(ctx, direction) - two-way sync of KV
  - SyncPolicies(ctx, direction) - two-way sync of ACL policies
  - SyncAuthMethods(ctx, direction) - two-way sync of auth mounts
  - Conflict resolution: newest timestamp wins (simple POC)
  - Track sync state (last sync time, items synced)

  **Must NOT do**: Don't create API handlers - that's next task.

  **Recommended Agent Profile**:
  - Category: `unspecified-high` — Core logic, complex

  **Parallelization**: Can Parallel: NO | Wave 3 | Blocks: 8 | Blocked By: 4, 5, 6

  **References**:
  - Pattern: Uses client implementations from tasks 4-5

  **Acceptance Criteria**:
  - [ ] SyncSecrets implements two-way sync
  - [ ] SyncPolicies implements two-way sync
  - [ ] SyncAuthMethods implements two-way sync
  - [ ] SyncState struct tracks progress

  **QA Scenarios**:
  ```
  Scenario: Sync engine compiles
    Tool: Bash
    Steps: go build passes
    Expected: No compile errors
    Evidence: .sisyphus/evidence/task-7-compile.txt
  ```

  **Commit**: NO | Message: - | Files: -


- [ ] 8. API endpoints for sync operations

  **What to do**: Update backend.go HandleRequest to handle:
  - POST /sync/secrets - triggers secret sync
  - POST /sync/policies - triggers policy sync  
  - POST /sync/auth - triggers auth method sync
  - POST /sync/all - triggers full sync

  **Must NOT do**: Don't change sync logic.

  **Parallelization**: Can Parallel: NO | Wave 3 | Blocks: 9 | Blocked By: 7

  **References**:
  - Pattern: `/Users/javierlimon/Documents/git/openbao/builtin/logical/kv/path.go` — Path operations pattern

  **Acceptance Criteria**:
  - [ ] /sync/secrets endpoint returns sync result
  - [ ] /sync/policies endpoint returns sync result
  - [ ] /sync/auth endpoint returns sync result
  - [ ] /sync/all triggers all three

  **QA Scenarios**:
  ```
  Scenario: API endpoints registered
    Tool: Bash
    Steps: go build -o vault-openbao-replicator .
    Expected: Binary compiles with all paths
    Evidence: .sisyphus/evidence/task-8-build.txt
  ```

  **Commit**: NO | Message: - | Files: -


- [ ] 9. Status endpoint

  **What to do**: Add GET /sync/status to HandleRequest that returns:
  - Last sync timestamp per type
  - Items synced count per type
  - Any errors from last sync
  - Sync state (idle, syncing, error)

  **Must NOT do**: Don't add new sync operations.

  **Parallelization**: Can Parallel: NO | Wave 3 | Blocks: 10 | Blocked By: 8

  **Acceptance Criteria**:
  - [ ] GET /sync/status returns JSON with sync state
  - [ ] Includes timestamps and counts

  **Commit**: NO | Message: - | Files: -


### Wave 4: Polish

- [ ] 10. Makefile and build instructions

  **What to do**: Create Makefile with:
  - build target: compile plugin binary
  - test target: run go test
  - clean target: remove binaries
  - Plugin registration command example

  **Must NOT do**: Don't run actual builds.

  **Parallelization**: Can Parallel: YES | Wave 4 | Blocks: - | Blocked By: 9

  **References**:
  - Pattern: `/Users/javierlimon/Documents/git/openbao/Makefile:1-30` — Build patterns

  **Acceptance Criteria**:
  - [ ] make build creates binary
  - [ ] make clean removes binary

  **QA Scenarios**:
  ```
  Scenario: Makefile works
    Tool: Bash
    Steps: cd plugins/vault-openbao-replicator && make build
    Expected: Binary created successfully
    Evidence: .sisyphus/evidence/task-10-make.txt
  ```

  **Commit**: NO | Message: - | Files: -


- [ ] 11. README documentation

  **What to do**: Create README.md with:
  - Overview and purpose
  - Prerequisites (Go 1.21+, Vault, OpenBao)
  - Build instructions
  - Configuration options
  - Usage examples (commands to register and use)
  - API endpoints documentation
  - Limitations and known issues

  **Must NOT do**: Don't document internal implementation details.

  **Parallelization**: Can Parallel: YES | Wave 4 | Blocks: - | Blocked By: 9

  **References**:
  - Pattern: `/Users/javierlimon/Documents/git/openbao/builtin/logical/kv/README.md` — Documentation style

  **Acceptance Criteria**:
  - [ ] README.md exists in plugin directory
  - [ ] Contains build and usage instructions
  - [ ] Lists all configuration options

  **Commit**: NO | Message: - | Files: -


- [ ] 12. Final verification

  **What to do**: Run full verification:
  - Plugin compiles successfully
  - All dependencies resolved
  - logical.Backend interface fully implemented
  - All sync operations present

  **Must NOT do**: Don't run integration tests (requires running Vault/OpenBao).

  **Parallelization**: Can Parallel: NO | Wave 4 | Blocks: - | Blocked By: 10, 11

  **Acceptance Criteria**:
  - [ ] go build ./... succeeds
  - [ ] go vet passes
  - [ ] No unused imports

  **QA Scenarios**:
  ```
  Scenario: Final build verification
    Tool: Bash
    Steps: cd plugins/vault-openbao-replicator && go build ./... && go vet ./...
    Expected: Build and vet pass
    Evidence: .sisyphus/evidence/task-12-verify.txt
  ```

  **Commit**: YES | Message: `feat(plugin): complete vault-openbao-replicator POC` | Files: plugins/vault-openbao-replicator/*


## Final Verification Wave (4 parallel agents)

- [ ] F1. Plan Compliance Audit — ensure all tasks executed
- [ ] F2. Code Quality Review — go vet, no obvious issues
- [ ] F3. File Structure Check — all expected files present
- [ ] F4. Interface Compliance — logical.Backend fully implemented

## Commit Strategy

Single commit after all tasks complete with message: `feat(plugin): complete vault-openbao-replicator POC`

## Success Criteria

1. Plugin compiles without errors
2. logical.Backend interface fully implemented
3. All sync operations available (secrets, policies, auth, all, status)
4. Configuration accepted via mount options
5. README provides clear usage instructions