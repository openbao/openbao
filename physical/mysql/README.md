# MySQL Physical Storage Backend for OpenBao

This package provides a MySQL storage backend for OpenBao, **fully compatible with HashiCorp Vault's MySQL storage backend**.

## Compatibility

This implementation is a direct port of Vault 1.14.1's MySQL storage backend, ensuring:
- **Same table structure** as Vault
- **Same HA locking mechanism** using MySQL's `GET_LOCK()` function
- **Same configuration parameters**
- **Zero-downtime migration** from Vault to OpenBao

## Features

- Full `physical.Backend` implementation (Put, Get, Delete, List, ListPage)
- High Availability (HA) support via `physical.HABackend` using MySQL's native locking
- TLS support for secure connections
- Compatible with Vault 1.14.1 MySQL storage schema

## Configuration

### Configuration Parameters

| Parameter                      | Required | Description                                            |
| ------------------------------ | -------- | ------------------------------------------------------ |
| `address`                      | Yes      | MySQL server address (e.g., `127.0.0.1:3306`)          |
| `username`                     | Yes      | MySQL username                                         |
| `password`                     | Yes      | MySQL password                                         |
| `database`                     | No       | Database name (default: `vault`)                       |
| `table`                        | No       | Table name for KV storage (default: `vault`)           |
| `ha_enabled`                   | No       | Enable HA support (default: `false`)                   |
| `lock_table`                   | No       | Table name for HA locks (default: `<table>_lock`)      |
| `max_parallel`                 | No       | Maximum number of parallel operations (default: `128`) |
| `max_idle_connections`         | No       | Maximum number of idle connections                     |
| `max_connection_lifetime`      | No       | Maximum connection lifetime in seconds                 |
| `tls_ca_file`                  | No       | Path to CA certificate file for TLS                    |
| `plaintext_connection_allowed` | No       | Set to `true` to suppress TLS warning                  |

### Example Configuration

```hcl
storage "mysql" {
  address    = "127.0.0.1:3306"
  username   = "vault"
  password   = "secret"
  database   = "vault"
  table      = "vault"
  ha_enabled = "true"
}
```

With TLS:

```hcl
storage "mysql" {
  address     = "127.0.0.1:3306"
  username    = "vault"
  password    = "secret"
  database    = "vault"
  table       = "vault"
  ha_enabled  = "true"
  tls_ca_file = "/path/to/ca.pem"
}
```

## Database Schema

The backend uses the **same table structure as Vault 1.14.1**:

### KV Store Table

```sql
CREATE TABLE IF NOT EXISTS vault (
    vault_key varbinary(3072),
    vault_value mediumblob,
    PRIMARY KEY (vault_key)
);
```

### HA Locks Table (when `ha_enabled = true`)

```sql
CREATE TABLE IF NOT EXISTS vault_lock (
    node_job varbinary(512),
    current_leader varbinary(512),
    PRIMARY KEY (node_job)
);
```

## Migration from Vault 1.14.1

Since this implementation uses the **exact same table structure and HA mechanism** as Vault 1.14.1, migration is straightforward:

### Steps

1. **Stop Vault 1.14.1**
   ```bash
   systemctl stop vault
   ```

2. **Backup your database** (recommended)
   ```bash
   mysqldump -u root -p vault > vault_backup.sql
   ```

3. **Replace the binary**
   - Replace the Vault binary with OpenBao binary
   - Or update your systemd service file to use OpenBao

4. **Start OpenBao**
   ```bash
   systemctl start vault  # or openbao if you renamed the service
   ```

### Configuration Compatibility

The configuration format is **100% compatible**. Your existing Vault configuration file works without modification:

```hcl
# This configuration works for both Vault and OpenBao
storage "mysql" {
  address    = "127.0.0.1:3306"
  username   = "vault"
  password   = "secret"
  database   = "vault"
  table      = "vault"
  ha_enabled = "true"
}
```

## HA Lock Mechanism

The HA implementation uses MySQL's native `GET_LOCK()` and `IS_USED_LOCK()` functions:

- **Lock acquisition**: Uses `GET_LOCK(key, timeout)` for atomic lock acquisition
- **Lock monitoring**: Uses `IS_USED_LOCK(key)` to verify lock ownership
- **Lock release**: Closes the database connection to release the lock

This is the same mechanism used by Vault, ensuring seamless failover behavior.

## Testing

To run the MySQL backend tests:

```bash
export MYSQL_ADDR="127.0.0.1:3306"
export MYSQL_USERNAME="root"
export MYSQL_PASSWORD="password"
export MYSQL_DATABASE="test_vault"
export MYSQL_TABLE="test_vault"

go test -v ./physical/mysql/...
```

## Notes

- This backend does **not** support transactions (same as Vault's MySQL backend)
- The HA lock is held by the database connection, not a separate heartbeat mechanism
- Closing the connection automatically releases the lock
- The `ListPage` operation is implemented client-side for compatibility
