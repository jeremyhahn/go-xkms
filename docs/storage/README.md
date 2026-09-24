# Storage Engines

xkms abstracts its local persistence layer through selectable storage engines. At startup, the `storage.backend` configuration field chooses which engine is used; the engine's behavior is transparent to the rest of the system. All storage state—keys, users, RBAC, CA serials, revocations, audit logs, and more—goes through the same Backend interface, so switching engines requires only a configuration change.

## Available Engines

xkms supports four storage engines via go-qrdb's SDK:

### File Engine (Default)

**Kind:** `file`

A flat, single-file-per-key layout in a directory. Each key is stored as a separate file at `<path>/<key>`, with subdirectories for nested key hierarchies.

**When to use:**
- Development and testing
- Single-node deployments without strict durability requirements
- Migrations from xkms's historical file-based storage

**Configuration:**

```yaml
storage:
  backend: file
  path: /var/lib/xkms/data
```

**Notes:**
- The `path` directory is created if it does not exist.
- File I/O performance is bounded by filesystem speed; this engine is slower than PebbleDB for large datasets.
- No data migration needed when switching to file (this is the historical format).

### PebbleDB Engine

**Kind:** `pebble`

An embedded LSM-tree database in a single directory, based on the open-source PebbleDB (used by CockroachDB and TiKV). Provides better write throughput and range query performance than the file engine.

**When to use:**
- Production single-node deployments
- Deployments that prioritize durability and performance over simplicity
- Environments with many small keys and frequent updates

**Configuration:**

```yaml
storage:
  backend: pebble
  path: /var/lib/xkms/data
```

**Notes:**
- The `path` directory is created if it does not exist.
- PebbleDB maintains internal LSM files; do not manually move or edit the directory.
- PebbleDB is the default engine when `storage.backend` is omitted and `path` is provided.
- Switching from file to pebble requires a one-time data migration (not handled automatically; contact support for migration procedures).

### Memory Engine

**Kind:** `memory`

An in-memory, non-persistent storage engine. All data is lost when the process exits.

**When to use:**
- Unit and integration tests
- Development and prototyping
- Ephemeral deployments that are recreated on each boot

**Configuration:**

```yaml
storage:
  backend: memory
```

**Notes:**
- The `path` field is ignored.
- No data persists across restarts.
- Ideal for CI/CD pipelines and containerized test environments where state is ephemeral.

### Object Storage Engine

**Kind:** `objstore`

A cloud-agnostic storage engine backed by go-objstore providers, supporting both local and remote object storage (S3, GCS, Azure Blob, etc.). Allows xkms to store all persistent data in object storage backends.

**When to use:**
- Cloud deployments where object storage is preferred over local disks
- Multi-region or highly distributed deployments
- Environments with strict compliance requirements for data residency

**Configuration:**

```yaml
storage:
  backend: objstore
  path: /var/lib/xkms/data  # Local cache or fallback path
  provider: s3
  options:
    bucket: my-xkms-bucket
    region: us-west-2
    credentials_file: /etc/aws/credentials
```

**Supported Providers:**

- `local` – Local filesystem storage (fallback for testing)
- `memory` – In-memory object store (testing only)
- `s3` – Amazon S3 (requires AWS credentials)
- `gcs` – Google Cloud Storage (requires GCP credentials)
- `azure` – Azure Blob Storage (requires Azure credentials)
- Others – Additional providers may be available depending on build tags

**Provider-Specific Options:**

Each provider accepts different options; consult go-objstore documentation for details. Common ones:

- **S3:** `bucket`, `region`, `credentials_file`, `endpoint`, `force_path_style`
- **GCS:** `project_id`, `bucket`, `credentials_file`
- **Azure:** `account`, `container`, `credentials_file`

**Notes:**
- Object storage engines are selectable only when built with appropriate build tags (e.g., `-tags objstore_s3,objstore_gcs`).
- The `path` field, if set, is used as a local cache or fallback; it is optional.
- Network latency for object storage is typically higher than local storage.

## Clustering

Clustering (Raft replication across multiple nodes) requires the **qrdb** embedded backend and is configured separately in the `cluster:` block. See [Clustering](../cluster/user.md) for details.

## Selecting an Engine

The `storage:` configuration block controls which engine is used:

```yaml
storage:
  backend: pebble  # or "file", "memory", "objstore"
  path: /var/lib/xkms/data
```

Environment variables override config file settings:

```bash
export XKMS_STORAGE_PATH=/mnt/fast-storage
xkmsd
```

The storage path defaults to `~/.xkms/data` if not specified.

## Performance Considerations

| Engine | Throughput | Latency | Durability | Best For |
|--------|-----------|---------|-----------|----------|
| file | Low | Medium | Good | Development, simple deployments |
| pebble | High | Low | Excellent | Production, high-frequency updates |
| memory | Very High | Very Low | None | Testing, ephemeral workloads |
| objstore | Medium | High | Excellent | Cloud deployments, compliance |

## Data Integrity

All engines use the same Backend interface and must respect the same contract:

- **Get** returns the exact value previously stored with Put, or an error if the key does not exist.
- **Put** atomically overwrites or creates the key-value pair.
- **Delete** atomically removes the key.
- **List** returns all keys with a given prefix in sorted order.
- **Scan** iterates all keys with a given prefix, invoking a callback for each.

No engine guarantees cross-key transactions or distributed consistency; use xkms's own locking and versioning layers for those concerns.

## Troubleshooting

**"storage: engine open-file: permission denied"**

The configured `path` directory is not writable by the xkms process. Ensure the directory exists and the process has write permissions.

**"storage: engine open-pebble: database already open"**

Multiple xkms processes are trying to access the same pebble database. Only one process may use a given PebbleDB directory at a time. Use separate `path` directories for each xkms instance, or deploy a single xkms server and route traffic through it.

**"storage: engine open-objstore: provider not available"**

The specified provider is not compiled in. Rebuild with the appropriate build tag (e.g., `go build -tags objstore_s3`).

## Migration

Switching storage engines requires manual data migration. The xkms development team can assist with:

- Exporting data from one engine and importing into another
- Verifying data consistency after migration
- Scheduling migrations in production environments with minimal downtime

For production migrations, open a support case with details about your current engine, target engine, and dataset size.
