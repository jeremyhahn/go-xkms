# xkey share -- Key Share Management

Manage locally stored Shamir secret shares for barrier unseal operations. Shares are distributed by the xkmsd server during a Shamir initialization ceremony. Each custodian stores their share locally and submits it back when a quorum is needed.

Local shares are stored in `~/.xkey/shares/`, encrypted by the local barrier when active.

## Command Tree

```
xkey share
├── list      List locally stored shares
├── receive   Poll server for distributed shares
├── import    Import a share from a JSON file
├── export    Export a share to a JSON file
├── unseal    Submit a share to unseal the server barrier
└── delete    Delete a locally stored share
```

## share list

List all Shamir shares stored on this machine.

```bash
xkey share list
```

**Output:**

```
Locally Stored Shares (2):

SERVER                              GROUP ID      GROUP NAME      INDEX  PURPOSE             RECEIVED AT
------                              --------      ----------      -----  -------             -----------
grpc://kms.example.com:9090         barrier-ops   Production Ops  2      production barrier  2025-06-15T10:30:00Z
grpc://kms-dev.internal:9090        dev-barrier   Dev Team        1      dev environment     2025-06-14T08:00:00Z
```

## share receive

Poll an xkmsd server for Shamir shares assigned to the authenticated user and store them locally.

```bash
xkey share receive --server <url>
```

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | xkmsd server URL (required) |

**Example:**

```bash
xkey share receive --server grpc://kms.example.com:9090
```

## share import

Import a Shamir share from a JSON file into the local store. The JSON file must contain a valid ShareEntry with `server_url`, `group_id`, `share_index`, and `share_data` fields.

```bash
xkey share import --file <path>
```

| Flag | Type | Description |
|------|------|-------------|
| `--file` | string | Path to JSON file containing the share (required) |

**Example:**

```bash
xkey share import --file /tmp/share-1.json
```

## share export

Export a locally stored Shamir share to a JSON file for backup or offline transfer. The output file is written with 0600 permissions.

```bash
xkey share export --server <url> --group-id <id> --file <path>
```

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | xkmsd server URL that issued the share (required) |
| `--group-id` | string | Custodian group ID (required) |
| `--file` | string | Output path for the exported share JSON (required) |

**Example:**

```bash
xkey share export --server grpc://kms.example.com:9090 \
  --group-id barrier-ops --file /tmp/share-backup.json
```

## share unseal

Submit a locally stored Shamir share to the xkmsd server to contribute toward the unseal quorum.

```bash
xkey share unseal --server <url> --group-id <id>
```

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | xkmsd server URL to submit the share to (required) |
| `--group-id` | string | Custodian group ID (required) |

**Example:**

```bash
xkey share unseal --server grpc://kms.example.com:9090 --group-id barrier-ops
```

**Output (quorum not yet reached):**

```
Share submitted for group barrier-ops
  Required:  3
  Submitted: 2
  Status:    1 more share(s) needed
```

**Output (quorum reached):**

```
Share submitted for group barrier-ops
  Required:  3
  Submitted: 3
  Status:    Quorum reached - barrier unsealed!
```

## share delete

Delete a Shamir share from local storage. This operation is permanent.

```bash
xkey share delete --server <url> --group-id <id>
```

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | xkmsd server URL that issued the share (required) |
| `--group-id` | string | Custodian group ID (required) |

**Example:**

```bash
xkey share delete --server grpc://kms.example.com:9090 --group-id barrier-ops
```

## See Also

- [Bootstrap Architecture](../../bootstrap/README.md) -- Trust establishment overview
- [Server Authentication](./auth.md) -- Server registration and login
- [CLI Reference](./README.md) -- Full CLI command index
