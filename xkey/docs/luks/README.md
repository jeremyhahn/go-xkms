# xkey LUKS2 Encrypted Storage

xkey supports LUKS2 encrypted storage as an optional base layer for protecting sensitive data at rest. The LUKS2 subsystem provides secure container management with features for creating, unlocking, migrating, and securely destroying encrypted volumes.

## Overview

LUKS2 (Linux Unified Key Setup version 2) is the standard for Linux disk encryption. xkey uses LUKS2 containers to store sensitive configuration, tokens, and credentials in an encrypted volume that can only be accessed with the correct passphrase.

LUKS is an optional base layer. The barrier (AES-256-GCM) is always active on top of whatever base backend is in use:

```
Without LUKS:  App --> Barrier (AES-256-GCM) --> filestorage --> ~/.xkey/data/
With LUKS:     App --> Barrier (AES-256-GCM) --> luks.Backend --> filestorage --> ~/.xkey/ (LUKS mount)
```

When LUKS is selected, data passes through two independent encryption layers: the barrier provides per-value AES-256-GCM encryption with integrity verification (GCM auth tag), and LUKS provides FIPS-validated kernel-level AES-256-XTS full-volume encryption via dm-crypt.

The `pkg/storage/luks/` package provides the `luks.Backend` implementation that bridges the LUKS volume to the `storage.Backend` interface via a `VolumeOperator` abstraction.

### Storage Layout

```
When sealed (encrypted, locked):
~/.xkey.luks          # Encrypted LUKS2 container file
~/.xkey/              # Empty or doesn't exist

When unsealed (decrypted, mounted):
~/.xkey.luks          # Encrypted LUKS2 container file
~/.xkey/              # Mounted filesystem with decrypted data
├── config.yaml          # xkey configuration
├── tokens.json          # OIDC tokens
├── aws-session.json     # AWS session data
├── oidc-providers.json  # OIDC provider configs
├── logs/                # Log files
├── pids/                # Process ID files
└── ...                  # Other sensitive data
```

## Commands

All LUKS commands require root privileges and are accessed under `xkey luks2`.

### seal - Create Encrypted Container

Creates a new LUKS2 encrypted container, optionally migrating existing data.

```bash
sudo xkey luks2 seal [flags]
```

**Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--size` | Container size (e.g., "100M", "1G", "500M") | 100M |
| `--path` | Custom LUKS file path | ~/.xkey.luks |
| `--mount-point` | Custom mount point | ~/.xkey |

**Examples:**
```bash
# Create 100MB encrypted container (default)
sudo xkey luks2 seal

# Create 500MB container
sudo xkey luks2 seal --size 500M

# Create 1GB container at custom location
sudo xkey luks2 seal --size 1G --path /secure/mydata.luks

# Create container with custom mount point
sudo xkey luks2 seal --mount-point /mnt/xkey
```

**Process:**
1. Prompts for passphrase (with confirmation)
2. Creates sparse file of specified size
3. Formats with LUKS2 encryption
4. Creates ext4 filesystem inside container
5. Migrates existing data from mount point (if any)
6. Locks the container

### unseal - Unlock Container

Unlocks an encrypted LUKS2 container and mounts it for use.

```bash
sudo xkey luks2 unseal [flags]
```

**Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--path` | Custom LUKS file path | ~/.xkey.luks |
| `--mount-point` | Custom mount point | ~/.xkey |

**Examples:**
```bash
# Unlock default container
sudo xkey luks2 unseal

# Unlock custom container
sudo xkey luks2 unseal --path /secure/mydata.luks

# Unlock with custom mount point
sudo xkey luks2 unseal --mount-point /mnt/xkey
```

**Process:**
1. Prompts for passphrase
2. Sets up loop device
3. Unlocks LUKS container
4. Mounts filesystem to mount point

### lock - Lock Container

Locks an unlocked LUKS2 container, unmounting and closing it.

```bash
sudo xkey luks2 lock [flags]
```

**Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--path` | Custom LUKS file path | ~/.xkey.luks |
| `--mount-point` | Custom mount point | ~/.xkey |

**Examples:**
```bash
# Lock default container
sudo xkey luks2 lock

# Lock custom container
sudo xkey luks2 lock --path /secure/mydata.luks
```

**Process:**
1. Unmounts filesystem
2. Closes LUKS container
3. Detaches loop device

### migrate - Migrate to New Container

Migrates data to a new or larger LUKS2 container.

```bash
sudo xkey luks2 migrate [flags]
```

**Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--size` | New container size | 2x current size |
| `--path` | New container path | Same as current |
| `--source-path` | Source container path | ~/.xkey.luks |
| `--keep-old` | Keep old container as backup | false |
| `--wipe` | Securely wipe old container | false |
| `--wipe-standard` | Wipe standard: nist, dod3, dod7 | dod3 |

**Examples:**
```bash
# Double the container size (default)
sudo xkey luks2 migrate

# Migrate to specific size
sudo xkey luks2 migrate --size 500M

# Migrate to new location
sudo xkey luks2 migrate --path /new/location.luks

# Keep old container as backup
sudo xkey luks2 migrate --keep-old

# Securely wipe old container after migration
sudo xkey luks2 migrate --wipe

# DoD 7-pass secure wipe (most thorough)
sudo xkey luks2 migrate --wipe --wipe-standard dod7
```

**Process:**
1. Locks current container if mounted
2. Renames existing container to .old
3. Creates new container
4. Unlocks both containers
5. Copies all data to new container
6. Locks both containers
7. Removes, wipes, or keeps old container based on flags

### wipe - Securely Destroy Container

Securely destroys a LUKS2 container by overwriting data using industry-standard wipe methods before removal.

```bash
sudo xkey luks2 wipe [flags]
```

**Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--standard` | Wipe standard: nist, dod3, dod7 | dod3 |
| `--force` | Skip confirmation prompt | false |
| `--path` | Custom LUKS file path | ~/.xkey.luks |
| `--mount-point` | Custom mount point | ~/.xkey |

**Examples:**
```bash
# Secure wipe with DoD 3-pass (default)
sudo xkey luks2 wipe

# NIST single-pass wipe (fastest)
sudo xkey luks2 wipe --standard nist

# DoD 7-pass secure wipe (most thorough)
sudo xkey luks2 wipe --standard dod7

# Skip confirmation (for scripting)
sudo xkey luks2 wipe --force

# Wipe custom container
sudo xkey luks2 wipe --path /secure/mydata.luks
```

**Security Note:**
The wipe command requires typing "DESTROY" to confirm the operation unless `--force` is used. This is a destructive operation that cannot be undone.

**Process:**
1. Locks container if mounted
2. Overwrites data using the selected wipe standard
3. Removes container file

## Security Considerations

### Passphrase Strength

- Use a strong, unique passphrase (minimum 12 characters recommended)
- Consider using a passphrase manager
- Passphrases are not recoverable - keep a secure backup

### Wipe Standards

xkey supports industry-standard wipe methods for secure data destruction:

| Standard | Name | Pattern | Description |
|----------|------|---------|-------------|
| `nist` | NIST SP 800-88 Rev 1 | Random (1 pass) | Single pass of random data. Fastest option, recommended by NIST for modern storage. |
| `dod3` | DoD 5220.22-M 3-pass | Zeros → Ones → Random | U.S. Department of Defense 3-pass standard. Default choice, balanced security. |
| `dod7` | DoD 5220.22-M ECE 7-pass | (Z→O→R) + R + (Z→O→R) | Extended 7-pass variant. Most thorough, slowest. |

**Recommendation:** For most use cases, the default `dod3` provides excellent security. Use `nist` when speed is important and you trust the underlying storage (SSDs with TRIM). Use `dod7` for maximum assurance on sensitive data.

### Container Sizing

- Default size: 100MB
- Minimum recommended: 32MB
- Consider future growth when sizing
- Use migrate command to resize later

### Best Practices

1. **Always lock when not in use**: Run `xkey luks2 lock` when done
2. **Use secure wipe for sensitive data**: Use `--wipe` flag during migration (defaults to DoD 3-pass)
3. **Keep backups**: Use `--keep-old` flag during migration for safety
4. **Verify after migration**: Unlock new container and verify data integrity
5. **Choose appropriate wipe standard**: Use `dod3` (default) for general security, `dod7` for highly sensitive data

## Automation

### Scripted Usage

For automation, passphrase can be piped via stdin:

```bash
# Seal with piped passphrase (passphrase + confirmation)
echo -e "mypassphrase\nmypassphrase" | sudo xkey luks2 seal

# Unseal with piped passphrase
echo "mypassphrase" | sudo xkey luks2 unseal

# Wipe without confirmation
sudo xkey luks2 wipe --force
```

### Systemd Integration

Create a systemd service to auto-unlock on boot:

```ini
[Unit]
Description=xkey LUKS Unlock
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xkey luks2 unseal
StandardInput=tty-force

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### Common Issues

**"Permission denied"**
- LUKS operations require root privileges
- Use `sudo` for all luks2 commands

**"No encrypted volume found"**
- Container doesn't exist at the specified path
- Check path with `ls -la ~/.xkey.luks`

**"Device or resource busy"**
- Container is already open or mounted
- Run `xkey luks2 lock` first

**"Wrong passphrase"**
- Incorrect passphrase entered
- Verify passphrase and try again

### Recovery

If the container is corrupted:
1. Keep a backup of the `.luks` file
2. Try `cryptsetup luksDump /path/to/file.luks` for header info
3. Consider professional data recovery for critical data

## See Also

- [xkey Configuration](configuration.md) - General configuration options
- [xkey Architecture](architecture.md) - System design and layered storage model
- [Auto-Unseal](auto-unseal.md) - Barrier and LUKS auto-unseal via TPM
- [Barrier Encryption](../../docs/seal/README.md) - Barrier encryption architecture
- [LUKS + Barrier Layered Architecture](../../docs/seal/barrier.md) - Detailed dual-layer encryption design
- [OIDC Guide](oidc.md) - Token storage in encrypted containers
