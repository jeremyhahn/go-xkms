# xhome - Unified Path Resolution

The `xhome` package (`xkey/pkg/xhome`) provides unified path resolution for xKey. Every component -- CLI, GUI, LUKS, barrier, config loader -- resolves paths through a single `Home` value so that the data directory is never hard-coded in multiple places.

## Resolution Order

`Resolve()` probes four strategies in order and returns the first valid candidate:

| Priority | Strategy | Path | Notes |
|----------|----------|------|-------|
| 1 | `XKEY_HOME` env var | Value of the variable | Created with 0700 if it does not exist. Relative paths are resolved to absolute. |
| 2 | Binary directory marker | Directory containing the running binary | Only if a `.xkey-home` file exists in that directory (portable/USB mode). |
| 3 | User home | `~/.xkey/` | Created with 0700 on first use. |
| 4 | System fallback | `/etc/xkey/` | Read-only, last resort. |

If none of the strategies succeed, `Resolve()` returns `ErrHomeNotResolved`.

## Directory Layout

Once a root is resolved, `Home` exposes well-known paths beneath it:

```
<root>/
  config.yaml     # ConfigPath()   - application configuration
  xkey.luks        # LUKSPath()     - LUKS2 encrypted container
  data/            # DataDir()      - barrier-encrypted data
  trust/           # TrustDir()     - public CA certificates
  ca/              # CADir()        - local User CA
  devices/         # DevicesDir()   - paired device configs
```

## API Reference

### Resolve

```go
func Resolve() (*Home, error)
```

Probes the resolution strategies in order and returns a `Home` pointing at the first valid directory. Directories for strategies 1 and 3 are created automatically with 0700 permissions if they do not exist.

### ResolveForUser

```go
func ResolveForUser(homeDir string) (*Home, error)
```

Probes the same strategies in the same order, but evaluates strategy 3
(`~/.xkey/`) against `homeDir` instead of the current process's home. A
command running under `sudo` passes the invoking user's home (looked up from
`SUDO_USER`) so that it shares state with that user's own session rather
than with root's; `XKEY_HOME` and the portable marker still take precedence.
An empty `homeDir` skips strategy 3. `xkey device` uses it for the shared
`devices.yaml`.

### Home

```go
type Home struct {
    Root string // Resolved root directory
}
```

**Path accessors** (all return `filepath.Join(Root, ...)`):

| Method | Returns |
|--------|---------|
| `ConfigPath()` | `<root>/config.yaml` |
| `DataDir()` | `<root>/data` |
| `TrustDir()` | `<root>/trust` |
| `CADir()` | `<root>/ca` |
| `DevicesDir()` | `<root>/devices` |
| `LUKSPath()` | `<root>/xkey.luks` |
| `MountPoint()` | `<root>` (the root itself) |

**Directory creators** (create with 0700 if missing, return the path):

| Method | Creates |
|--------|---------|
| `EnsureDataDir()` | `<root>/data` |
| `EnsureTrustDir()` | `<root>/trust` |
| `EnsureCADir()` | `<root>/ca` |
| `EnsureDevicesDir()` | `<root>/devices` |

### Test Helpers

```go
func SetRoot(dir string)  // Override resolved root for testing
func ResetRoot()           // Clear the override
```

`SetRoot` takes priority over all strategies including `XKEY_HOME`. Always pair with `ResetRoot` in test cleanup.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `XKEY_HOME` | Overrides all other resolution strategies. The directory is created if it does not exist. Relative paths are resolved to absolute. |

## CLI Data Directory Chain

The `xkey` CLI never hard-codes `~/.xkey/data`. Every command group that
persists state resolves the data directory through one chain in
`xkey/cmd/xkey/cmd/datadir.go`, then appends its own feature segment:

| Priority | Source | Notes |
|----------|--------|-------|
| 1 | The group's `--data-dir` flag | Only `pin` and `barrier` expose one. |
| 2 | `XKEY_DATA_DIR` env var | Used as given (cleaned), whether or not it exists. |
| 3 | Config key `data_dir` | Same handling as the env var. |
| 4 | `Home.DataDir()` | `<root>/data` under the home resolved by the order above. |

The chain has a creating variant (`resolveDataDir`, used by commands that
initialise state) and a non-creating variant (`resolveDataDirExisting`,
used by read-only commands so that inspecting state never manufactures an
empty data directory). Feature groups obtain `<dataDir>/<feature>` from
`featureDataDir` / `featureDataDirExisting`.

| Group | Location | Variant |
|-------|----------|---------|
| `pin` | `<dataDir>/pin` | creating for `set-*`, existing for reads |
| `barrier` | `<dataDir>` | creating |
| `extension` | `<dataDir>/extension/pairing.json` | creating for `host`, existing for `unpair` / `pair-status` |
| `trust` (and `browser launch`) | `trust.store_path` if set, else `<dataDir>/trust` | creating (the store creates itself on open) |
| `auth` | `<dataDir>/auth` | creating (the storage backend creates itself on open) |
| `agent` / `device enroll` | `<dataDir>/agent` | creating |
| `backup` / `device sync` | `<dataDir>` | creating |

Because they share the chain, all of these groups honour `XKEY_HOME`, the
portable `.xkey-home` marker, `XKEY_DATA_DIR` and `data_dir` identically.
A test in the CLI package (`TestNoAdHocDataDirLiterals`) fails the build
if any command source outside `datadir.go` spells the data directory by
hand.

The home **root** is addressed the same way. `backup` keeps its default
directory at `<root>/backups` and `device` keeps the shared `devices.yaml`
at `<root>/devices.yaml`, both under `Resolve()` (or `ResolveForUser` under
`sudo`), never under `$HOME/.xkey` directly (#442). A companion gate
(`TestNoAdHocHomeRootLiterals`) fails the build on a quoted `".xkey"` path
segment in any command source.

## Binary Directory Marker

For portable or USB deployments, place an empty `.xkey-home` file next to the xkey binary:

```
/mnt/usb/
  xkey              # binary
  .xkey-home        # marker file (can be empty)
  config.yaml
  data/
  trust/
```

When the binary detects this marker in its own directory, it uses that directory as the xKey home without requiring environment variables or a user home directory.

## Errors

| Error | Description |
|-------|-------------|
| `ErrHomeNotResolved` | No strategy found a valid directory |
| `ErrRootNotDirectory` | Resolved path exists but is not a directory |
| `ErrRootNotAccessible` | Resolved directory cannot be read |
| `ResolveError` | Wraps a failed resolution attempt with strategy name, path, and underlying error |

## Usage Examples

### Basic resolution

```go
home, err := xhome.Resolve()
if err != nil {
    log.Fatal(err)
}
fmt.Println("Config:", home.ConfigPath())
fmt.Println("Data:  ", home.DataDir())
```

### Ensure directories exist before writing

```go
home, _ := xhome.Resolve()

dataDir, err := home.EnsureDataDir()
if err != nil {
    return fmt.Errorf("creating data dir: %w", err)
}
// Write files into dataDir
```

### Override for testing

```go
func TestMyComponent(t *testing.T) {
    dir := t.TempDir()
    xhome.SetRoot(dir)
    t.Cleanup(xhome.ResetRoot)

    home, err := xhome.Resolve()
    // home.Root == dir
}
```

## See Also

- [xkey Configuration](configuration.md) - Application configuration loaded from `ConfigPath()`
- [xkey Architecture](architecture.md) - System design and component layout
- [LUKS2 Encrypted Storage](luks.md) - LUKS container at `LUKSPath()`
- [Auto-Unseal](auto-unseal.md) - Barrier and LUKS auto-unseal via TPM
