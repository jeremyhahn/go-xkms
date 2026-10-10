# Build System

Every optional feature of go-xkms is compiled in by default. A build opts a
feature out with `WITH_<FEATURE>=0`, and a binary built without a feature
**fails closed** when its configuration asks for it: `xkms.AutoInitialize`
returns an `*xkms.FeatureNotCompiledError` naming the feature and the toggle
that compiles it in, rather than starting without it.

The `xkey` module follows the same convention through `xkey/Makefile`.

## Quick start

```bash
make build-full                      # every WITH_* feature on
make build-minimal                   # every WITH_* feature off
make build WITH_VAULT=0              # the default build without Vault
make build WITH_AWS=0 WITH_GCP=0 WITH_AZURE=0   # drop the cloud providers
make show-backends                   # the backends the current settings compile
make help                            # every toggle with its current value
```

The Makefile turns the `WITH_*` toggles into Go build tags. A plain
`go build ./...` passes no tags and so builds the minimal set; build through
`make`, or pass the tags yourself, to get the default full set.

## Feature toggles

| Variable | Default | Build tag | What it compiles in |
|----------|---------|-----------|---------------------|
| `WITH_PKCS8` | 1 | `pkcs8` | Tag for PKCS#8 software keys; the PKCS#8 backend itself is always compiled |
| `WITH_TPM2` | 1 | `tpm2` | The TPM 2.0 slot of the PKCS#11 provider module (`pkg/pkcs11/module`); the TPM 2.0 backend itself is always compiled |
| `WITH_PKCS11` | 1 | `pkcs11` | PKCS#11 / HSM backend (needs cgo) |
| `WITH_AWS_KMS` | 1 | `awskms` | AWS KMS backend |
| `WITH_GCP_KMS` | 1 | `gcpkms` | Google Cloud KMS backend |
| `WITH_AZURE_KV` | 1 | `azurekv` | Azure Key Vault backend |
| `WITH_VAULT` | 1 | `vault` | HashiCorp Vault Transit backend |
| `WITH_FROST` | 1 | `frost` | FROST threshold-signing backend |
| `WITH_AWS_S3` | 1 | `awss3` | AWS S3 object store |
| `WITH_MINIO` | 1 | `minio` | MinIO object store |
| `WITH_GCP_STORAGE` | 1 | `gcpstorage` | Google Cloud Storage object store |
| `WITH_AZURE_BLOB` | 1 | `azureblob` | Azure Blob object store |
| `WITH_GLACIER` | 1 | `glacier` | AWS Glacier archive store |
| `WITH_AZURE_ARCHIVE` | 1 | `azurearchive` | Azure Archive store |

The software, symmetric and post-quantum backends have no toggle and are
always compiled. The CBOR, JSON and MessagePack codecs (`codec_cbor`,
`codec_json`, `codec_msgpack`) are always on.

### Provider umbrellas

`WITH_AWS`, `WITH_GCP` and `WITH_AZURE` are unset by default. When set, each
overrides every toggle of its provider:

| Umbrella | Sets |
|----------|------|
| `WITH_AWS` | `WITH_AWS_KMS`, `WITH_AWS_S3`, `WITH_GLACIER` |
| `WITH_GCP` | `WITH_GCP_KMS`, `WITH_GCP_STORAGE` |
| `WITH_AZURE` | `WITH_AZURE_KV`, `WITH_AZURE_BLOB`, `WITH_AZURE_ARCHIVE` |

### Toggles in `xkey/Makefile`

`xkey` compiles `WITH_PKCS11` and the six object-store toggles above, all
defaulting to 1, plus the same provider umbrellas. It has no KMS toggles of
its own.

## Build profiles

| Target | Root module | `xkey` module |
|--------|-------------|---------------|
| `build-full` | Compiles every package and builds `xkmsctl` and `xkmsd` into `build/bin/` with every toggle at 1 | Compiles every package and builds `xkey` into `build/bin/` with every toggle at 1 |
| `build-minimal` | The same with every toggle at 0 | The same with every toggle at 0 |

Both profiles build on the host (cgo, no Docker). The `xkey` profiles use the
committed `frontend/dist`, so they need no npm. `xkmsctl` is always built with
`CGO_ENABLED=0`, so its tag set drops `pkcs11`.

## Failing closed

A configuration that names a backend the binary was built without is an
error, not a silent skip:

| Where | Configured as | Result |
|-------|---------------|--------|
| `AutoConfig.BackendConfigs` | a key whose backend is not registered | `*FeatureNotCompiledError` |
| `AutoConfig.DefaultBackend` | a known backend that is not registered | `*FeatureNotCompiledError` |
| `AutoConfig.Datastore` | key storage cannot be derived for a backend | `*BackendStorageError` |

Both errors match a sentinel with `errors.Is` — `xkms.ErrFeatureNotCompiled`
and `xkms.ErrBackendStorageUnresolved`. `FeatureNotCompiledError` carries the
feature, its `WITH_*` toggle and its build tag:

```
xkms: backend "vault" is not compiled into this binary; build with WITH_VAULT=1 (build tag "vault")
```

`xkms.RequireBackend(name)` performs the same check for callers that look up
a backend factory directly. A compiled-in backend whose hardware or service
is absent at run time (no TPM device, no reachable KMS) is still logged and
skipped by auto-discovery; only a build-time absence fails closed.

## Tests

`make test` and the `test-<package>` targets use their own fixed tag set
(`TEST_TAGS`), so the `WITH_*` toggles do not change unit tests. The
`integration-test-<feature>` targets add the `WITH_*` tags and run in the
devcontainer (Docker); for example `make integration-test-vault` or
`make integration-test-pkcs11`.

## See also

- `pkg/xkms/registry.go` and `pkg/xkms/register_*.go` — backend registration
  and the feature-to-toggle map
- [Getting Started](../../xkey/docs/usage/getting-started.md)
