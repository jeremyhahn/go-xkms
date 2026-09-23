- **xkmsd config, bootstrap, env, and CLI backward-compat shapes are gone — BREAKING.**
  The pre-viper environment-variable ladder (`applyEnvOverrides`/`legacyEnv` in
  `pkg/config/config.go` and `pkg/config/load.go`) is deleted outright: only
  the viper-derived `XKMS_<SECTION>_<KEY>` name resolves any config key now
  (`pkg/config/load.go`'s `canonicalEnvName`), and a variable spelled any
  other way is silently not read. The 67 removed names and their
  replacements:

  | Removed | Replacement |
  |---|---|
  | `XKMS_HOST` | `XKMS_SERVER_HOST` |
  | `XKMS_REST_PORT` | `XKMS_SERVER_REST_PORT` |
  | `XKMS_GRPC_PORT` | `XKMS_SERVER_GRPC_PORT` |
  | `XKMS_QUIC_PORT` | `XKMS_SERVER_QUIC_PORT` |
  | `XKMS_MCP_PORT` | `XKMS_SERVER_MCP_PORT` |
  | `XKMS_STORAGE_BACKEND` | `XKMS_STORAGE_BACKEND` (unchanged spelling, now the only one) |
  | `XKMS_STORAGE_PATH` | `XKMS_STORAGE_PATH` (unchanged spelling, now the only one) |
  | `XKMS_CLUSTER_ENABLED` | `XKMS_CLUSTER_ENABLED` (unchanged) |
  | `XKMS_CLUSTER_NODE_ID` | `XKMS_CLUSTER_NODE_ID` (unchanged) |
  | `XKMS_CLUSTER_SHARD_ID` | `XKMS_CLUSTER_SHARD_ID` (unchanged) |
  | `XKMS_CLUSTER_RAFT_ADDRESS` | `XKMS_CLUSTER_RAFT_ADDRESS` (unchanged) |
  | `XKMS_CLUSTER_LISTEN_ADDRESS` | `XKMS_CLUSTER_LISTEN_ADDRESS` (unchanged) |
  | `XKMS_CLUSTER_PEERS` | `XKMS_CLUSTER_PEERS` (unchanged) |
  | `XKMS_CLUSTER_JOIN` | `XKMS_CLUSTER_JOIN` (unchanged) |
  | `XKMS_CLUSTER_RAFT_CA_CERT` | `XKMS_CLUSTER_RAFT_TLS_CA_CERT_FILE` |
  | `XKMS_CLUSTER_RAFT_CERT` | `XKMS_CLUSTER_RAFT_TLS_CERT_FILE` |
  | `XKMS_CLUSTER_RAFT_KEY` | `XKMS_CLUSTER_RAFT_TLS_KEY_FILE` |
  | `XKMS_SOCKET_PATH` | `XKMS_UNIX_SOCKET_PATH` |
  | `XKMS_SOCKET_MODE` | `XKMS_UNIX_SOCKET_MODE` |
  | `XKMS_UNIX_PROTOCOL` | `XKMS_UNIX_PROTOCOL` (unchanged) |
  | `XKMS_LOG_LEVEL` | `XKMS_LOGGING_LEVEL` |
  | `XKMS_LOG_FORMAT` | `XKMS_LOGGING_FORMAT` |
  | `XKMS_DATA_DIR` | `XKMS_STORAGE_PATH` (the PKCS8-relative-path side effect this name carried is gone with it) |
  | `TPM_DEVICE_PATH` | `XKMS_BACKENDS_TPM2_DEVICE_PATH` |
  | `PKCS11_LIBRARY` | `XKMS_BACKENDS_PKCS11_LIBRARY` |
  | `AWS_REGION` | `XKMS_BACKENDS_AWSKMS_REGION` |
  | `AWS_ACCESS_KEY_ID` | `XKMS_BACKENDS_AWSKMS_ACCESS_KEY` |
  | `AWS_SECRET_ACCESS_KEY` | `XKMS_BACKENDS_AWSKMS_SECRET_KEY` |
  | `AWS_ENDPOINT` | `XKMS_BACKENDS_AWSKMS_ENDPOINT` |
  | `GCP_PROJECT_ID` | `XKMS_BACKENDS_GCPKMS_PROJECT_ID` |
  | `GOOGLE_APPLICATION_CREDENTIALS` | `XKMS_BACKENDS_GCPKMS_CREDENTIALS_FILE` |
  | `AZURE_KEYVAULT_URL` | `XKMS_BACKENDS_AZUREKV_VAULT_URL` |
  | `AZURE_TENANT_ID` | `XKMS_BACKENDS_AZUREKV_TENANT_ID` |
  | `AZURE_CLIENT_ID` | `XKMS_BACKENDS_AZUREKV_CLIENT_ID` |
  | `AZURE_CLIENT_SECRET` | `XKMS_BACKENDS_AZUREKV_CLIENT_SECRET` |
  | `VAULT_ADDR` | `XKMS_BACKENDS_VAULT_ADDRESS` |
  | `VAULT_TOKEN` | `XKMS_BACKENDS_VAULT_TOKEN` |
  | `VAULT_NAMESPACE` | `XKMS_BACKENDS_VAULT_NAMESPACE` |
  | `XKMS_PHONE_TRANSPORT` | `XKMS_BACKENDS_PHONE_TRANSPORT` |
  | `XKMS_PHONE_DEVICE_ADDRESS` | `XKMS_BACKENDS_PHONE_DEVICE_ADDRESS` |
  | `XKMS_PHONE_NOISE_STATIC_KEY` | `XKMS_BACKENDS_PHONE_NOISE_STATIC_KEY` |
  | `XKMS_PHONE_STATIC_KEY` | `XKMS_BACKENDS_PHONE_PHONE_STATIC_KEY` |
  | `XKMS_PHONE_CONFIG_PATH` | `XKMS_BACKENDS_PHONE_CONFIG_PATH` |
  | `XKMS_PHONE_REQUEST_TIMEOUT` | `XKMS_BACKENDS_PHONE_REQUEST_TIMEOUT` |
  | `XKMS_NOISE_ENABLED` | `XKMS_BOOTSTRAP_NOISE_ENABLED` |
  | `XKMS_NOISE_STATIC_KEY` | removed outright, no replacement (see below) |
  | `XKMS_NOISE_STATIC_KEY_FILE` | removed outright, no replacement (see below) |
  | `XKMS_NOISE_PORT` | `XKMS_SERVER_NOISE_PORT` |
  | `XKMS_SPKI_PIN` | `XKMS_BOOTSTRAP_SPKI_PIN_SHA256` (no longer also flips `bootstrap.spki.enabled`; set it explicitly) |
  | `XKMS_DANE_ENABLED` | `XKMS_BOOTSTRAP_DANE_ENABLED` |
  | `XKMS_DANE_HOSTNAME` | `XKMS_BOOTSTRAP_DANE_HOSTNAME` |
  | `XKMS_DANE_PORT` | `XKMS_BOOTSTRAP_DANE_PORT` |
  | `XKMS_DANE_DNS_SERVER` | `XKMS_BOOTSTRAP_DANE_DNS_SERVER` |
  | `XKMS_RATELIMIT_ENABLED` | `XKMS_RATELIMIT_ENABLED` (unchanged) |
  | `XKMS_RATELIMIT_REQUESTS_PER_MIN` | `XKMS_RATELIMIT_REQUESTS_PER_MIN` (unchanged) |
  | `XKMS_RATELIMIT_BURST` | `XKMS_RATELIMIT_BURST` (unchanged) |
  | `XKMS_RNG_MODE` | `XKMS_RNG_MODE` (unchanged) |
  | `XKMS_RNG_FALLBACK` | `XKMS_RNG_FALLBACK_MODE` |
  | `XKMS_RNG_TPM2_DEVICE` | `XKMS_RNG_TPM2_DEVICE` (unchanged; no longer also sets `use_simulator`) |
  | `XKMS_RNG_TPM2_SIMULATOR_HOST` | `XKMS_RNG_TPM2_SIMULATOR_HOST` (unchanged; no longer also sets `use_simulator`) |
  | `XKMS_RNG_TPM2_SIMULATOR_PORT` | `XKMS_RNG_TPM2_SIMULATOR_PORT` (unchanged; no longer also sets `use_simulator`) |
  | `XKMS_RNG_PKCS11_MODULE` | `XKMS_RNG_PKCS11_MODULE` (unchanged) |
  | `XKMS_RNG_PKCS11_SLOT` | `XKMS_RNG_PKCS11_SLOT_ID` |
  | `XKMS_RNG_PKCS11_PIN` | `XKMS_RNG_PKCS11_PIN` (unchanged; no longer also sets `pin_required`) |
  | `XKMS_CREDENTIALS_SEAL_STRATEGY` | `XKMS_CREDENTIALS_SEAL_STRATEGY` (unchanged) |
  | `XKMS_SEAL_STRATEGY` | `XKMS_BARRIER_STRATEGY` |
  | `XKMS_SEAL_PASSPHRASE` | `XKMS_BARRIER_PASSPHRASE` |

  Config-key removals bundled into the same cleanup:
  - `bootstrap.noise.static_key_hex` / `static_key_file` /
    `p256_static_key_hex` / `p256_static_key_file` (`config.NoiseBootstrapConfig`,
    go-xkms#35) are gone outright, along with the one-time
    config-to-barrier migration that used to read them
    (`legacyOrGenerateNoiseStaticKey`/`legacyOrGenerateP256StaticKey` in
    `pkg/server/bootstrap_key_custody.go`). The bootstrap listener's static
    keys are now exclusively barrier-sealed (when a barrier is configured)
    or persisted to a fixed file under `storage.path` (when it is not);
    there is no config-supplied key path at all.
  - `pkg/server/credentials/service.go`'s underscored strategy aliases
    `aws_kms`/`gcp_kms`/`azure_kv` and the `software` alias for `passphrase`
    are gone from `validStrategies`; only `awskms`/`gcpkms`/`azurekv`/
    `passphrase` (and `manual`/`barrier`/`tpm2`/`pkcs11`/`vault`) remain.
  - `pkg/acme/qrdb.BarrierConfig`/`ShamirConfig`/`ErrBarrierCredentialUnsupported`
    and `Config.Barrier` are gone: this struct always rejected
    `Enabled: true` (it had no credential or auto-unseal source), so the
    field and its dead `embedded.BarrierConfig` wiring in `service.go`
    carried no reachable behavior. Encryption at rest for the embedded ACME
    data plane is configured through the parent xkmsd barrier only.
  - `pkg/acme/client/service.Config`'s deprecated `Client`/`Renewal`/`SDK`
    fields and their `ClientConfig`/`RenewalConfig`/`SDKConfig` types are
    gone; the multi-account `Accounts`/`Certificates` maps are the only
    configuration surface. `pkg/acme/gui/client/api/config_handlers.go` and
    `renewal_handlers.go` now read/write a well-known `"default"` entry in
    `Accounts`/`Certificates` instead: `GET/PUT /api/v1/config` drops the
    `timeout` field (no equivalent on `AccountConfig`), and
    `GET/PUT /api/v1/renewal/config` drops `checkInterval`/
    `renewalThreshold`/`maxRetries`/`retryInterval`/`notifyOnSuccess`/
    `notifyOnFailure` (no equivalent on `CertRenewalConfig`, which only
    carries `Auto`/`DaysBefore`) — none of those fields drove real renewal
    behavior even before removal: `renewal_orchestrator.go`'s ticker already
    used a hardcoded interval, ignoring `Config.Renewal.CheckInterval`.

  CLI surface:
  - `xkmsctl`'s `--protocol`/`-P` deprecated alias for `--transport` is
    gone; `--transport` is the only flag.
  - `xkmsctl barrier`/`ceremony`'s `software` alias for the `passphrase`
    barrier strategy is gone from `validBarrierStrategies`.
  - `xkmsctl`'s `CanonicalRedirectError` type (never constructed) is
    deleted, and `status`/`claim-cert`/`claim-share`/`sign-csr` are now
    registered exactly once, under `ceremony` — `init` no longer carries a
    second, duplicate copy of the same four subcommands.
  - `xkmsd init`'s "legacy `--so`/`--threshold` pair" backward-compat
    validation branch (and its now-dead `ErrThresholdRequiresOfficers`/
    `ErrThresholdExceedsOfficers` sentinels) is removed; `--so` itself stays
    (it has an independent, still-live use building officer configs for
    enrollment).

  Config loaders stay lenient (unknown YAML/JSON keys are ignored), so a
  file that still names a removed key parses without error — it is simply
  never read. A shipped config or script naming an old environment variable
  or flag silently stops taking effect; there is no warning and no fallback.
  Every shipped config (`configs/xkmsd*.yaml`), example
  (`examples/config.example.yaml`), integration-test compose/Dockerfile/
  script under `test/integration/{bootstrap,cluster,pkcs11/module,api,sdk}/`,
  and doc under `docs/xkmsd-configuration/`, `docs/configuration/bootstrap.md`,
  `docs/trust-bootstrap/`, `docs/auth/bootstrap.md`, `docs/init/credentials.md`,
  `docs/acme/qrdb/configuration.md`, `docs/key-management/`, `docs/ssh/README.md`,
  and `docs/acme/protocols/README.md` was updated to the new names or to
  drop the removed ones. `configs/README.md` and `docs/xkmsd-configuration/
  engineering.md` document the single-name-only environment resolution rule
  directly.
