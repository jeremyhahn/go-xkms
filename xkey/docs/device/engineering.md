# Device Pairing and Enrollment — Engineering

> **Status: NORMATIVE** · Feature: `device` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

For the phone-pairing verbs (`pair`, `scan`, `listen`, `attest*`, `*-sync`,
`share*`, `relay`'s Noise/barrier semantics) see
[phone-hsm/engineering.md](../phone-hsm/engineering.md); this page covers
only the client-side agent-enrollment flow, the devices.yaml config surface,
and QR-code pairing.

## Exported surface — `cmd/xkey/cmd` (device group)

Types (`cmd/xkey/cmd/device.go`):

- `PairedDevice = pairing.PairedDevice` — alias to the one owned type
  (`xkey/pkg/pairing/device.go`); the CLI never defines its own pairing
  record.
- `Duration = pairing.Duration` — YAML-marshalable `time.Duration` alias,
  likewise owned by `pkg/pairing`.
- `AttestationPolicy` — `default_grace_period`, `require_device_attestation`,
  `min_security_level`, `verify_boot_state`, `auto_attest_on_connect`,
  `allow_unattestable_devices` (see
  [phone-hsm/architecture.md](../phone-hsm/architecture.md) for what that
  field means), plus the inlined `pairing.ApplicationPolicy` keys
  `allowed_applications` and `allow_unpinned_signatures` — the
  attested-application allow-list pairing and every re-attestation enforce
  (see [phone-hsm/engineering.md](../phone-hsm/engineering.md)).
  `(*DevicesConfig).applicationPolicy()` returns it, nil-safe
  (`cmd/xkey/cmd/device.go`).
- `DevicesConfig` — `Devices []PairedDevice`, `DefaultDevice string`,
  `AttestationPolicy *AttestationPolicy`; this is the root of `devices.yaml`.
- `deviceConfig() xkeyconfig.DeviceConfig` — the `device` group's
  configuration-layer accessor: `GetConfig().Device` when a configuration was
  loaded, else `xkeyconfig.DefaultConfig().Device`
  (`cmd/xkey/cmd/device.go:521`); the `device`-group counterpart to
  `listenerConfig` (`cmd/xkey/cmd/listen_config.go:26`).
- `GetTrustNewDevices(cmd *cobra.Command) (bool, error)` — resolves whether
  device commands accept an unpaired device's empty Noise prologue:
  `--trust-new-devices` when explicitly set, else `device.trust_new_devices`
  from the unified config, else `false` (`cmd/xkey/cmd/device.go:536`);
  exported so other command files under `cmd/xkey/cmd` that build a phone
  key-backend config resolve the setting the same way. The error is
  `ErrCommandFlagInvalid` from a flag declared with the wrong pflag type; it
  is not a config-validation error (`xkeyconfig.Config.Validate` rejects a
  malformed `device.trust_new_devices` before `GetConfig()` ever returns it).
- `resolveDeviceScanTimeout(cmd *cobra.Command) (time.Duration, error)` —
  resolves the BLE scan timeout `device pair` (auto-discovery) and `device
  scan` share: `--timeout` when explicitly set, else `device.scan_timeout`
  from the unified config, else `30s` (`cmd/xkey/cmd/device.go:548`).

Sentinel errors (`cmd/xkey/cmd/device.go`): `ErrDeviceBLEUnavailable`,
`ErrDeviceNoDevicesFound`, `ErrDevicePairingCancelled`, `ErrDeviceNotPaired`,
`ErrDeviceConfigSaveFailed`, `ErrDeviceConfigLoadFailed`,
`ErrDeviceNotFound`, `ErrDeviceNotConnected`, `ErrDeviceAlreadyPaired`,
`ErrDeviceAttestationRequired`, `ErrBootHashMismatch`,
`ErrSecurityLevelInsufficient`. Errors returned with additional context wrap
one of these through `SentinelCauseError` or `DetailError` rather than being
constructed inline.

Agent-enrollment surface (`cmd/xkey/cmd/device_enroll.go`):

- `deviceEnrollCA` — the CA contract `device enroll` needs: `SignCSR([]byte)
  ([]byte, error)`, `GetCACertificate() ([]byte, error)`, `Close() error`.
  `*xkmsdCA` (`cmd/xkey/cmd/agent_ca.go`) is the production implementation,
  shared with `agent code`/`agent approve`.
- `deviceEnrollCAFactory` — package-level `var`, swappable in tests, that
  builds the production CA client.
- `deviceEnrollMasterProbe` — package-level `var` wrapping
  `probeMasterWithClientCert`, the mTLS confirmation dial against `--server`.
- Errors: `ErrDeviceEnrollServerRequired`, `ErrDeviceEnrollServerInvalid`,
  `ErrDeviceEnrollCodeUnsupported`, `ErrDeviceEnrollMasterUnreachable`,
  `ErrDeviceEnrollTrustAnchorInvalid`.
- File constants: `deviceEnrollKeyFile` (`agent-key.pem`, mode 0600),
  `deviceEnrollCSRFile` (`agent-csr.pem`), `deviceEnrollCertFile`
  (`agent-cert.pem`), `deviceEnrollCAFile` (`ca-cert.pem`) — all written under
  `agentCertDir()` (shared with `agent/`).

Relay/QR surface (`cmd/xkey/cmd/device_relay.go`): `ErrDeviceRelayStartFailed`,
`ErrDeviceRelayStopFailed`.

## Exported surface — `xkey/pkg/qrgen`

- `PairingPayload` — `Version int` (must be `1`), `Type string` (must be
  `"xkey-pair"`), `NoisePub string` (base64url, 32 raw bytes), `Addr string`
  (`host:port` when `Transport` is `"tcp"`), `Transport string` (`"tcp"`,
  `"ble"` or `"usb"`), `Name string` (≤64 bytes), `Code string` (optional).
- `EncodePairingPayload(*PairingPayload) (string, error)` /
  `DecodePairingPayload(string) (*PairingPayload, error)` — JSON +
  base64url round trip, with `validate()` enforced on both directions.
- `ToURI(*PairingPayload) (string, error)` / `FromURI(string)
  (*PairingPayload, error)` — the `xkey-pair://<base64url-json>` scheme.
- `GenerateTerminalQR` — ASCII-terminal QR rendering (`xkey/pkg/qrgen/qrgen.go`).
- Errors: `ErrInvalidPayload`, `ErrUnsupportedVersion`, `ErrInvalidURI`,
  `ErrInvalidTransport`, `ErrInvalidNoisePub`, `ErrInvalidAddr`,
  `ErrNameTooLong`.

## Exported surface — `xkey/pkg/qrscan`

`Scanner` with a `Mode` of `ScanModeOTP`, `ScanModePairing` or `ScanModeAny`
(`xkey/pkg/qrscan/scanner.go`); see [engineering.md](../oath/engineering.md)
for the only mode with a shipped CLI verb today (`xkey oath scan`).

## Invariants

- **`devices.yaml` is written with mode 0600** (`saveDevicesConfig`,
  `cmd/xkey/cmd/device.go) — it holds `LocalNoisePrivateKey`.
- **Under `sudo`, the CLI resolves the invoking user's home, not root's.**
  `resolveInvokingUserHome` reads `SUDO_USER` and calls
  `xhome.ResolveForUser` against that account's home directory so `sudo xkey
  device pair` and the same user's own unprivileged session (GUI or a plain
  CLI invocation) read the same `devices.yaml`. An unresolvable home is an
  error, never a silent fallback to root's home (#442).
- **The barrier custody of the Noise static private key (#42)** applies to
  every phone-backed device command, gated behind the `ble` tag
  (`cmd/xkey/cmd/device_barrier.go:14` `//go:build ble`) — see
  [phone-hsm/cli.md](../phone-hsm/cli.md#the-barrier-when-one-exists-42) for
  the full rule; it is not re-derived here.
- **`device enroll` persists credentials before probing the master.** A
  rejected probe still leaves an operator with material to inspect
  (`runDeviceEnroll`, `cmd/xkey/cmd/device_enroll.go`).

## Configuration

Two `device.*` settings have config-file/environment meaning and resolve
through the real, layered config system (`xkey/pkg/config`, env prefix
`XKEY_`), the same three-tier precedence `device relay --listen` already used
(`configuredAddress`, `cmd/xkey/cmd/listen_config.go:38`): an explicitly-set
flag, then the unified config (environment beats the config file inside
`xkeyconfig.Load`), then a built-in default. `xkeyconfig.DeviceConfig`
(`xkey/pkg/config/config.go`) is the typed home for both:

| Setting | Flag | Config key | Env | Default | Resolver |
|---|---|---|---|---|---|
| Trust an unpaired device (empty Noise prologue) | `--trust-new-devices` (persistent, on `deviceCmd`) | `device.trust_new_devices` | `XKEY_DEVICE_TRUST_NEW_DEVICES` | `false` | `GetTrustNewDevices` |
| BLE scan timeout, shared by `device pair` (auto-discovery) and `device scan` | `--timeout` (on `device pair` and `device scan`) | `device.scan_timeout` | `XKEY_DEVICE_SCAN_TIMEOUT` | `30s` | `resolveDeviceScanTimeout` |

Both resolvers detect "explicitly set" with `commandFlagChanged`
(`cmd/xkey/cmd/xkmsd_client.go`), which checks `pflag.Flag.Changed` on
whichever of `cmd.Flags()`/`cmd.PersistentFlags()` declared the flag — not
whether the flag's value is non-default — so `--trust-new-devices=false`
still overrides a config file that turned the setting on
(`TestGetTrustNewDevices_FlagBeatsConfiguration`,
`cmd/xkey/cmd/device_config_test.go`). `xkeyconfig.Config.Validate` rejects a
`device.scan_timeout` of zero or less, from any source, before `GetConfig()`
can ever return it (`xkey/pkg/config/config.go`).

Four other `device.*` settings are per-invocation choices with no
config-file meaning and are read directly off the flag, with no viper
binding of any kind: `device pair --device`/`--force`
(`cmd/xkey/cmd/device_pair.go:runDevicePair`), and `device status --device`
(`cmd/xkey/cmd/device.go:runDeviceStatus`). Before go-xkms#1071 these, plus
`--trust-new-devices` and `--timeout` above, were bound to the package-level
`viper` singleton with `viper.BindPFlag` only
(`device.trust_new_devices`, `device.pair.*`, `device.scan.timeout`,
`device.status.device`) — a singleton that never called `ReadInConfig` or
`AutomaticEnv` anywhere in `cmd/xkey/cmd`, so the binding never gave any of
them a config-file or environment source; it only made `viper.GetString`/
`GetBool` on that key mirror the bound flag, and nothing ever called either.
Every one of those bindings has been deleted (go-xkms#1071); a config file
or `XKEY_DEVICE_PAIR_*`/`XKEY_DEVICE_STATUS_*` variable naming one of the
four per-invocation settings is not read by anything and has no effect.

`device listen`'s and `device sync`'s own `device.listen.*`/`device.sync*`
viper bindings (`cmd/xkey/cmd/device_listen.go`, `device_sync.go`) are the
same shape of defect but were out of go-xkms#1071's scope and remain
unconverted; do not assume they resolve through configuration until they
are.

`devicesConfigFileName = "devices.yaml"` is the on-disk file name, resolved
under the xkey home directory (`xkey/pkg/xhome`); see
[architecture/xhome.md](../architecture/xhome.md). It is unrelated to
`xkeyconfig.DeviceConfig` above: `devices.yaml` holds paired-device records
(`DevicesConfig`), not settings.

**`device listen` and `device sync`/`sync-push`/`sync-pull`/`sync-status`
never bound their flags to viper at all**, despite appearing to
(`device_listen.go`, `device_sync.go` pre-go-xkms#871): `runDeviceListen` and
`runDeviceSyncMode`/`runDeviceSyncStatus` always read their flags directly
via `cmd.Flags().GetString`/`GetBool`/`GetDuration`, so the
`viper.BindPFlag("device.listen.*", ...)` and
`viper.BindPFlag("device.sync*.*", ...)` calls that used to sit in each
command's `init()` were dead code -- bound but never read back through
`viper.Get*` anywhere -- and were deleted rather than wired up: `sync`'s
`--trust-store`/`--oath`/`--passwords`/`--all`/`--dry-run` select what one
invocation does and have no sensible config-file meaning, and `listen`'s
settings had no config/environment claim to make true in the first place (its
`--help` never mentioned one). Both remain CLI-flag-only, now honestly.

## Tests

- `cmd/xkey/cmd/device_test.go`, `device_record_roundtrip_test.go` — the
  device-agnostic `list`/`unpair`/`status` verbs and `DevicesConfig`
  round-tripping.
- `cmd/xkey/cmd/device_config_test.go` — the config-file/environment
  precedence table above: `deviceConfig`, `GetTrustNewDevices`,
  `resolveDeviceScanTimeout`, and that the four per-invocation flags no
  longer mirror into the package-level `viper` singleton. Companion generic
  tests for `commandFlagBool`/`commandFlagDuration`/`commandFlagChanged` live
  in `cmd/xkey/cmd/xkmsd_client_test.go`, beside `commandFlagString`.
- `xkey/pkg/config/config_test.go`, `load_test.go` — `DeviceConfig`'s
  defaults, `Validate` rejecting a non-positive `scan_timeout`, and that
  `XKEY_DEVICE_TRUST_NEW_DEVICES`/`XKEY_DEVICE_SCAN_TIMEOUT` win over the
  config file the same way every other leaf does.
- `cmd/xkey/cmd/device_enroll_test.go`, `device_enroll_phone_test.go`,
  `device_enroll_phone_ca_test.go` — the CSR/CA/probe flow with a fake
  `deviceEnrollCA` and a fake `deviceEnrollMasterProbe`.
- `cmd/xkey/cmd/device_relay_test.go` — the TCP relay and its QR output.
- `cmd/xkey/cmd/device_pair_flow_test.go`,
  `device_pair_reconnect_interop_test.go`, `device_pair_policy_test.go`,
  `device_barrier_test.go`, `device_listen_bridge_test.go`,
  `device_listen_enrollment_test.go` — `ble`-tagged; exercise the phone flow
  this folder points at [phone-hsm](../phone-hsm/) for.
- `xkey/pkg/qrgen/payload_test.go`, `qrgen_test.go` — payload validation,
  encode/decode, and URI round-tripping.
- `xkey/pkg/qrscan/scanner_test.go` — scanner mode behavior.
