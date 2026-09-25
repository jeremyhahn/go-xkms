# Device Pairing and Enrollment — Engineering

> **Status: NORMATIVE** · Feature: `device` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

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
  [phone-hsm/architecture.md](../phone-hsm/architecture.md) for what the last
  field means).
- `DevicesConfig` — `Devices []PairedDevice`, `DefaultDevice string`,
  `AttestationPolicy *AttestationPolicy`; this is the root of `devices.yaml`.
- `GetTrustNewDevices(cmd *cobra.Command) bool` — reads the
  `--trust-new-devices` persistent flag; exported so other command files
  under `cmd/xkey/cmd` that build a phone key-backend config can read it.

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

`device.*` and `piv`-style persistent flags on `deviceCmd` and its
subcommands are bound to the package-level `viper` singleton with
`viper.BindPFlag` only (`device.trust_new_devices`, `device.pair.*`,
`device.scan.timeout`, `device.status.device`, `device.listen.*`). **That
singleton never calls `ReadInConfig` or `AutomaticEnv`** anywhere in
`cmd/xkey/cmd`, so — unlike the flags below — none of these device flags is
settable through `~/.config/xkey/config.yaml` or an environment variable;
`viper.GetString`/`GetBool` on these keys only ever reflects the bound CLI
flag.

The one exception is `device relay --listen`, which resolves through the
real, layered config system (`xkey/pkg/config`, env prefix `XKEY_`):
`relayListenAddress` (`cmd/xkey/cmd/listen_config.go:57`) reads `--listen`,
then `phone.relay_listen_address` from `xkeyconfig` (env
`XKEY_PHONE_RELAY_LISTEN_ADDRESS`), then the built-in default `:8444`
(`xkeyconfig.DefaultConfig().Phone.RelayListenAddress`).

`devicesConfigFileName = "devices.yaml"` is the on-disk file name, resolved
under the xkey home directory (`xkey/pkg/xhome`); see
[architecture/xhome.md](../architecture/xhome.md).

## Tests

- `cmd/xkey/cmd/device_test.go`, `device_record_roundtrip_test.go` — the
  device-agnostic `list`/`unpair`/`status` verbs and `DevicesConfig`
  round-tripping.
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
