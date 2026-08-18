# TPM 2.0 — Engineering Contract

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-08-19

## Exported surface — `pkg/tpm2`

The package is large; the map in [`architecture.md`](architecture.md)
§"Shape chosen" is the index. The groups an implementer reaches for:

| Need | Start at |
|---|---|
| open a device, run a session | `tpm.go`, `session.go`, `auth.go` |
| create or load a key | `key.go`, `template.go`, `secretkey.go` |
| sign / verify / derive | `ecdsa.go`, `rsa.go`, `ecdh.go`, `sigscheme.go`, `kdf.go` |
| seal to platform state | `seal.go`, `sealer.go`, `policy.go`, `pcr.go` |
| NV storage | `nvram.go`, `nv_extend.go` |
| attest / certify | `attestation.go`, `certify_verify.go`, `eventlog.go` |
| IDevID / TCG enrollment | `cert_idevid.go`, `idevid_csr.go`, `tcg_csr_serverside.go`, `cert_convert.go` |
| provision the platform | `platform.go`, `platform_keystore.go`, `platform_types.go`, `provision.go` |
| ask what this TPM can do | `capabilities.go`, `capability_device.go`, `version.go` |
| lockout state | `lockout.go` |
| randomness | `random.go` |

`reexports.go` is the curated surface for consumers that should not import the
whole package. `pkg/tpm2/store` holds the key-backend types (`KeyBackend` in
`store/interfaces.go`). `pkg/tpm2/mocks` supplies test substitutes.

`pkg/attestation` is the verification half: `verifier.go`, `invariants.go`,
`types.go`, `errors.go`, `truststore/`, `android/`.

## Invariants

- **Every session and object context must be released.** This is the single
  most important rule in the package, and it has three dedicated simulator
  suites: `object_context_leak_simulator_test.go`,
  `auth_session_leak_simulator_test.go`,
  `auth_session_leak_transport_fault_simulator_test.go`, plus
  `resource_leak_simulator_test.go`. A leak does not fail immediately — it
  exhausts the TPM hours later, which is why it needs tests rather than care.
- **A quote is meaningless without a fresh nonce.** Never verify a quote whose
  nonce you did not just generate.
- **`ImportAttestation*` stores, `VerifyAttestationQuote` decides.** Storing
  evidence is not verifying it.
- **PCR selection is fixed at seal time.** Changing the selection does not
  re-bind existing sealed blobs; it makes new ones behave differently.
- **NV indices must not collide.** PIV storage derives its indices from a
  configured base (`pivcert.GetNVIndex`); other NV users must not overlap it.
- **Failed authorizations advance the lockout counter**, and it persists across
  reboots. Retrying blindly is how a TPM becomes unusable for its recovery
  interval.
- **The simulator serves one client at a time.** Two suites sharing a simulator
  block each other; this is a property of the simulator, not a bug to work
  around with retries.
- **Concurrency.** TPM access is serialised — the device has a single command
  channel. Do not expect parallel throughput.

## Error semantics

Typed errors throughout; `pkg/attestation/errors.go` holds the verification
vocabulary. The categories that need distinguishing:

| Condition | Meaning |
|---|---|
| PCR mismatch on unseal | the platform state changed — the mechanism working |
| auth failure | wrong authorization; **advances the lockout counter** |
| lockout active | the TPM is refusing authorizations |
| NV exhausted | no room for another index |
| session/context exhaustion | handles leaked earlier in this process |
| EK chain does not verify | the manufacturer root is not trusted |
| AK certification invalid | the AK is not bound to that EK |
| quote signature or nonce invalid | the evidence is not fresh or not from that AK |

**Fail closed:** every one of these refuses. Nothing degrades to a software key
or an unverified acceptance.

## Configuration

`pkg/tpm2/config.go`. The settings that change behaviour:

- **Device path**, or simulator host/port. In the shipped configs the simulator
  is addressed as `simulator_host` / `simulator_port` (default `2321`) — **not**
  as `device_path`. A `tcp://host:port` string in `device_path` names a file
  that does not exist; `Config.ToTPMConfig` maps the simulator fields to
  `CommandAddress` and clears the device path. The integration config
  (`configs/xkmsd-integration.yaml`) documents this at length because it has
  cost time before.
- **Hierarchy authorizations** — endorsement, lockout, owner. Platform-held.
- **PCR selection and policy** — `pkg/seal/policy` and `pcr.go`.
- **Session encryption** — TPM2 session encryption is configurable; see the
  legacy `docs/configuration/tpm2-session-encryption.md` pending its own
  migration.

## Persistence

Three distinct stores, all on the device:

- **Persistent handles** — long-lived keys such as the SRK.
- **NV indices** — PIV certificates (`pkg/pivcert/tpm2`), platform data. Finite.
- **Sealed blobs** — held outside the TPM, decryptable only by it under policy.

Nothing here is portable: a sealed blob is bound to that TPM, and often to that
TPM in that measured state. Plan recovery accordingly — this is the same
constraint that makes barrier recovery keys worth having
([`../sealing-and-barrier/`](../sealing-and-barrier/engineering.md)).

## Test strategy

The suite is unusually large and deliberately structured:

- **Unit** — one `_test.go` per file.
- **Simulator suites** (`*_simulator_test.go`) — the whole device surface
  against `tpm_simulator.go`: crypto ops, key lifecycle, algorithm agility,
  attestation certify, IDevID CSR round-trip and sizing, seal-with-PCR-policy,
  SSRK platform policy, capabilities, PIN enrollment.
- **Leak suites** — object contexts, auth sessions, auth sessions under
  transport fault, general resources. These are the regression guard for the
  package's hardest rule.
- **Regression fixtures** — `loadkeypair_delete_regression_simulator_test.go`,
  `left_alone_fixes_test.go` keep specific past bugs from returning.
- **Harness** — `simharness_simulator_test.go`.
- **Integration** — `test/integration/tpm2`, `test/integration/acme-tpm`.

Hardware runs need a real TPM; the simulator covers everything else, one client
at a time.

## Observability

TPM operations log with the correlation ID. Two things are worth logging
explicitly at startup because they are invisible otherwise: which device or
simulator was opened, and the current lockout state. A deployment silently on a
simulator, or one whose TPM is in lockout, looks identical to a healthy one
until the first operation fails.
