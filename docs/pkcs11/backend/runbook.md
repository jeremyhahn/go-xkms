# Operational Runbook

## 1. Build with the tag

```bash
go build -tags pkcs11 ./cmd/xkmsd
```

cgo is required. Without the tag the daemon starts, logs `PKCS#11 backend
enabled in config but not compiled in (use -tags pkcs11)`, and serves no
`pkcs11` backend.

## 2. Prepare the token (operator action, not a boot action)

xkmsd never initializes a token. Do it once with vendor tooling.

SoftHSM2:

```bash
softhsm2-util --init-token --slot 0 --label 'xkms' --so-pin 12345678 --pin 87654321
softhsm2-util --show-slots
```

Any device:

```bash
pkcs11-tool --module /path/to/vendor.so --list-slots
pkcs11-tool --module /path/to/vendor.so --login --pin <PIN> --list-objects
```

## 3. Point xkms at it

```yaml
backends:
  pkcs11:
    enabled: true
    library: "/usr/lib/softhsm/libsofthsm2.so"
    token: "xkms"
    pin: "87654321"
```

Known library paths:

| Device | Library |
|---|---|
| SoftHSM2 | `/usr/lib/softhsm/libsofthsm2.so` |
| YubiKey PIV | `libykcs11.so` (`/usr/lib/x86_64-linux-gnu/libykcs11.so`) |
| nCipher / nShield | `/opt/nfast/toolkits/pkcs11/libcknfast.so` |
| Nitrokey HSM / SmartCard-HSM | `/usr/lib/opensc-pkcs11.so` |

`PKCS11_LIBRARY` overrides `backends.pkcs11.library` at load time. There is no
environment override for the PIN — see [configuration.md](configuration.md).

Prefer `token:` (label) over a slot number: slot numbers are not stable across
reboots or re-enumeration, and on a multi-token host the wrong slot means the
PIN is presented to the wrong token, which consumes a retry.

## 4. Verify

Startup emits:

```
PKCS#11 backend initialized  backend=pkcs11 library=... token=...
```

Then round-trip a key through the SDK/CLI against the `pkcs11` backend
(generate → sign → verify). REST callers must pass the backend explicitly
(`?backend=pkcs11`). Confirm on the device side that the object exists and that
the private half is not readable:

```bash
pkcs11-tool --module /path/to/vendor.so --login --pin <PIN> --list-objects --type privkey
```

## 5. Test entry points

These are three different layers. Do not substitute one for another.

| Target | Layer | What it runs |
|---|---|---|
| `make integration-test-pkcs11-backend` (alias `integration-test-pkcs11`) | **client / this backend** | `test/integration/pkcs11` in Docker against SoftHSM2 |
| `make integration-test-pkcs11-module-all` | module xkms provides | module + conformance + pkcs11-tool + OpenSSL + SSH |
| `make integration-test-xkey-pkcs11` | xkey consumer | xkey's FIDO2 adapter + PIV tests |

The client suite's Docker environment (`test/integration/pkcs11/docker-compose.yml`):

```yaml
    environment:
      - PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
      - PKCS11_TOKEN_LABEL=test-token
      - PKCS11_PIN=1234
```

and the container initializes the token before running
`go test -tags='integration pkcs11 codec_cbor codec_json codec_msgpack' ./test/integration/pkcs11`.

Coverage across unit + integration for this backend:

```bash
make coverage-pkcs11   # ./test/integration/pkcs11/... ./pkg/backend/pkcs11/... , requires SoftHSM
```

Historical note: `integration-test-pkcs11` was once defined twice in the
Makefile. `make` takes the last definition, so the xkey target silently replaced
the SoftHSM client suite and it never ran. The xkey target is now
`integration-test-xkey-pkcs11` (`Makefile:3470`). If you add a target, grep for
the name first.

## 6. Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `pkcs11: library not found` | `Config.Validate()` could not stat `library` | fix the path; check `ldd` for missing vendor deps |
| `failed to load PKCS#11 library: <path>` | `C_GetFunctionList` unavailable / not a Cryptoki module | wrong `.so`; check architecture and `LD_LIBRARY_PATH` |
| `pkcs11: token not found: token label "x" not found` | label mismatch (labels are space-padded to 32 bytes) | `--show-slots` / `--list-slots` and copy the label exactly |
| `pkcs11: token not initialized` on every call | `Login()` was never called, or it failed | check startup logs; the token must already be SO-initialized |
| `failed to create session pool: pkcs11: session pool login failed` | wrong user PIN (`CKR_PIN_INCORRECT`) or locked token | verify the PIN; check the device's retry counter before retrying |
| `pkcs11: session pool requires non-nil PKCS#11 context` | pool constructed before the context | call `Login()`/`Initialize()` first |
| `pkcs11: failed to open session pool sessions` | device session limit below `SessionPoolSize` | lower `session-pool-size` |
| `CKR_USER_ALREADY_LOGGED_IN` | another pool/manager already logged in on the token | benign; tolerated by both the pool and the import/export paths |
| `CKR_OPERATION_ACTIVE` | a search or crypto operation was left open on a session | a session handle escaped its `WithSession` callback — file a bug |
| `pkcs11: invalid pin length` / `invalid SO pin length` | PIN shorter than 4 characters | supply a real PIN |
| `pkcs11: SO PIN required ... (provide management key)` | YubiKey PIV key generation without `so-pin` | set the management key as `SOPIN` |
| `CKR_ATTRIBUTE_VALUE_INVALID` on YubiKey keygen | full attribute template sent to `libykcs11` | ensure the library path is detected as PIV (`IsYubiKeyPIV`) |
| `pkcs11: unsupported key algorithm: YubiKey PIV does not support Ed25519 keys` | Ed25519 on PIV | use ECDSA P-256 or RSA |
| `backend.ErrKeyNotExportable` | `attrs.Exportable=false`, or `CKA_EXTRACTABLE=false` on the object | non-recoverable for that key; see [security.md](security.md) |
| `pkcs11: imported key could not be labelled with its CKA_LABEL/CKA_ID` | token dropped the identity attributes and refused `C_SetAttributeValue` | the object was destroyed; import to a token that honours the template |
| `failed to unwrap key with RSA-OAEP` / `CKR_ARGUMENTS_BAD` | token does not support OAEP unwrap for secret keys (SoftHSM2) | use an `RSA_AES_KEY_WRAP_*` algorithm (hybrid path) |
| `CKR_KEY_FUNCTION_NOT_PERMITTED` from `DeriveKeyECDH` | base key lacks `CKA_DERIVE` | see the caveat in [operations.md](operations.md#ecdh-key-agreement) |
| `ML-DSA` / `ML-KEM` refused | `probeQuantumMechanisms` did not see the mechanism | token lacks PKCS#11 v3.2 PQC support |
| Fewer keys than expected from `ListKeys` | one `C_FindObjects` call caps at 256 handles | filter on the device, or reduce objects per token |

## 7. Shutdown

`Close()` closes the session pool (releasing any goroutine already blocked
waiting for a session via the `done` channel) and then finalizes the Cryptoki
context only if this backend created it. It is safe to call more than once.
