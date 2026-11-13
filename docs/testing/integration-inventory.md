# Integration test inventory (#1607 slice a)

> **Status: REFERENCE** · Last verified: 2026-11-13 on main `d55b1b73c`
> Scope: every directory under `test/integration`, the layer it drives, every
> `time.Sleep` in its `_test.go` files, and the slice (b) verdict under the
> test standard (m653: integration tests are CLI multi-protocol E2E only).

## Layers

- **CLI E2E**: the test runs a built binary (`xkms`, `xkmsctl`, `xkey`,
  `xkmsd`, the ACME client) with `exec.Command`.
- **direct client**: a Go HTTP, gRPC, QUIC or SDK client against a running
  server, without the CLI.
- **service**: an in-process go-xkms service or handler set (`pkg/xkms`,
  `pkg/acme/admin`, `pkg/acme/server/handlers`, `pkg/trust/clusterca`).
- **store**: a key backend or storage package called in-process
  (`pkg/backend/*`, `pkg/storage/*`, `pkg/keyprovider/*`).
- **DAO**: a `pkg/dao` data-access object.
- **other**: an in-process library package (crypto, encoding, TPM),
  an external tool against the PKCS#11 module, Playwright (no Go), or a helper.

## Verdicts

- **keep**: CLI E2E, or a product surface only an external tool reaches
  (PKCS#11 module via `pkcs11-tool`/OpenSSL, browser Playwright).
- **move to unit suite of `<pkg>`**: the test calls the package in-process; in
  slice (b) its scenarios go to the package's unit tests (named after each
  verdict) and the integration file goes.
- **rewrite as CLI E2E**: a direct client to a running server; slice (b)
  replaces it with the same scenario through the CLI on every transport.
  This fourth verdict is not in the brief's list; it covers direct-client
  tests that are neither a duplicate nor unit material.
- **remove**: nothing in go-xkms is under test.

Slice (b) diffs each moved scenario against the unit suite assertion by
assertion before it deletes anything; this table names the scenarios, not
the per-assertion diff.

## Table

`files` = `_test.go` files (recursive). `sleeps` = `time.Sleep` lines in them.

| directory | files | layer | evidence | sleeps | slice (b) verdict |
|---|---|---|---|---|---|
| `acme-admin/` | 1 | service | `acme-admin/admin_integration_test.go:106` `admin.NewTenantAwareAdminService` | 0 | move to unit suite of `pkg/acme/admin` (tenant admin on objstore) |
| `acme-client/` | 0 | other (Playwright) | `acme-client/playwright/` only, no Go | 0 | keep (browser E2E) |
| `acme-multiprotocol/` | 4 | direct client | `acme-multiprotocol/helpers.go:316` `RunMultiProtocolTest` runs `api.AdminAdapter` per protocol | 0 | rewrite as CLI E2E (`xkmsctl acme` account, role, tenant, edge cases) |
| `acme-server/` | 0 | other (Playwright) | `acme-server/playwright/` only, no Go | 0 | keep (browser E2E) |
| `acme-tpm/` | 10 | service | `acme-tpm/enroll01_integration_test.go:34` imports `pkg/acme/server/handlers`; `acme-tpm/swtpm_helper_test.go:35` `pkg/acme/client/service` | 4 | move to unit suite of `pkg/acme/server/handlers` (device-attest-01, enroll-01, TCG-CSR, permanent identifier on swtpm) |
| `acmeadmin/` | 4 | CLI E2E | `acmeadmin/harness.go:149` `exec.CommandContext(ctx, cfg.Binary, ...)` (`xkmsctl`, `harness.go:94`) | 2 | keep |
| `acmeclient/` | 7 | CLI E2E | `acmeclient/acmeclient_test.go:267` `exec.CommandContext(ctx, cfg.Binary, ...)` (`ACME_CLIENT_BIN`, `:71`) | 1 | keep |
| `acmeserver/` | 4 | direct client | `acmeserver/acmeserver_test.go:90` `http.Client`; `acmeserver/acmeserver_admin_test.go:25` reuses `acme-multiprotocol` | 0 | rewrite as CLI E2E (endpoints, admin, GUI routes) |
| `api/` | 21 | CLI E2E + direct client | `api/commands/runner.go:177` `exec.Command(r.CLIBinPath, ...)`; direct: `api/grpc_test.go:40`, `api/rest_test.go:60`, `api/quic_test.go:67`, `api/webauthn_test.go:64`, `api/e2e_test.go:24` | 0 | keep the CLI files; rewrite `grpc_test.go`, `rest_test.go`, `quic_test.go`, `mcp_test.go`, `mcp_comprehensive_test.go`, `webauthn_test.go`, `e2e_test.go` as CLI E2E |
| `awskms/` | 2 | store | `awskms/awskms_integration_test.go:36` `pkg/backend/awskms` | 0 | move to unit suite of `pkg/backend/awskms` (LocalStack key lifecycle, sign/verify) |
| `azurekv/` | 4 | store | `azurekv/azurekv_integration_test.go:42` `pkg/backend/azurekv` | 5 | move to unit suite of `pkg/backend/azurekv` (rotation, import/export) |
| `backend/` | 3 | store | `backend/software_integration_test.go:31` `pkg/backend/software`; `backend/tpm2_integration_test.go:29` | 0 | move to unit suites of `pkg/backend/software`, `pkg/keyprovider/symmetric`, `pkg/backend/tpm2` |
| `bootstrap/` | 3 | direct client | `bootstrap/bootstrap_listener_keys_test.go:55` `bootstrap.Fetch`; `bootstrap/testutil.go:109` `transport.WithAddress` | 0 | rewrite as CLI E2E (bootstrap fetch, listener keys, SDK transport) |
| `certstore/` | 1 | DAO | `certstore/certstore_integration_test.go:38` `pkg/dao` | 0 | move to unit suite of `pkg/certstore` |
| `challenges/` | 6 | direct client + service | `challenges/helpers.go:120` `http.Client` (dns01, endorse01, enroll01, http01); `challenges/dns01/dns01_e2e_test.go:47` in-process `handlers` | 2 | rewrite `*_test.go` (HTTP) as CLI E2E; move `dns01_e2e_test.go`, `http01_e2e_test.go` to unit suite of `pkg/acme/server/handlers` |
| `cluster/` | 9 | direct client | `cluster/cluster_test.go:118` `http.Client` per node; `cluster/cluster_resilience_test.go:51` `docker` | 3 | rewrite as CLI E2E (`--server` per node: join, leader, replication, CAS, resilience) |
| `clusterca/` | 1 | service | `clusterca/clusterca_test.go:68` `pkg/trust/clusterca`; `:57` in-process ACME server | 2 | move to unit suite of `pkg/trust/clusterca` |
| `common/` | 1 | direct client | `common/common_test.go:82` `http.Client` | 1 | rewrite as CLI E2E |
| `correlation/` | 1 | other (library) | `correlation/integration_test.go:23` `pkg/correlation` | 0 | move to unit suite of `pkg/correlation` |
| `crypto/` | 8 | other (library) | `crypto/aead_integration_test.go:24` `pkg/crypto/aead` (and ecdh, ecies, rand, wrapping, x25519, chacha20poly1305) | 0 | move to unit suites of `pkg/crypto/<alg>` |
| `encoding/` | 5 | other (library) | `encoding/jwk_integration_test.go:28` `pkg/encoding/jwk`; `encoding/helpers_test.go:27` `pkg/backend/software` | 0 | move to unit suites of `pkg/encoding/{jwe,jwk,jwt}` (interop) |
| `fido2/` | 7 | CLI E2E + service | `fido2/cli_test.go:55`, `fido2/cli_multiprotocol_test.go:109` `exec.Command(cfg.CLIBinPath, ...)`; `fido2/registration_ceremony_test.go:31` `pkg/xkms`; `fido2/fido2_integration_test.go:22` `pkg/fido2` | 5 | keep `cli_*`; move ceremony, hardware and WebAuthn-server files to unit suite of `pkg/fido2` / `pkg/webauthn` |
| `frost/` | 3 | CLI E2E + store | `frost/cli_integration_test.go:648` `exec.Command(cliPath, ...)`; `frost/backend_integration_test.go:14` `pkg/keyprovider/frost` | 0 | keep `cli_integration_test.go`; move the rest to unit suite of `pkg/keyprovider/frost` |
| `gcpkms/` | 3 | store | `gcpkms/gcpkms_integration_test.go:31` `pkg/backend/gcpkms` | 0 | move to unit suite of `pkg/backend/gcpkms` (emulator lifecycle) |
| `health/` | 1 | other | `health/integration_test.go:28` `qrdbsdk` (`go-qrdb/sdk/go`) HealthChecker only | 6 | remove: no go-xkms package under test; the checker's coverage belongs to go-qrdb. **Done in slice (b)**: directory and its Makefile target removed |
| `initceremony/` | 3 | CLI E2E | `initceremony/init_factor_persistence_test.go:300` `exec.CommandContext(ctx, bin, "init", ...)`; `initceremony/admin_transports_test.go:189` | 0 | keep |
| `logins/` | 4 | CLI E2E + direct client | `logins/fido2_test.go:113` `exec.CommandContext(ctx, bin, ...)` (`xkey`); `logins/piv_test.go:44` `xkms.NewLoginClient`; `logins/testutil.go:175` `http.Client` (mTLS, OIDC) | 0 | keep `fido2_test.go`; rewrite `piv_test.go`, `mtls_test.go`, `oidc_test.go` as CLI E2E |
| `luks/` | 1 | other (library) | `luks/luks_test.go:32` `pkg/luks` | 0 | move to unit suite of `pkg/luks` |
| `metrics/` | 1 | other (library) | `metrics/integration_test.go:27` `pkg/metrics` | 0 | move to unit suite of `pkg/metrics` (`/metrics` handler) |
| `oidccredentials/` | 6 | CLI E2E + service | `oidccredentials/main_test.go:117` `exec.Command(env.xkmsctl, ...)`, `:148` `xkey`; `oidccredentials/lease_test.go:34` `pkg/oidc/credential` | 0 | keep CLI files; move `lease_test.go` to unit suite of `pkg/oidc/credential` |
| `opaque/` | 1 | other (library) | `opaque/integration_test.go:29` `pkg/opaque` | 0 | move to unit suite of `pkg/opaque` |
| `pkcs11/` | 71 | other (PKCS#11 ABI) + store | `pkcs11/module/concurrency_test.go:65` `miekg/pkcs11`; `pkcs11/module/pkcs11_tool_test.go:126` `pkcs11-tool`; `pkcs11/integration_test.go:37` `pkg/backend/pkcs11`; `pkcs11/barrier/barrier_test.go:51` `pkg/embeddednode` | 5 | keep `module/` (the PKCS#11 module is a product surface: cabi, conformance, fips, OpenSSL, pkcs11-tool, ssh); move top-level `*_integration_test.go` to unit suite of `pkg/backend/pkcs11`; move `barrier/` to unit suite of `pkg/embeddednode` |
| `pkcs8/` | 1 | store | `pkcs8/pkcs8_integration_test.go:27` `pkg/keyprovider/pkcs8` | 0 | move to unit suite of `pkg/keyprovider/pkcs8` |
| `quantum/` | 4 | other (library) + store | `quantum/dilithium2_integration_test.go:26` `pkg/quantum/dilithium2`; `quantum/backend_integration_test.go:14` `pkg/keyprovider/quantum` | 0 | move to unit suites of `pkg/quantum/{dilithium2,kyber768}`, `pkg/keyprovider/quantum` |
| `ratelimit/` | 1 | other (library) | `ratelimit/integration_test.go:27` `pkg/ratelimit` | 6 | move to unit suite of `pkg/ratelimit` (refill, cleanup with an injected clock instead of the sleeps). **Done in slice (b)**: every case is in `pkg/ratelimit/clock_test.go`, driven by the unexported `Limiter.now` clock; directory and its Makefile target removed |
| `rfc8555/` | 11 | service | `rfc8555/rfc8555_6_2_test.go:25` `pkg/acme/server/handlers`; `rfc8555/rfc8555_7_2_test.go:19` `pkg/acme/nonce` | 0 | move to unit suite of `pkg/acme/server/handlers` (RFC 8555 sections 6.2-8.1) |
| `sdk/` | 2 | direct client | `sdk/go/sdk_integration_test.go:37` `xkms.NewEmbedded`, `:431` `xkms.NewFromURL`; `sdk/go/multiprotocol_test.go:36` | 0 | move to unit suite of `sdk/go` (embedded client, URL parsing) |
| `signing/` | 1 | other (library) | `signing/integration_test.go:28` `pkg/signing` | 0 | move to unit suite of `pkg/signing` |
| `sshagent/` | 1 | other (external tool) | `sshagent/git_signing_test.go:107` `exec.Command("git", ...)`; `:39` `sdk/go/client/ssh` | 0 | keep (git commit signing through the agent is an external-tool surface) |
| `sshbackend/` | 9 | store + direct client | `sshbackend/matrix_test.go:36` `pkg/ssh/backend`; `sshbackend/aws_test.go:23` `sdk/go` | 0 | move to unit suite of `pkg/ssh/backend` (backend matrix: software, pkcs11, tpm2, cloud) |
| `storage/` | 9 | store | `storage/memory_storage_integration_test.go:28` `pkg/storage`; `storage/hardware_storage_integration_test.go:28` `pkg/storage/hardware` | 2 | move to unit suites of `pkg/storage`, `pkg/storage/file`, `pkg/storage/hardware` |
| `tpm2/` | 24 | other (TPM library) + service | `tpm2/tpm2_integration_test.go:23` `pkg/tpm2`; `tpm2/peergate_qrdb_node_test.go:46` `pkg/server` | 2 | move to unit suite of `pkg/tpm2` (simulator: quote, NV, policy, IDevID, event log); move `peergate_qrdb_node_test.go` to `pkg/attestation/peergate` |
| `vault/` | 2 | store | `vault/vault_integration_test.go:32` `pkg/backend/vault` | 0 | move to unit suite of `pkg/backend/vault` (transit, tamper) |
| `web/` | 0 | other (Playwright) | `web/playwright.config.ts`, no Go | 0 | keep (browser E2E) |
| `webauthn-browser/` | 0 | other (Playwright) | `webauthn-browser/playwright.config.ts`, no Go | 0 | keep (browser E2E) |
| `xkeytest/` | 0 | other (helper) | `xkeytest/authenticator.go:63` `exec.CommandContext(ctx, bin, ...)`, used by `logins/fido2_test.go:34` | 0 | keep (CLI E2E helper, no tests) |
| `xkms/` | 6 | service + DAO | `xkms/service_integration_test.go:32` `pkg/xkms`; `xkms/piv_integration_test.go:32` `pkg/dao` | 0 | move to unit suite of `pkg/xkms` (key ID, PIV, coverage scenarios) |
| `xkmsdtest/` | 2 | other (daemon harness) | `xkmsdtest/xkmsdtest.go:236` `exec.Command(bin, "-config", config)`; `xkmsdtest/xkmsdtest_test.go:173` `http.Client` | 1 | keep (self-test of the xkmsd harness used by CLI E2E suites) |

All `evidence` paths are relative to `test/integration/`.

## test/integration/api

Not CLI-only. The CLI suites run the binary (`api/commands/runner.go:177`,
`api/cli_test.go:32`, `api/cli_complete_test.go:92`,
`api/cli_multiprotocol_test.go:50`, `api/ssh_parity_test.go:109`), but these
files go below the CLI:

- `api/grpc_test.go:40` `grpc.NewClient`, `:49` `pb.NewKeystoreServiceClient`
- `api/e2e_test.go:24` imports the gRPC proto `pb`
- `api/rest_test.go:60`, `api/quic_test.go:67`, `api/webauthn_test.go:64`
  `http.NewRequest` against the server
- `api/mcp_test.go`, `api/mcp_comprehensive_test.go` (MCP client, no `exec`)

## Sleep list

Every `time.Sleep` in a `test/integration` `_test.go` file (paths relative to
`test/integration/`).

| file:line | duration | waits for |
|---|---|---|
| `acme-tpm/enroll01_integration_test.go:201` | 100 ms | HTTP server start |
| `acme-tpm/enroll01_integration_test.go:505` | 100 ms | poll interval (order status) |
| `acme-tpm/tpm_challenges_test.go:345` | 100 ms × 10 | poll loop (challenge status) |
| `acme-tpm/tpm_challenges_test.go:431` | 100 ms | poll interval (challenge status) |
| `acmeadmin/main_test.go:108` | 2 s | retry until the CA bundle fetch succeeds |
| `acmeadmin/main_test.go:145` | 2 s | poll for the admin credential files |
| `acmeclient/acmeclient_service_test.go:53` | 2 s | daemon initialisation |
| `azurekv/azurekv_rotation_integration_test.go:147` | 100 ms | timestamp difference |
| `azurekv/azurekv_rotation_integration_test.go:167` | 100 ms | before rotation |
| `azurekv/azurekv_rotation_integration_test.go:181` | 100 ms | after rotation |
| `azurekv/azurekv_rotation_integration_test.go:351` | 100 ms | between rotations |
| `azurekv/azurekv_rotation_integration_test.go:363` | 100 ms | between rotations |
| `challenges/dns01/dns01_e2e_test.go:312` | 2 s | challenge to fail or stay pending |
| `challenges/http01/http01_e2e_test.go:260` | 2 s | challenge to fail |
| `cluster/cluster_test.go:191` | `interval` | poll helper until the cluster condition holds |
| `cluster/testmain_test.go:106` | 2 s | poll for the admin credential |
| `cluster/testmain_test.go:195` | 2 s | retry each node until it answers |
| `clusterca/clusterca_test.go:532` | `settle` | settle after remove |
| `clusterca/clusterca_test.go:540` | `settle` | settle (retry) |
| `common/common_test.go:253` | 100 ms × 2^i | exponential backoff in the retry helper |
| `fido2/cli_multiprotocol_test.go:329` | 1 s | before authentication |
| `fido2/cli_multiprotocol_test.go:463` | 1 s | between authentications |
| `fido2/cli_multiprotocol_test.go:596` | 1 s | between operations |
| `fido2/fido2_integration_test.go:184` | 500 ms | between attempts |
| `fido2/webauthn_server_test.go:624` | 1 s | before second user registration |
| `health/integration_test.go:304` | 100 ms | uptime to advance |
| `health/integration_test.go:375` | 10 ms | simulated work in a check |
| `health/integration_test.go:539` | 10 ms | simulated database check |
| `health/integration_test.go:549` | 5 ms | simulated cache check |
| `health/integration_test.go:559` | 15 ms | simulated storage check |
| `health/integration_test.go:637` | `expectedDelay` | slow check for latency measurement |
| `pkcs11/module/openssl_provider_test.go:851` | 500 ms | retry the OpenSSL client until it connects |
| `pkcs11/module/openssl_ssh_test.go:1747` | 20 ms | poll until a file exists (10 s deadline) |
| `pkcs11/module/openssl_ssh_test.go:1804` | 20 ms | poll until the probe connection succeeds |
| `pkcs11/module/openssl_x509_tls_test.go:408` | 500 ms | retry the OpenSSL TLS client until it connects |
| `pkcs11/pkcs11_cert_integration_test.go:694` | 100 ms | timestamp difference |
| `ratelimit/integration_test.go:56` | 1100 ms | token refill |
| `ratelimit/integration_test.go:128` | 600 ms | token refill (2 req/s) |
| `ratelimit/integration_test.go:181` | 400 ms | cleanup worker |
| `ratelimit/integration_test.go:540` | 1100 ms | one-token refill |
| `ratelimit/integration_test.go:606` | 100 ms | between requests |
| `ratelimit/integration_test.go:640` | 300 ms | cleanup worker stopped |
| `storage/hardware_storage_integration_test.go:208` | (i+1) × 10 ms | backoff in a retry loop |
| `storage/memory_storage_integration_test.go:324` | `duration` | load run duration |
| `tpm2/idevid/idevid_full_test.go:116` | `backoff` | TPM connection retry |
| `tpm2/tpm2_integration_test.go:135` | `backoff` | TPM connection retry |
| `xkmsdtest/xkmsdtest_test.go:150` | 2 × `retryInterval` | delayed start in a goroutine (retry test) |

## Totals

| measure | brief baseline | counted at `d55b1b73c` | command |
|---|---|---|---|
| directories under `test/integration` | 51 | 48 | `ls -d test/integration/*/ \| wc -l` |
| `_test.go` files under `test/integration` | n/a | 269 | `find test/integration -name '*_test.go' \| wc -l` |
| integration `_test.go` files with `time.Sleep` | 25 | 25 | `grep -rlE 'time\.Sleep' test/integration --include=*_test.go \| wc -l` |
| `time.Sleep` lines in integration `_test.go` | n/a | 47 | `grep -rn 'time\.Sleep' test/integration --include=*_test.go \| wc -l` |
| `time.Sleep` lines in `_test.go`, whole repo | 278 | not recounted | `grep -rn 'time\.Sleep' --include=*_test.go . \| wc -l` |

The directory count differs: `ls -d test/integration/*/` lists 48
top-level directories. 51 matches no listing at this commit (all
directories, recursively, is 83), so the baseline likely came from an
older tree. The lane could not run `grep` (blocked in lanes), so the
two sleep counts came from Serena `search_for_pattern 'time\.Sleep\('`
on `test/integration/**/*_test.go`; the repo-wide 278 was not recounted.
