# Init Ceremony — Architecture

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-10-04

## The problem

A brand-new KMS has no CA, no barrier and no administrator, and nothing that
could authenticate one. `xkmsd init` is the one-shot bootstrap that creates the
trust root and the first administrator so `xkmsd run` has someone to serve.

## Shape chosen: one administrator, bootstrapped by go-qrdb's first boot

go-qrdb owns the node's first boot and its barrier ceremony (holder
enrolment, HPKE-sealed share envelopes, quorum unseal). go-xkms owns the CA
and the hardware-side concerns. The join is `Node.FirstBoot`, which honours
`mtls_binding_policy`, fed a CA through the narrow `pkg/init.CeremonyCA`
interface (`CALifecycle`, `CAIssuer`, `CATrustChain`) wrapped by
`pkg/init.CAAdapter`.

`xkmsd init` does exactly this, in order (`cmd/xkmsd/init_ceremony.go`
`executeBootstrap`, `bootstrapDurableAdmin`):

1. Build a software-backed bootstrap CA and write its public artifacts
   (`ca-bundle.pem`, `spki-pin.txt`) to the data directory
   (`persistCABundle`, `cmd/xkmsd/init_ceremony.go:376`).
2. Open the durable qrdb node from the same storage and seal configuration
   `xkmsd run` resolves, and unseal it.
3. Run `RunFirstBoot` (system tenant, built-in roles, the administrator and its
   CA-issued certificate, bound by SPKI thumbprint) and persist the
   administrator credential (`admin-cert.pem`, `admin-key.pem`).
4. Preflight, then enroll, the administrator's login factors (`mtls`, `piv`,
   `pkcs11`, `fido2`), persisting each through the node's user auth-factor
   store.
5. Close the node so `xkmsd run` can reopen the same Pebble directory.

The bootstrap CA's key is discarded when init exits, but its root stays in
`ca-bundle.pem`, and the administrator certificate chains to it. `xkmsd run`
adds `<datastore.path>/ca-bundle.pem` to the client CAs it advertises
(`configuredClientCAs`, `pkg/server/tls_pool.go:86`), because a `crypto/tls`
client with a static certificate list, as every SDK transport and `xkmsctl`
use, withholds a certificate whose issuer the server does not list
(go-xkms#794). The same pool is the listener config's static `ClientCAs`
(`buildUnifiedTLSConfig`, `pkg/server/unified_tls.go:114`): go-qrdb's
client-trust pool captures that set when the node wires the config and
verifies every client chain against it, so the node's mTLS authenticator
accepts the administrator on REST, gRPC, QUIC, MCP and unix alike. `/auth/me`
reports that identity's method as `mtls` (`identityAuthMethod`,
`pkg/api/rest/handlers_auth.go:579`). The root grants nothing: the
administrator is still identified by the SPKI thumbprint enrolled on the
account (`userIdentity`, `pkg/auth/mtls.go:226`). A missing bundle is
skipped; a bundle that does not parse fails start-up with `*ErrCertParse`.

Rejected alternatives:

- **An M-of-N officer ceremony in go-xkms.** Removed: holder enrolment, share
  custody and quorum unseal belong to go-qrdb's holder/quorum model and are
  served by the node. xkms carries no copy.
- **Re-exposing the barrier, custodian, share, backup, init-claim and audit
  verbs through xkms transports.** Removed (a pass-through is a second
  implementation to keep in sync); use go-qrdb's own surface.
- **Passing the full `ca.TrustedCA` to the bootstrap.** Rejected: a wide
  dependency hides what is used.

## Holder certificates name the registered holder, never the CSR

A certificate signed from a CSR (`CAAdapter.SignCSR`) follows go-qrdb's
`SignCSROptions` contract: Subject exactly `CN=<registered username>`,
`OU=<scope tenant>`, `OU=<profile>`, no SAN; the CSR contributes only its
public key. `ca.SignOptions.RawSubject` writes it verbatim. This keeps a
registrant from obtaining `CN=admin, OU=system`.

The bootstrap administrator certificate is always scoped to the `system`
tenant, because no tenant barrier is unsealed when it is issued.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| Node first boot, holder/quorum barrier ceremony | `go-qrdb/sdk/go` | go-qrdb |
| Ceremony state aliases, `SPKIPin` | `pkg/init/ceremony.go` | go-xkms (aliases) |
| CA bridge | `pkg/init/ca_adapter.go` | go-xkms |
| Admin factor enrollment | `pkg/init/admin_enrollment.go`, `admin_factors.go` | go-xkms |
| Threshold registry aliases | `pkg/init/threshold*.go` | go-qrdb (aliases) |
| Driver | `cmd/xkmsd/init.go`, `init_ceremony.go`, `init_node.go` | go-xkms |
| First-boot wiring shared with `xkmsd run` | `pkg/server` (`RunFirstBoot`, `PersistAdminCredential`) | go-xkms |
