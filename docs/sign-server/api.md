# Sign Server — API

> **Status: NORMATIVE** · Feature: `sign-server` · Repo: `go-xkms` · Last verified: 2026-10-01

The sign server has no network API of its own. On its unix socket it serves a
subset of the keystore gRPC service (`xkms.v1.KeystoreService`), the one a
remote-mode PKCS#11 module needs to sign:

| RPC | Admitted when |
|---|---|
| `Health` | always (status and build version only) |
| `Sign` | the request's backend and key ID belong to a private key a slot names |
| `PKCS11StateGet`, `PKCS11StateList` | the token is a configured slot |
| `PKCS11StatePut`, `PKCS11StatePutIfAbsent`, `PKCS11StateCAS`, `PKCS11StateCAD`, `PKCS11StateDelete` | the token is a configured slot and the key is under `pkcs11/counters/token/` |

Every other RPC, and every streaming RPC, answers `PermissionDenied`. A peer
whose uid and gid are not allowlisted is refused when it connects, so its first
RPC fails with `Unavailable`.

Request and response shapes are the keystore service's; see
[`../pkcs11-provider-module/api.md`](../pkcs11-provider-module/api.md) for the
`PKCS11State*` contract.

The embedder's Go API (`pkg/signserver`, `sdk/go/signserver`) is in
[`engineering.md`](engineering.md). There are no REST, QUIC or MCP routes:
the server exists to be reached only from the same host by one named process.
