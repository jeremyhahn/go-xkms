# Sign Server — Architecture

> **Status: NORMATIVE** · Feature: `sign-server` · Repo: `go-xkms` · Last verified: 2026-10-08

## The problem

An IKE daemon authenticates with a private key it reaches through PKCS#11: it
loads `libxkms_pkcs11.so` and signs with `CKM_ECDSA`. The process that owns
the node's keys and configures the daemon is a pure-Go daemon built with
`CGO_ENABLED=0`. It cannot load the `.so`, but it must:

- create the IKE key, in the backend it chooses (TPM 2.0 by default; software,
  an HSM or a cloud KMS by configuration), under the `CKA_LABEL` and `CKA_ID`
  the IKE daemon will look it up by;
- give the IKE daemon a token that signs with that key and does nothing else;
- keep every other process on the host away from it.

`pkg/signserver` is that token's server, embedded in the owning daemon and
re-exported as `sdk/go/signserver`. The IKE daemon's module runs in remote
mode against its unix socket.

## Shape chosen: the keystore gRPC service, narrowed, on an exclusive socket

```
 owning daemon (CGO_ENABLED=0)                   IKE daemon (loads the .so)
 ────────────────────────────────                ───────────────────────────
 signserver.Server                               libxkms_pkcs11.so, remote mode
   xkms.NewService(backends) ── own instance       XKMS_PKCS11_TARGET=unix://...
   pkcs11state.Store(StateDAOs)                    │
   CreateKey ─► module.ProvisionECKeyPair          │
                 (in-process Module,               ▼
                  embedded transport)        /run/<daemon>/ike.sock
   unix.GRPCServer ◄───────────────────────── gate 1: SO_PEERCRED allowlist
     policy interceptor ─────────────────────── gate 2: RPC allowlist
       admitSign ────────────────────────────── gate 3: named keys only
```

Three gates stand between a process and a signature:

1. **Peer credentials.** The listener is `pkg/api/unix` with
   `ExclusivePeers`: only the configured uids and gids are admitted, checked
   with SO_PEERCRED at accept time. The daemon's own uid and root are not
   admitted implicitly. A refused peer cannot complete a single RPC.
2. **RPC allowlist.** A gRPC interceptor serves `Health` (the probe every
   transport sends on connect), `Sign`, `PKCS11StateGet`, `PKCS11StateList`,
   and `PKCS11StatePut`/`PutIfAbsent`/`CAS`/`CAD`/`Delete` only for keys under
   `pkcs11/counters/token/` (the PIN-lockout counters a module charges on
   `C_Login`). Every other unary RPC and every streaming RPC is refused with
   `PermissionDenied`. The policy is an allowlist, so an RPC added to the
   keystore service later stays closed until it is named.
3. **Named keys.** Each `Slot` names its token label and the `CKA_LABEL`s it
   may sign with. `Sign` is admitted only for the (backend, key ID) of a
   private key object carrying one of those labels. The allowlist is rebuilt
   from the token records by `Refresh` (at `New` and after `CreateKey`) and
   swapped atomically; readers never lock.

The token state reads and the counter writes are also confined to configured
slots' tokens.

## Its own key service

The server composes its own `*xkms.XKMSService` with `xkms.NewService`. It
never initializes or reads the process-wide service, so it can run beside a
go-qrdb node, a go-quicbaas composition or anything else the daemon embeds.
This required the service's backend lookup to be instance-scoped: servicer
methods used to resolve backends through the package singleton, so an
instance built outside `Initialize` could not see its own backends.

## Keys are created by the module itself

`CreateKey` does not write token records. It calls
`module.ProvisionECKeyPair`, which drives an in-process `pkg/pkcs11/module`
`Module` over the embedded transport to the server's own service, with
`module.NewRemoteStorage(service, "", token)` as its token store. That is the
same service and the same records the IKE daemon's module reads, so the
objects are attribute for attribute what `C_GenerateKeyPair` creates.

## PINs

The user PIN is checked by the module, against the verifier in the token
record, with the durable lockout counter. It protects the token against a
process that is admitted but does not know the PIN and goes through the module.
It is **not** what gates the `Sign` RPC: a process on an allowlisted uid that
speaks gRPC directly can sign with a named key without the PIN. The peer
allowlist is the access control. List only the uid of the consumer.

## Trust boundaries

- The server runs inside the owning daemon and has its privileges.
- The socket's file mode (default `0660`) only has to let the consumer reach
  it; the allowlist decides.
- The token store (`StateDAOs`, the `pkcs11state` database of the daemon's
  go-qrdb datastore) holds the PIN verifiers and key objects. It must be
  private to the daemon and durable for keys to survive a restart.
- Key material stays in the chosen backend; the token records hold only key
  identifiers and public attributes.

## Rejected alternatives

- **`p11-kit server` in front of the module.** It adds a C daemon and a second
  socket protocol, and does nothing about which keys or operations a client may
  use.
- **Serving the full keystore service on the socket.** Every key operation and
  every key in the backend would be reachable by the consumer.
- **A separate sign-server binary.** The owning daemon already holds the
  backends and decides which keys exist; a second process would need its own
  credentials to them and its own lifecycle.

## What this feature deliberately does not do

- It does not issue certificates or attest keys; that is the CA and
  attestation features.
- It creates EC keys on P-256 and P-384 only, the curves IKEv2 signs with here.
- It has no network listener.
