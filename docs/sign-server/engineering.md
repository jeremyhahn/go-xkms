# Sign Server — Engineering Contract

> **Status: NORMATIVE** · Feature: `sign-server` · Repo: `go-xkms` · Last verified: 2026-10-08

## Exported surface — `pkg/signserver`

| Name | Contract |
|---|---|
| `New(ctx, Config) (*Server, error)` | validate, compose the key service and token store, load the signing allowlist; does not bind |
| `(*Server).Serve() error` | bind the socket and serve until `Stop`; nil after `Stop` |
| `(*Server).Stop(ctx) error` | stop and remove the socket |
| `(*Server).CreateKey(ctx, KeyRequest) (*Key, error)` | create a named key, idempotently, and admit it for signing |
| `(*Server).Refresh(ctx) error` | rebuild the signing allowlist from the token records |
| `(*Server).SocketPath() string` | the bound path |
| `Config` | `SocketPath`, `SocketMode`, `AllowedUIDs`, `AllowedGIDs`, `Backends`, `DefaultBackend`, `StateDAOs`, `Slots`, `Logger` |
| `Config.StateDAOs` | a `*qrdbsdk.DAOFactory` serving `StateDatabase`; the token records are `pkcs11state` DAO entities in it |
| `StateDatabase` | `"pkcs11state"`, the go-qrdb database the embedder opens on its datastore before `New` |
| `Slot{Token, Keys}` | token label and the `CKA_LABEL`s it may sign with |
| `KeyRequest{Token, Label, ID, Curve, Backend, UserPIN, SOPIN}` | the key to create; `Label` must be one of the slot's `Keys` |
| `Key` | alias of `module.ProvisionedKeyPair` (`Label`, `ID`, `KeyID`, `Backend`, `Curve`, `PublicKey`, `Created`) |
| `Error{Op, Err}`, `SlotError{Token, Err}` | typed wrappers; `errors.Is` reaches the sentinel |
| `DefaultSocketMode` | `0o660` |

## Exported surface — `sdk/go/signserver`

Aliases of every name above, plus the provisioning surface from
`pkg/pkcs11/module` for an embedder that provisions a remote-mode token without
running a server: `ProvisionECKeyPair`, `ProvisionConfig`, `KeyPairRequest`,
`ProvisionedKeyPair`, `ProvisionError`, `PKCS11Transport`,
`PKCS11StateClient`, `NewRemoteStorage`, and the `ErrProvision*` sentinels.
The package builds with `CGO_ENABLED=0`.

## Errors

Configuration (`New`): `ErrSocketPathRequired`, `ErrNoAllowedPeers`,
`ErrBackendsRequired`, `ErrStateStorageRequired`, `ErrSlotsRequired`,
`ErrSlotTokenRequired`, `ErrSlotDuplicate`, `ErrSlotKeysRequired`, and the key
service's own (`xkms.ErrDefaultBackendNotFound` for a named default that is not
configured). A `StateDAOs` that does not serve `StateDatabase` fails `New` as
`Error{Op: "open token store"}`.

Requests: `ErrUnknownSlot`, `ErrKeyNotNamed` (`CreateKey`), and, returned to a
peer as gRPC `PermissionDenied`, `ErrKeyNotAdmitted`, `ErrTokenWriteDenied`,
`ErrUnknownSlot`, `ErrRequestShape`. `CreateKey` also returns the
`ErrProvision*` sentinels and `*module.ProvisionError` with the failing
Cryptoki step (`ErrProvisionKeyConflict` for a different key under the label
or id, `ErrProvisionSOPINRequired` for an uninitialized token without an SO
PIN).

## Invariants

- The peer policy is exclusive: an empty allowlist is a configuration error,
  and the daemon's uid and root are not admitted unless listed.
- Only the RPCs in the policy table are served; streams never are.
- `Sign` is admitted only for keys a slot names; the allowlist is an immutable
  set swapped with `atomic.Pointer`.
- Token-record writes from a peer are confined to `pkcs11/counters/token/` of a
  configured slot.
- `CreateKey` is serialized, so two creates of one label cannot both see it
  absent.
- The server's key service is its own instance; the process singleton is never
  touched.

## Configuration example

```go
ds, err := xkms.OpenDatastore(ctx, xkms.DatastoreConfig{Path: "<install-dir>/state"}, logger)
if err != nil {
	return err
}
defer ds.Close()
if _, err := ds.DatabaseKVStore(ctx, signserver.StateDatabase); err != nil {
	return err
}
srv, err := signserver.New(ctx, signserver.Config{
	SocketPath:     "/run/<daemon>/ike.sock",
	AllowedUIDs:    []uint32{ikeUID},
	Backends:       map[string]xkms.ServiceBackend{"tpm2": tpmBackend},
	DefaultBackend: "tpm2",
	StateDAOs:      ds.DAOFactory(), // durable, private to the daemon
	Slots:          []signserver.Slot{{Token: "ike", Keys: []string{"vtep-ike"}}},
})
if err != nil {
	return err
}
key, err := srv.CreateKey(ctx, signserver.KeyRequest{
	Token: "ike", Label: "vtep-ike", ID: []byte{0x01}, Curve: "P-256",
	UserPIN: userPIN, SOPIN: soPIN,
})
// key.PublicKey goes into the certificate request.
go srv.Serve()
```

## Test strategy

`pkg/signserver/server_test.go` runs a real server on a unix socket with a
software backend and a token store over an in-process DAO:

- `TestRemoteModuleSignsThroughSignServer` — a remote-mode module on the
  allowlisted uid logs in, finds each key by `CKA_LABEL` and by `CKA_ID`, signs
  with `CKM_ECDSA` on P-256 and P-384, and the signature verifies under the
  provisioned public key.
- `TestSignServerRefusesUnlistedUID` — the same flow on an unlisted uid is
  refused at accept time; the module's `C_Initialize` fails.
- `TestSignServerPolicyDeniesEverythingButSigning` — direct gRPC on an admitted
  uid: unnamed keys, `GenerateKey`, `ListKeys`, object and token-state writes,
  and other tokens are `PermissionDenied`; the slot's reads and counter writes
  succeed.
- `TestCreateKey`, `TestCreateKeyOnUninitializedTokenNeedsSOPIN` — idempotency,
  conflicts, curve and PIN refusals.
- `TestNewValidatesConfig`, `TestNewRefusesAStateFactoryWithoutTheDatabase`,
  `TestServeReportsBindFailure`,
  `TestRefreshHonoursCancellation`, policy and error-message tests.

The `pkg/api/unix` tests cover the exclusive policy and the interceptor hook;
`pkg/pkcs11/module/provision_test.go` covers provisioning against an in-process
service. The same flow was verified through the C ABI of the built `.so`.
