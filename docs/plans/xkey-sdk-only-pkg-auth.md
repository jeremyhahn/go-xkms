# xkey-sdk-only: pkg/auth through sdk/go (lane sxsdkk, row #2084)

## Gap

docs/SPEC.md:180: xkey reaches go-xkms through sdk/go only. The done-check
on f40fb74bf finds three xkey test files importing
`github.com/jeremyhahn/go-xkms/pkg/auth`:

- xkey/cmd/xkey/cmd/password_vault_passkey_test.go
- xkey/cmd/xkey/cmd/xkmsd_harness_test.go
- xkey/pkg/gui/services/staticpw_vault_passkey_test.go

and xkey/docs/usage/api-parity.md:33 still names `types.SymmetricKeyProvider`
at `pkg/types/types.go:2112`.

## Name map

- `auth.Identity` -> `xkms.QRDBIdentity` (sdk/go/types_qrdb.go)
- `auth.WithIdentity` -> `xkms.QRDBWithIdentity` (sdk/go/types_qrdb.go)

## Docs fix

api-parity.md cites `SymmetricKeyProvider` at `sdk/go/types.go:113`.

## Test

sdk/go/qrdb_identity_reexport_test.go `TestReexport_QRDBIdentity` pins that
`QRDBWithIdentity` and `auth.WithIdentity` share one context key.

## Checks

Results to follow.
