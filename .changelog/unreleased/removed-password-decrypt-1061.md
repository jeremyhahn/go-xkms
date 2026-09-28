- **BREAKING: `password get` no longer accepts `decrypt`/`user_pin`.** Every
  store reachable through `XKMSService.PasswordGet`
  (`staticpw.BackendStore`, `staticpw.ScopedStore`, `staticpw.DAOStore`)
  returns an entry exactly as stored; confidentiality at rest is the tenant
  barrier's, not a per-request decryption step, so the fields could never be
  honoured and were previously rejected with `ErrPasswordDecryptNotSupported`
  whenever either was set. Removed end to end instead of being kept as
  accepted-but-rejected fields: `xkmsctl password get`'s `--decrypt` and
  `--user-pin` flags (`cmd/xkmsctl/password.go`), the `Decrypt`/`UserPIN`
  fields on `transport.PasswordGetRequest` (`pkg/api/transport/types.go`) and
  every transport that populated them (gRPC, Unix, QUIC), the gRPC
  `PasswordGetRequest.decrypt` proto field — number `2` and the name
  `decrypt` are now `reserved` in `xkmsv1.PasswordGetRequest`
  (`pkg/api/grpc/proto/xkmsv1/xkms.proto`) and regenerated with the pinned
  `protoc`/`protoc-gen-go`/`protoc-gen-go-grpc` toolchain — and the
  now-unreachable `xkms.ErrPasswordDecryptNotSupported` sentinel. `password
  get` on an unlocked session still returns the entry, including the
  password field, unchanged; a locked session still fails with
  `staticpw.ErrStoreLocked`. Docs updated to match
  (`docs/password-vault/{cli,api,user,engineering}.md`), including
  correcting `engineering.md`'s references to a `migration.go` and an
  `encrypted_store.go` that do not exist in `pkg/staticpw`, and the
  `pkg/staticpw` package comment's reference to a nonexistent
  `types.SymmetricEncrypter` interface. go-xkms#1061.
