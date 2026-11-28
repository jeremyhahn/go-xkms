# CA: CLI reference

`xkey ca` (`xkey/cmd/xkey/cmd/ca.go:130`). Every verb resolves its client in
`getSDKClient` (`ca.go:99`).

| Verb | Source |
| --- | --- |
| `info` | `ca.go:181` |
| `issue` | `ca.go:196` |
| `sign-csr` | `ca.go:238` |
| `revoke <serial>` | `ca.go:257` |
| `crl` | `ca.go:287` |
| `check-revocation <serial>` | `ca.go:306` |
| `bundle` | `ca.go:324` |

## Flags

- `--local` (persistent on `ca`, `ca.go:351`): serve the verb from the local
  embedded CA. `getSDKClient` then returns `newLocalCAClient()`
  (`ca.go:117`), which opens `localca.NewClient(<data dir>, nil)`
  (`ca.go:125`).

## Errors

- `ErrCALocalStoreBarrierEncrypted` (`ca.go:79`): `--local` on a
  barrier-encrypted store; the CLI has no barrier key, so the GUI owns the
  CA in that case.
