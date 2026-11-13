# Plan: `xkey acme account` and `xkey acme revoke` (row acme, epic #2085)

## Objective

Give xkey its first ACME verbs as a thin front end over `pkg/acme/client`,
reached only through `sdk/go/acme` (`NewACMEClient`, `ACMEClientParams`).
xkey holds no ACME client logic.

## Commands and flags

Shared (persistent on `xkey acme`):

- `--directory <url>` ACME directory URL (required).
- `--account-key <file>` PEM private key of the ACME account (PKCS#8, EC or
  PKCS#1); required. The key is read and handed to the client as a
  `crypto.Signer`; it is never printed.
- `--trusted-root <file>` (repeatable) PEM CA certificates to trust;
  `--system-roots` adds the OS pool.

Verbs:

| Command | sdk/go call |
|---|---|
| `xkey acme account register --contact mailto:a@b` | `ACMEClient.RegisterAccount()` (contact goes in `ACMEClientParams.AccountEmail`) |
| `xkey acme account update --contact a@b [--contact ...]` | `ACMEClient.UpdateAccount(ctx, contacts)` |
| `xkey acme account deactivate --yes` | `ACMEClient.DeactivateAccount(ctx)` (irreversible, needs `--yes`) |
| `xkey acme revoke --cert <pem> [--reason keyCompromise]` | `ACMEClient.RevokeCertificate(ctx, cert, reason)` |

`--reason` takes an RFC 5280 name (unspecified, keyCompromise, caCompromise,
affiliationChanged, superseded, cessationOfOperation, certificateHold,
removeFromCRL, privilegeWithdrawn, aACompromise) or its number.

Storage: the client requires an account DAO; the CLI passes one from
`NewACMEStorageFactoryFromKVStore` over an in-memory qrdb KV store. The ACME
server is the source of truth: the account is found again from the account
key (RFC 8555 7.3.1), so no local state is needed for these verbs.

## Slices

1. This plan (docs commit).
2. Tests: cobra tests against a fake client behind a small `acmeClient`
   interface in the cmd package; register passes the contact, update and
   deactivate call their methods, revoke parses the certificate and reason,
   bad flags and a missing cert file fail clearly, no output carries key
   material.
3. Feat: `acme.go`, `acme_account.go`, `acme_revoke.go`; the interface is
   satisfied by `*sdkacme.ACMEClient`, built by `sdkacme.NewACMEClient`.
4. Docs: `xkey/docs/acme/README.md` marks account and revoke implemented.

## Out of scope (later slices of the row)

- `enroll` (enroll-01), `endorse` (endorse-01), `renew`.
- The GUI `acme` surface.
- Account keys held in a TPM or other key store, EAB, persistent local
  account records.
- Server-side ACME (row acme-issuance).

## Results (lane sacmeb)

- Slices 2-4 done as planned. The CLI logger writes warnings only, to stderr.
- Departure: `pkg/acme/client` imports `pkg/acme/linter` (zlint), so
  `xkey/go.mod` gains three indirect requires (zlint, zcrypto, go-toml v1)
  for the readonly build; no existing version changes. Kept in its own
  `build(xkey)` commit.
