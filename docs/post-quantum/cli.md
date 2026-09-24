# Post-Quantum Cryptography — CLI

> **Status: NORMATIVE** · Feature: `post-quantum` · Repo: `go-xkms` · Last verified: 2026-09-24

Binary: `xkmsctl`. There is no `xkmsctl quantum` (or `pqc`) command group.
Post-quantum algorithms surface in exactly one general-purpose verb, as
**discovery**, not generation.

Global flags — including `--backend`, `--transport`, `--server`, `--token` —
are documented in
[`../key-management/cli.md`](../key-management/cli.md) §Global flags.

## `xkmsctl algorithms`

Lists the cryptographic algorithms the connected server supports, grouped by
purpose, with which backends provide each (`cmd/xkmsctl/algorithms.go:28-42`).
Discovery is unauthenticated.

```
xkmsctl algorithms
```

Output groups by purpose (`printAlgorithmGroup`,
`cmd/xkmsctl/algorithms.go:76-102`):

```
Signing:
  ML-DSA-44 [post-quantum] sizes=... backends=quantum
  ML-DSA-65 [post-quantum] sizes=... backends=quantum
  ML-DSA-87 [post-quantum] sizes=... backends=quantum
  ...
Key encapsulation:
  ML-KEM-512 [post-quantum] backends=quantum
  ML-KEM-768 [post-quantum] backends=quantum
  ML-KEM-1024 [post-quantum] backends=quantum
```

The exact set an operator sees reflects the connected server's compiled-in
backends — this command answers "can this deployment do X", it does not
generate anything. `-o json` (the global `--output` flag) emits the same
`client.AlgorithmInfo` list as JSON.

## No CLI verb generates a post-quantum key

`xkmsctl key generate <key-id>` is the general key-generation verb (see
[`../key-management/cli.md`](../key-management/cli.md)); its `--key-algorithm`
flag's help text is `"Key algorithm (rsa, ecdsa, ed25519)"`
(`cmd/xkmsctl/key.go:1780`) and its `--algorithm` flag is scoped to symmetric
AEAD names (`"aes-128-gcm, aes-192-gcm, aes-256-gcm"`,
`cmd/xkmsctl/key.go:1779`). Neither flag's parsing path, nor the REST request
the CLI sends, ever constructs a `types.QuantumAttributes`
(`pkg/api/rest/handlers.go:241-360`; see
[`../post-quantum/engineering.md`](engineering.md) §"What is absent"). There
is no `xkmsctl` flag combination that reaches
`pkg/keyprovider/quantum.QuantumBackend.GenerateKey`.

A post-quantum key is reachable from a CLI today only through
`pkcs11-module`'s PKCS#11 v3.2 mechanisms (`CKM_ML_DSA_KEY_PAIR_GEN`,
`CKM_ML_KEM_KEY_PAIR_GEN`) via a PKCS#11-speaking tool such as `pkcs11-tool`
or `openssl` against the module — see
[`../pkcs11-provider-module/cli.md`](../pkcs11-provider-module/cli.md) — or by
embedding go-xkms as a Go library and calling `quantum.New`/`GenerateKey`
directly (see [`user.md`](user.md)).
