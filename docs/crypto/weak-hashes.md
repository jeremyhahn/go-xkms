# Weak hash policy

> **Status: REFERENCE** · Last verified: 2026-10-12
> Cross-cutting reference for the weak-digest policy in `pkg/types/hashpolicy.go` and the `crypto.allow_weak_hashes` opt-in.

go-xkms refuses the collision-broken digests by default and offers one
documented, auditable way to re-admit them.

| Digest | Why |
| --- | --- |
| MD4, MD5 | practical chosen-prefix collisions |
| SHA-1 | SHAttered / SHA-1 is a Shambles chosen-prefix collisions |
| MD5+SHA1 | the TLS ≤1.1 CertificateVerify concatenation; no stronger than its parts |
| RIPEMD-160 | no current standards approval, 160-bit digest |

NIST SP 800-131A Rev. 2 disallows all five for digital signature generation. A
signature, certificate, or TPM attestation quote over one of them is forgeable
by an attacker who can influence the signed message.

## Where the policy applies

The policy governs the two general-purpose hash tables in `pkg/types`:

* `types.AvailableHashes()` (`pkg/types/types.go:3102`) — the advertised set,
  re-exported by `pkg/tpm2/store.AvailableHashes`
  (`pkg/tpm2/store/helpers.go:157`), which delegates and keeps no table of its
  own.
* `types.ParseHash(name)` — the parser every API layer uses to turn a
  caller-supplied algorithm name into a `crypto.Hash`.

Both apply two filters: the implementation must be linked into the binary
(`crypto.Hash.New` panics rather than erroring for an unlinked hash), and the
digest must not be weak unless the policy admits it. A refused name resolves to
`0`, which callers must surface as an error — never substitute a default for a
name the caller did supply.

One resolver sits outside the policy: `tpm2.ParseHash`
(`pkg/tpm2/types.go:1049`) maps the `hash` name in the IAK, LAK, IDevID and
LDevID configuration (`pkg/tpm2/config.go`) to SHA-1, SHA-256, SHA-384 or
SHA-512 without consulting `types.AllowWeakHashes`.

The policy does **not** govern key derivation. Hash strength requirements are
purpose-scoped: SP 800-131A Rev. 2 keeps SHA-1 acceptable outside signature
generation, and the ANSI X9.63 / SP 800-56A concatenation KDFs accept it
unconditionally so that PKCS#11 `CKD_SHA1_KDF` works in a compliant
deployment. See [kdf.md](kdf.md).

RSA-OAEP is refused with SHA-1 or MD5 unconditionally and independently of this
policy (`xkms.ErrWeakOAEPHash`): no ciphertext in this codebase was ever
produced with SHA-1 OAEP, so there is nothing to read back and no reason to
accept it.

## Opting in

```yaml
crypto:
  allow_weak_hashes: true
```

`server.New` — the one composition root every deployment goes through — applies
the setting (`pkg/server/server.go:590`) to `pkg/types` before any transport is started, and the daemon logs
a warning naming the re-admitted digests on every start, so an opt-in is
visible in the operator's logs and in the audit trail. The setting is read once
at startup; a SIGHUP reload does not change it.

A library embedding xkms without a `Config` gets the refusing default;
`types.SetAllowWeakHashes` is the programmatic equivalent.

FIPS mode is the ceiling. Under `crypto/fips140.Enabled()` — true under
`GODEBUG=fips140=on|only` at runtime, or by default in a `GOFIPS140` build — the opt-in is ignored: `types.SetAllowWeakHashes` refuses to
loosen the policy inside the validated module's boundary
(`pkg/types/hashpolicy.go:94`), so no configuration
file can widen the approved-algorithm set.

Refusing governs whether a weak digest is **performed**, never whether it is
**advertised**. The PKCS#11 module still lists its SHA-1 mechanisms (`CKM_SHA_1`,
`CKM_SHA1_RSA_PKCS`, `CKM_ECDSA_SHA1`; it registers no MD5 mechanism) in
`C_GetMechanismList` when the policy refuses them, exactly as it does under
FIPS mode — a caller is told the mechanism is unavailable rather than told it
does not exist.

## API

```go
types.AllowWeakHashes() bool        // current policy
types.SetAllowWeakHashes(bool)      // set once, from the composition root
types.IsWeakHash(crypto.Hash) bool  // classification, policy-independent
types.IsWeakHashName(string) bool   // same, by name — for callers that must
                                    // refuse a specific digest with a specific
                                    // error whatever the policy says
types.WeakHashNames() []string      // sorted canonical names, for diagnostics
```
