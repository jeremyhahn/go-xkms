# Consumer Notes: OpenSSL and OpenSSH

What works when the module is driven by the two consumers that matter most, what
does not, and the setup each needs. Command recipes live in
[usage.md](usage.md); this page is the caveats.

Every "works" below is backed by an integration test that verifies the result
**outside** the module — a signature is checked against exported public key
material with the token unable to participate, so a token echoing back whatever
it produced cannot pass. The tests are in
`test/integration/pkcs11/module/` and run under `make
integration-test-pkcs11-openssl-all`.

## Before anything: the module must reach a daemon

```bash
export XKMS_PKCS11_TARGET=unix:///var/run/xkms/xkms.sock
```

Without a reachable daemon `C_Initialize` fails with `CKR_DEVICE_ERROR`, which
every consumer below reports as a generic load failure.

## OpenSSL 3+: pkcs11-provider

The provider is the supported OpenSSL path. OpenSSL 3 replaced ENGINEs with
providers, and OpenSSL 4.0 removed ENGINEs outright.

### Setup

pkcs11-provider is configured through `openssl.cnf`, not the command line, so
every invocation needs a config file and `OPENSSL_CONF` pointing at it.

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/lib/libxkms_pkcs11.so
pkcs11-module-token-pin = 123456
pkcs11-module-quirks = no-deinit
activate = 1
```

Keep the default provider active: verification and public-key parsing need it.

`pkcs11-module-token-pin` lets the provider log in without prompting. The
`PKCS11_PIN` environment variable does the same for non-interactive use.

`pkcs11-module-quirks = no-deinit` is pkcs11-provider's documented workaround
(`provider-pkcs11(7)`). OpenSSL 4.0 runs `OPENSSL_cleanup()` from a global
destructor rather than `atexit()`, so it can execute after a PKCS#11 module's own
teardown and crash on the way out — after the operation has already succeeded and
written its output. Harmless on OpenSSL 3.

Objects are addressed by RFC 7512 URI:

```
pkcs11:object=my-signing-key;type=private
```

### What works

| Operation | Notes |
|-----------|-------|
| Provider loads and enumerates the module | |
| RSA sign / verify | PKCS#1 v1.5 |
| RSA-PSS sign / verify | The test also asserts the signature does **not** verify as v1.5, which is what catches a silent downgrade |
| RSA-OAEP encrypt / decrypt round trip | |
| ECDSA sign / verify | P-256, P-384, P-521 |
| Ed25519 sign / verify | `-rawin`; there is no `-digest` option for Ed25519 |
| Object enumeration | |
| CSR and self-signed certificate issuance | |
| TLS handshake with `s_server` holding a module-resident key | |

Key generation is not covered on the provider lane; use `pkcs11-tool
--keypairgen`.

### Known behaviours

- **The provider abandons a whole slot if any one object fails to convert.** It
  enumerates every object in the slot when it opens it, so a slot holding an
  object the provider cannot represent takes every other key on that slot with
  it.
- **The provider is known to segfault on exit** on some OpenSSL 3.0.20 builds
  after producing correct output. SoftHSM shows the same symptom, so it is a
  provider bug, not a module one. Check for the output file rather than trusting
  the exit status.

## OpenSSL: the legacy libp11 ENGINE

Deprecated upstream and removed entirely in OpenSSL 4.0. Use it only for existing
integrations.

### Setup

```ini
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so
MODULE_PATH = /usr/lib/libxkms_pkcs11.so
init = 0
```

`MODULE_PATH` is required. Without it libp11 silently probes for OpenSC instead
and fails in a way that does not mention this module at all.

### What works

RSA sign/verify (v1.5 and PSS), RSA-OAEP decrypt, CSR issuance, self-signed
certificate issuance that verifies, and a TLS handshake with the private key in
the token.

### What does not

| Limitation | Detail |
|-----------|--------|
| **Key generation** | `openssl genpkey -engine pkcs11` appears to succeed and generates the key **in software**, writing it to stdout in the clear. The ENGINE is loaded and then ignored. A caller who assumed otherwise would believe a software key was hardware-protected. Generate keys with `pkcs11-tool --keypairgen` or through the provider. |
| **Ed25519** | The ENGINE predates EdDSA in OpenSSL and has no representation for a key whose signing convention is raw-message rather than digest-then-sign. The token signs Ed25519 correctly; the ENGINE cannot carry the key. |

Both limitations are pinned by tests that fail if libp11 ever gains the
capability, so the gap is noticed rather than assumed permanent.

## OpenSSH

### Setup

```bash
ssh-add -s /usr/lib/libxkms_pkcs11.so     # add to the agent
ssh -I /usr/lib/libxkms_pkcs11.so user@host
```

or in `~/.ssh/config`:

```
Host example.com
    PKCS11Provider /usr/lib/libxkms_pkcs11.so
```

### What works

`ssh-keygen -D` lists token keys, and each comes back under the SSH algorithm its
PKCS#11 key type implies:

| Key generated as | Listed as |
|------------------|-----------|
| `rsa:2048` | `ssh-rsa` |
| `EC:secp256r1` | `ecdsa-sha2-nistp256` |
| `EC:secp384r1` | `ecdsa-sha2-nistp384` |
| `EC:secp521r1` | `ecdsa-sha2-nistp521` |
| `EC:edwards25519` | `ssh-ed25519` |

For each, the agent obtains a signature from the token, the signature verifies
against the public key `ssh-keygen` exported, and a real `sshd` accepts a login
with the private key never leaving the token.

`ssh-keygen -D` rebuilds the public key itself from `CKA_EC_PARAMS` and
`CKA_EC_POINT`, so a token reporting the wrong curve OID would have its keys
dropped from the listing or reported under the wrong algorithm.

### Version requirement for Ed25519

**OpenSSH 10.1 or later** is required to host an Ed25519 key on a PKCS#11 token.
OpenSSH 9.2's `ssh-pkcs11` layer handled only RSA and ECDSA and printed "skipping
unsupported key type" for anything else. RSA and ECDSA work on earlier versions.

## pkcs11-tool (OpenSC)

Used throughout for key generation, listing, signing and object management. One
non-defect worth not chasing:

**`pkcs11-tool --read-object --type pubkey` cannot build an `EVP_PKEY` for a
P-384 key** (P-256 and P-521 work). The module's `CKA_EC_PARAMS` and
`CKA_EC_POINT` are correct — reconstructing the SubjectPublicKeyInfo by hand and
parsing it with OpenSSL succeeds and reports `NIST CURVE: P-384`. It is an OpenSC
bug. Export P-384 public keys through pkcs11-provider instead:

```bash
openssl pkey -in "pkcs11:object=my-key;type=public" -pubout
```

## What makes these consumers work

Three object-model details exist specifically because real Cryptoki consumers
need them, and none was caught by the Go unit suite or the OASIS conformance
suite:

- **Key objects carry all twelve boolean capability attributes**, defaulted to
  `CK_FALSE`. Answering `CKR_ATTRIBUTE_TYPE_INVALID` for an absent attribute is
  spec-correct per §5.7.5, but libp11 refused to load such a key at all and
  pkcs11-tool warned on every listing. Deny-by-default semantics are unchanged;
  the object is simply readable.
- **RSA and EC private key objects carry the public components** —
  `CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`, `CKA_EC_PARAMS`, `CKA_EC_POINT`. libp11
  reads `CKA_MODULUS` off the *private* key to build the public half. Per §4.9's
  RSA private key table those attributes belong there.
- **Raw `CKM_RSA_PKCS` and `CKM_ECDSA` send a "no hash" sentinel to the service**,
  not an empty hash name. An empty name resolved to the SHA-256 default, so the
  server re-hashed the DigestInfo OpenSSL had already built: signing "succeeded",
  returned a correctly sized signature, and verified against nothing.

## See also

- [usage.md](usage.md) — command recipes for pkcs11-tool, OpenSSL, SSH, p11-kit, NSS, Java
- [support-matrix.md](support-matrix.md) — what the token advertises
- [deviations.md](deviations.md) — what it will not do
