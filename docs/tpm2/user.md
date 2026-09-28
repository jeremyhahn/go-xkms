# TPM 2.0 — User Guide

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-09-28

## What a TPM gives you that software cannot

Three things, and they are worth separating because people conflate them:

1. **Keys that cannot be copied.** A key marked fixed to the TPM cannot be
   exported by anyone, including you.
2. **Data that only unlocks on this machine, in this state.** Sealing binds data
   to PCR values — the measurements of firmware and boot.
3. **Evidence.** Attestation lets a remote party check what this machine is
   before trusting it, and the answer comes from the chip rather than from
   software that could be lying.

## There is no `xkmsctl tpm` group

You reach the TPM by choosing it:

```
xkmsctl --backend tpm2 key generate node-key --key-algorithm ecdsa --curve P-256
xkmsctl seal "secret" --backend tpm2
xkmsctl barrier init --barrier-strategy tpm2 --user-pin -
xkmsctl key attest node-key --backend tpm2 --output evidence.json
```

## Check three things on any TPM deployment

A healthy TPM, a simulator standing in for one, and a TPM sitting in lockout all
behave identically until an operation fails.

```
xkmsctl backends get tpm2 -o json   # configured? HardwareBacked? Attestation?
xkmsctl pin lockout -o json         # in dictionary-attack lockout?
```

and, in the server's startup log, which device or simulator it actually opened.

## Sealing: choosing what to bind to

Sealing to PCRs means the data unseals only when the machine measures the same.
That is the feature, and it is also the outage:

- Bind to **firmware and boot PCRs** and the data survives ordinary kernel
  updates.
- Bind to PCRs that change on every update and the data stops unsealing after
  the next one.

Neither is wrong. Decide which you meant, and keep a recovery path either way —
a sealed blob is bound to that TPM and cannot be moved.

## Attestation: what it actually proves

```
xkmsctl key attest node-key --backend tpm2 --output evidence.json
```

The evidence proves the key was generated inside a TPM whose endorsement key
chains to a manufacturer you trust. Two caveats that matter:

- **A quote needs a fresh nonce.** Evidence you did not just request proves
  nothing about now.
- **Storing evidence is not verifying it.** The CA can import an attestation and
  verify it separately; make sure whoever consumes it does the second part.

Enrolling a whole machine by its TPM is the ACME `enroll-01` path — the server
encrypts a secret to the TPM's endorsement key and only the real chip can
recover it. See [`../acme-issuance/user.md`](../acme-issuance/user.md).

## Identity keys: the password uses them, the platform administers them

The IDevID and IAK follow TCG *TPM 2.0 Keys for Device Identity and
Attestation* v1.00 r12 (the document is in `docs/references/`). The
consequence you will notice: an IDevID or IAK `password` lets a holder
**sign** with the key, and nothing more. Certifying the key, re-certifying
it, or releasing an enrollment credential against it requires the
**endorsement hierarchy authorization** — `ek.hierarchy-auth` — because
those are ADMIN-role operations, and the key's policy reserves them for the
Privacy Administrator. Provisioning uses that authorization itself; you do not
need to do anything for enrollment to work, but you do need to know that a
leaked signing password does not let anyone re-enroll the device as something
else.

**Binding an identity key to the platform state.** `idevid.platform-policy`
and `iak.platform-policy` (the default configuration sets the first) do not
change the key. They provision the key's *Policy NV Index* — the reserved
index the TCG specification assigns to each key — with a Delegation Policy
that says "the platform PCR holds the value it holds now". Signing with a
key that has no `password` then goes through that delegation, and stops
working when the platform state moves: a firmware or boot-chain change. That
refusal is the binding. To resume after a legitimate change, the Privacy
Administrator (anyone holding `ek.hierarchy-auth`) rewrites the delegation
for the new state; the key and its certificates are untouched. A key with a
`password` keeps signing with the password regardless — the specification
keeps the password as a way to use the key — so if platform state is to be
the only way, give the key no password you keep. A separate device Owner can
also define the index and write their own delegation through the SDK
(`DefineDevIDPolicyNV`, `WriteDevIDDelegationPolicy`), for example the
specification's example policy that lets any local process sign.

**Naming.** Both keys are named by one rule. Set `idevid.cn` / `iak.cn` to
choose a name explicitly. Leave them unset and the name is
`<idevid.model>-<idevid.serial>` for both keys — the same device information
the TCG-CSR-IDEVID carries to the CA. If neither a name nor both model and
serial are available, provisioning refuses with `ErrDevIDCNUnresolved` rather
than inventing a name: the key store files artifacts under the name, and a
fabricated default would put every device on the same file.

**Signing.** An RSA IDevID names no signature scheme, which is what Template
H-1 requires of a signing DevID. The padding and digest are chosen per signing
operation, so the same device identity key signs a certificate with PKCS#1
v1.5 and a TLS 1.3 handshake with RSA-PSS. An IAK is the opposite by design:
it is a Restricted key, it names its scheme, and it signs only what the TPM
itself produced.

**Curves.** `idevid.ecc.curve` and `iak.ecc.curve` accept `P-256`, `P-384` and
`P-521` — Templates H-2, H-3 and H-4, each with the nameAlg the specification
pairs it with (SHA-256, SHA-384, SHA-512). SM2 is not available: Template H-5
needs SM3-256, which the toolchain does not implement.

**The device string.** `tpm.device-string` is the optional per-device string
of §7.3.1, appended to the `'IDEVID'` and `'IAK'` strings the templates
require. It is printable ASCII, one value for the device rather than one per
key, and the combined string must fit the crypto suite's `unique` field — for
P-256 that is 32 octets in all, so 26 after `'IDEVID'`. Leave it empty unless
you have a reason to set it: it changes the keys.

```yaml
tpm:
  device-string: "SN-0000-0001"
```

**Upgrading a device provisioned before this release.** The key attributes,
the policy, the `unique` string and the RSA scheme are all inputs to how the
TPM derives a primary key, so an IDevID or IAK created under the previous
templates is a *different key* from the one the current code derives — there
is no in-place migration, by the nature of primary keys. Re-provision the
device and re-issue its identity certificates. Do it once: every change in
this release that moves a derivation input lands together. The old
certificates remain valid for the old keys, which the new code cannot
reproduce. Setting `tpm.device-string` afterwards re-keys again, so choose it
before provisioning a fleet.

Separately, an IAK provisioned with `iak.cn` unset was stored under an empty
name; it is now named `<model>-<serial>`, and artifacts under the old empty
name are not found by the new one. A configured `iak.cn` is unaffected.

**Provisioning either completes or refuses.** With an `idevid` section
configured, `Install` needs the TPM's EK certificate: the enrollment CSR
carries it and the CA checks it -- both that it is present and that it
chains to a TPM-manufacturer trust anchor the CA operator configured (see
[`../certificate-authority/user.md`](../certificate-authority/user.md)
"Enrolling a device with a TPM") -- before issuing an identity. If the
certificate is not in NV RAM (`ek.cert-handle`) or the certificate store,
provisioning stops with `ErrDevIDProvisionEKCert` and mints no IDevID —
previously it logged "continuing without it" and reported success, leaving a
device that could not enroll. Write the manufacturer's certificate first
(`ProvisionEKCert`, or the SDK's equivalent), or install without the IDevID
step if the platform is not meant to carry an identity. A failed key creation
or an unreadable key handle is reported the same way
(`ErrDevIDProvisionIDevID`, `ErrDevIDProvisionIAK`,
`ErrDevIDProvisionLookup`) rather than skipped.

**The manufacturer EK certificate download is off by default.** If the
certificate is not in NV RAM or the certificate store, `EKCertificate`
returns `ErrEndorsementCertNotFound` without making any network call — an
air-gapped host is never at risk of blocking on it. To opt in, set
`ek.cert-download: true`; `EKCertificate` then makes one bounded HTTPS
request to the manufacturer's EK certificate service
(`https://ekop.intel.com/ekcertservice/` by default,
`ek.cert-download-url` to point elsewhere) as a last resort. Bound the
request with `ek.cert-download-timeout` (10s if unset); a slow or
unreachable service fails with `ErrEKCertServiceUnreachable` instead of
hanging, and a response that is not a valid DER or PEM certificate fails
with `ErrEKCertServiceParseFailed`.

```yaml
tpm:
  ek:
    cert-download: true
    cert-download-timeout: 10s
    # cert-download-url: https://ekop.intel.com/ekcertservice/
```

## The lockout counter

Failed authorizations advance a counter that survives reboots. When it fills,
the TPM refuses authorizations until either the lockout authorization clears it
or its own recovery interval elapses.

```
xkmsctl pin lockout -o json
xkmsctl pin lockout-reset --so-pin -
```

**Check before retrying.** A wrong PIN entered five more times is how a
development machine becomes unusable for hours.

## Development without hardware

The simulator covers the whole surface. Two things surprise people:

- It is configured as **`simulator_host` / `simulator_port`** (default `2321`),
  **not** as `device_path`. A `tcp://host:port` in `device_path` names a file
  that does not exist.
- It serves **one client at a time**. A second connection blocks rather than
  being refused, which looks exactly like a hang.

## Session encryption is not a setting

Everything secret that crosses the bus to the TPM — the SO PIN, the USER PIN,
sealed data such as the PKCS#11 PIN, decrypted plaintext — is encrypted, and
every PIN is proven through a salted session rather than sent. There is
nothing to turn on, and nothing to turn off: an `encrypt-sessions` key left in
an old `tpm` configuration block, or `encrypt_session` in a backend
configuration map, is no longer read. How it works is in
[`engineering.md`](engineering.md) §"Bus protection".

## Legacy symmetric key cleanup

Releases before the change that moved TPM symmetric (AES) keys onto the
Platform SRK sealed them on the Shared SRK with no authorization, storing the
AES key as `<CN>.priv` next to `<CN>.pub` in the TPM2 key directory. Those
keys are refused rather than loaded:

```
$ xkmsctl key encrypt old-key "s3cret" --backend tpm2
Error: tpm: symmetric key predates Platform SRK protection (Shared SRK
parent, no authorization); delete and regenerate it: old-key: delete
old-key.priv from the TPM2 key directory
```

`xkmsctl key delete` cannot remove one of these: for a sealed (keyed-hash)
key it first unseals to prove you own it, and a pre-migration key was never
sealed under a PIN it can unseal with — the delete fails before it reaches
the files. There is no automatic scan for them. To recover:

1. The error above names the CN and the `.priv` file to remove. Find the
   TPM2 key directory this deployment is using — for `xkmsd` it is
   `tpm2-keys` under the configured `storage.path`; for a standalone client
   backend it is the directory the `tpm2` backend was configured with — and
   remove both `<CN>.priv` and `<CN>.pub` for that CN by hand.
2. Generate a replacement key under the same CN, for example
   `xkmsctl key generate <CN> --key-type symmetric --algorithm aes-256-gcm --backend tpm2`.
   It is sealed under the Platform SRK per the rules in
   [`engineering.md`](engineering.md) §"Symmetric keys".

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| TPM unavailable | no device, wrong path, or permissions | check the server's startup log for what it opened |
| everything hangs against the simulator | another process holds the single connection | stop the other one |
| sealed data will not unseal after a firmware or kernel update | the PCRs changed | expected; use the recovery path, and reconsider the PCR selection |
| authorization keeps failing | check lockout **before** retrying | `xkmsctl pin lockout` |
| TPM refuses everything | dictionary-attack lockout | `pin lockout-reset --so-pin -`, or wait out the interval |
| NV space exhausted | too many NV indices | free some, or review the PIV NV base index |
| attestation rejected | the EK does not chain to a trusted manufacturer root | import the manufacturer chain server-side |
| EK certificate missing and `ErrEndorsementCertNotFound` on an air-gapped host | `ek.cert-download` is off (the default), so no network lookup is attempted | write the certificate locally (`ProvisionEKCert`), or set `ek.cert-download: true` if the host does have a path to the manufacturer service |
| IAK/IDevID enrollment refused, "endorsement key certificate is not chained to a trusted tpm manufacturer root" | `ca.tcg-config.trust-anchors` is unset or does not name this device's manufacturer | see [`../certificate-authority/user.md`](../certificate-authority/user.md) "Enrolling a device with a TPM" |
| the TPM "stops working" after hours of uptime | leaked sessions or object contexts | a code defect — the leak test suites exist for this |
| `tpm2: failed to resolve the session salt key` | the EK handle could not be read for a reason other than being absent — often a transport fault | fix the transport; no session is started unsalted in its place |
| a node's TPM behaves oddly in ways nothing explains | firmware bugs are real | check the chip's firmware revision before the code |

## Where to go next

- Keys in the TPM: [`../crypto-backends/user.md`](../crypto-backends/user.md)
- Sealing and the barrier: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- PINs and lockout: [`../pin-management/user.md`](../pin-management/user.md)
- Enrolling hardware: [`../acme-issuance/user.md`](../acme-issuance/user.md)
