# Certificate Authority CLI

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl ca`, the go-xkms server CLI (`cmd/xkmsctl/ca.go`, `cmd/xkmsctl/ca_tcg.go`); the normative reference is [`docs/certificate-authority/cli.md`](../../../../docs/certificate-authority/cli.md).

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl ca`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons.
> `xkey` has its own `xkey ca` command group with a different surface —
> see [the xkey CLI reference](README.md).

The `ca` command group drives the xkmsd Certificate Authority: issuance, CSR
signing, revocation and CRLs. The `ca tcg` subgroup issues TPM device identity
certificates. Every command asks the server named by the global `--server`
flag; the server does the signing with its own CA keys.

```
xkmsctl ca
├── bundle            # CA certificate chain (PEM)
├── certificate       # CA certificate details
├── sign-csr          # Sign a PEM CSR
├── issue             # Server-generated key pair plus certificate
├── revoke            # Revoke by serial
├── crl               # Current CRL (PEM)
├── status            # Revocation status by serial
└── tcg
    ├── issue-ek      # TPM Endorsement Key certificate
    ├── issue-ak      # TPM Attestation Key certificate
    ├── issue-lak     # Local Attestation Key certificate
    ├── sign-csr      # IAK and IDevID certificates from a TCG-CSR-IDEVID
    └── enroll        # TCG-CSR-IDEVID enrollment with a credential challenge
```

**`--output` is a file on some commands.** `sign-csr`, `issue`, `crl` and every
`ca tcg` command define their own `--output` naming an output file or
directory, which hides the global `-o/--output` format flag on those commands.
`-o json` is refused there. The other commands (`bundle`, `certificate`,
`revoke`, `status`) take the global `-o json`.

## CA Commands

Flags are defined in `cmd/xkmsctl/ca.go:568` onward.

### bundle

Prints the CA certificate chain as PEM. No flags.

```bash
xkmsctl ca bundle > ca-bundle.pem
xkmsctl --server https://kms.example.com:8443 ca bundle
```

### certificate

Prints the CA certificate's subject, issuer, serial and validity.

| Flag | Description |
|------|-------------|
| `--identity` | CA identity/CN; empty selects the default CA |

```bash
xkmsctl ca certificate
xkmsctl ca certificate --identity "Intermediate CA" -o json
```

### sign-csr

Signs a PEM CSR and prints the serial and certificate.

| Flag | Default | Description |
|------|---------|-------------|
| `--csr` | | CSR PEM file (required) |
| `--profile` | | Certificate profile, for example `server` or `client` |
| `--validity` | `0` | Validity in days; 0 uses the CA default |
| `--output` | | Write the certificate (PEM) to this file |

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.csr -nodes -subj "/CN=server.example.com"
xkmsctl ca sign-csr --csr server.csr --profile server --validity 365 --output server.crt
```

### issue

The server generates the key pair and returns the certificate, chain and
private key.

| Flag | Default | Description |
|------|---------|-------------|
| `--cn` | | Common name (required) |
| `--profile` | | Certificate profile |
| `--org` | | Organization |
| `--sans` | | Comma-separated SANs, for example `DNS:example.com,IP:192.0.2.1` |
| `--validity` | `0` | Validity in days; 0 uses the CA default |
| `--algorithm` | | `ecdsa-p256`, `rsa2048` or `ed25519` |
| `--output` | | Write the certificate (PEM) to this file |

With `--output`, the private key goes to `<output>.key` with mode 0600
(`cmd/xkmsctl/ca.go:312`). Without it, the key is printed to stdout.

```bash
xkmsctl ca issue --cn server.example.com --profile server \
  --sans "DNS:server.example.com,DNS:www.example.com" --validity 365 --output server.pem
```

### revoke

| Flag | Default | Description |
|------|---------|-------------|
| `--serial` | | Serial number in hex (required) |
| `--reason` | `0` | RFC 5280 reason code |

RFC 5280 reason codes: 0 unspecified, 1 keyCompromise, 2 cACompromise,
3 affiliationChanged, 4 superseded, 5 cessationOfOperation, 6 certificateHold,
8 removeFromCRL, 9 privilegeWithdrawn, 10 aACompromise.

```bash
xkmsctl ca revoke --serial 01AB23CD --reason 1
```

### crl

Prints the current CRL as PEM, or writes it to `--output`.

```bash
xkmsctl ca crl --output current.crl
```

### status

Reports whether a serial is revoked, and the reason if it is.

```bash
xkmsctl ca status --serial 01AB23CD
xkmsctl ca status --serial 01AB23CD -o json
```

## TCG Commands

Flags are defined in `cmd/xkmsctl/ca_tcg.go:630` onward.

### tcg issue-ek and tcg issue-ak

Issue an Endorsement Key or Attestation Key certificate for a DER-encoded public
key.

| Flag | Description |
|------|-------------|
| `--cn` | Common name (required) |
| `--ek-pub` (issue-ek) / `--pub` (issue-ak) | DER public key file (required) |
| `--org` | Organization |
| `--output` | Write the certificate (PEM) to this file |

```bash
xkmsctl ca tcg issue-ek --cn device-001 --ek-pub ek_pub.der --output ek_cert.pem
xkmsctl ca tcg issue-ak --cn device-001-ak --pub ak_pub.der --output ak_cert.pem
```

### tcg issue-lak

Issues a Local Attestation Key certificate in the WebAuthn Level 2 §8.3.1 TPM
attestation profile. The LAK must already exist on the device, certified
under its IAK with TPM2_Certify (`xkey tpm lak create`). The CA verifies the
submitted evidence before issuing (`cmd/xkmsctl/ca_tcg.go:492`).

| Flag | Description |
|------|-------------|
| `--tpm-manufacturer` | TCG manufacturer code, for example `id:49465800` (required) |
| `--tpm-model` | TPM model (required) |
| `--tpm-firmware` | TPM firmware version (required) |
| `--iak-cert` | The device's IAK certificate, DER (required) |
| `--certify-info` | Raw TPM2_Certify `TPMS_ATTEST` (required) |
| `--signature` | The IAK's signature over certifyInfo (required) |
| `--signature-algorithm` | The IAK's X.509 signature algorithm, for example `ECDSA-SHA256` (required) |
| `--lak-public-area` | The LAK's marshalled `TPMT_PUBLIC` (required) |
| `--nonce` | Qualifying data the evidence must echo |
| `--output` | Write the certificate (PEM) to this file |

```bash
xkmsctl ca tcg issue-lak \
  --tpm-manufacturer id:49465800 --tpm-model NPCT6xx --tpm-firmware 7.2.3.1 \
  --iak-cert iak_cert.der --certify-info certify_info.bin --signature signature.bin \
  --signature-algorithm ECDSA-SHA256 --lak-public-area lak_pub_area.bin \
  --nonce nonce.bin --output lak_cert.pem
```

### tcg sign-csr

Signs a packed TCG-CSR-IDEVID and issues the IAK and IDevID certificates.

| Flag | Description |
|------|-------------|
| `--cn` | Common name for the device identity (required) |
| `--csr` | Packed TCG-CSR-IDEVID file (required) |
| `--org` | Organization |
| `--output` | Directory; receives `iak_cert.der` and `idevid_cert.der` |

```bash
xkmsctl ca tcg sign-csr --cn device-001 --csr tcg_csr.bin --output ./certs
```

### tcg enroll

Validates the packed CSR, issues the IAK and IDevID certificates, and creates
a credential-activation challenge for the device.

| Flag | Description |
|------|-------------|
| `--cn` | Common name for the device (required) |
| `--packed-csr` | Packed TCG-CSR-IDEVID file (required) |
| `--org` | Organization |
| `--output` | Directory; receives `iak_cert.der`, `idevid_cert.der` and, when the server returns a challenge, `credential_blob.bin` and `encrypted_secret.bin` (`cmd/xkmsctl/ca_tcg.go:460`) |

```bash
xkmsctl ca tcg enroll --cn device-001 --packed-csr tcg_csr.bin --output ./enrollment
```

## Connecting to a server

The CA commands use the root connection flags: `-s/--server` (unix, http(s),
grpc(s) or quic URL; default `xkms-data/xkms.sock`), `--transport`, `--tls-ca`,
`--tls-cert`, `--tls-key`, `--spki-pin` and `--token`. See `xkmsctl --help`.

```bash
xkmsctl --server grpcs://kms.example.com:9443 ca certificate
xkmsctl --server https://kms.example.com:8443 \
  --tls-cert client.crt --tls-key client.key --tls-ca ca.crt \
  ca issue --cn myserver --output myserver.pem
```

## See Also

- [Certificate authority](../../../../docs/certificate-authority/user.md)
- [Certificate Management CLI](./cert.md)
- [Certificate Management Guide](../certificate-management.md)
