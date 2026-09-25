# PIV Certificate Management — User Guide

> **Status: NORMATIVE** · Feature: `piv` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

`xkey piv` stores and manages X.509 certificates in NIST SP 800-73-4 PIV
slots, across a software file store, TPM2 NV storage, or a PKCS#11 hardware
token — pick the backend with `--backend`, independently of where
certificates are stored with `--piv-storage`.

## Standard slots

| Slot | Purpose |
|---|---|
| `9a` | PIV Authentication |
| `9c` | Digital Signature |
| `9d` | Key Management |
| `9e` | Card Authentication |
| `82`–`95` | Retired key-management slots (historical decryption keys) |

## Generate a new key and certificate

The simplest path — a self-signed certificate you can start using
immediately:

```
xkey piv generate 9a
```

If your deployment has a certificate authority configured for the active
backend, ask for a CA-signed certificate instead:

```
xkey piv generate 9a --output-format ca-signed --subject "CN=Alice"
```

To get a CSR you will have an external CA sign yourself:

```
xkey piv generate 9a --output-format csr -o alice.csr
```

## Store a certificate you already have

```
xkey piv store 9a auth.pem
xkey piv show 9a
```

## Everyday operations

```
xkey piv list
xkey piv status
xkey piv export 9a --format pem --output /backup/9a.pem
xkey piv delete 9c
```

## Move between backends

```
xkey piv export 9a --format pem --output /tmp/9a.pem
xkey piv --backend tpm2 store 9a /tmp/9a.pem
xkey piv --backend tpm2 status
```

TPM2 and PKCS#11 support require a binary built with `-tags tpm2` or `-tags
pkcs11` respectively; the release binaries carry both. Without the matching
tag, `--backend tpm2` or `--piv-storage pkcs11` fails immediately with a
build-tag error rather than a confusing runtime failure.

## Log in with a PIV certificate instead of WebAuthn

```
xkey auth login --server https://kms.example.com --email you@example.com --piv --slot 9a
```

## PIV on a paired phone

Certificates and keys can also live in a paired phone's hardware Keystore.
See [phone-hsm/user.md](../phone-hsm/user.md) and
[phone-hsm/cli.md](../phone-hsm/cli.md#piv-on-the-phone) for `device
phone-list`, `phone-generate`, `phone-push-cert`, `phone-pull-cert` and
`piv-sync`.
