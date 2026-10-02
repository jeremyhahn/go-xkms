# Init Ceremony — User Guide

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-10-02

## What a ceremony is, and why it is one

A new KMS has no CA, no barrier, no officers, and no way to authenticate anyone.
Everything it will ever issue traces back to one event. The init ceremony is
that event: it creates the CA, opens the barrier, issues the first officer
certificates, and splits the recovery shares.

It is called a ceremony because it is the only moment when all the shares exist
in one place. Who is present, and what they leave with, is the whole security
model.

## Two roles

- **The operator** runs `xkmsd init` on the server.
- **Each officer** runs `xkmsctl init claim-cert` and
  `xkmsctl init claim-share` from their own machine, and leaves with a
  certificate and a share.

## Before the day

Each officer generates a key and a CSR **locally** and hands over only the CSR.
The private key never travels.

The operator publishes the server's **SPKI pin** out of band — in a chat the
officers already trust, on paper, in a provisioning system. Officers need it,
because at claim time they have no CA bundle yet and the pin is the only thing
verifying they are talking to the real server:

```
xkmsctl bootstrap spki show-pin --cert-file kms.crt
```

## The operator's part

```
xkmsd init
```

The ceremony stands up the CA, initializes the barrier with the configured
strategy, records the officers, splits the shares, and enrols admin factors.

Then, per officer:

```
xkmsctl init sign-csr --username alice --csr alice.csr --role custodian --output alice.crt
```

Roles are `so`, `admin`, `operator`, `user`, `auditor`, `custodian`. `so` is the
security officer — a control-plane credential that works before any tenant
barrier unseals. Hand it out deliberately.

In single-admin mode, admin factors enrolled during the ceremony (mTLS, FIDO2,
PIV) are persisted durably: `xkmsd init` writes them into the same store
`xkmsd run` reads at login, so they survive a restart with no re-enrollment.
`--barrier-strategy shamir` is not yet supported for the durable node's own
encryption-at-rest (the ceremony's own M-of-N officer/share distribution,
above, is unaffected); `xkmsd init` refuses up front rather than leave the
node half-sealed.

## Each officer's part

```
xkmsctl init status

xkmsctl init claim-cert --username alice --key alice.key \
    --spki-pin "$PIN" --output alice.crt --ca-output ca-bundle.pem

xkmsctl init claim-share --username alice --cert alice.crt --key alice.key \
    --spki-pin "$PIN" --ca-cert ca-bundle.pem --output alice.share
```

Two things to get right:

**Use `--ca-output`.** The CA bundle comes back with your certificate and it is
what every later command needs. Fetching it separately later is more work and
less safe.

**Keep the share.** It is emitted once. There is no command that reissues it,
and there will not be — a server that could hand out its own shares would not be
protecting anything.

## After the ceremony

```
xkmsctl --tls-ca ca-bundle.pem --tls-cert alice.crt --tls-key alice.key \
    --server https://kms.example.com:8443 barrier status
```

Store the share somewhere it will still exist and still be findable in a year,
and somewhere different from where the other officers stored theirs. The
threshold only helps if the shares are actually separated.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| SPKI pin mismatch | the pin is wrong, or you are not talking to the server you think | **stop.** Confirm the pin out of band; do not proceed |
| "already claimed" | that credential was already collected | if it was not you, that is an incident |
| key does not match | `--key` is not the key for the submitted CSR | use the key you generated the CSR with |
| ceremony in the wrong state | steps are out of order | `init status` shows where things stand |
| routes return 404 | no ceremony configured on this server | server-side configuration |
| ceremony aborts on a random-source error | the server could not get good randomness | do not retry until that is fixed; the material would be untrustworthy |
| `init: --barrier-strategy shamir is not yet supported for the durable node barrier` | the node barrier's own Shamir split ceremony is not wired yet | use `none`, `passphrase` or `tpm2` for the node barrier strategy; the ceremony's own officer/share distribution is unaffected |

The pin mismatch is the one row in this table that is a security event rather
than a mistake. Everything else is recoverable by doing the step again.

## Where to go next

- Where the SPKI pin comes from: [`../trust-bootstrap/user.md`](../trust-bootstrap/user.md)
- What the shares unlock: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- Holding and submitting shares afterwards: [`../share-custody/user.md`](../share-custody/user.md)
- Routine certificate issuance from here on: [`../acme-issuance/user.md`](../acme-issuance/user.md)
