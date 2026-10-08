# Audit Log — User Guide

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-10-07

## What gets recorded

Every refused operation and every security-relevant success is written through
`pkg/audit` to go-qrdb's audit logger: the node's own trail, or a local file
logger when no node is embedded. Never put key material, PINs, passphrases, share
bytes or tokens in an event's `Details`.

## Reading it

Reading the trail back is go-qrdb's `AuditService` (`audit:read`, confined to
the caller's own tenant). xkms does not re-expose it; see
[architecture.md](architecture.md) for the sink and
[engineering.md](engineering.md) for the write-failure policy.
