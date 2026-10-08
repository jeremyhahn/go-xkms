# Audit Log — API

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-10-04

No API surface in xkms: the audit query routes, RPCs and MCP method were removed; the read side is go-qrdb's `AuditService`. Writers use `pkg/audit` in-process.
