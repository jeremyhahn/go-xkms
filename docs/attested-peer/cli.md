# Attested Peer — CLI

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-09-05

No CLI surface: this feature is a verification primitive reached only through
the Go package `pkg/attestation/peer` and its `sdk/go` aliases. The decision it
renders is consumed in-process by a transport gate (go-qrdb#278) and by the
platform's collector (go-trusted-platform#226); an operator inspects the
resulting verdicts on the consumer's surfaces, not here.
