# Attested Peer — CLI

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-09-16

No CLI surface: this feature is a set of verification primitives reached only
through the Go package `pkg/attestation/peer` and its `sdk/go` aliases. The
decision it renders is consumed in-process by a transport gate (go-qrdb#278)
and by the platform's collector (go-trusted-platform#226); an operator
inspects the resulting verdicts on the consumer's surfaces, not here.

This covers the device-credential and channel-binding primitives too. Both
take a parsed certificate or a live TLS connection state — neither is
something a command line holds — so exposing them as verbs would mean
re-parsing at a boundary that proves nothing. Inspecting a certificate's TCG
extensions by hand is `xkmsctl cert`'s job, not this feature's.
