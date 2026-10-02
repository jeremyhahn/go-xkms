# Attested Peer — CLI

> **Status: NORMATIVE** · Feature: `attested-peer` · Repo: `go-xkms` · Last verified: 2026-10-02

No CLI surface: this feature is a set of verification primitives reached only
through the Go package `pkg/attestation/peer` and its `sdk/go` aliases. The
decision it renders is consumed in-process by go-qrdb's attested-caller gate,
through the `pkg/attestation/peergate` verifier a host composes into its node;
an operator inspects refusals in that node's audit trail
(`auth.peer_attestation` records), not here.

The gate verifier, its evidence cache and its collector have no CLI either:
the collector's challenge and submit calls are defined over the TLS connection
a peer's request arrived on, which only the host's transport holds.

This covers the device-credential and channel-binding primitives too. Both
take a parsed certificate or a live TLS connection state — neither is
something a command line holds — so exposing them as verbs would mean
re-parsing at a boundary that proves nothing. Inspecting a certificate's TCG
extensions by hand is `xkmsctl cert`'s job, not this feature's.
