# Init Ceremony — API

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-10-04

No API surface: `xkmsd init` is a local one-shot command. The REST, gRPC, MCP,
QUIC and embedded init-claim routes were removed with the M-of-N ceremony;
holder enrolment and quorum unseal are go-qrdb's own API on the node.
