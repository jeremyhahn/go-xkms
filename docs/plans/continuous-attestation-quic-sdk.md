# Continuous attestation: verdict verbs on QUIC, REST clients and sdk/go (go-xkms#2088, slice 4)

## Objective

SPEC.md:81's verdict verbs have server routes on every transport and client
transports for gRPC, Unix and MCP. This slice gives the QUIC and REST client
transports (and sdk/go users of either) the three verbs.

## Routes and pairs

- `GET /api/v1/attestation/verdicts?device=` — `ListAttestationVerdicts` (`attestation_verdicts:list`)
- `GET /api/v1/attestation/verdicts/latest?device=` — `GetLatestAttestationVerdict` (`attestation_verdicts:get`)
- `POST /api/v1/attestation/verdicts` body `{"device_id": ...}` — `ReattestDevice` (`attestation_verdicts:create`)

No request carries a tenant: the server uses `callerTenant(ctx)`.

## Names

- `wire.AttestationVerdictsPath`, `wire.AttestationVerdictLatestPath`, `wire.AttestationVerdictDeviceParam`
- `wire.AttestationVerdictClient{Do Requester}` satisfying `transport.AttestationVerdictService`
- `verdicts()` accessors in packages quic and rest
- No new resource, action, route or error.

## Files

- pkg/api/rest/wire/attestation_verdicts.go and _test.go
- pkg/api/transport/quic/transport_attestation_verdicts.go and _test.go
- pkg/api/transport/rest/transport_attestation_verdicts.go and _test.go
- sdk/go/transport/client.go, sdk/go/transport/types.go (aliases)
- .changelog/unreleased/added-2088-attestation-verdict-quic-sdk.md

## Checks

- `go test -count=1 -race -tags "codec_cbor codec_json codec_msgpack" ./pkg/api/rest/wire/... ./pkg/api/transport/quic/... ./pkg/api/transport/rest/...`
- `cd sdk/go && go build ./...`
- `make lint`
- `git status --porcelain` empty

## Out of scope

- compose and server wiring: later slice
- USB, proto, gRPC, MCP

## Results

- Built as planned: wire.AttestationVerdictClient, the QUIC and REST
  client transports' `verdicts()` accessor plus three methods, and the
  sdk/go/transport aliases (`Client` unchanged).
- Left: compose and server wiring of `SetContinuousAttestation` (next slice).
- go test -race (wire, quic, rest; codec tags): pass.
- sdk/go go build ./...: pass.
- make lint: pass (0 issues on every module and tag set).
- git status --porcelain: empty before this commit.
