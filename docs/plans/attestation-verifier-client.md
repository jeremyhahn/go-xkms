# attestation-verifier: the appraisal service in transport.Client (slice 5 of row 1660)

## Objective

`transport.Client` embeds `AttestationAppraisalService`, so an SDK caller
holding a `Client` reaches the 8 appraisal verbs without a type assertion.

## Change

- pkg/api/transport/client.go: `AttestationAppraisalService` in `Client`,
  after `SigningKeyService`.
- sdk/go/transport/client.go: `AttestationAppraisalService` alias.
- sdk/go/transport/types.go: aliases for the request/response types the 8
  signatures use (only those not already aliased).
- The seven `transport.Client` mocks get the 8 methods:
  cmd/xkmsctl/backends_test.go (`mockBackendsClient`),
  cmd/xkmsctl/ca_test.go (`mockCAClient`),
  cmd/xkmsctl/cert_test.go (`mockCertClient`),
  pkg/auth/pkcs11_tls_test.go (`authMockClient`),
  sdk/go/crypto_test.go (`noopClient`),
  sdk/go/transport/client_subinterface_test.go (`stubClient`),
  xkey/pkg/pairing/bridge_test.go (`mockTransportClient`).
- The four `XKMSServicer` mocks are left alone:
  sdk/go/examples/embedded/main.go, sdk/go/options_test.go,
  sdk/go/xkms_test.go, test/integration/sdk/go/testservice.go.

## Tests

- `_ AttestationAppraisalService = (*stubClient)(nil)` and a row in
  `TestClientComposesAllSubInterfaces` (test commit before the feat commit).

## Checks

- root `go build ./...`; transport + xkmsctl tests; pkg/auth vet;
  sdk/go build/test/vet; xkey pairing vet; `make lint`.

## Out of scope

Proto, server code, transports, XKMSServicer mocks, docs/SPEC.md.

## Results

- Missed mocks (not in the brief's list; they embed the sub-interfaces
  instead of declaring methods, so the ResolveSigningKey grep missed them),
  found by make lint's xkey typecheck and given an embedded
  `transport.AttestationAppraisalService`:
  xkey/pkg/gui/services/ca_service_test.go (`mockCAClient`),
  key_service_test.go (`mockClient`, and `sealMockClient` through it),
  piv_service_test.go (`mockPIVClient`),
  xkey/cmd/xkey/cmd/sdk_client_fake_test.go.
- root `go build ./...`: pass.
- `go test` pkg/api/transport/... and cmd/xkmsctl/...: pass.
- `go vet` pkg/auth/...: pass.
- sdk/go build, transport tests, vet: pass.
- xkey `go vet ./pkg/pairing/...`: pass.
- `make lint` run 1: fail, xkey typecheck
  (xkey/pkg/gui/services/ca_service_test.go:455, missing
  AppraiseAttestationQuote); run 2 after the xkey fakes: pass.
