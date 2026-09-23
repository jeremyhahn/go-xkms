- **`CA.QuantumSafeTLSConfig` deleted — BREAKING.** The method cleared
  `tls.Config.CurvePreferences` behind a stale TODO that predated Go's
  built-in support for hybrid post-quantum key exchange, and stood next to
  `TLSConfig`, `ServerTLSConfig`, `ClientTLSConfig`, and `MutualTLSConfig`,
  none of which ever pin `CurvePreferences`. With `CurvePreferences` nil, Go's
  `crypto/tls` already negotiates `X25519MLKEM768` by default, so the
  dedicated method added an API surface without adding behavior. Deleted the
  method, its `TrustedCA` interface entry (`sdk/go`'s public re-export), the
  `MockCertificateAuthority` mock, and every test and doc mention. Callers use
  `TLSConfig`/`ServerTLSConfig`/`ClientTLSConfig` and get the same curve
  negotiation. Files: `pkg/ca/tls.go`, `pkg/ca/interface.go`,
  `pkg/ca/interface_contract_test.go`, `pkg/ca/coverage_gap_test.go`,
  `pkg/ca/coverage_boost2_test.go`, `pkg/ca/coverage_boost3_test.go`,
  `test/mocks/ca_mock.go`, `pkg/init/ceremony_test.go`,
  `pkg/api/rest/handlers_init_test.go`, `pkg/server/server_init_test.go`,
  `pkg/acme/server/handlers/test_helpers_test.go`,
  `xkey/pkg/ca/embedded_service_test.go`, `docs/ca/api-reference.md`,
  `docs/ca/README.md`. go-xkms#689.
