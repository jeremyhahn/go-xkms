# CA: engineering

## Tests

| Area | Tests |
| --- | --- |
| sdk/go embedded CA | `sdk/go/embedded_service_test.go`: `TestNewEmbeddedClient_WithCA`, `TestNewEmbeddedService_NoCA` |
| local CA opener | `xkey/pkg/localca/localca_test.go` |
| CLI `--local` | `xkey/cmd/xkey/cmd/ca_test.go`: `TestRunCAInfo_Local`, `TestRunCAIssue_Local`, `TestGetSDKClient_LocalRefusesBarrierStore` |
| CA profiles | `xkey/cmd/xkey/cmd/ca_profile_registry_test.go`: help profiles and defaults are in `sdk/go`'s `NewDefaultProfileRegistry` |
| GUI service | `xkey/pkg/gui/services/ca_service_test.go`: `TestCAService_SetClient`, `TestCAService_LocalClientWithoutServer` |
| GUI wiring | `xkey/pkg/gui/connection_wiring_test.go`: `TestApplyConnectionEvent_CAFollowsTheConnection` |
| GUI view | `xkey/frontend/src/views/CA.test.ts` (vitest), `xkey/frontend/tests/e2e/ca.spec.ts` (Playwright mock tier) |

## Rules

- xkey reaches the CA through `sdk/go` only; a CA surface `sdk/go` lacks is
  an `sdk/go` change, never a root `pkg/ca` import.
- The CLI never opens a barrier-encrypted CA: it holds no barrier key.
