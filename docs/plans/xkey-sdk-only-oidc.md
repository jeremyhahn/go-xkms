# xkey-sdk-only: pkg/oidc through sdk/go/oidc (#2084, lane sxsdkd)

Objective: xkey imports go-xkms/pkg/oidc nowhere; every use goes through
github.com/jeremyhahn/go-xkms/sdk/go/oidc (row xkey-sdk-only, docs/SPEC.md).

## Files (28, all tests)

- xkey/cmd/xkey/cmd: cov704o_helpers_test.go, oidc_aws_cmds_test.go,
  oidc_aws_cov_test.go, oidc_barrier_test.go, oidc_callback_test.go,
  oidc_cmds_test.go, oidc_cov704e_test.go, oidc_login_flow_test.go,
  oidc_test.go
- xkey/pkg/gui/services: coverage_phase3_a_test.go, coverage_phase5_test.go,
  coverage_phase6_test.go, final_coverage3_test.go, final_coverage_a_test.go,
  final_coverage_b_test.go, final_coverage_push3_test.go,
  final_coverage_push4_test.go, final_coverage_push6_test.go,
  final_misc_coverage_test.go, oidc_callback_test.go,
  oidc_server_service_test.go, oidc_service_coverage_test.go,
  oidc_service_test.go, oidc_token_store_security_test.go,
  surgical_coverage_c_test.go, surgical_final_b_test.go
- xkey/pkg/oidc/aws: client_test.go, login_test.go

## Symbols sdk/go/oidc lacks

- types: RedirectURLError, CallbackHostError
- consts: TokenEncodingJSON, CodexAuthModeChatGPT
- vars: ErrInvalidTokenEncoding, ErrCodexAuthInvalid, ErrCodexAuthMode

## Slices

1. test: sdk/go/oidc/reexport_test.go asserts each alias equals the pkg symbol.
2. feat: the seven re-exports in sdk/go/oidc/oidc.go.
3. refactor: switch the imports (cmd/xkey/cmd, pkg/gui/services, pkg/oidc/aws).

Out of scope: pkg/oidc itself, other go-xkms/pkg imports in xkey, go.mod.
