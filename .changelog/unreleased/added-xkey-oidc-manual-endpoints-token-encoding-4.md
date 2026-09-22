- **`xkey oidc` can now authenticate against providers with no discovery
  document, and can address a token endpoint that expects a JSON body
  instead of form encoding** (#4, gaps 2 and 3 of 4; gap 1, CLI token-store
  custody, and gap 4, RFC 8628 device flow, remain open pending an owner
  ruling). `pkg/oidc.ProviderConfig` gained `AuthorizationEndpoint`,
  `TokenEndpoint`, `JwksURI`, and `UserinfoEndpoint` fields: setting any of
  them makes `NewProvider` skip `.well-known/openid-configuration` entirely
  and use the supplied endpoints, requiring the first three and validating
  with the existing `ErrMissingAuthEndpoint`/`ErrMissingTokenEndpoint`/
  `ErrMissingJWKSURI` family via the new `ErrIncompleteManualEndpoints`. A
  bare `SkipDiscovery: true` with no manual endpoint keeps its prior
  contract — an uninitialized `Provider` the caller populates itself. The
  CLI exposes this through `--authorization-endpoint`, `--token-endpoint`,
  `--jwks-uri`, and `--userinfo-endpoint` on `xkey oidc login` and
  `xkey oidc providers add`; a partial set is refused with a typed error
  (`ErrOIDCIncompleteEndpoints`) naming exactly which flags are missing,
  and a saved provider's manual endpoints now carry into `xkey oidc refresh
  --provider <name>` too, so a manual-endpoint provider survives past the
  first login. A new `TokenEncoding` field (`pkg/oidc.TokenEncoding`, `form`
  default or `json`) selects how the authorization-code exchange and
  refresh requests are POSTed; `pkg/oidc.EncodeTokenRequestBody` is the one
  place that makes this decision, used by `Client.doPlainTokenRequest` and
  `Client.doDPoPTokenRequest` (and therefore by the GUI's `OIDCService`,
  which already builds providers through `pkg/oidc.NewProvider`/`NewClient`)
  and by the CLI's `exchangeCodeForTokens`/`refreshTokens` alike, so the
  encoding decision lives in one place instead of being duplicated between
  the CLI and the library. `--token-encoding` on `xkey oidc providers add`
  and `xkey oidc login` persists the choice per provider
  (`oidc-providers.json`'s `token_encoding` key); an unrecognized value is
  refused via `oidc.ErrInvalidTokenEncoding`. Background auto-refresh
  carries the resolved token endpoint and encoding across its re-exec the
  same way it already carries the client ID. Files:
  `xkey/pkg/oidc/provider.go`, `xkey/pkg/oidc/token_encoding.go`,
  `xkey/pkg/oidc/client.go`, `xkey/pkg/oidc/errors.go`,
  `xkey/cmd/xkey/cmd/oidc.go`. Tests: `pkg/oidc/provider_test.go`,
  `pkg/oidc/token_encoding_test.go`, `pkg/oidc/client_test.go`,
  `pkg/oidc/client_dpop_test.go`, `cmd/xkey/cmd/oidc_test.go`,
  `cmd/xkey/cmd/oidc_cmds_test.go` cover manual-endpoint discovery skipping
  against a server that never serves `.well-known`, partial-endpoint
  refusal, form vs. json request bodies against a fake token endpoint for
  both exchange and refresh (including the DPoP path), and refusal of an
  unrecognized encoding.
