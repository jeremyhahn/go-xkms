# Authentication Adapter Framework

> **Status: REFERENCE** · Last verified: 2026-10-12
> The `pkg/auth` authenticator seam and how `xkmsd` builds it from `auth:`; [rbac](../rbac/engineering.md) is normative for authorization.

## Interface

Every transport authenticates through one interface,
`auth.Authenticator` (`pkg/auth/auth.go:48`):

```go
type Authenticator interface {
    AuthenticateHTTP(r *http.Request) (*Identity, error)
    AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error)
    Name() string
}
```

`auth.Identity` is an alias for go-qrdb's `qrdbsdk.Identity`
(`auth.go:42`). The authenticators fill `Subject`, `Roles` and `TenantID`
(for example `pkg/auth/jwt.go:233`, `:253`; `pkg/auth/mtls.go:258`, `:283`).
A handler reads it back with `auth.GetIdentity(ctx)` (`auth.go:98`).

Never decide authorization from the identity's role strings. `Roles` holds
qrdb role identifiers, so comparing it with a role name matches nothing real
(go-xkms#1074). Use `(*auth.Authorizer).Authorize(ctx, identity, resource,
action)` (`pkg/auth/authorize.go:60`) for a resource:action decision, or
`auth.HoldsSystemRole` (`pkg/auth/rolemembership.go:75`) where the decision
really is role membership.

## Authenticators

| Type | Constructor | `Name()` | Purpose |
|---|---|---|---|
| `JWTAuthenticator` | `NewJWTAuthenticator(*JWTConfig)` (`jwt.go:60`) | `jwt` | Bearer token verified against `JWTConfig.PublicKey`, with optional `Issuer`, `Audience` and `HeaderName` (`jwt.go:48`) |
| `MTLSAuthenticator` | `NewMTLSAuthenticator(*MTLSConfig)` (`mtls.go:131`) | `qrdbsdk.MethodMTLS` | TLS client certificate; see below |
| `OIDCAuthenticator` | `NewOIDCAuthenticator(ctx, *OIDCConfig)` (`oidc.go:163`) | `oidc` | OIDC ID and access tokens; `OIDCConfig` (`oidc.go:98`) takes `Issuer`, `ClientID`, `Audience`, `JWKSCacheTTL` (default one hour) and `HTTPClient` |
| `CompositeAuthenticator` | `NewCompositeAuthenticator(...Authenticator)` (`composite.go:35`) | `composite` | Tries each in order. The first success wins; if all fail, the last error is returned (`composite.go:26-28`) |
| `NoOpAuthenticator` | `NewNoOpAuthenticator()` (`noop.go:28`) | `noop` | Admits every request anonymously |
| `QRDBBearerAuthenticator` | `NewQRDBBearerAuthenticator(source)` (`qrdb_bearer.go:62`) | `jwt` | Carries a host's session tokens into an embedded go-qrdb node's authenticator chain (`qrdb_bearer.go:39-43`) |
| `StaticTokenAuthenticator` | `NewStaticTokenAuthenticator(token, identity)` (`statictoken.go:39`) | `statictoken` | One per-launch bearer token, accepted over loopback HTTP only, for the desktop standalone mode (`statictoken.go:26-30`) |
| `LiveAuthenticator` | `NewLiveAuthenticator(a)` (`live.go:68`) | the wrapped one | Wraps an authenticator so it can be replaced while requests are in flight (`live.go:32-36`) |

`OIDCAuthenticator` is a library type only: `xkmsd` never builds it from
configuration.

### mTLS

`MTLSConfig` (`pkg/auth/mtls.go:105`) has three optional fields:

- `ExtractMetadata`: derives certificate metadata.
- `ExtractSubject`: defaults to the certificate's Common Name.
- `UserStore`: maps a certificate to a user.

With a `UserStore` set, the user is found by the certificate's SPKI
thumbprint (`qrdbsdk.ComputeSPKIThumbprint`), and the identity is never
derived from certificate fields (`mtls.go:113-123`). The lookup fails closed:

| Outcome | Error |
|---|---|
| Account is disabled | `ErrUserDisabled` |
| Account's method policy excludes mTLS | `*qrdbsdk.AuthMethodNotPermittedError` |
| Certificate is bound to no user | `ErrCertNotBound` |
| Any other store failure | `*UserLookupError` |

### PKCS#11-backed client TLS

`auth.NewPKCS11TLSConfig(*PKCS11TLSConfig)` (`pkg/auth/pkcs11_tls.go:236`)
returns a `*tls.Config`, a cleanup function and an error. The private key
never leaves the token. `PKCS11TLSConfig` (`pkcs11_tls.go:51`) has these
fields:

| Field | Meaning |
|---|---|
| `ModulePath` | Path to the PKCS#11 module |
| `SlotID` | Slot to use |
| `PIN` | A `*secure.Secret`; nil is rejected |
| `CertLabel` | Optional; when empty, the first certificate is used |
| `CACerts` | Optional; when nil, the system roots are used |
| `Module` | Optional pre-initialised module |

## How xkmsd builds the authenticator

`(*Server).buildAuthenticator` (`pkg/server/server.go:1257`) reads `auth:`
(`AuthConfig`, `pkg/config/config.go:420`):

| `auth.type` | Result |
|---|---|
| `enabled: false`, or `none`/`noop`/`""` | `NoOpAuthenticator`. `cmd/xkmsd` refuses to start on it, because the config flags it as a compliance gap |
| `jwt` | `JWTAuthenticator`. Requires `auth.jwt.public_key_file`, else `ErrJWTPublicKeyRequired` |
| `mtls` | `MTLSAuthenticator` with the qrdb user store. Requires `tls.enabled`, else `ErrMTLSRequiresTLS` |
| `composite` | `auth.composite.methods` (`jwt`, `mtls`) chained in order (`server.go:1371`) |
| `adaptive` | Removed. Fails with `ErrAdaptiveRemoved` and names `composite` as the replacement (`server.go:1329-1334`, `pkg/config/auth.go:43`) |
| anything else | `ErrUnknownAuthType`: fails closed |

When `composite.methods` is empty, the chain is derived
(`server.go:1423`):

- JWT is added when `public_key_file` is set or a token issuer exists.
- mTLS is added when TLS is enabled.
- A single result is used bare, without a composite wrapper.
- An empty result is `ErrCompositeMethodsRequired`.

```yaml
auth:
  enabled: true
  type: composite
  jwt:
    public_key_file: /etc/xkms/jwt-public.pem
  composite:
    methods: ["jwt", "mtls"]
  enable_rbac: true
```

`auth.enable_rbac` builds an `auth.Authorizer` over the qrdb RBAC client. If
there is no qrdb identity plane, the server logs a warning and authorisation
is permissive (`server.go:1513-1519`). See
[RBAC configuration](../rbac/engineering.md#configuration).

## TLS

`tls:` (`TLSConfig`, `pkg/config/config.go:382`) is turned into a
`*tls.Config` by `(*TLSConfig).LoadTLSConfig` (`pkg/config/tls.go:26`). It
has these keys:

- `cert_file`, `key_file` and `ca_file`
- `client_auth` and `client_cas`
- `min_version` and `max_version`
- `cipher_suites` and `prefer_server_ciphers`
- `watch_cert_files`
- `server_cn`, `extra_sans` and `include_localhost_sans`

`client_auth` maps onto Go's `tls.ClientAuthType` (`tls.go:100-115`):

| `client_auth` | `tls.ClientAuthType` |
|---|---|
| `none` or `""` | `NoClientCert` |
| `request` | `RequestClientCert` |
| `require` | `RequireAnyClientCert` |
| `verify` | `VerifyClientCertIfGiven` |
| `require_and_verify` | `RequireAndVerifyClientCert` |

## Embedding example

```go
tlsConfig, err := (&config.TLSConfig{
    Enabled:    true,
    CertFile:   "server.pem",
    KeyFile:    "server-key.pem",
    CAFile:     "ca.pem",
    ClientAuth: "require_and_verify",
}).LoadTLSConfig()

jwtAuth, err := auth.NewJWTAuthenticator(&auth.JWTConfig{PublicKey: pub})
chain, err := auth.NewCompositeAuthenticator(
    auth.NewMTLSAuthenticator(&auth.MTLSConfig{UserStore: users}),
    jwtAuth,
)

srv, err := rest.NewServer(&rest.Config{ // pkg/api/rest/server.go:114, :270
    Port:          8443,
    Backends:      backends,
    TLSConfig:     tlsConfig,
    Authenticator: chain,
})
```

In a handler:

```go
identity := auth.GetIdentity(r.Context())
if err := authorizer.Authorize(r.Context(), identity, auth.ResourceKeys, auth.ActionList); err != nil {
    // 403
}
```

`auth.ResourceKeys` is defined at `pkg/auth/permissions.go:40` and
`auth.ActionList` at `:135`.
