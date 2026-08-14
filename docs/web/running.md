# Running the Web Console

`xkmsd` always serves the console over TLS, and the certificate is minted by
the **embedded CA** — there is no step where you generate or install one, and
no mode in which the console is served in the clear.

## Starting the server

### Production

```sh
xkmsctl init            # provisions CA + admin mTLS + an encrypted barrier
xkmsd -c /etc/xkms/xkmsd.yaml
```

Then browse to `https://<host>:8443/ui/`. Sign in with a passkey (enroll one
first) or with a PIV / mTLS client certificate.

### Local development

```sh
xkmsd -c configs/xkmsd-local.yaml
```

No flags. That config is secure: TLS on with a CA-minted cert,
`auth.type: adaptive` (anonymous only until the first user is provisioned,
enforced thereafter), and an encrypted barrier with a development passphrase
so it auto-unseals at boot.

## If the daemon refuses to start

`xkmsd` is **secure-by-default**: it refuses to start when encryption-at-rest
(the barrier), TLS, authentication, or a CA is missing, because those are
required by FedRAMP / PCI-DSS / HIPAA. It logs the exact gaps and exits, so
the UI never comes up.

A refusal means the configuration genuinely opts out of a control — the fix is
to turn that control on (or run `xkmsctl init` to provision it), not to force
past the gate. The gaps are named precisely in the error, e.g.:

```
gaps: ["encryption-at-rest disabled (barrier.enabled=false): data is stored in plaintext",
       "authentication disabled (auth.enabled=false): access is anonymous"]
```

Each maps to a config section: `barrier.enabled`, `auth.enabled`/`auth.type`,
`tls.enabled`, and the `ca` block.

## Prerequisites for the UI to be served

- The binary must be built with the `ui` tag (`make build-ui`). A plain
  `xkmsd` build serves the API only; the embed stub reports "no UI" and the
  mount is skipped.
- `protocols.rest: true` and a free REST port (default **8443** — the
  devcontainer already uses 8443, so pick another port or stop the container).
- `ui.enabled` is true by default; set it false under `ui:` to disable.

## Verifying

```sh
curl -sk https://localhost:8443/api/v1/capabilities
# {"version":"...","webauthn_enabled":true,"piv_login_enabled":false,"ui_enabled":true}

curl -sko /dev/null -w '%{http_code}\n' https://localhost:8443/ui/   # 200
```

The startup log line `mounted SPA web UI prefix=/ui/` confirms the UI is
served. `Starting REST server port=8443` followed by `address already in use`
means another process holds the port.

## Configuration reference

```yaml
ui:
  enabled: true          # default true; static assets, no compliance impact
  path_prefix: "/ui/"    # mount prefix
  redirect_root: false   # when true, GET / → /ui/

cors:                    # only needed when the browser is served cross-origin
  enabled: false         # default: no CORS headers (same-origin UI needs none)
  allowed_origins: []    # explicit origins; "*" is a reported compliance gap
  allow_credentials: false
  max_age_seconds: 3600

auth:
  piv_login:             # browser cert-login exchange (POST /api/v1/auth/login/piv)
    enabled: false       # requires tls.client_auth to request client certs
    trusted_issuers: []  # optional issuer-DN allowlist
  session:
    access_token_ttl: "15m"
    refresh_token_ttl: "8h"
    login_rate_per_min: 10
```

## Desktop app

Build the Wails shell (see `web/desktop/`). In **remote** mode it manages a
remote `xkmsd`; in **standalone** mode it boots the engine in-process on a
loopback-only listener with a per-launch bearer token, so a single desktop
binary is a complete local KMS with no separate daemon.
