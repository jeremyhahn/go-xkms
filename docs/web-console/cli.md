# Web Console — CLI

> **Status: NORMATIVE** · Feature: `web-console` · Repo: `go-xkms` · Last verified: 2026-09-24

**No `xkmsctl` verbs.** `xkmsctl` has no `web` or `console` command group —
the console is reached through a browser or the `xkms-console` desktop
binary, not driven by `xkmsctl`. The REST surface the console exercises
overlaps heavily with `xkmsctl`'s own transport; see
[api.md](api.md) and the cross-reference in
[`../key-management/cli.md`](../key-management/cli.md).

## Building

```sh
make build-web     # build @go-xkms/sdk, the SPA, stage dist/ into both embeds
make build-ui      # build xkmsd with the embedded UI (adds the "ui" build tag)
make dev-web       # Vite dev server, proxying to XKMS_DEV_API (default :8443)
```

`make build-web` copies the built `dist/` into `web/dist` (the `xkmsd`
embed, `web/embed.go`) and into `web/desktop/frontend/dist` (the Wails
embed, `web/desktop/frontend/embed.go`). A plain `go build ./...` — without
`make build-ui` — compiles `xkmsd` against `web/embed_stub.go` instead and
serves the API only.

Desktop shell:

```sh
cd web/desktop
go build -tags desktop -o xkms-console .   # real window (needs cgo + WebKit)
go build -o xkms-console .                 # connection logic only; runGUI returns GUIUnavailableError
```

## Running the desktop shell

Two environment variables select the mode (`web/desktop/main.go`'s
`resolveConnection`); there are no command-line flags on `xkms-console`
itself:

| Variable | Effect |
|---|---|
| `XKMS_DESKTOP_MODE` | `remote` or `standalone`. Unset: `remote` when `XKMS_SERVER_URL` is set, else `standalone`. |
| `XKMS_SERVER_URL` | Remote mode's target. Unset falls back to the first saved bookmark; neither present is a `*ConfigError`. |
| `XKMS_CONFIG` | Standalone mode's daemon config path. Default `/etc/xkms/xkmsd.yaml`. |

```sh
XKMS_DESKTOP_MODE=remote XKMS_SERVER_URL=https://kms.example.com:8443 ./xkms-console
XKMS_DESKTOP_MODE=standalone XKMS_CONFIG=/etc/xkms/xkmsd.yaml ./xkms-console
```

Bookmarks persist at `$XDG_CONFIG_HOME/xkms-desktop/bookmarks.json` (via
Go's `os.UserConfigDir()`), written mode `0600`, managed from the running
GUI's `SaveBookmark`/`ListBookmarks` bridge calls — there is no CLI verb to
manage them outside the GUI.

## Testing

```sh
make test-web            # sdk/ts + svelte-auth + web/app, under coverage
make coverage-web        # same, plus lcov reports per package
make coverage-sdk-ts     # one package at a time
make test-web-e2e        # Playwright, mock tier (web/app/e2e/)
make integration-test-web  # Playwright, live tier (test/integration/web/) — devcontainer only
```

See [engineering.md](engineering.md) §"Test strategy" for what each layer
proves and why `integration-test-web` is excluded from the
`integration-test` aggregate.
