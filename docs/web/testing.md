# Testing the Web Console

Four layers, fastest first. The first three run in `make test`; the fourth
runs in `make integration-test`.

| Layer | Command | What it proves |
|---|---|---|
| Go unit | `make test-go` | Handlers, servicer, transports, RBAC gates |
| TS unit + component | `make test-web` | SDK wire contracts, auth store, every view |
| Playwright — mock tier | `make test-web-e2e` | The real SPA against an intercepted API |
| Playwright — live tier | `make integration-test-web` | The real SPA against a real `xkmsd` |

## Unit and component tests

`make test-web` type-checks and tests all three web packages, **under
coverage**, so the 90% thresholds in each vitest config gate the build. A
plain `vitest run` reports no coverage and therefore enforces nothing — that
is why the target uses `test:coverage`.

```sh
make test-web           # all three packages
make coverage-web       # same, plus lcov reports per package
make coverage-sdk-ts    # one package at a time
```

Thresholds are 90% statements / lines / functions everywhere. Branch coverage
is held at 90% for `sdk/ts` and `svelte-auth` but 80% for `web/app`: the
Svelte compiler emits implicit branches for every `{#if}`, keyed `{#each}`,
and optional prop, so chasing that number buys assertions about generated
code rather than behaviour.

What these tests are for, concretely: the SDK suites pin **wire contracts** —
which verb, which path, and whether each field belongs in the body or the
query string. That is the defect class this project keeps hitting (`cert save`
puts `key_id` in the query; `sign` sends `backend` in both body and query;
`BackendCapabilities` is PascalCase on the wire), so those assertions earn
their keep. The view suites assert the request shape a screen sends and that
RBAC-gated controls are *absent*, not merely disabled.

## Playwright — mock tier (`web/app/e2e/`)

Hermetic and fast: it drives the real SPA in a real browser against
`page.route()` interception, so it needs a browser but no server.

```sh
make test-web-e2e
# or, from web/app:  npx playwright test
```

- `support/mockApi.ts` — the default response table, keyed by `METHOD pathname`.
- `support/mockAuth.ts` — seeds an authenticated session.

A note on that seeding, because it is not obvious: putting a token in
`localStorage` does **nothing**. The auth store only reaches `authenticated`
through a real login ceremony or the desktop bootstrap, and nothing calls
`validateSession()` on boot. The helper therefore injects a fake
`window.go.main.bridge` so the app's own `bootstrapDesktop()` calls the real
`setAuthenticated()` — using the seam that already exists rather than faking
storage or changing source.

Coverage: capability-gated login methods, nav RBAC/capability gating,
navigation across every authenticated route, representative mutations with
exact request-body assertions, and the 500 / 403 / rejected-mutation paths.

## Playwright — live tier (`test/integration/web/`)

The real thing: `run-server.sh` builds the SPA and an `xkmsd` with the `ui`
tag, boots it against `config.yaml`, and waits on `/health`. Passkey login
runs through Chrome's CDP virtual authenticator
(`tests/support/virtualAuthenticator.ts`, reused from the WebAuthn RP ceremony
suite), so registration and login exercise the real go-webauthn RP and issue
real tokens.

```sh
make integration-test-web
```

Run this in the devcontainer, per the project's integration-test policy —
never against a host you care about, since it boots a daemon and writes a
keystore.

### Known gap

`tests/auth.spec.ts` passes: a real registration ceremony and a real login
ceremony both round-trip against the live server. The key-lifecycle and
barrier/audit specs are currently **red for a server-side reason, not a test
defect** — after the first user registers, every tenant-scoped call 403s
because that user's tenant (`system`) has no entry in the barrier registry.
See the note in [parity.md](parity.md) and the tracking discussion; the specs
are written correctly and should pass once the tenant scoping is settled.
Until then `integration-test-web` is deliberately **not** part of the
`integration-test` aggregate, so the aggregate stays honest.
