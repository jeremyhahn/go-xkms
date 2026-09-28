# Audit Log — CLI

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1115)

Binary: `xkmsctl`, group `audit` (`cmd/xkmsctl/audit.go`). One verb. Global
flags: [`../key-management/cli.md`](../key-management/cli.md).

## `xkmsctl audit query`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--actor` | string | `""` | filter by actor (the event's subject) |
| `--resource` | string | `""` | filter by resource type — `keys`, `certs`, `users`, … |
| `--action` | string | `""` | filter by action |
| `--outcome` | string | `""` | `allow` or `deny` |
| `--tenant` | string | `""` | filter by tenant ID; honoured only for a system-tenant caller holding `audit:read:cross`, otherwise the server uses your own tenant (see [api.md](api.md) §"Tenant scoping") |
| `--from` | string | `""` | events at or after this RFC 3339 timestamp |
| `--to` | string | `""` | events at or before this RFC 3339 timestamp |
| `--limit` | int | `0` | events per page; `0` uses the server default |
| `--cursor` | string | `""` | continue from a previous page's next cursor |
| `--all` | bool | `false` | page through everything |

## The query worth knowing

Start with denials. A log of successes tells you what worked; the denials tell
you what was attempted.

```
xkmsctl audit query --outcome deny --from 2026-08-18T00:00:00Z -o json
```

Then narrow:

```
xkmsctl audit query --actor alice --resource keys --outcome deny -o json
xkmsctl audit query --resource keys --action sign \
    --from 2026-08-18T00:00:00Z --to 2026-08-19T00:00:00Z --all -o json
xkmsctl audit query --tenant acme --outcome deny --limit 100
```

## Paging

An audit log is unbounded, so results are cursor-paged. Either follow the
cursor yourself:

```
xkmsctl audit query --resource keys --limit 100
xkmsctl audit query --resource keys --limit 100 --cursor "$NEXT"
```

or let the client do it with `--all` — which will fetch everything matching, so
bound it with `--from`/`--to` first.

## Timestamps are RFC 3339

`--from` and `--to` take RFC 3339, e.g. `2026-08-18T14:30:00Z`. A shell-friendly
form:

```
xkmsctl audit query --outcome deny --from "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"
```

## Exit codes

`0` on success, including when nothing matched — an empty result is an answer.
Non-zero on a malformed timestamp, an invalid cursor, or an RBAC denial (which
itself becomes an audit record).

## Parity coverage

**Defect: `audit query` has no `CommandDefinition` in
`test/integration/api/commands/commands.go`**, despite the route existing on
REST, gRPC, QUIC, Unix and MCP. It is a single verb with a well-defined filter
set — one of the cheapest gaps in the repo to close.
