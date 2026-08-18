# Audit Log — User Guide

> **Status: NORMATIVE** · Feature: `audit-log` · Repo: `go-xkms` · Last verified: 2026-08-19

## What is recorded

Every audited operation produces one record:

| Field | Meaning |
|---|---|
| `timestamp` | when |
| `subject` | who |
| `action` | what they did |
| `resource` | what kind of thing — `keys`, `certs`, `users`, … |
| `resource_id` | which one |
| `outcome` | `allow` or `deny` |
| `details` | extra context |

**Refused operations are recorded too.** That is the part people forget, and it
is the part that matters after an incident.

## Start with denials

```
xkmsctl audit query --outcome deny --from 2026-08-18T00:00:00Z -o json
```

A log of successes tells you what worked. The denials tell you what someone
tried.

## Narrowing down

```
# one person
xkmsctl audit query --actor alice --from 2026-08-18T00:00:00Z

# one kind of thing
xkmsctl audit query --resource keys --action sign

# one tenant
xkmsctl audit query --tenant acme --outcome deny

# a window
xkmsctl audit query --resource certs \
    --from 2026-08-18T00:00:00Z --to 2026-08-19T00:00:00Z
```

Timestamps are RFC 3339. A useful shell form:

```
xkmsctl audit query --outcome deny \
    --from "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"
```

## Paging

The log is unbounded, so results come back a page at a time with a cursor:

```
xkmsctl audit query --resource keys --limit 100
xkmsctl audit query --resource keys --limit 100 --cursor "$NEXT"
```

`--all` follows the cursors for you — bound the query with `--from`/`--to`
first, or you will ask for the entire history.

## Where the records live

Your deployment uses one of three backends, and the difference matters:

- **Chained file** — on local disk, each record chained to the one before it.
  Tamper-evident: altering history breaks the chain. Single host.
- **qrdb** — durable, queryable, replicated with the database. This is what
  `audit query` reads.
- **None** — auditing is disabled. If `audit query` returns 404 rather than an
  empty result, that is what you are looking at.

## Retention is yours

Nothing here expires or prunes records. That is deliberate — a KMS that quietly
discarded audit history after N days would be worse than one that grows — but it
does mean archival and retention are your operational responsibility.

## Two things not to do

**Do not treat an empty result as an error.** "Nothing matched" is a real
answer, and often the one you wanted.

**Do not put secrets in the details of anything you build on top of this.** The
`details` field reaches durable, queryable, exportable storage. Anything written
there should be considered published.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| 404 from `audit query` | auditing is not configured on this server | server-side configuration |
| empty results | nothing matched | widen the window or drop a filter |
| "invalid timestamp" | not RFC 3339 | `2026-08-18T14:30:00Z` |
| "invalid cursor" | the cursor is stale or from another query | start the query again |
| permission denied | you do not hold `audit:read` | and your attempt is now itself in the log |
| the query takes a long time | unbounded range | add `--from` and `--to` |
| an operation you know happened is not in the log | it may not be an audited path | worth reporting — a missing audit call is a defect |

## Where to go next

- Who is allowed to do what: [`../auth-factors/user.md`](../auth-factors/user.md)
- Barrier events, the highest-value records: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- Certificate issuance and revocation: [`../certificate-authority/user.md`](../certificate-authority/user.md)
