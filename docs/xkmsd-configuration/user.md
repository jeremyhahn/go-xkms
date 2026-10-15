# xkmsd Configuration — User Guide

> **Status: NORMATIVE** · Feature: `xkmsd-configuration` · Repo: `go-xkms` · Last verified: 2026-09-28

## Where a setting comes from

A setting is resolved from four places. The highest one that says anything
wins:

1. a command-line flag you passed (`--host 10.0.0.5`)
2. an environment variable (`XKMS_SERVER_HOST=10.0.0.5`)
3. the configuration file (`server: {host: "10.0.0.5"}`)
4. the built-in default

A flag counts only when you pass it, so leaving `--host` off never undoes an
environment variable.

## Environment variable names

Take the key's path in the file, join it with underscores, uppercase it and
prefix `XKMS_`:

| File key | Variable |
|---|---|
| `server.host` | `XKMS_SERVER_HOST` |
| `server.rest_port` | `XKMS_SERVER_REST_PORT` |
| `server.grpc_port` | `XKMS_SERVER_GRPC_PORT` |
| `logging.level` | `XKMS_LOGGING_LEVEL` |

This works for every key in the file, whether or not your file mentions it;
a hyphen in a key becomes an underscore (`trust.server-url` →
`XKMS_TRUST_SERVER_URL`). An optional section such as `acme` or
`backends.awskms` comes into being when either the file or the environment
sets a key in it. `XKMS_<SECTION>_<KEY>` is the only name any key resolves
under — there is no legacy or pre-viper alias (see `configs/README.md`).

## Choosing the bind host

`server.host` is the address every network listener binds: REST (and HTTP/3
on the same port), gRPC, MCP, the metrics endpoint and the Noise bootstrap
listener. The embedded qrdb node's unified API server uses the same value.

- Leave it empty to listen on every interface, IPv4 and IPv6. This is the
  default.
- Set it to one address to listen only there, for example `127.0.0.1` for a
  host-local deployment or the machine's LAN address behind a firewall.

The shipped example pins `127.0.0.1`; open it up deliberately.

## Behind a reverse proxy

The REST login rate limiter (and the ACME request limiter) counts requests per
client IP address. By default that is the address of whoever opened the
connection, without the port, and the `X-Forwarded-For` / `X-Real-IP` headers
are ignored: any client can write those headers, so believing them would let a
client pick a fresh rate-limit bucket for every request.

When xkmsd sits behind a reverse proxy or load balancer, every request arrives
from the proxy's address, so all clients share one bucket. List the proxy in
`server.trusted_proxies` and the limiter takes the client from its forwarding
header instead:

```yaml
server:
  trusted_proxies:
    - 10.0.0.10        # one proxy
    - 10.20.0.0/16     # or a whole subnet of them
```

Only the right-most `X-Forwarded-For` entry that is not itself a trusted
proxy counts, which is the address your proxy saw. Anything a client put
further left is ignored. A value that is not an IP address or CIDR prefix stops
xkmsd at startup.

## A value that will not decode

If an environment variable or file value cannot be read as the field's type,
for example a port that is not a number, `xkmsd` refuses to start and names
the key. Fix the value; there is no fallback.

## Quoting

Quote values that look like numbers but are strings, such as a file
permission mode: `"0660"`. An unquoted `0660` is read as the number 432.

## Certificate names

The daemon issues its own TLS server certificate (a self-signed bootstrap one
until the CA composes, then a CA-issued one). Its subject alternative names
are entirely yours to set:

| Key | Variable | Adds |
|---|---|---|
| `tls.server_cn` | `XKMS_TLS_SERVER_CN` | the common name |
| `tls.extra_sans` | `XKMS_TLS_EXTRA_SANS` | aliases and addresses clients dial |
| `server.host` | `XKMS_SERVER_HOST` | the bind host, when it is a name or address |
| `tls.include_localhost_sans` | `XKMS_TLS_INCLUDE_LOCALHOST_SANS` | `localhost`, `127.0.0.1`, `::1` (default `true`) |

The cluster peers' hosts are always included. The machine hostname is covered
by the bootstrap certificate only; if clients dial a node by a name that is
not `server.host` or a peer host, list it in `tls.extra_sans`, because the
CA-issued certificate is shared by every node and carries no node-local
names. Set `tls.include_localhost_sans: false` on a node that must not
present loopback names; nothing else adds them. A certificate issued before a
change to any of these keys is reissued at the next start.
