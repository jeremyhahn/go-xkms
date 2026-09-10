# xkmsd Configuration — Architecture

> **Status: NORMATIVE** · Feature: `xkmsd-configuration` · Repo: `go-xkms` · Last verified: 2026-09-09

## The problem

An infrastructure decision — which host a listener binds, which port, what
address is advertised — must come from configuration, never from a literal in
the code. The company ruling of 2026-08-26 (handbook
`software/conventions/configuration.md` §3) makes every such value settable
through the configuration file, the environment and command-line flags,
resolved by viper under one precedence order, with a literal allowed only as
the value of the defaults layer.

Before this feature existed, `server.host` validated, loaded, and was then
ignored on the REST listen path; the library gRPC listener hardcoded the
wildcard and had no host field; nothing had a defaults layer; and the daemon
exposed no flag for any listener setting. Those are items 1–3 of the
remediation issue (go-xkms#140, cluster 1).

## Layers and precedence

```
flags  >  environment  >  file  >  defaults
```

| Layer | Where it lives | Mechanism |
|---|---|---|
| defaults | `config.Defaults()` (`pkg/config/load.go`) | rendered to a key map and registered with viper, so every key is known |
| file | the YAML at `--config` / `XKMS_CONFIG` | `viper.MergeConfig`, decoded with the struct's `yaml` tags |
| environment | `XKMS_<SECTION>_<KEY>` | `SetEnvPrefix("XKMS")` + `SetEnvKeyReplacer(".", "_")` + `AutomaticEnv`, plus a registered alias table for pre-viper names |
| flags | `xkmsd --host …` | applied only when the flag was set (`flag.Visit`, the standard-library form of `Changed()`) |

The first three layers resolve inside `config.Load`; the daemon applies the
flag layer on top of what `Load` returned. A flag's own default is never
written into the configuration — that is what lets `--host ""` (every
interface) still win over a file that pins a host, and what keeps an unset
flag from clobbering the environment.

### Why the defaults layer is a Config, not scattered constants

Registering `Defaults()` with viper is what makes the environment resolve a
key the file omits: viper only consults the environment for keys it knows.
One rendering of one struct keeps the defaults, the file keys and the
environment names from drifting apart.

### Why `server.host` defaults to empty

`DefaultServerHost` is the empty host. `net.JoinHostPort("", port)` renders
`:port`, which binds every interface, dual-stack. The alternative literal
`0.0.0.0` is IPv4-only and, because `server.host` also seeds the local
certificate SANs and the Raft Noise bind host, it would leak a wildcard into
places a wildcard must never appear.

## Data flow

```
xkmsd.yaml ─┐
XKMS_* ─────┼─► config.Load ─► *config.Config ─► serverFlags.apply ─► Server
Defaults() ─┘                                        (--host)          │
                                                                       ├─► buildRESTConfig ─► rest.Config.Host ─► net.JoinHostPort
                                                                       ├─► qrdb_node.go    ─► qcfg.Server.Host (unified API server)
                                                                       └─► metrics / MCP / Noise listeners
```

Every listener consumes `config.Server.Host`; none holds an address literal.
The library gRPC server (`pkg/api/grpc`) takes `ServerConfig.Host` from its
caller and binds `net.JoinHostPort(host, port)`.

## Legacy environment names

`applyEnvOverrides` in `pkg/config/config.go` is the pre-viper ladder of
legacy names (`XKMS_HOST`, `XKMS_REST_PORT`, …), each read through
`legacyEnv`. It runs after viper's unmarshal and sits in the same environment
layer. A legacy name applies only when non-empty and only when the key's
canonical name is absent, so the canonical name wins when both are set, and
an empty legacy variable in an old unit file changes nothing. Legacy names are
kept out of viper's bindings on purpose: with `AllowEmptyEnv` an empty
`XKMS_HOST` would otherwise clear a pinned host. Each name leaves the ladder
when its cluster is remediated and operators have moved to the canonical
form.

## Rejected alternatives

- **A mutation-guard test around the literal.** Detecting a reintroduced
  literal is a fence, not a fix; the ruling requires the configuration path
  to be correct.
- **`BindPFlag`.** A bound flag's zero value is indistinguishable from unset,
  so `--host ""` could not be expressed. `Changed()` semantics can.
- **Defaulting the host to `0.0.0.0`.** See above.
- **Converting all 66 legacy environment names in this slice.** Out of the
  cluster's scope and would exceed the reviewable diff budget; the table
  exists so each cluster converts its own.
