# Host Embedding — User Guide

> **Status: NORMATIVE** · Feature: `host-embedding` · Repo: `go-xkms` · Last verified: 2026-09-29

For a developer embedding go-xkms in a daemon that hosts a go-qrdb node.

## Mount the full module

1. Initialize the XKMSService with your key backends
   (`xkmssdk.ServiceInitialize`).
2. Build the module with `xkmssdk.NewServiceModule`, passing a resolver for
   that service and one option per dependency you have (see
   [`api.md`](api.md) §"Go SDK").
3. Register it on your node with `qrdbsdk.WithModule`.

Supply only what you have. Each missing dependency turns off exactly the
features that need it, and the module logs one line per feature:

```
level=INFO msg="xkms feature off" module=xkms feature=policies reason="compose: policies is off: no PCR reader was supplied"
```

## Check what composed

After the first request, `module.HostStores()` returns the composition.
Inspect `Disabled` to report or alert on features that are off:

```go
for _, reason := range module.HostStores().Disabled {
    var off *xkmssdk.ServiceModuleFeatureDisabledError
    if errors.As(reason, &off) {
        log.Printf("xkms %s off: missing %s", off.Feature, off.Missing)
    }
}
```

## Keep or share the barrier

By default the module leaves `/api/v1/barrier/*`, `/api/v1/custodian/*`,
`/api/v1/shares/*` and `/api/v1/init/*` unregistered, so your daemon can serve
its own barrier on those paths. To let xkms serve them over your node's
barrier instead, add `xkmssdk.WithServiceModuleBarrierRoutes()` together with
the barrier registry and qrdb client options.

## Tenant passwords

A tenant user's Password Manager entries live behind that tenant's barrier.
The user opens the session with `POST /api/v1/password-vault/unlock`
(`{"user_pin": "..."}`), verified against the PIN backend you supplied.
Without `WithServiceModulePINBackend`, tenant stores cannot be unlocked.

The same option also mounts PIN management on your host: `/api/v1/pin/*`
(set, change and verify the SO and user PINs, read and reset the lockout).
Each route is permission-gated -- `pin:read` to verify a PIN or read the
lockout, `pin:write` to set, change or reset -- and, like the platform store
and policies, refuses a tenant-scoped caller.
