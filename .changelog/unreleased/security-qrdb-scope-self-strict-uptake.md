- **A system-tenant identity can no longer reach another tenant's escrow
  records.** The qrdb permission vocabulary xkms consumes gained a fourth
  scope, `ScopeSelfStrict`, which admits a request only when the caller's
  own tenant is the target tenant — for *every* identity, the system tenant
  included. The three existing scopes could not express that: `ScopeSelf`
  admits the caller's own tenant **or** a system-lifted identity acting
  across tenants, `ScopeCross` is system-only by design, and
  `ScopeTenantOnly` excludes the system tenant altogether, so the system
  tenant could not use it for its *own* data. Escrow therefore sat on
  `ScopeSelf` and inherited the system lift, which made a system
  administrator able to read any tenant's escrowed key material. Each
  tenant, including the system tenant, is its own boundary; a system
  administrator administers the system tenant, it does not impersonate the
  others. Taking go-qrdb v0.19.0-alpha activates the new scope — enforcement
  lives entirely in qrdb's permission layer, so no xkms call site changes.
  The bump is purely additive: the qrdb `sdk/go` exported surface went from
  2730 to 2731 declarations with zero removals.
