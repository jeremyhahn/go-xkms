- **go-qrdb pinned to `v0.16.3-alpha`, and every in-tree `transport.RoleClient`
  now implements `ReconcileBuiltInRoles`** (#406). go-qrdb#354 added the method
  to the interface, which is a breaking change for every implementor: go-xkms
  stopped compiling against the current qrdb release, and because
  `pkg/acme/qrdb` is reachable from `sdk/go/acme`, so did every consumer that
  bumped qrdb (go-quicbaas#573). All four modules — root, `sdk/go`, `xkey`,
  `web/desktop` — move to `v0.16.3-alpha` together.

  The method is implemented, not stubbed. `pkg/qrdbrole` holds ONE
  implementation of qrdb's reconciliation semantics over the `RoleClient` seam
  — seed a built-in the tenant does not hold, replace a drifted one's
  permission set, leave a converged one completely alone (zero writes), repair
  Owner when present and never create it, and never touch a custom role — read
  from `qrdbsdk.BuiltInRoles` and `qrdbsdk.AllPermissions` so the definition is
  qrdb's rather than a copy. `pkg/acme/qrdb`'s `memoryRoleClient` and
  `pkg/testutil`'s `QRDBFakeTransport` delegate to it; the three narrow
  handler-test mocks report the verb as unexercised exactly as their sibling
  methods do.

- **`transport.UserNotFoundError` is populated per go-qrdb#343** in the
  in-memory user fakes (#406): `ID` carries the numeric id for an id lookup and
  `Lookup` carries the descriptor for a lookup by username, email or SPKI
  thumbprint, formatted through `transport.UserLookupKey`. The field became a
  `uint64` upstream, so the previous string assignment no longer compiled.

- **The absent-key characterization narrowed to Delete** (#406, #252).
  go-qrdb v0.16.3-alpha fixed `Exists` and `Get` for a key that was never
  written, so `storagetest.Config.AbsentKeyDivergence` — which asserted the
  wrong answer on purpose and was written to fail the day it became right —
  did. Both verbs are now held to the correct answer on every backend, and the
  flag is `AbsentDeleteDivergence`, covering the one verb still divergent.

- **`CompareAndDelete` is available from every embedded constructor**, and the
  characterization that recorded its absence is now a conformance test (#406).
  The `FastStateMachine` gained the guarded-delete opcode (go-qrdb#175), so the
  guarded path answers and nothing falls through to the transaction the
  embedded transport still does not wire. `PutIfAbsent` and `CompareAndSwap`
  are unaffected and remain unavailable (#61, #125). The availability note on
  `Backend.CompareAndDelete` was re-derived by measurement, which is what the
  characterization existed to force.
