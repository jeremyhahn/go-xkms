- **The signed CRL is now a replicated artifact, so any go-xkms instance in a
  qrdb/Raft cluster can serve it, not just the one that most recently
  generated it** (#275). Revocation *state* (serial, reason, revokedAt) has
  been persisted through `CA.revocationStore` since the datastore-backed
  revocation store landed, and replicates under Raft — but the signed CRL
  *bytes* `GenerateCRL` produced were hard-coded to
  `certstore.compositeCertStore`'s in-memory cache, an unreplicated,
  per-process map. `POST /ca/crl` was consequently the only way to obtain a
  CRL at all, and it answered from whatever a single instance happened to
  have signed. `pkg/ca/crl_persistence.go` persists the CRL DER alongside its
  `Number`/`ThisUpdate`/`NextUpdate` as a sibling of the revocation records,
  keyed by the issuing certificate's Subject Key Identifier
  (`crl/<ski-hex>`), through the same `revocationStore` (preferred) /
  `objectStore` (legacy fallback) preference order `recordRevocation`
  already uses — so the artifact replicates exactly the way the state that
  produced it does, with no new storage wiring.

  A new `CA.CRL(ctx)` accessor returns the persisted DER, regenerating and
  persisting first only when none exists yet or the published `NextUpdate`
  has passed; `recordRevocation` also refreshes the CRL (best-effort) right
  after a successful revocation, so a client rarely observes staleness in
  practice. There is deliberately no leader election and no background
  scheduler: any instance may sign a refresh, staleness is detected and
  repaired on read, and `GenerateCRL` remains available as the explicit,
  always-regenerate force-refresh verb. `compositeCertStore.StoreCRL`/
  `GetCRL` stay as the in-memory hot-path cache `CA.CRL` checks before
  falling through to the persisted artifact, rather than a second, competing
  source of truth.

  `GET /ca/crl` (`application/pkix-crl`) is new and reads without forcing a
  signing operation; `POST /ca/crl` is unchanged in behavior but is now
  documented as the explicit force-regenerate verb. REST is the only CA
  transport that exposes a CRL read today — gRPC, QUIC, MCP, and the Unix
  socket transport carry only the generate verb, and none of them gained a
  new one here.

  Separately, `OCSPResponder.checkCertificateStatus`'s cold path (consulted
  when a serial is absent from the in-memory revocation map, e.g. a fresh
  process that has not reloaded state yet) only ever read `ca.objectStore`,
  never the preferred `ca.revocationStore` — so a CA configured with only the
  datastore-backed store, the common replicated configuration, silently fell
  back to always answering `ocsp.Good` on that path. `getRevocationBlob`
  gives both the OCSP responder and the CRL persistence layer the same
  store-preference read, closing that gap.

  Files: `pkg/ca/crl_persistence.go`, `pkg/ca/crl_persistence_test.go`,
  `pkg/ca/ca.go`, `pkg/ca/ca_extensions.go`, `pkg/ca/ocsp.go`,
  `pkg/ca/ocsp_revocationstore_test.go`, `pkg/ca/interface.go`,
  `pkg/ca/provider/provider.go`, `pkg/certstore/composite_certstore.go`,
  `pkg/api/rest/handlers_ca.go`, `pkg/api/rest/routes.go`,
  `pkg/xkms/servicer_ca.go`, `docs/ca/`. Verified by
  `go test ./pkg/ca/... ./pkg/certstore/... ./pkg/api/rest/...`: persist/read
  round trip across independent `*CA` instances sharing a backend,
  refresh-on-revoke incrementing the `Number` extension and including the new
  serial, regenerate-on-read past `NextUpdate` and not before it (via an
  injected clock), `GenerateCRL` forcing regeneration even when the published
  CRL is still fresh, `GET /ca/crl` returning `application/pkix-crl` and a
  404 for an unknown issuer, and the OCSP cold path answering from a
  revocation-store-only CA.
