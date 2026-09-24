- **The ACME server's Replay-Nonce store is now the bounded, encrypted-counter
  `pkg/acme/nonce` service instead of an unbounded in-memory map.**
  `pkg/acme/server/handlers.RestService` (`service.go`) mints and redeems
  nonces through `pkg/acme/nonce.MultiService`, deleting `pkg/acme/common`'s
  `NonceStore`/`GenerateNonce` (and their tests) — the one remaining nonce
  implementation is the one that was already complete but unwired. A nonce
  flood no longer grows the store without limit: `Params.NonceMaxUsed`
  (`acme.nonce.max_used`, default `nonce.DefaultMaxUsed` = 65536) caps the
  redeemed-set per signing epoch, and `Params.NonceLifetime`
  (`acme.nonce.lifetime`, default 10m, matching the previous TTL) rotates to a
  fresh counter window on that schedule, retiring every nonce still
  outstanding from the epoch before — the wall-clock-lifetime substitute for
  a scheme with no per-nonce timestamp to expire (`RestService.mintNonce`,
  `currentNonceEpoch`, `rotateNonceEpoch`). Each epoch gets a prefix derived
  from the node identity, the shared key, and the epoch's own start time
  (`nonceEpochPrefix`), which is why the prefix must be unique per epoch:
  AES-GCM authenticates a nonce against the key alone, not against which
  epoch minted it, so a stale-epoch nonce falling back to the current epoch's
  identical prefix would decrypt cleanly and be checked against unrelated
  counter state instead of being rejected outright. Added
  `nonce.MultiService.SetLocal` (`pkg/acme/nonce/service.go`), the seam a
  rotation needs to swap the locally-minting service without leaking the
  retired epoch's registry entry. The node prefix
  (`Params.NoncePrefix`) is derived from `cluster.node_id`
  (`cmd/xkmsd/acme.go` `clusterNoncePrefix`) so nodes in a Raft cluster mint
  distinguishable nonces; the encryption key (`Params.NonceKey`) is **not**
  yet wired to any cluster-shared secret — no such secret was found already
  wired into xkmsd reachable from ACME server construction (the cluster CA's
  own key is asymmetric and not deterministically derivable across backends;
  the tpm-kek cluster seed exists only for that one key strategy; the CA
  object store is unwired for the primary CA) — so each node currently mints
  from its own randomly generated key, correct for the common single-node
  deployment and no worse than before for a load-balanced one: nonces still
  don't validate across nodes without sticky routing, and RFC 8555 clients
  already retry a `badNonce` with a fresh nonce. Tests: `pkg/acme/nonce`
  already covered replay/too-high/too-low/malformed/maxUsed-eviction at the
  package level; new `pkg/acme/server/handlers/nonce_wiring_test.go` and
  `pkg/acme/nonce/service_test.go` (`TestMultiService_SetLocal`) cover the
  wiring: single valid redemption, replay rejection, malformed rejection,
  foreign-prefix rejection, bounded memory under a flood, epoch rotation
  (including no double-rotation under concurrent access), and shared-key
  cross-node validation. `test/integration/rfc8555/rfc8555_6_5_test.go` and
  `rfc8555_7_2_test.go` were rewritten against `pkg/acme/nonce` in place of
  the deleted package.