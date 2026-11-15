# Continuous attestation: compose and xkmsd wiring of the verdict store

Row: continuous-attestation (docs/SPEC.md:81), epic #2088, slice 5.

## Gap

Slices 1-4 added the engine and verdict store (pkg/attestation/continuous),
the servicer verbs (`ListAttestationVerdicts`, `GetLatestAttestationVerdict`,
`ReattestDevice`) and every transport, client and sdk/go alias. Nothing calls
`SetContinuousAttestation`, so xkmsd and every embedding host answer
`ErrNotConfigured` for all three verbs.

## Store-only wiring

- pkg/compose: `FeatureVerdicts`, `BuildVerdictStore(daos)`, a
  `Stores.Verdicts` field built whenever the DAO factory is supplied,
  `appraisal.DatabaseName` in `Databases`, and `Wire` calling
  `SetContinuousAttestation(nil, store)`.
- pkg/server `composedStores`: builds the verdict store on the datastore's
  `attestation` database; a failure logs a warning, the server still starts.

List and latest are then served from persisted verdicts; `ReattestDevice`
keeps answering `ErrNotConfigured`.

## Blocked (out of scope)

The engine. `continuous.NewEngine` needs a production `EvidenceSource` (none
exists in go-xkms), an appraiser wired in xkmsd (xkmsd never calls
`SetAttestationAppraiser`) and a device `Inventory`.

Open for the row, named in docs/SPEC.md (row set to `in progress` after
slice 5): a production `EvidenceSource` (device quote collection, the
go-trusted-platform side) and an `Inventory` implementation (the device
registry, row #2093). Until both exist xkmsd does not start the engine.

## Tests

- `TestBuildVerdictStore`: memory factory, nil factory, unavailable factory.
- `TestBuild_VerdictsNeedTheDAOFactory`: disabled without DAOs, built with them.
- `TestWire_ServesStoredVerdictsWithoutEngine`: list not configured before
  Wire, served after; re-attest still not configured.
- `TestDatabases_FollowTheSuppliedDependencies`: `appraisal.DatabaseName` always.

## Checks

- go test -race (codec tags) ./pkg/compose/
- go test -race (codec tags) ./pkg/server/
- go build ./... (root) and sdk/go
- make lint

## Results

- go test -race (codec tags) ./pkg/compose/: ok.
- go test -race (codec tags) ./pkg/server/: ok.
- go build ./... (root): ok.
- go build ./... (sdk/go): ok.
- make lint: 0 issues on every module and tag set.

Departure: `TestBuild_NoDependenciesLeavesEveryFeatureOffWithTypedReasons`
(pkg/compose/restored_test.go) lists every feature's reason, so it gained
`FeatureVerdicts` in the feat commit. In pkg/server the store build is a
small `verdictStore` helper called from `composedStores`.

Fix (lane row2088c): lane-verify gate 10 failed on
`TestModule_HostMount_MissingDependenciesAreTypedAndOff`
(pkg/apimodule/module_host_stores_test.go), which lists every feature
off without its dependency. Commit 9713d2bd3 adds
`FeatureVerdicts: "DAO factory"` to its expected map; no other
pkg/apimodule test lists the off features.
`go test (codec tags) ./pkg/apimodule/`: ok.

## Codex findings on row2088c (lane row2088d)

1. Replayed nonce: 14b4947f6 adds
   `TestEngine_ReplayedQuoteWithOldNonceIsUnverified` (real appraiser; the
   source replays its first signed quote and old nonce). It passes on the
   code, so it guards a regression. By hand: with engine.go's
   `issued.Nonce = nonce` removed the replay is verified and the test
   fails; engine.go restored, never committed.
2. History duplicates: test ced48cf32 (bounded in 5aae09d89) fails on the
   old store; fix 265400184 de-duplicates by verdict ID in ListVerdicts.
   go-qrdb v0.51.0-alpha gap: ForEachPage has no shared snapshot and the
   GenericDAO has no snapshot or cursor iteration; pin unchanged.
3. SDK verbs: test 09ca21119 (sdk.New and sdk.NewEmbedded); fix 82ebc1de2
   composes the verdict interfaces into transport.Client and XKMSServicer,
   adds embedded forwarding and sdk/go type aliases, updates the doubles;
   3f3902298 updates the xkey doubles.
4. SPEC row wording (docs/SPEC.md:81) waits on the owner; not edited.
