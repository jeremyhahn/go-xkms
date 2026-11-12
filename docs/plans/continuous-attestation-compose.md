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
