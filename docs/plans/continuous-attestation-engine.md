# Continuous attestation engine (row continuous-attestation, docs/SPEC.md:81, epic #2088)

## Objective

xkms re-attests enrolled devices on a schedule and on demand and publishes the
verdict. The outcomes (admit, quarantine, remediate, disconnect) belong to the
consumer above xkms; nothing in this package imports or names it.

## Slice 1 (this slice): library engine in pkg/attestation/continuous

Types:

- `EvidenceSource` — `Collect(ctx, tenant, deviceID string, nonce []byte) (*appraisal.AppraiseQuoteRequest, error)`.
- `Appraiser` — the subset of `*appraisal.Appraiser` the engine calls (`AppraiseQuote`).
- `Verdict{Tenant, DeviceID, Result *appraisal.AttestationResult, Verified bool, At time.Time, Cause string}`.
- `Publisher` — `Publish(ctx, Verdict)`.
- `Store` — tenant-scoped qrdb DAO collection (the appraisal Store pattern) with
  `SaveVerdict`, `LatestVerdict`, `ListVerdicts`.
- `Engine` — `Reattest(ctx, tenant, deviceID)` on demand; `Run(ctx)` scheduled:
  every enrolled device of every registered tenant once per `Interval`, driven
  by an injected ticker, never a sleep. A fresh random nonce per run. A failed
  `Collect` or appraisal is a verdict with `Verified=false` and a cause, never a
  silent skip.

Checks (tests, committed before the feat commit):

1. On-demand pass and fail verdicts from appraisaltest fixtures.
2. Nonce freshness: two runs, two different nonces.
3. A Collect error recorded as an unverified verdict with a cause.
4. Tenant isolation of the verdict store.
5. Scheduled pass driven by a fake ticker visits each device once per tick.
6. A Publisher receives each verdict.

## Later slices (out of scope here)

- Wiring to a transport / service verb and to real evidence sources.
- Retention and pruning of old verdicts.

## Results to follow

(one line per run of the gates)
