# #1608: close the verifier-appraisal-seam row

Objective: prove each claim of the SPEC row `verifier-appraisal-seam`
(docs/SPEC.md:138) against go-xkms code, then set it to `shipped` with
code citations. Docs only; no Go file changes.

## Claims and proof (1-based lines on the branch head)

| Claim | Proof (go-xkms file:line) | Holds |
|---|---|---|
| Appraisal code lives in `pkg/attestation/appraisal` | `Appraiser` verifier.go:242, `NewAppraiser` :262, `AppraiseQuote` :528, `AppraiseHost` host.go:146, `AppraiseContainer` container.go:74 | yes |
| Reference-values store is `NewStore` | store.go:82 (`PutReferenceValues` store.go:122; Appraiser verb verifier.go:369) | yes |
| SDK re-export | sdk/go/attestation_appraisal.go:40 `NewAttestationAppraiser`, :59 `NewAttestationAppraisalStore` | yes |
| Service layer serves it | pkg/xkms/servicer_attestation.go:32 `SetAttestationAppraiser`, verbs :51-:136 | yes |
| go-quicbaas re-exports them | docs/attestation-verifier/architecture.md:319-320 only; go-xkms cannot prove a go-quicbaas fact | recorded only |

## Blocker: SPEC row not edited

The lane's policy guard refuses any edit to docs/SPEC.md (protected path,
LANE_POLICY_ALLOW not set), although the brief allows this row. The row
stays `planned`. Proposed replacement for docs/SPEC.md:138, verified above:

| verifier-appraisal-seam | shipped | Seam with go-quicbaas (owner ruling 2026-10-18, CA m665). The go-quicbaas appraisal code and reference-values store moved into go-xkms `pkg/attestation/appraisal` (`docs/attestation-verifier/architecture.md:319`): the `Appraiser` (`verifier.go:242`, `NewAppraiser` `:262`) with `AppraiseQuote` (`verifier.go:528`), `AppraiseHost` (`host.go:146`) and `AppraiseContainer` (`container.go:74`), and the tenant-scoped endorsement and reference-values store `NewStore` (`store.go:82`). `XKMSService` serves it (`SetAttestationAppraiser`, `pkg/xkms/servicer_attestation.go:32`) and `sdk/go` re-exports it (`NewAttestationAppraiser`, `NewAttestationAppraisalStore`, `sdk/go/attestation_appraisal.go:40`, `:59`). go-quicbaas re-exports them, as go-xkms records only (`architecture.md:320`). Seams: receives from go-quicbaas. | none |

## Stale citations

- Fixed in architecture.md:322-344 (store.go, verifier.go, host.go,
  container.go lines).
- Left, stale (another row): SPEC.md:42 cites `verifier.go:252` (the
  `Appraiser` type is at :242) and `store.go:74` (`NewStore` is at :82).
- Not checked (outside the brief's range): architecture.md:380-383.

## Checks

- `make lint-gates`: fails in check-test-helpers (Makefile:4029), `go list`
  in xkey: go.sum checksum mismatch for go-luks2 v1.0.0-rc.4 (moved
  upstream tag); environmental, no Go/go.sum file changed here.
- `make lint`: actionlint passes; golangci-lint (.) fails at Makefile:4240,
  "context loading failed: no go files to analyze", the same module-load
  failure; no Go file changed here.

## Out of scope

Any Go file, any other SPEC row, ROADMAP.md, go-quicbaas code.
