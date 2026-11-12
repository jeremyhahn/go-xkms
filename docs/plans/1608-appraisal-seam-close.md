# #1608: close the verifier-appraisal-seam row

Objective: prove each claim of the SPEC row `verifier-appraisal-seam`
(docs/SPEC.md:138) against go-xkms code, then set it to `shipped` with
code citations. Docs only; no Go file changes.

## Claims and proof

| Claim | Proof (go-xkms file:line) | Holds |
|---|---|---|
| Appraisal code lives in `pkg/attestation/appraisal` | pending | pending |
| Reference-values store is `NewStore` | pending | pending |
| SDK re-export | pending | pending |
| Service layer serves it | pending | pending |
| go-quicbaas re-exports them | not provable from go-xkms | recorded only |

## Checks

- pending

## Out of scope

Any Go file, any other SPEC row, ROADMAP.md, go-quicbaas code.
