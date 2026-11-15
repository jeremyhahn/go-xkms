# 2183 narrowing: keep what main d55b1b73c needs to go green (CA rulings 654, 661)

Base: main d55b1b73c. Tip: d86d32331 (lane mf2183c). Range: `git log --reverse d55b1b73c..HEAD`.
The execution slice narrows by new commits on top of the tip: path-scoped
restores to main's content for every RESTORE row, then reduced re-applies for MINIMAL rows. History is
not rewritten. Every commit in the range appears exactly once in the table below.

Sources: commit messages, docs/plans/2541-webauthn-500.md (Integration cause),
docs/plans/8475-mcp-go-6911.md and 2042-devcontainer-steps.md (vuln), 2042-fold.md,
coverage-hang.md, 2042-shard-balance.md, go.mod diff, vuln.go.dev GO-2026-6911,
`go list -m -versions github.com/mark3labs/mcp-go`. I could not read the logs of main's run 43427982299
(no gh in the lane), so the failure lines below are the ones the plans quote.

## Table

| # | Group | Commits | Verdict | Reason / test / fold ref |
|---|-------|---------|---------|--------------------------|
| 1 | Devcontainer coverage memory | 0c7a9f129 8a420cc00 | KEEP | The Devcontainer job never got past `make coverage` on main (2042-devcontainer-steps.md: "lost runner or timeout"). |
| 2 | Coverage as 6 package shards + merge/threshold | 2e017c68f f223b19b9 4f5b94710 e414778b0 f052c43cd 0fc492bb6 ada2ebeb8 7439d864d 10edf189f 44842be75 b052dd261 | KEEP | Coverage job (#2042, DS-8139); buildgates tests come with it. |
| 3 | Runner routing for coverage/Integration (bigdisk, then hosted per DS-8215/ruling 442) | 50d466e5f 236fb9c82 18d8fd52d e182eb318 7f01d0e15 09760bd4a 04ba82d78 | KEEP | CI config; tests in buildgates. |
| 4 | deps-check bumps (all four modules) + go-jose v4.1.9 parse helpers + go.sum | c83763762 0f14ef8cf dcb2e5347 aa26ea370 3e9e12f5c 748cf6b7b 63545c422 2cdc6ba46 | KEEP | deps-check job (#2047); jose test aa26ea370 proves main's parsing behaviour on the new go-jose. |
| 5 | Merges (main, #2042, #2081, #2071, the coverage-hang, tpm2 and CORS branch merges) | 875927360 1beef4d3d 367f191a9 044221ec7 825ce6162 7b7815db5 be644c5e5 d0d0e5246 14c52484f | KEEP | No content of their own beyond conflict resolution; what they bring in is classified on its own row. |
| 6 | #2020/#1998 folds: GOMEMLIMIT 5GiB, -p=1, vitest localStorage under Node 25, sidecar cgroup, race-job bounds | 0a2777afb 7bf359619 c731cd755 709c5c2c4 285b309cf 27f482c16 f07a1dbac d001618ee d456e7a18 | KEEP | Race job and coverage memory on 8g hosted containers; web unit tests (vitest localStorage). Verdicts in 2042-fold.md. |
| 7 | Coverage shard P1, shard balance (extras-nofrost/extras-other), coverage hang, hosted 8g bound | f96b86b68 85f4f1b47 f9a92b831 b008fd850 b8fbc05ac f8f55c448 13f10336b 73e60895c da0c58c35 fb470b961 3e73d6740 2a42396b3 5cd5e27dd b5f449a89 589680363 5923ed0f2 6d6408da5 fa6a040bc 990d44601 128ddb741 783fa5ac3 b779ffbb7 | KEEP | Coverage shards finish within their timeout and memory (b5f449a89 shuts down test Servers: the hang). |
| 8 | CI triggers (ready_for_review, ci:full on the main-fix PR) | 3c237a208 37707a080 b7c781a36 390999778 | KEEP | CI config. |
| 9 | GO-2026-6911: own streamable HTTP transport, no cross-origin redirect | 756552ac1 d8bf196dd d1ea91990 34af8b06a fa900ccc9 a431edb36 | KEEP | `make vuln` (Devcontainer security step) fails on main: "GO-2026-6911 ... pkg/mcptool/client.go:280:53 mcptool.Client.Connect calls client.NewStreamableHttpClient". No mcp-go release fixes it: v1.5.0 is the newest release and the advisory says "introduced 0", with no fixed version (checked 2026-11-15). So ruling 661(3)'s bump does not apply and the custom transport stays. Test: pkg/mcptool/client_redirect_test.go. |
| 10 | Own transport correctness: response ID correlation, IDs compared by value, Close cancels in-flight requests, media type case | 52734e0cd af9249254 7b171d63d dc5a2fed7 c15438f1b 78d4d46ec 20e6fbf2d 61d59d40d | KEEP | Codex P1s on the kept transport (row 9); tests in streamable_test.go. The verify13 P1 on this code is listed under the P1s below. |
| 11 | server/discover session opening (MCP 2026-07-28, mcp-go v1.5) + 5 s probe | 21b4ef276 f9c6c3a38 49ad498c2 a3b05034b | MINIMAL (conditional) | Needed only if mcp-go v1.5 servers (the deps-check bump, row 4) refuse a bare initialize. Next slice: revert f9c6c3a38 and a3b05034b and run `make test-mcp`. If it is green, RESTORE them (an MCP protocol feature; no row) and drop the two tests. If it is red, keep them, with tests 21b4ef276 and 49ad498c2. |
| 12 | #2071 WebAuthn 500, smallest set: 500 logs its cause, user store on the service context, service principal's WebAuthn grant, refresh store on the service context, unified-surface CORS; plan docs | a4c2a9612 4a0d6ae71 29f0f3df3 a1ae1253a 2abe83769 ab7b379bd fab16e8f7 1e73974a4 e3c2649ae 24d80b212 807b27364 e08346e02 0c368f17e 5bd415978 3717b7d72 95edf01c0 95cd6b8c5 5d10e076e e94891abe | KEEP | Integration (webauthn-browser) fails on main with `ERROR webauthn: internal error error="get user by email: qrdb user lookup: qrdb/auth: unauthenticated: no valid credentials provided"` (2541-webauthn-500.md), then the grant and refresh-store layers. Ruling 661(1) set. The grant ends as amended by row 19 (no users:create). Tests: qrdb_userstore_callcontext_test.go, the grant test, the refresh store test, the CORS test, and the self-built module host over an enforcing node (the unified server the suites reach). |
| 13 | Host token path (#2071 Codex P1 1-2): NewHostServer CallContext, refresh resolver on the bound context, P1 notes | ea83da41a 955fc155e ded5754bb 81137d408 e7d3a3f3d 76f673f41 9c0ae765a | RESTORE -> #2202 | API module hosts (NewHostServer) are not in the Integration suites ("neither is in the six tests", 2541 plan). Fold ref: #2202. |
| 14 | Passkey account binding: BindUser on user_handle subjects, then OwnerSubject, then Metadata[passkey_handle] + auth.PolicySubject, with the vault/OIDC/policy callers moved to it | 24f183bce 5dc11b772 54628ea3a 5f1493028 a1e70591c fe35c0fe3 352d3d463 55258f6e8 c28b80cfc ac79fcf8f a6ecc4c2d 0b2546b74 e2ae675d8 | RESTORE -> #2202 (conditional, ruling 661(1)) | Identity work main did not need. Gate: after the restore, run integration/web key-lifecycle.spec.ts (a passkey session holding keys:create/sign/delete). If it goes red the way #2071's P1 (3) describes (roles never load for a handle subject), keep only the final form as MINIMAL: 54628ea3a's bind with a6ecc4c2d's PolicySubject and the callers e2ae675d8/352d3d463 need, tests 5dc11b772 and ac79fcf8f. Everything else stays RESTORE -> #2202. |
| 15 | Pin: go-qrdb + sdk v0.58.3, then v0.58.4 (CORS AllowCredentials seam); go-enclave v0.11 (replace dropped); build/vet drift | f5785a76f be325c303 cfbc5f559 664d23236 f4363db20 | KEEP | The deps state of row 4. It also removes the second GO-2026-6911 path: go-qrdb v0.51 sdk/go reaches mcp-go replica_forward.go, v0.58 sdk/go imports no mcp-go package (8475 plan, "Second path"). The ChangePassword part of cfbc5f559 is narrowed by row 24. |
| 16 | Pin runtime drift: tenant metadata CAS, authz grantor rule, nil node ctx, empty-passphrase creds, fixtures, localseal nil-safe destroy, xkey empty-password secret, fido2 codec tags, fido2 public-registration fixture | 58e859305 1e8913935 3b6099bc3 ddfb6038f 7d204e532 e0f1e6949 05ab3cb49 | MINIMAL | Forced by go-qrdb v0.58 / go-enclave v0.11. Tests: 1e8913935 (tenant-binding fixtures), ddfb6038f (localseal Unseal(nil)), 05ab3cb49 (fido2 ceremony), and the `make integration-test-fido2` build for e0f1e6949. Keep as is. |
| 17 | CORS under the pin: go-qrdb config.CORS wraps the unified server outside auth, request headers, allow_credentials, NodeCORS reads config only | 3164702b3 71ab0125b 881e2b84a 405fa8bad 63a93e886 9bddd2d23 19d86448e cb9977948 6e115429c | MINIMAL | The pin moves CORS into go-qrdb (config.CORS), so the CORS seam is set there. Webauthn-browser's cross-origin test needs it. Tests: 3164702b3, 405fa8bad, 9bddd2d23, cb9977948. |
| 18 | Tenant-scoped refresh recheck, refresh records with tenant, subject revocation by tenant, pre-tenant record match, PIV-only refresh, tenant-scoped WebAuthn user store, provisioned-tenant host | c995d4948 8ca7313bb 2184badf1 caba4649b 283e5c9d2 fcce24943 3a6e03f4c 8782d20b9 c0f22d541 4990d974b e0e9b3bd1 25d7a898f b514b8bf2 384e77da5 | RESTORE -> #2202 | Tenant scope belongs to qrdb on ruling 636's layering (qrdb owns users, invitations and tenant scope). Main does not need it: the suites run in the system tenant. Fold ref: #2202. |
| 19 | Ruling 602: WebAuthn grant without users:create; anonymous registration/begin answers 403 registration_refused | bbb1cdd43 9d464c079 c23e7fc43 7dfe87453 cee1dc93a | KEEP | Row 12's grant would otherwise open anonymous sign-up. Tests bbb1cdd43 and c23e7fc43. The Integration suites (row 20) assert the 403. |
| 20 | End-to-end suite rework: mTLS-admin bootstrap + unseal in TestMain, admin-provisioned account + invitation redemption in the browser suites, admin role for operators, key-lifecycle import fix, /health/ready poll | dd779a905 e1928204c 5a0aa02f2 2974b5e22 e607b607a | KEEP | Integration needs it once anonymous sign-up is refused (row 19). Only the system tenant is used. |
| 21 | Invitation redemption through the embedded node's user service | 679d81f30 99323744e | MINIMAL | e1928204c redeems an invitation, and over an enforcing node the node client refuses redemption's unauthenticated caller. Narrow it to invitations in the WebAuthn (system) tenant: refuse any other tenant's invitation before any lookup. Drop the non-system-tenant wiring and its test case (RESTORE -> #2202). Test: 679d81f30, system-tenant case only, plus the new test under the P1s below. |
| 22 | TPM2 seal/unseal serialization (sealMu) and Platform passwords resolved before the lock | c044aaf89 50974be8a a31bb404d c7867670c | MINIMAL | 50974be8a names go-enclave v0.11 conformance ("Protect/Unprotect safe for concurrent use", TPM_RC_VALUE on the salted session start), so the pin forces it and the RESTORE condition in the brief does not hold. Tests: seal_concurrency_simulator_test.go (c044aaf89) and a31bb404d. |
| 23 | xkey socket dirs (testsupport.SocketDir, sun_path) | f34e928c9 e50bf2627 | KEEP | xkey unit tests on a long TMPDIR runner ("bind/connect: invalid argument"). |
| 24 | PIN/barrier credential source, rewrap order, setup-wizard/SO/onboarding source records, Wails bindings, gofmt | 22ca6e423 d737fe546 e41ceae37 567bb59a7 795cefa01 fb2c76ea6 0066a3070 2c0033f6a af7c92deb 16cb4ea4c 92a1989fa d86d32331 | RESTORE -> #2098 | PIN credential lifecycle, a feature main did not need. Narrow to MINIMAL: keep only cfbc5f559's BarrierService.ChangePassword adaptation to go-enclave v0.11's current-credential argument, with main's semantics (ChangeUserPIN calls it as main did, passing the current PIN as the current credential). Keep 3b6099bc3 (row 16). Regenerate the Wails bindings to cfbc5f559's signature. Test: barrier_service_test.go as cfbc5f559 left it, plus `make` xkey unit tests. Fold ref: #2098. |

Commit count: 194 (every sha above appears once).

## verify13 P1s (ruling 661(2))

- pkg/xkms/servicer_invite.go:242 (cross-tenant enrolment by email). The flagged `BeginInviteRegistration(ctx, u.Email)` is already on main (since 4347233f4, 2026-09-29), so the defect is on main. On the narrowed tree the redemption is MINIMAL (row 21), so the code stays.
  - Next slice, test first: an invitation whose tenant is not the WebAuthn tenant is refused, and no passkey is enrolled on that tenant's account or on a same-email account in another tenant.
  - Fix: the tenant guard of row 21.
  - Tenant-scoped redemption itself goes to #2202.
- pkg/tpm2/seal.go:247 (a failed PlatformPassword unseal becomes empty authorization). The flagged line is in lockSeal (row 22, MINIMAL, kept). Line 247 is `secret := pp.Bytes()`, and PlatformPassword.Bytes swallows its unseal error.
  - The defect is on main: `func (p *PlatformPassword) Bytes()` at pkg/tpm2/password.go:134 is unchanged since 7b41da311. Main feeds it into the session auth at pkg/tpm2/session.go:726, :894 and :921 (`keyAuth = keyAttrs.Password.Bytes()`, both files unchanged by #2183).
  - Next slice, test first: a PlatformPassword whose backing unseal fails makes Seal/Unseal return that error, with no TPM command under empty auth.
  - Fix: lockSeal resolves through an error-returning read.
  - Main's other Bytes() callers route to the tpm2 row. The coordinator names it; no row number was given.
- pkg/mcptool/streamable.go:358 (ping requests dropped). The flagged code is the kept transport (rows 9-10), not on main.
  - Next slice, test first: a server-initiated `ping` request on the event stream gets an empty-result response with its ID.
  - Fix: answer ping in the transport's request dispatch.

## Main CI jobs on the narrowed tree

| Job | Failure on main (source) | Rows that make it green |
|-----|--------------------------|-------------------------|
| Devcontainer image (make coverage, make security, make deps-check) | Never passed `make coverage` (lost runner or timeout); `make vuln`: GO-2026-6911 via pkg/mcptool/client.go:280 and go-qrdb v0.51 replica_forward.go (2042-devcontainer-steps.md, 8475 plan) | 1, 2, 6, 7, 9, 15 |
| Coverage shards + threshold | Hang/timeout and memory (coverage-hang.md, 2042-hosted-coverage-memory.md) | 2, 3, 7, plus the new KEEP change below |
| Race | GOMEMLIMIT 10GiB in an 8g container; fido2/authenticator beside other packages (2042-fold.md) | 6 |
| Unit (web vitest) | jsdom localStorage under Node 25 (2042-fold.md) | 6 |
| deps-check | Direct dependencies behind (#2047) | 4, 15 |
| Integration (webauthn-browser, web, api) | The registration/begin 500 above, then the grant, refresh store and CORS layers (2541 plan) | 12, 16 (fido2 tags), 17, 19, 20, 21; 14 if its gate fails |
| Integration (tpm2: TestIntegration_PeerGate_QRDBNodeAdmitsOnlyAnAttestedPeer) | Red on #2183 16cb4ea4c; not among main's quoted failures, so I attribute it to the pin (see below) | 15, 22, plus a MINIMAL fix in the next slice |
| xkey unit | sun_path on a long TMPDIR | 23 |

- PeerGate test (ruling 661(4)): since d55b1b73c the only change to test/integration/tpm2 is cfbc5f559's compile drift for go-qrdb v0.58. None of main's quoted failures names it. So I attribute the failure to the go-qrdb pin (peer admission under v0.58), and it needs a MINIMAL fix in the next slice. This is inferred, not run: the target needs Docker (swtpm compose), which the lane does not have.
  - Next slice: read the failing assertion in 16cb4ea4c's Integration log first.
  - If it also fails on main's tree, route it to the tpm2 row instead.
- Coverage shard 1 timeout (ruling 661(4)): one KEEP change in the CI template's CUSTOMIZE region. Raise the coverage shard job's `timeout-minutes: 90` (.github/workflows/ci.yml:1312, "one sixth of the unit suite under -race") to 150, and raise the Makefile's per-shard timeout by the same amount. Add a buildgates test that pins the value.

## Next slice order

1. Make the restore commits for rows 13, 14, 18 and 24, plus the non-system part of 21 and the conditional rows 11 and 14 once their gates are run. Each takes main's content per path where a file is wholly RESTORE, or does a hand narrowing where a file mixes rows.
2. For each verify13 P1, commit the test, then the fix.
3. Make the coverage timeout change and the PeerGate fix.
4. Run the unit tests of the touched packages, `make integration-test-fido2`, `make test-mcp` and the xkey tests. Integration suites that need Docker go to CI.
