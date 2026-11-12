# TPM policies: verify reports the reference end to end (lane stpmpb, #1443)

Row: tpm-policies (docs/SPEC.md:131). Builds on stpmpa (transport parity,
docs/plans/tpm-policies-transport-parity.md), which left the server-side
verify cells open: `tpmpolicytest.NewOffline` has no TPM and `VerifyPolicy`
reads the NV counter (pkg/tpm2/policy/service.go:483).

## Objective

Prove over the TPM simulator, through xkmsd's own wiring, that a branch
updated from a signed reference manifest is reported with its Reference by
`verify`, on the XKMSService and on the gRPC server.

## Slice (pkg/server/tpm_policy_simulator_test.go, tag tpm_simulator)

1. Server built from config: `backends.tpm2` on the simulator with
   `reference_signer.public_key` = PEM of a fresh P-256 key in t.TempDir();
   shared setup factored with `newTPMPolicyServer`.
2. Signed CoRIM from `appraisaltest.SignCoRIM` with a final value for PCR 23
   (final values need no event log; `attestation.PredictPCRs` takes them).
3. Create policy "boot" with branches "current" and "next" on PCR 23.
4. Update "next" from the CoRIM: the branch carries a Reference whose Digest
   is sha256 of the CoRIM; "current" carries none.
5. Verify through the XKMSService: "current" matches and is approved, no
   Reference; "next" mismatches on PCR 23, is approved and reports the same
   Reference.
6. The same update and verify through `grpcinternal.NewService(nil, nil, svc)`:
   the pb Reference digest equals the update's.
7. A CoRIM signed by a second key is refused on update through both paths;
   no branch gains a Reference.

If a Reference is dropped on a path, the fix goes in its own commit after the
failing test commit.

## MCP server verify cell: stays open

pkg/api/mcp's tests have no simulator-backed XKMSService, and the MCP tool
serves the same `XKMSService.TPMPolicyVerify` call this slice proves; the
MCP mapping of the Reference is covered by stpmpa's client-side parity tests.

## Out of scope

pkg/tpm2/policy, pkg/attestation, proto definitions, the MCP simulator
harness, CLI integration targets.

## Results

- TestTPMPolicy_VerifyReportsReference passes on the XKMSService and the
  gRPC server; no Reference was dropped, so no fix commit. The policy-level
  Match is false while "next" mismatches (it is the AND of the branches).
- go build ./..., unit tests of pkg/api/grpc, pkg/api/transport, pkg/api/mcp
  and pkg/tpm2/policy: pass. make lint: 0 issues (first run hit two missing
  shared GOCACHE entries, typecheck; rerun on a private GOCACHE was clean).
