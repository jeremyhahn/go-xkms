# tpm-policies: verify reports the reference over the MCP server and in xkey and xkmsctl

Row: tpm-policies (docs/SPEC.md:131), issue #1443. Lane stpmpd, building on
stpmpa (transport parity), stpmpb (verify Reference over xkmsd, XKMSService
and gRPC) and stpmpc (matrix and results).

## Objective

Close the last open transport cell of the parity matrix, the MCP server
verify cell, and assert the Reference line both CLIs print on verify.

## Slices

1. MCP server cell over the TPM simulator (pkg/server/tpm_policy_simulator_test.go,
   TestTPMPolicy_VerifyReportsReference):
   - `mcp.NewServer` on the same simulator-backed XKMSService, no-op authenticator.
   - `InvokeMethod("tpm.policy.update")` with the forged CoRIM is refused as a
     `*mcp.KeyOpError`.
   - `InvokeMethod("tpm.policy.update")` with the signed CoRIM on branch "next",
     then `InvokeMethod("tpm.policy.verify")`; the result goes through JSON into
     `transport.TPMPolicyVerifyResponse`: "current" matches with no Reference,
     "next" is approved, mismatches the policy PCR and carries the Reference
     digest.
2. xkmsctl: TestTPMPolicyVerifyCmd gains a case whose branch carries a Reference
   and asserts "Reference: boot-image-v2 signed by Example Provider, sha256 abcd".
3. xkey: TestTPMPolicyUpdate_FromReferenceValues runs verify after the branch
   update and asserts "  Reference: (no id), sha256 <digest>".
4. Docs: the parity matrix MCP server verify cell and the verify-reference
   plan's MCP section point here; results below.

A dropped Reference found by these tests gets its own fix commit after the
failing test commit.

## Out of scope

Proto definitions, docs/SPEC.md, the GUI view.

## Results

- Simulator test, `-tags "codec_cbor codec_json codec_msgpack tpm_simulator" -run TestTPMPolicy ./pkg/server/`: pass (MCP server cell: pass).
- xkmsctl, `-run TestTPMPolicy ./cmd/xkmsctl/`: pass.
- xkey, `-run TestTPMPolicy ./cmd/xkey/cmd/`: failed on the Reference line (the fake dropped the Reference on verify); fixed in xkey/internal/tpmpolicyfake/fake.go, then pass.
- `go build ./...`: pass.
- `go test ./pkg/api/mcp/... ./pkg/api/grpc/...`: pass.
- `make lint`: pass (0 issues on every module and tag set).
