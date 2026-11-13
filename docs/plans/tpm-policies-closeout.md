# tpm-policies: row close-out (lane stpmpe)

## Objective

Close row tpm-policies (docs/SPEC.md:131, issue #1443): map every clause of
the row to the test that proves it, make the CLI integration command set
exercise named branches across xkmsd's transports, and run every package
the row touched on the branch tip.

## Clause map

| Clause | Proving test (file:line) | Tag |
|---|---|---|
| UpdatePolicy updates one branch from a signed CoRIM, no raw PCRs | pkg/tpm2/policy/reference_simulator_test.go:128 TestService_UpdateBranchFromReferenceValues; :174 TestService_UpdateBranchRefusals | tpm_simulator |
| NV-counter revocation | pkg/tpm2/policy/service_simulator_test.go:198 TestService_RevokeAndRestore | tpm_simulator |
| Re-approval without rekey | pkg/tpm2/policy/service_simulator_test.go:130 | tpm_simulator |
| verify reports the Reference on every transport | pkg/server/tpm_policy_simulator_test.go TestTPMPolicy_VerifyReportsReference; matrix in docs/plans/tpm-policies-transport-parity.md (every cell pass) | tpm_simulator |
| verify reports the Reference in xkmsctl | cmd/xkmsctl/tpm_policy_test.go TestTPMPolicyVerifyCmd | none |
| verify reports the Reference in xkey | xkey/cmd/xkey/cmd/tpm_policy_test.go TestTPMPolicyUpdate_FromReferenceValues | tpm_simulator |
| `.tpmpolicy` binding record | pkg/tpm2/policy_binding_record_simulator_test.go:46, :60 | tpm_simulator |
| Static resolver re-exported through sdk/go | sdk/go/tpmpolicy_test.go:27, :44 (surface sdk/go/tpmpolicy.go:91-94, :216-218) | none |
| Per-node records keyed `<node>/<tenant>/` | pkg/tpm2/policy/registry_test.go:167 TestRegistry_NodesOwnTheirRecords | none |
| Per-tenant TPM modes | pkg/tpm2/policy/registry_test.go:342 TestParseMode; pkg/tpm2/policy/service_failure_test.go:51 | none |
| go-quicbaas consumes the policies | out of this repo; the surface it uses is sdk/go/tpmpolicy.go | n/a |
| Named branches end to end through the CLI (integration) | test/integration/api/commands/commands.go PolicyCommands; runner_test.go TestPolicyCommandsCreateNamedBranches | integration (Docker, CI only) |

## Slices

1. Test commit: TestPolicyCommandsCreateNamedBranches (runner_test.go)
   requires tpm-policy-create to pass `--branch name=current;pcr=sha256:23`
   and `--branch name=next;pcr=sha256:23` (no `--pcrs`), and tpm-policy-verify
   to expect "Branch current: PCRs match, approved: true" and
   "Branch next: PCRs match, approved: true". Fails before slice 2.
2. Integration set: commands.go tpm-policy-create builds the two named
   branches; tpm-policy-verify expects both branch lines; tpm-policy-update
   keeps no --branch (it re-captures every branch).
3. Gate runs of ./pkg/api, ./pkg/tpm2/policy, the binding tests in
   ./pkg/tpm2, TestTPMPolicy in ./pkg/server and ./cmd/xkmsctl, sdk/go TPM,
   xkey TestTPMPolicy; go vet -tags integration ./test/integration/api/...;
   go build ./...; make lint.

## Why the signed-CoRIM update stays out of the integration set

test/integration/api/config.test.yaml configures no reference_signer, and a
committed signing key would fail the Releasability scrub. The signed-CoRIM
update over every transport is proved by pkg/server/tpm_policy_simulator_test.go
TestTPMPolicy_VerifyReportsReference.

## Out of scope

Proto definitions and generated code, docs/SPEC.md, config.test.yaml,
go-quicbaas (no cross-repo edit), pkg/tpm2/policy.

## Results

- TestPolicyCommandsCreateNamedBranches before the commands.go edit: fail (create passed --bank sha256 --pcrs 23; verify had no expected lines), as required.
- TestPolicyCommandsCreateNamedBranches after the edit: pass.
- go vet -tags integration ./test/integration/api/...: pass.
- ./pkg/api/transport/... ./pkg/api/rest/...: pass.
- ./pkg/api/grpc/... ./pkg/api/mcp/... ./pkg/api/unix/...: pass.
- ./pkg/api/apierrors/... tenantgate/... keyops_parity_test/... authz_consistency_test/...: pass.
- ./pkg/tpm2/policy/... (tpm_simulator): pass.
- ./pkg/tpm2 -run 'PolicyBinding|StaticPolicy|AuthorizedPolicy' (tpm_simulator): pass.
- ./pkg/server -run TestTPMPolicy (tpm_simulator): pass.
- ./cmd/xkmsctl -run TestTPMPolicy: pass.
- sdk/go -run TPM: pass.
- xkey ./cmd/xkey/cmd -run TestTPMPolicy (tpm_simulator): pass.
- go build ./...: pass.
- make lint: pass (0 issues in every module and tag set).

Row tpm-policies: all clauses proved; integration targets run in CI only (Docker)
