# tpm-policies: branch and reference parity on every transport

Row: tpm-policies (docs/SPEC.md:131), epic #1443.

## Objective

The policy branch name, its reference value digests and the verify
reference must cross every transport unchanged, in both directions. Only
the REST server handler tests exercise them today; this slice adds the
same three cases to each client transport test and to the gRPC and MCP
server tests, and fixes any transport that drops a field.

## Cases

- A: update with branch.
- B: update with branch plus reference_values.
- C: verify reporting the reference.

## Matrix

| Test file | A | B | C |
|---|---|---|---|
| pkg/api/transport/rest | pass | pass | pass |
| pkg/api/transport/grpc | pass | pass | pass |
| pkg/api/transport/unix | pass | pass | pass |
| pkg/api/transport/mcp | pass | pass | pass |
| pkg/api/transport/quic | pass | pass | pass |
| pkg/api/grpc (server) | pass | pass | pass, results to follow (pkg/server/tpm_policy_simulator_test.go, simulator) |
| pkg/api/mcp (server) | pass | pass | open (see below) |

Cell values: pass (the test passed as written), fixed (a fix commit was
needed after the test commit), or open (not tested in this slice).

The client tests run against a mock that echoes the update request, so
every field must arrive and come back unchanged. The server tests run on
the offline policy service, which has no reference signer. They prove
that the update hands over the branch and the reference values, because
each combination draws a different answer from the service, the same
way the REST handler test does. No transport dropped a field.

Open: the server-side verify-reference cells need a branch updated from
a signed CoRIM. No test helper builds one for the offline service
(pkg/testutil/tpmpolicytest offers only NewOffline and Calls). The proto
conversion of the verify reference is tested in pkg/api/grpc/pbconv.
MCP renders the precondition class (no reference signer) as an internal
error (-32603, the class table in pkg/api/mcp/errors_shared.go), where
REST answers 409 and gRPC FailedPrecondition. That is the project-wide
mapping and is left as is.

The gRPC server verify cell is proved over the TPM simulator in
pkg/server/tpm_policy_simulator_test.go (lane stpmpb, plan
docs/plans/tpm-policies-verify-reference.md). The MCP server verify cell
stays open: pkg/api/mcp's tests have no simulator-backed XKMSService, and
MCP serves the same XKMSService call that test proves.

## Out of scope

Proto definitions, SPEC.md, ROADMAP.md, CI files and go.mod.
