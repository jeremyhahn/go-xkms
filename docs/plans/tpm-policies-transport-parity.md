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
| pkg/api/transport/rest | todo | todo | todo |
| pkg/api/transport/grpc | todo | todo | todo |
| pkg/api/transport/unix | todo | todo | todo |
| pkg/api/transport/mcp | todo | todo | todo |
| pkg/api/transport/quic | todo | todo | todo |
| pkg/api/grpc (server) | todo | todo | todo |
| pkg/api/mcp (server) | todo | todo | todo |

Cell values: pass (the test passed as written) or fixed (a fix commit
was needed after the test commit).

## Out of scope

Proto definitions, SPEC.md, ROADMAP.md, CI files and go.mod.
