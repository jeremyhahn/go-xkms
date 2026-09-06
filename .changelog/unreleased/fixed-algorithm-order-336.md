- **The algorithm string the REST, MCP and gRPC transports display now
  resolves the key's family in the same order as `KeyAttributes.ID()`**
  (#336). Presentation-only: `getAlgorithmString` was a pure formatter, could
  not address or route a key, and no production path builds the two-family
  descriptor that would expose the divergence — but it was a third resolution
  order (`SymmetricAlgorithm` before `KeyAlgorithm`, the opposite of `ID()`),
  and #158 exists precisely because contradictory family resolution silently
  picks sides. The three identical per-transport copies are deleted and
  replaced by one canonical `KeyAttributes.AlgorithmString()` in `pkg/types`,
  directly below `ID()` and mirroring its switch arm for arm (X25519, quantum,
  asymmetric, symmetric); as a side effect X25519 and quantum keys now display
  their family instead of an empty string. `pkg/types/types.go`,
  `pkg/api/rest/handlers.go`, `pkg/api/mcp/{handlers,utils}.go`,
  `pkg/api/grpc/service.go`, `docs/key-management/engineering.md`. The two
  tests that pinned the divergent order now compute their expected value from
  `ID()` itself, and a property test in `pkg/types` iterates two-family
  descriptors asserting `AlgorithmString()` agrees with `ID()`'s family, so a
  fourth order cannot reappear silently.
