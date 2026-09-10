- **The Go SDK aliases the failure-class parse error (#391).**
  `sdk/go` gains `PeerFailureClassError = peer.FailureClassError`, the typed
  error `PeerFailureClass.UnmarshalText` returns for a name that is not
  `none`, `absence` or `cryptographic`. A consumer that persists a verdict's
  class as text can now parse it back through the alias type's own method and
  `errors.As` the rejection, instead of reimplementing the mapping or
  importing `pkg/attestation/peer` across the layer boundary.
