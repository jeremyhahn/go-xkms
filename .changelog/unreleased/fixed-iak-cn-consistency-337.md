- **The IAK CN no longer diverges between provisioning and restart: an
  unconfigured CN is empty on both paths instead of becoming
  `"default-device-id"` after a cold-cache rebuild** (#337).
  `pkg/tpm2/key.go`.

  `IAKAttributesFromConfig` — the path provisioning uses — assigns
  `config.IAK.CN` verbatim, but `IAKAttributes`' cold-cache rebuild (every
  fresh process attaching to an already-provisioned TPM) fabricated
  `"default-device-id"` when the configured CN was empty. The same TPM
  therefore described its IAK differently depending on whether the process
  provisioned it or attached to it, and certificate-store lookups keyed on
  the CN missed artifacts written at provisioning time. The fallback occurred
  exactly once in the repository, was documented nowhere, and provisioning
  never produced it — no artifact created by the normal path carries it, so
  removing it changes only the rebuild path's fabricated value. The rebuild
  now assigns `config.IAK.CN` verbatim, exactly as provisioning and the
  IDevID sibling do. No consumer requires a non-empty CN: the certificate
  store keys on whatever CN the attributes carry (consistent again), and
  `pkg/ca`'s `attestationBlobKey` already derives a stable key for an empty
  CN. Verified by `TestIAKAttributes_ColdCacheEmptyCNStaysEmpty`, which
  provisions, clears the cache, rebuilds from the simulator TPM and asserts
  the two paths agree (it fails against the removed fallback), alongside the
  existing configured-CN cold-cache test.

  Nothing about sealing or unsealing changes: `Seal` and `Unseal` default to
  the Platform SRK and the CN `platform-sealing-key`, never to the IAK
  attributes.

  Upgrade note, for a deployment that leaves `iak.cn` unset (no shipped
  configuration sets it): an IAK certificate or attestation blob that a
  *restarted* process wrote was stored under the fabricated
  `"default-device-id"`, while everything the provisioning process wrote was
  stored under the empty CN. The store was already split between the two.
  Both paths now use the provisioning value, so anything written under
  `"default-device-id"` is no longer found and must be re-imported or
  re-published.
