- **A partial RP policy write silently cleared the SO's UV, attestation,
  enterprise and block settings, and concurrent policy writers silently lost
  updates** (#321, #326). `xkey/pkg/authenticator/rp_policy.go`,
  `rp_policy_update.go` (new), `rp_policy_entity.go`,
  `dao_rp_policy_store.go`, `rp_policy_memory.go`, `rp_policy_backend.go`,
  `cmd_config.go`, `xkey/cmd/xkey/cmd/fido2_policy.go`.

  `RPPolicyStore.SetPolicy` replaces the whole record, and both partial-field
  callers — the CTAP `SetRPPolicy` vendor command and `xkey fido2 policy set`
  — built the record from only the fields the request carried. Changing one
  setting cleared every other one to its **permissive** zero value:
  `UVOverride: "required"` reverted to "use the RP's request", the forced
  attestation override vanished, and an RP block was lifted by any write that
  omitted `blocked`. The wire could always express presence (the CBOR map's
  key set, cobra's `Changed`); the domain type discarded it.

  Presence now has a home of its own: `RPPolicyUpdate` carries a pointer per
  field (nil = leave stored value unchanged, pointer-to-zero = explicit
  clear), and `RPPolicyStore.UpdatePolicy` applies it onto the freshly-read
  stored record in every store implementation. The stored `RPPolicy` and
  every enforcement read stay plain, non-pointer values — no new nil checks
  on the block-enforcement path. Both partial-field callers now build an
  `RPPolicyUpdate` from the presence they observe while decoding; `SetPolicy`
  remains the full-record replace used by migration and the GUI's
  fully-populated policy form.

  The read-modify-write is also no longer a racy Get-then-Save (#326):
  `RPPolicyEntity` implements the DAO's `Versioned` contract, every save goes
  through `SaveWithCondition` guarded on the observed version with a bounded
  retry, and a writer that loses every retry receives the typed
  `ErrRPPolicyConflict` instead of reporting success over a lost update.
  Because the pinned SDK documents `SaveWithCondition` as a read followed by
  a write rather than an atomic CAS, the store additionally serializes its
  own writers on a mutex — the version condition catches writers using a
  separate store instance over the same records.

  Verified by regression tests that fail with the defect re-introduced: a
  two-key CBOR vendor request and a `--blocked`-only CLI invocation against a
  populated RP preserve every other field; blocking an RP survives unrelated
  writes; an explicit `blocked=false` still unblocks; two concurrent
  updaters carrying different fields both land under `-race` (100
  iterations); and a writer that keeps losing the version race gets
  `ErrRPPolicyConflict` after exactly the bounded number of re-reads.
