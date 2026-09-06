- **`CreateIDevID` no longer carries a guard that could set `adminWithPolicy`
  on a key with no `authPolicy`, and now refuses to create one that would**
  (#278). `pkg/tpm2/key.go`, `pkg/tpm2/types.go`, `pkg/tpm2/tpm.go`. With
  `adminWithPolicy` SET the TPM authorizes ADMIN-role commands only through a
  policy session satisfying the object's `authPolicy` and refuses the auth
  value with `TPM_RC_AUTH_TYPE` (TCG TPM 2.0 Library Part 1, section 19.6); an
  empty `authPolicy` is satisfiable by no session, because a session's policy
  digest starts at zero and can never equal a zero-length value. The pair
  therefore closes the ADMIN role — `TPM2_Certify`, which `CreateIDevID`
  itself issues — permanently, and cannot be undone afterwards, since the
  attribute is an input to a primary key's derivation. The guard that set it
  (`idevidAttrs.Password == nil && idevidAttrs.PlatformPolicy`) never ran:
  `CreateIDevID` builds those attributes from `IDevIDAttributesFromConfig`
  alone, which sets `Password` from `types.NewPassword`, and that constructor
  documents that it never returns nil — so **no created key changes and no
  deployed device identity is re-keyed**. Per TCG section 3.10 the attribute
  is mandatory only for applications administering a key by policy alone, and
  the platform policy cannot serve: it is a `PolicyOR` of `PolicyPCR` and
  `PolicyAuthValue` built for USER-role signing and unsealing, carrying no
  `TPM2_PolicyCommandCode` term, without which no session can authorize an
  ADMIN-role command. The dead guard is replaced by `assertAdminAuthorizable`,
  which runs on the selected template before `TPM2_CreatePrimary` and returns
  the new `ErrAdminWithPolicyNoAuthPolicy` rather than minting an
  unadministrable key — so the obvious tightening of the dead predicate now
  fails loudly at provisioning instead of bricking the ADMIN role of every
  device it touches. A stale comment in `Sign` that described the attribute as
  set is corrected. Verified on the TPM simulator: a `platform-policy: true`
  IDevID is read back from its persistent handle with `adminWithPolicy` CLEAR
  and an empty `authPolicy`, and a `TPM2_Certify` against it under password
  auth succeeds, proving the ADMIN role is reachable; reviving a live guard
  makes the same test fail with `TPM_RC_AUTH_TYPE`.
