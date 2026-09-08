- **IDevID and IAK keys are created to TCG "TPM 2.0 Keys for Device Identity
  and Attestation" v1.00 r12, Template H-0, with the specification's
  IDevID/IAK Key Policy as their `authPolicy`.** Previously `adminWithPolicy`
  was CLEAR and no policy was attached, so the key's authValue — empty on the
  default configuration — authorized *administration* of the device identity
  as well as use of it. Now `userWithAuth` and `adminWithPolicy` are both SET
  (§7.2.4): the authValue can sign, and only the Privacy Administrator, holding
  `endorsementAuth`, can certify the key or release a credential against it,
  through the §7.3.6.6 `PolicyOR` of PolicyUser, PolicyCertify,
  PolicyActivateCredential and PolicyDelegationNV. `TPM2_Certify` and
  `TPM2_ActivateCredential` on these keys now run under `DevIDAdminSession`,
  which authorizes exactly one command; the authValue is refused for them
  with `TPM_RC_AUTH_TYPE`. Every policy digest is computed through go-tpm's
  trial-policy calculator and pinned to the digests TCG publishes in
  Tables 14–19 (`devid_policy_test.go`). The specification is checked in
  under `docs/references/`.

  **This re-keys every IDevID and IAK.** `adminWithPolicy` and `authPolicy`
  are inputs to a primary key's derivation, so a device provisioned before
  this change holds identity keys that `CreateIDevID`/`CreateIAK` can no
  longer derive. The key-template change in this same release moves further
  derivation inputs, so the two share **one** upgrade note: see *Upgrade
  note* under "IDevID and IAK key creation templates now match TCG …" in
  `changed-tcg-devid-key-templates-1.md`. Re-provision once, for both.
  `ErrDevIDTemplateNonConformant` refuses, before `TPM2_CreatePrimary`, any
  template whose attributes or policy depart from Template H-0.

- **One naming rule for both device identity keys.** `DevIDCommonName`
  resolves an IDevID or IAK Common Name as: explicit `cn`, else the device's
  configured model and serial number as `model-serial` (the Platform Identity
  Information the TCG-CSR-IDEVID carries, §7.2.3 step 4a), else
  `ErrDevIDCNUnresolved`. The IAK previously took `iak.cn` verbatim and was
  left empty when unset, while the IDevID already derived `model-serial`;
  the two keys of one device could therefore be named by different logic.
  **Upgrade note:** an IAK provisioned with no `iak.cn` was stored under an
  empty name and is now named `<model>-<serial>`; artifacts written under the
  empty name are not found by the new name and must be re-imported or the
  device re-provisioned. A configured `iak.cn` is unaffected.

- **`store.FileBackend` refuses an empty Common Name (`ErrEmptyKeyCN`).**
  The storage key is the CN plus an extension, so an empty CN degenerated to
  the bare extension — `.key`, `.crt` — one slot shared by every nameless key
  in the backend, last writer wins. `Get`, `Save` and `Delete` now refuse
  rather than compose that key (#440).
