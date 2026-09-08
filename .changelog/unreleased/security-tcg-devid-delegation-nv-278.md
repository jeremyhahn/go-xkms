- **IDevID and IAK delegation through the TCG Policy NV Index, and
  `platform-policy` on an identity key now means what the specification says
  it means.** TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12
  §7.3 delegates use of a recoverable IDevID/IAK through a reserved NV index
  (§7.3.2: `0x01C90010`/`0x01C90018` for SHA256) whose Name is the fourth
  branch of the key policy. `DefineDevIDPolicyNV` defines that index to NV
  Policy Template I-0/I-1..I-3 under Owner authorization (§7.3.5),
  idempotently, and refuses with `ErrDevIDPolicyNVIndex` any index whose Name
  is not the specification's Table 18 — one attribute bit off can never
  delegate the key. `WriteDevIDDelegationPolicy` writes a Delegation Policy as
  a `TPMT_HA` (hash ID, then digest; §7.3.5 NOTE) under a
  `PolicySecret(TPM_RH_ENDORSEMENT)` session, so only the Privacy
  Administrator chooses it (§7.2.4). `DevIDDelegatedSession` satisfies a
  `DevIDDelegation`, executes `TPM2_PolicyAuthorizeNV` and completes the key
  policy's `PolicyOR`; the TPM refuses it whenever the index holds a different
  policy, and the TPM's response code stays in the error chain. The
  specification's example Delegation Policies (`DevIDSigningDelegation`,
  `DevIDAttestationDelegation`) are pinned to Table 20 in
  `devid_policy_test.go`; the simulator suite defines, writes, signs through
  the delegation, and proves a foreign index, a wrong authorization, a replaced
  policy and a moved platform are each refused.

  Previously `platform-policy: true` on an IDevID or IAK was ignored for the
  key's USER role (the key's policy is fixed by Template H-0, so a
  platform-policy session could never satisfy it). Now `CreateIDevID` and
  `CreateIAK` provision the key's Policy NV Index with
  `DevIDPlatformDelegation` — `TPM2_PolicyPCR` over the platform PCR in the
  key's nameAlg — and, for a key with no authValue, `CreateKeySession` hands
  out the delegated session, so signing stops when the platform state moves and
  resumes once the Privacy Administrator rewrites the delegation for the new
  state. The key and its certificates never change. A configured authValue is
  still used in preference (§7.2.4 keeps it as a USER path on Template H-0):
  making platform state the only path means an authValue nobody knows, which
  is the Owner's decision, not this library's. The IDevID signing path in
  `Sign` now takes its authorization from `CreateKeySession` like every other
  key instead of presenting the password directly.

  **Upgrade note:** no re-key. The default configuration sets
  `idevid.platform-policy`, so a device provisioned with it now defines and
  writes NV index `0x01C90010` (34 bytes) during provisioning; provisioning
  fails closed if the Owner or Endorsement authorization is refused. A device
  provisioned before this change is not touched: its IDevID keeps signing with
  its (empty) authValue exactly as before, and the index is defined and
  written only by re-provisioning or by the Owner calling
  `DefineDevIDPolicyNV` / `WriteDevIDDelegationPolicy` through the SDK.
