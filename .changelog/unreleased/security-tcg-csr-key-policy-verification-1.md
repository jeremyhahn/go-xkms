- **A TCG-CSR-IDEVID whose keys are not TCG Template H-0 keys under the
  §7.3.6.6 IDevID/IAK Key Policy is refused.** The stateless verifier checked
  Restricted, fixedTPM, fixedParent and Sign. It now applies the whole rule the
  provisioning path applies before `TPM2_CreatePrimary`: decrypt CLEAR (§4.1,
  §4.2 "Not-decrypting"), `adminWithPolicy` SET (§7.2.4), and `authPolicy`
  equal to `DevIDKeyPolicyDigest(kind, nameAlg)`. §4 obliges the CA to verify
  "key Attributes and Policies"; a key administered by a policy the
  specification did not write is refused with
  `ErrDevIDTemplateNonConformant`.

  **Upgrade note:** this is the CA half of the re-key the IDevID/IAK key policy
  change already requires. A device provisioned before that change presents a
  public area with no `authPolicy` and is refused at enrollment; it must be
  re-provisioned. There is no separate migration.


  The CA checks the object attributes and the policy, and deliberately not the
  creation-only rules the provisioning path also applies — the §7.3.1 unique
  string and the H-1 through H-4 scheme, symmetric, exponent and kdf. §7.3.1
  fixes the unique field "at the time of key creation"; `TPM2_CreatePrimary`
  consumes it as derivation input and returns an `outPublic` whose unique field
  holds the generated public key, and `outPublic` is what a TCG-CSR-IDEVID
  carries. Demanding the string of a received public area would refuse every
  genuine device. `assertDevIDAttributesConformant` is the shared half, so the
  attribute and policy rules still have one definition.
