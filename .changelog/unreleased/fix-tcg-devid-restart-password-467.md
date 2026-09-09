- **A device identity key's configured authValue survives a restart, and an
  IAK with one can be provisioned at all.** The cold-cache rebuilds
  `IDevIDAttributes()` and `IAKAttributes()` reconstructed the key from the
  TPM and configuration but never restored `idevid.password` /
  `iak.password`, so a key provisioned with an authValue signed in the
  process that provisioned it and answered `TPM_RC_BAD_AUTH` to every
  USER-role command from the next boot on. Separately, `CreateIAK`
  authorized the IAK's self-certification (`TPM2_CertifyCreation`) with the
  EK's password instead of the IAK's, invisible while both were empty and a
  provisioning failure the moment `iak.password` was set. The
  configuration-derived fields of both keys -- CN, key type, platform
  binding, signature algorithm and authValue -- are now assigned by one
  function on the provisioning and restart paths, so a fourth field cannot
  drift the way the CN (#337), PlatformPolicy and KeyType (#466) and the
  password did. The simulator harness also registers the simulator's close
  before provisioning can fail, so a failed harness reports its failure
  instead of hanging every later test on the simulator lock (#467).
