- **`FactoryReset` now evicts an IAK at 0x81010002 and still preserves
  manufacturer EKs.** 0x81010002 is the TCG ECC EK address, and it is also
  this package's default IAK handle (`IAKConfig.Handle`). `factoryResetInternal`
  used to preserve both TCG EK addresses unconditionally, so an IAK there
  survived every reset. Both TCG EK addresses and the configured
  `Config.EK.Handle` are still preserved. The one exception: a TCG EK address
  that this package's own configuration places a key at (the IAK, IDevID or
  Platform SRK) is now evicted (`ownedPersistentHandles`,
  `pkg/tpm2/provision.go`). A foreign object at 0x81010002, such as a
  manufacturer ECC EK beside a configured RSA EK, is still preserved. Tests:
  `TestFactoryReset_IAKAtLegacyECCHandle_Evicted` and
  `TestFactoryReset_ForeignObjectAtTCGECCEKHandle_Preserved`
  (`pkg/tpm2/provision_test.go`). go-xkms#798.
