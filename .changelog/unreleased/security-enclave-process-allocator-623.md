- **Locked-memory allocations go through the process allocator, and a failed
  FIDO2 PIN-hash cache no longer keeps accepting the old PIN.** The sealed
  compare-and-delete guard (`pkg/storage/sealed`) and the `pkg/pintpm2`
  FIDO2 hash cache now allocate through go-enclave's
  `enclave.ProcessAllocator()`, so they respect the process's locked-memory
  budget. A refusal is a typed error (`ErrGuardEnclaveFailed`,
  `ErrFIDO2HashCacheFailed`) wrapping `ErrBudgetExhausted`,
  `ErrLockedMemoryUnavailable` or `ErrLimitDiscoveryFailed`.
  `cacheFIDO2Hash` used to discard its allocation error. After a
  `ChangeUserPIN` whose new-hash allocation failed, the old PIN's hash stayed
  cached, so `VerifyFIDO2Hash` accepted a PIN the TPM no longer held. The old
  hash is now dropped, and `SetUserPIN`, `ChangeUserPIN` and `VerifyUserPIN`
  return the typed error. The TPM's decision still stands. (go-xkms#623,
  #981)
