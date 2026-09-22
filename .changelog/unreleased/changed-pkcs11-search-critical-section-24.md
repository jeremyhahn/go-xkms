- **A pooled PKCS#11 session's object search is now one critical section per
  session handle (#24, #107).** `SessionPool` (`session_pool.go`) gains
  `WithSearch`, which runs `FindObjectsInit` / `FindObjects` /
  `FindObjectsFinal` under a lock keyed by the session handle, so a second
  search on the same handle can never start while an earlier one on that
  handle is still open — serialized per handle rather than across the whole
  pool, and with the same panic-safety `discardAndReplace` already gives
  `WithSession` (#107). The three search sites in
  `pkg/storage/hardware/pkcs11_cert_storage.go` (`ListCerts`,
  `findCertificateHandle`, `findChainMemberHandles`) route through it via a
  new optional `PKCS11SearchProvider` interface, following the same
  optional-interface pattern `PKCS11SOSessionProvider` already uses. The
  equivalent pooled-session searches in `pkg/backend/pkcs11`
  (`Backend.FindSecretKey`, `findKeyPairByID`, `findRSASigner`,
  `findECDSASigner`) — the sites `golangci-lint` flagged for a discarded
  `FindObjectsFinal` return — now go through the same lock via a new
  `SessionPool.FindObjectHandle` helper instead of hand-rolling the
  Init/Find/Final sequence. This closes a real, if narrow, defect: two
  sequential borrowers of the same handle could previously have their
  searches overlap if a caller's own `Init`/`Final` pairing were not
  perfectly scoped. **It does not resolve #24's `CertificateRenewal` flake.**
  Scored interleaved, run-by-run, against apt SoftHSM 2.6.1 in the
  devcontainer (300 iterations per tree, same host load): fixed tree 13/300
  (4.3%) vs. unfixed tree 18/300 (6.0%), z = 0.92 — not statistically
  significant, and both trees still fail overwhelmingly with
  `CKR_OPERATION_ACTIVE` (10/13 fixed, 15/18 unfixed) rather than a
  converted error, so the flake's mechanism is unchanged by this fix. #24
  stays open per its own prior conclusion: the defect is not reproducible in
  this repository's session bookkeeping and likely sits in SoftHSM 2.6.1 or
  the miekg binding.
