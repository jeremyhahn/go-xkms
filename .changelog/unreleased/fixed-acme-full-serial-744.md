- **BREAKING: ACME certificates are now keyed by their full X.509 serial
  number, not its low 64 bits.** `OrderFinalizeHandler` stored an issued
  certificate's `ACMECertificate.ID` (and the "id" segment of its
  `/acme/cert/{id}` URL) as `cert.SerialNumber.Uint64()`, silently taking the
  low 64 bits of the CA's 128-bit serial (`pkg/ca.SerialNumberBits`) when it
  overflowed `uint64` - so two certificates whose serials happened to share
  those bits collided in storage, and the second issuance silently
  overwrote the first's record. `entities.ACMECertificate.Serial` now holds
  the certificate's complete serial number as a canonical lowercase hex
  string (no truncation, no precision loss), and it is what
  `/acme/cert/{id}` and certificate revocation key on; the DAO's own numeric
  row key is an FNV-1a hash of `Serial` (`entities.StringToEntityID`,
  mirroring `Tenant` and `ExternalAccountBinding`), kept only to satisfy the
  generic DAO's `uint64` entity-ID contract, and is never a certificate's
  public identity. `/acme/cert/{id}` accepts an optional `0x`/`0X` prefix and
  normalizes case, so differently-spelled encodings of the same serial reach
  the same record; a malformed or non-positive serial in the URL is rejected
  with a typed `*entities.InvalidSerialError` (surfaced as an ACME
  `malformed` error), never a panic. `pkg/acme/admin`'s certificate lookups
  already matched on the full decimal serial parsed from the stored PEM and
  are unaffected. No migration is provided (pre-release alpha): existing
  stored `ACMECertificate` records keyed by the old truncated numeric ID are
  no longer reachable by that ID and must be re-issued if still needed.
  Follow-up: the new FNV-1a row key is itself only 64 bits, so a hash
  collision between two DIFFERENT full serials remains possible in
  principle (astronomically unlikely, but the whole point of this fix).
  Certificate fetch (`CertificateHandler`) and revoke (`RevokeCertHandler`)
  now verify the fetched row's `Serial` matches the requested serial and
  treat a mismatch as not-found, never serving or revoking the wrong
  certificate. `storage.SaveCertificateNoCollision` (used by
  `OrderFinalizeHandler` and the ACME client's local certificate cache)
  refuses to overwrite a row already holding a different certificate,
  returning a typed `*storage.CertificateSerialCollisionError`; it uses the
  DAO's atomic `SaveIfAbsent` when the backing store supports it, and falls
  back to a Get-then-Save sequence otherwise (not atomic against a
  concurrent writer - go-qrdb does not expose a way through the SDK
  boundary to detect "atomic unsupported" as distinct from other
  `SaveIfAbsent` failures, so this function cannot do better without a new
  go-qrdb primitive, which it does not add). `admin.CertificateInfo.ID` and
  its SDK mirror are removed - no consumer read it, and it was an opaque
  internal storage hash with no business being on the wire; `SerialNumber`
  is the certificate's identity. (go-xkms#744).
