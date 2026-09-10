- **Hardware certificate storage can release one record of a cert/chain pair (#143).**
  `HardwareCertStorage` gains `DeleteCertChain`; `DeleteCert` on PKCS#11
  now releases only the certificate object and leaves the `id-chain-<n>`
  objects, which `DeleteCertChain` releases on their own; on TPM2 the one
  NV index per id records its kind (`SaveCertChain` stamps a `Record: chain`
  PEM header), so every method addresses the record only when it is of
  its kind — a certificate read or delete of a chain record, and a chain
  read or delete of a certificate record, is `ErrNotFound`, as is an absent
  record. The storage adapter routes
  `certs/{id}-chain.pem` and `certs/{id}.pem` to their own releases; it
  still does not claim `storage.CompareAndDeleter`, now because a token or
  NV index has writers its lock cannot serialise, and the absence is
  pinned. The hybrid store and the external adapter follow.
  The hybrid store's deletes report a real failure on either side as an
  error instead of masking it behind the other side's absence. PKCS#11 object searches now page through `C_FindObjects`
  until the token returns an empty page, so a chain member past the first
  page is neither invisible to the delete nor to its verification.
  With the kind in the TPM2 record, a chain that overflowed to the external
  side is released there while the hardware certificate stays, and a stale
  one-member hardware chain behind a newer external chain goes with the
  chain instead of reappearing on the next read. A PKCS#11 object whose id
  cannot be read fails the search as an unknown outcome instead of being
  skipped.
  A PKCS#11 listing classifies chain members by the exact `<id>-chain-<n>`
  shape rather than any `-chain-` infix, so a certificate whose id merely
  contains the infix no longer disappears from `ListCerts`. Ids of the
  shapes the chain encoding reserves, `<id>-chain` and `<id>-chain-<n>`, are
  refused on every path that accepts a certificate id, on every store
  (`ErrIDReservedForChain`), so `certs/<id>-chain.pem` can only ever name
  `<id>`'s chain.
