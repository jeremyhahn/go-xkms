### Fixed

- **xkey GUI: a failed PIV certificate delete is no longer read as "no
  certificate" on any error whose text happens to contain "not found".**
  `PIVService.DeleteCertificate` removes both the certificate and the key, and
  decided whether a failed certificate delete should block the key delete with
  `strings.Contains(err.Error(), "not found")`. A permission error naming a
  path, a missing *backend*, a missing key and an unknown slot all satisfy
  that, so any of them read as "carry on" — and the slot was reported empty
  while it still held a certificate, which is the opposite of the method's
  contract.

  The in-process path now classifies on the sentinel alone
  (`errors.Is(err, xkms.ErrPIVCertificateNotFound)`), which every local backend
  produces: the file backend wraps it in a `PIVStorageError` and the tpm2
  backend maps `storage.ErrNotFound` onto it. The remote path matches the
  sentinel, or the sentinel's own rendered text — which is what the server
  actually sends, since the error message goes into the response body — and
  nothing looser. Anything else now fails closed.

- **xkey GUI: deleting a PIV slot no longer reports success when the key was
  never inspected.** `DeleteCertificate` removes both the certificate and the
  key. When the certificate delete succeeded and the subsequent key listing
  failed, it logged the failure and returned `nil`, so the GUI reported the
  slot cleared while the backing key may still exist. Both paths now return the
  listing error, wrapped, naming that the key may remain.
