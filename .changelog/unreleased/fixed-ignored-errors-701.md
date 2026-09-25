- **Library code no longer silently discards errors on cleanup and
  security-relevant paths.** More than 200 `_ =` sites across the root
  module, sdk/go and xkey now return, join or log the error. Examples:
  - a failed barrier re-seal after an unlock audit write fails now surfaces
    through the D-Bus error;
  - truststore and LUKS rollback failures are joined into the primary error;
  - `WritePolicyHMAC` reports Close and cleanup failures;
  - FROST nonce-cleanup deletes are returned.

  A failed deadline set on the phone TCP pairing server and on FunctionFS
  reads is now fatal instead of silently skipping the timeout. `CABundleFiltered`
  reports PEM encode failures as `ErrCertificateEncoding`. (go-xkms#701, #983,
  #986, #991)
