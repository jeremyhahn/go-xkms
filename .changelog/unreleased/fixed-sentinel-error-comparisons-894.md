- **Sentinel error comparisons across the stack now go through `errors.Is`
  (or `errors.As` for a typed return code) instead of a bare `==`/`!=`, so a
  wrapped error still classifies correctly instead of silently falling
  through to the generic branch (go-xkms#894).** `pkg/acme/admin` was the
  widest exposure: `tenant_handlers.go` (23 comparisons) and `handlers.go`
  (5) mapped service errors to HTTP status via `err == ErrX`, so any call
  site that later wraps `ErrTenantNotFound`/`ErrCertificateNotFound`/etc.
  with `fmt.Errorf`'s `%w` would have reported 500 instead of 404/409/etc.;
  `types.go`'s `IsNotFoundError`/`IsValidationError`/`IsAlreadyExistsError`/
  `IsUnauthorizedError` had the same bug one level down, switching on `err`
  directly, and `auth.go`'s tenant-scope middleware switched on the raw
  error from `RequireTenantScope`. `pkg/keyprovider/{pkcs8,quantum,symmetric}`
  compared 11 sites against `storage.ErrNotFound` the same way before
  classifying a lookup as `backend.ErrKeyNotFound`. `pkg/backend/tpm2`
  compared the TPM constructor's error against `pkgtpm2.ErrNotInitialized`
  twice on the first-boot simulator auto-provisioning path. PKCS#11 Cryptoki
  return codes needed a different fix, not just `errors.Is`: `pkcs11.Error`
  wraps a `CK_RV` `uint`, so a compare against a code needs the code
  extracted first. `pkg/backend/pkcs11` and `pkg/storage/hardware` (the
  packages that talk to Cryptoki directly) gained a shared `isCKR(err,
  code)` helper (`errors.As` into `pkcs11.Error`, then compare the code) and
  every `err == pkcs11.Error(pkcs11.CKR_*)` site in both packages — login/
  already-initialized handling in `pkcs11.go`, `pkcs11_ecdh.go`,
  `pkcs11_importexport.go`, `pkcs11_symmetric.go`, `session_pool.go`,
  `attestation.go`'s unreadable-attribute classification, and the
  token-full detection in `pkcs11_cert_storage.go` — now goes through it. A
  parallel class of bug in `pkg/tpm2` compared raw `tpm2.TPMRC` response
  codes the same fragile way in `provision.go`, `key.go` and
  `platform_keystore.go`; those now go through `errors.Is` against the
  package's existing named `tpmRCHandle`/`tpmRCNVDefined` constants (the
  three call sites that had inlined the same magic numbers instead of
  reusing them now reuse them). The remaining sweep across the non-test
  tree (root, `sdk/go`, `xkey`) converted: `pkg/xkms/servicer_tenant.go`,
  `pkg/acme/client/service/device_tpm.go`, `pkg/pkcs11/module/storage.go`
  (3 sites), `pkg/tpm2/{cert_idevid.go,tpm.go,ecdsa.go,rsa.go}`,
  `pkg/acme/audit/checksum.go`, `pkg/acme/challenges/dns-01/providers/
  cloudflare/cloudflare.go` (a `errRecordNotFound` DNS-01 TXT-record check),
  `pkg/storage/hardware/hybrid_cert_storage.go` (4 sites in the hardware/
  external storage fallback), `examples/certificates/hardware/{hybrid,
  tpm2,pkcs11}` and `examples/webauthn/server` (including one
  `http.ErrServerClosed` shutdown check), and in `xkey`:
  `pkg/gui/services/oidc_service.go`, `pkg/pairing/tcp_transport.go`,
  `pkg/phone/usb_transport.go`, `test/integration/phone/tcp_transport.go`,
  and the stdin-prompt `err != nil && err != io.EOF` guards in `cmd/xkey/cmd/
  {migrate,barrier,import_data,pin,unseal,seal}.go`. Two `io.EOF`
  comparisons were deliberately left on `==`: `pkg/tpm2/eventlog.go` and
  `xkey/pkg/gadget/functionfs.go` are genuine hot Read loops (parsing a TPM
  event log record-by-record, and a continuous FunctionFS event-poll loop)
  using `io.EOF` as the io.Reader contract's own loop-termination signal,
  matching the exception the Go standard library's own `bufio`/`io` code
  uses. `pkg/backend/gcpkms/gcpkms.go`'s `err == iterator.Done` was left for
  the same reason: it is the documented idiom for
  `cloud.google.com/go/iterator`'s pagination sentinel, not a wrapped
  application error. Custom `Is(target error) bool` implementations
  (`sdk/go/errors.go`, `pkg/api/transport/errors.go`,
  `pkg/acme/server/handlers/compliance_attestation.go`,
  `pkg/acme/qrdb/kvstore_adapter.go`, `pkg/storage/kvadapter/errors.go`)
  were left untouched: comparing `target` with `==` inside a type's own
  `Is` method is the correct implementation of the `errors.Is` protocol, not
  an instance of the bug. New tests proving a wrapped sentinel still
  classifies correctly: `pkg/acme/admin/tenant_handlers_test.go`
  (`TestGetTenant_NotFound_Wrapped`), `handlers_coverage_boost_test.go`
  (`TestGetCertificate_NotFound_Wrapped`), `types_coverage_test.go`
  (`TestIsNotFoundError_WrappedSentinel`),
  `pkg/keyprovider/pkcs8/pkcs8_test.go` (`TestGetKey_NotFound_Wrapped`,
  `TestDeleteKey_NotFound_Wrapped`),
  `pkg/keyprovider/quantum/errors_wrapped_test.go`
  (`TestGetKey_NotFound_Wrapped`),
  `pkg/keyprovider/symmetric/errors_wrapped_test.go`
  (`TestDeleteKey_NotFound_Wrapped`), and `errors_isckr_test.go` in both
  `pkg/backend/pkcs11` and `pkg/storage/hardware`
  (`TestIsCKR_WrappedError`, `TestIsCKR_NotAPKCS11Error`).
