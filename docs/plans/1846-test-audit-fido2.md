# #1846 test audit, slice 1: pkg/fido2 (top-level package)

Objective (CA m1804, ruling 273(12)): one test path per behaviour, at the
uppermost layer that reaches it. Remove duplicates, tests of the standard
library or a dependency, tautologies and sleeps standing in for
synchronisation. No behaviour loses its only test; coverage stays within
0.5 points of the baseline.

Scope: `pkg/fido2/*_test.go` only. Out of scope: `authenticator/`, `uhid/`,
`virtualdevice/` (later slices), production code.

## Coverage

| | `go test -count=1 -cover ./pkg/fido2/` |
|---|---|
| before | 92.0% |
| after  | 92.0% |

## Test counts per file (`func Test`)

| file | before | removed | after |
|---|---|---|---|
| authdata_test.go | 14 | 0 | 14 |
| coverage_boost_test.go | 43 | 26 | 17 |
| coverage_test.go | 33 | 14 | 19 |
| ctap2_test.go | 33 | 2 | 31 |
| ctap_status_test.go | 4 | 0 | 4 |
| derive_hmac_secret_test.go | 4 | 0 | 4 |
| device_edge_cases_test.go | 10 | 1 | 9 |
| device_test.go | 15 | 3 | 12 |
| fido2_test.go | 38 | 4 | 34 |
| hid_linux_test.go | 31 | 3 | 28 |
| hmac_secret_derivation_test.go | 10 | 0 | 10 |
| hmac_secret_test.go | 19 | 6 | 13 |
| pin_retries_test.go | 5 | 0 | 5 |
| pinuvauth_test.go | 27 | 0 | 27 |
| prf_test.go | 2 | 0 | 2 |
| protocol_edge_cases_test.go | 30 | 3 | 27 |
| rpid_test.go | 3 | 0 | 3 |
| select_device_open_test.go | 3 | 0 | 3 |
| types_test.go | 12 | 7 | 5 |
| webauthn_assert_options_test.go | 6 | 0 | 6 |
| webauthn_assertion_pin_test.go | 5 | 0 | 5 |
| webauthn_assertion_test.go | 5 | 0 | 5 |
| webauthn_attestation_test.go | 8 | 0 | 8 |
| webauthn_registration_options_test.go | 6 | 0 | 6 |
| **total** | **366** | **69** | **297** |

## Removed tests

| file | test | reason |
|---|---|---|
| coverage_boost | TestSelectDevice_WithAllowedVendors | duplicate of TestHandler_SelectDevice_WithVendorFilter at fido2_test.go |
| coverage_boost | TestSelectDevice_FilterOutNonAllowedVendor | duplicate of TestHandler_SelectDevice_NoMatchingDevice at fido2_test.go |
| coverage_boost | TestSelectDevice_WithAllowedProducts | duplicate of TestHandler_SelectDevice_WithProductFilter at fido2_test.go |
| coverage_boost | TestSelectDevice_FilterOutNonAllowedProduct | duplicate of TestHandler_SelectDevice_AllFilteredOut at fido2_test.go |
| coverage_boost | TestSelectDevice_WithVendorAndProductFilters | duplicate of TestHandler_SelectDevice_FilterBothVendorAndProduct at fido2_test.go |
| coverage_boost | TestSelectDevice_VendorMatchProductMismatch | duplicate of TestHandler_SelectDevice_FilterBothVendorAndProduct at fido2_test.go (vendor-match/product-miss device is skipped there) |
| coverage_boost | TestEnrollKey_CustomTimeout | duplicate of TestHandler_EnrollKey_WithCustomTimeout at fido2_test.go |
| coverage_boost | TestUnlockWithKey_CustomTimeout | duplicate of TestHandler_UnlockWithKey_WithTimeout at fido2_test.go |
| coverage_boost | TestDeriveSecret_WithProvidedChallengeNotEmpty | duplicate of TestHMACSecretExtension_DeriveSecret_WithCustomChallenge at hmac_secret_test.go |
| coverage_boost | TestVerifyHMACSecret_EmptySecret | duplicate of TestVerifyHMACSecret_AllCases at hmac_secret_test.go |
| coverage_boost | TestVerifyHMACSecret_64ByteSecret | duplicate of TestVerifyHMACSecret_AllCases at hmac_secret_test.go |
| coverage_boost | TestVerifyHMACSecret_WrongLength | duplicate of TestVerifyHMACSecret_AllCases at hmac_secret_test.go |
| coverage_boost | TestHandler_SelectDevice_WithDevicePath | duplicate of TestHandler_SelectDevice_SpecificPath at fido2_test.go |
| coverage_boost | TestHandler_SelectDevice_DevicePathOpenError | duplicate of TestHandler_SelectDevice_InvalidPath at fido2_test.go |
| coverage_boost | TestLoggerPrintf | tautology (asserts only a non-nil handler; logger case in TestNewHandlerWithLogger) |
| coverage_boost | TestNewHandlerWithLogger_NilLoggerParam | duplicate of TestNewHandlerWithLogger at fido2_test.go |
| coverage_boost | TestHandlerClose | duplicate of TestHandler_Close at fido2_test.go |
| coverage_boost | TestParseAuthDataExtensions_EdgeCases | duplicate of TestParseAuthDataExtensions at hmac_secret_test.go (same three cases) |
| coverage_boost | TestParseAuthDataExtensions_WithInvalidAttestedCredData | duplicate of TestParseAuthDataExtensions_InvalidAttestedData at hmac_secret_test.go |
| coverage_boost | TestParseAuthDataExtensions_WithInvalidCredIDLength | duplicate of TestParseAuthDataExtensions_InvalidCredIDLength at hmac_secret_test.go |
| coverage_boost | TestGenerateDerivedKey_ValidSecret | duplicate of TestGenerateDerivedKey at hmac_secret_test.go |
| coverage_boost | TestGenerateDerivedKey_InvalidSecretLength | duplicate of TestGenerateDerivedKey at hmac_secret_test.go |
| coverage_boost | TestDiscardLoggerPrintf | tautology (no assertion) |
| coverage_boost | TestIsFIDO2Device | duplicate of TestHandler_IsFIDO2Device at fido2_test.go |
| coverage_boost | TestListDevices_EnumerateError | duplicate of TestHandler_ListDevices_EnumerateError at fido2_test.go |
| coverage_boost | TestSelectDevice_EnumerateError | duplicate of TestHandler_SelectDevice_EnumerateError at fido2_test.go |
| coverage | TestHMACSecretInput_Coverage | tautology (struct fields read back) |
| coverage | TestEnrollmentResult_Coverage | tautology (struct fields read back) |
| coverage | TestAllStatusCodes_Coverage | duplicate of TestStatusCodeConstants at device_test.go |
| coverage | TestAllCTAPCommands_Coverage | duplicate of TestCTAP2CommandConstants at ctap2_test.go |
| coverage | TestDefaultTimeoutConstants_Coverage | tautology (constants restated) |
| coverage | TestMockHIDDevice_Reset_Coverage | tautology (tests the test double) |
| coverage | TestDeviceInfo_AllFields_Coverage | tautology (struct fields read back) |
| coverage | TestHandleCTAPError_UnknownError_Coverage | duplicate of TestHandleCTAPErrorUnknownStatusRendersHex at ctap_status_test.go |
| coverage | TestMockHIDDevice_ReadAfterClose_Coverage | tautology (tests the test double) |
| coverage | TestReadBuffer_Coverage | tautology (tests the test double) |
| coverage | TestWaitForDevice_NoDev_Coverage | duplicate of TestWaitForDevice_ContextCanceled at coverage_boost_test.go |
| coverage | TestSendCBOR_EmptyResponse_Coverage | duplicate of TestSendCBOR_EmptyResponse_FC at device_edge_cases_test.go (upper layer: NewCTAPHIDDevice) |
| coverage | TestReadResponse_ChannelIDMismatch_Coverage | duplicate of TestReadResponseSync_CIDMismatch_FC at device_edge_cases_test.go (upper layer: SendCBOR) |
| coverage | TestReadResponse_KeepaliveHandling_Coverage | duplicate of TestReadResponseSync_Keepalive_FC at device_edge_cases_test.go (upper layer: SendCBOR) |
| device_edge_cases | TestReadResponseSync_IncompleteFirstPacket_FC | duplicate of TestReadResponse_IncompleteFirstPacket_Coverage at coverage_test.go (which asserts the error) |
| hmac_secret | TestNewHMACSecretExtension_NotSupported | duplicate of TestNewHMACSecretExtension_NoSupport at coverage_boost_test.go (upper layer: real GetInfo) |
| hmac_secret | TestVerifyHMACSecret | duplicate of TestVerifyHMACSecret_AllCases (superset) |
| hmac_secret | TestHMACSecretOutput | tautology (struct field read back) |
| hmac_secret | TestAuthenticationResult_Flags | tautology (struct fields read back) |
| hmac_secret | TestGenerateDerivedKey_Deterministic | duplicate of TestGenerateDerivedKey (determinism check) |
| hmac_secret | TestGenerateDerivedKey_DifferentInputs | duplicate of TestGenerateDerivedKey_Uniqueness |
| hid_linux | TestLinuxHIDDevice_ImplementsInterface | tautology (compile-time assertion, no runtime check) |
| hid_linux | TestLinuxHIDDeviceEnumerator_ImplementsInterface | tautology (compile-time assertion, no runtime check) |
| hid_linux | TestHidrawDevInfoStruct | tautology (zero values of a struct) |
| device | TestMockHIDDevice | tautology (tests the test double) |
| device | TestMockHIDDeviceEnumerator | tautology (tests the test double) |
| device | TestCTAPHIDPacketStructure | duplicate of TestCTAPHIDConstants_Coverage at coverage_test.go (subset) |
| ctap2 | TestCreateClientDataHash_EdgeCases | duplicate of TestCreateClientDataHash at types_test.go (SHA-256 length is stdlib) |
| ctap2 | TestDefaultPublicKeyCredentialParameters_Coverage | duplicate of TestDefaultPublicKeyCredentialParameters at types_test.go |
| types | TestDeviceInfo_Fields | tautology (struct fields read back) |
| types | TestDevice_Fields | tautology (struct fields read back) |
| types | TestErrorTypes | tautology (sentinels are non-nil) |
| types | TestPublicKeyCredentialDescriptor | tautology (struct fields read back) |
| types | TestAuthenticatorOptions | tautology (struct fields read back) |
| types | TestRelyingParty | tautology (struct fields read back) |
| types | TestUser | tautology (struct fields read back) |
| fido2 | TestDiscardLogger | tautology (no assertion) |
| fido2 | TestDiscardLogger_Printf | tautology (no assertion) |
| fido2 | TestHandler_WaitForDevice_Timeout | duplicate of TestWaitForDevice_ContextCanceled at coverage_boost_test.go (asserts DeadlineExceeded) |
| fido2 | TestHandler_EnrollKey_WithTimeout | duplicate of TestHandler_EnrollKey_WithCustomTimeout |
| protocol_edge_cases | TestGenerateDerivedKey_InvalidLength | duplicate of TestGenerateDerivedKey at hmac_secret_test.go |
| protocol_edge_cases | TestParseAuthDataExtensions_WithAttestedCredData | duplicate of TestParseAuthDataExtensions_WithAttestedData at hmac_secret_test.go |
| protocol_edge_cases | TestParseAuthDataExtensions_InvalidAttestedCredData | duplicate of TestParseAuthDataExtensions_InvalidAttestedData at hmac_secret_test.go |

Kept on purpose: spec-pinned wire constants (CTAPHID, CTAP2 commands, COSE
algorithms, extension IDs, HID ioctls) are the only check of those values;
TestHandler_WaitForDevice's sleep models a device arriving later, it is not
synchronisation.

## Gates

- race: `go test -race -count=1 ./pkg/fido2/` pass
- vet: `go vet ./pkg/fido2/` clean
- make lint: pass, 0 issues (run with the DS-7500 module env; without it
  golangci-lint stops at package loading, "no go files to analyze")
- `go test -list '^Test' ./pkg/fido2/`: 297 tests, matching the table
- unused helpers removed with their tests: EmptyResponseMockDevice,
  MismatchedCIDMockDevice, KeepaliveMockDevice (coverage_test.go),
  IncompletePacketDeviceFC (device_edge_cases_test.go), testLoggerCB,
  ErrorEnumeratorCB (coverage_boost_test.go)

# Slice 2: pkg/ca (top-level package)

Scope: `pkg/ca/*_test.go` only. Out of scope: `checkpoint/`, `provider/`,
production code. Tests run with the Makefile TEST_TAGS
(`codec_cbor,codec_json,codec_msgpack,tpm_simulator,frost`); without
`codec_json` the package fails to build its signer store.

Method: each test was run on its own with a coverage profile. A test in a
`coverage_*` file is removed when one surviving test covers every block it
covers (a superset); that surviving test is named in the table and kept.

## Coverage (slice 2)

| | `go test -count=1 -cover ./pkg/ca/` (TEST_TAGS) |
|---|---|
| before | 91.7% |
| after  | (pending) |

Baseline test count: 1842 `func Test` in 95 files.
