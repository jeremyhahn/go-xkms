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
| after  | 91.7% |

Baseline test count: 1842 `func Test` in 95 files. After: 1565 (277
removed). Four of the 1842 are build-tagged out under TEST_TAGS (awskms,
azurekv, gcpkms and the frost race file), so `go test -list` prints 1839
before.

## Test counts per file (slice 2)

Only changed files are listed; the other 78 files keep their counts.

| file | before | removed | after |
|---|---|---|---|
| coverage_boost_test.go | 73 | 27 | 46 |
| coverage_gap_test.go | 119 | 43 | 76 |
| coverage_boost2_test.go | 70 | 46 | 24 |
| coverage_boost3_test.go | 74 | 36 | 38 |
| coverage_boost4_test.go | 25 | 6 | 19 |
| coverage_boost5_test.go | 18 | 7 | 11 |
| coverage_boost6_test.go | 9 | 2 | 7 |
| coverage_boost7_test.go | 48 | 30 | 18 |
| coverage_boost8_test.go | 28 | 5 | 23 |
| coverage_boost9_test.go | 50 | 18 | 32 |
| coverage_boost10_test.go | 38 | 19 | 19 |
| coverage_boost11_test.go | 34 | 17 | 17 |
| coverage_boost12_test.go | 16 | 6 | 10 |
| coverage_boost13_test.go | 12 | 3 | 9 |
| coverage_boost14_test.go | 21 | 6 | 15 |
| coverage_boost15_test.go | 40 | 4 | 36 |
| coverage_boost18_test.go | 8 | 2 | 6 |
| total (95 files) | 1842 | 277 | 1565 |

Kept on purpose: TestOCSPCreateResponse_RefusesSHA1UnderFIPSOnly
(coverage_boost15). Its branch runs only under `GODEBUG=fips140=only`, so a
per-test profile taken without it cannot show a superset.

Helpers removed with their last caller: buildRSAPSSCert
(coverage_boost2_test.go), buildSelfSignedLeaf (coverage_boost4_test.go).

## Removed tests (slice 2)

Every row is "duplicate": the named test exercises the same function (its
name names the same subject) and covers a superset of the removed test's
blocks. Coverage-file tests whose only superset is a test of another
subject were kept.

| file | test | reason |
|---|---|---|
| coverage_boost10 | TestBuildCSRTemplate_WithSANs_B10 | duplicate of TestBuildCSRTemplate_WithDNSSANs at csr_test.go |
| coverage_boost10 | TestCACertificate_NotInitialized_B10 | duplicate of TestCA_CACertificate_NotInitialized at ca_core_test.go |
| coverage_boost10 | TestExists_EmptyCN_B10 | duplicate of TestExists_EmptyCN_B7 at coverage_boost7_test.go |
| coverage_boost10 | TestExists_FoundInCertStore_B10 | duplicate of TestExists_MatchesAlgorithm at session1_extensions_test.go |
| coverage_boost10 | TestGenerateCRL_Success_B10 | duplicate of TestCA_GenerateCRL_Empty at ca_core_test.go |
| coverage_boost10 | TestGetXSignedCertificates_MatchingSuffix_B10 | duplicate of TestGetXSignedCertificates_WithStoredCert at coverage_gap_test.go |
| coverage_boost10 | TestImportCertificate_Success_B10 | duplicate of TestImportCertificate_RoundTrip at session1_extensions_test.go |
| coverage_boost10 | TestListRevocationBlobs_RevocationStorePath_B10 | duplicate of TestListRevocationBlobs_RevocationStorePath at coverage_gap_test.go |
| coverage_boost10 | TestLoad_AlreadyInitialized_B10 | duplicate of TestCA_Load_AlreadyInitialized at ca_core_test.go |
| coverage_boost10 | TestMergeSubjects_PartialOverride_B10 | duplicate of TestMergeSubjects at ca_core_test.go |
| coverage_boost10 | TestNewFromMultiIdentityConfig_NilConfig_B10 | duplicate of TestNewFromMultiIdentityConfig_NilParams at coverage_boost_test.go |
| coverage_boost10 | TestReadCrossSignedCertificate_InvalidPEM_B10 | duplicate of TestReadCrossSignedCertificate_InvalidPEM at cross_signing_test.go |
| coverage_boost10 | TestSigner_NotInitialized_B10 | duplicate of TestSigner_NotInitialized at session1_extensions_test.go |
| coverage_boost10 | TestSigner_Success_B10 | duplicate of TestSigner_ReturnsSigner at session1_extensions_test.go |
| coverage_boost10 | TestXSignedCertificate_EmptyIssuer_B10 | duplicate of TestXSignedCertificate_EmptyIssuerCN at cross_signing_test.go |
| coverage_boost10 | TestXSignedCertificate_NilAttrs_B10 | duplicate of TestXSignedCertificate_NilAttrs at cross_signing_test.go |
| coverage_boost10 | TestXSignedCertificate_NotFound_B10 | duplicate of TestXSignedCertificate_NotFound at cross_signing_test.go |
| coverage_boost10 | TestXSignedIntermediateCertificates_IntermediateFound_B10 | duplicate of TestXSignedIntermediateCertificates_RootExcluded at cross_signing_test.go |
| coverage_boost10 | TestXSignedRootCertificate_WithParentInStore_B10 | duplicate of TestXSignedRootCertificate_WalksToRoot at cross_signing_test.go |
| coverage_boost11 | TestCreatePlatformManufacturerExtension_Success_B11 | duplicate of TestCreatePlatformManufacturerExtension_Success at tcg_oids_test.go |
| coverage_boost11 | TestCreatePlatformModelExtension_Success_B11 | duplicate of TestCreatePlatformModelExtension_EmptyString at tcg_oids_test.go |
| coverage_boost11 | TestCreateTPFIPS140Extension_Success_B11 | duplicate of TestCreateTPFIPS140Extension_False at tcg_oids_test.go |
| coverage_boost11 | TestCreateTPIssuerKeyStoreExtension_Success_B11 | duplicate of TestCreateTPIssuerKeyStoreExtension_EmptyString at tcg_oids_test.go |
| coverage_boost11 | TestCreateTPKeyStoreExtension_Success_B11 | duplicate of TestCreateTPKeyStoreExtension_EmptyString at tcg_oids_test.go |
| coverage_boost11 | TestCreateTPMSpecificationExtension_Success_B11 | duplicate of TestCreateTPMSpecificationExtension_Success at tcg_oids_test.go |
| coverage_boost11 | TestGetECDSASignatureAlgorithm_NilCurve_B11 | duplicate of TestGetECDSASignatureAlgorithm_NilCurve at csr_test.go |
| coverage_boost11 | TestGetECDSASignatureAlgorithm_P384_B11 | duplicate of TestGetECDSASignatureAlgorithm_AllCurves at csr_test.go |
| coverage_boost11 | TestGetECDSASignatureAlgorithm_P521_B11 | duplicate of TestGetECDSASignatureAlgorithm_AllCurves at csr_test.go |
| coverage_boost11 | TestGetSignatureAlgorithm_UnsupportedKeyType_B11 | duplicate of TestGetSignatureAlgorithm_UnsupportedKeyType at csr_test.go |
| coverage_boost11 | TestMarshalHardwareModuleName_Success_B11 | duplicate of TestMarshalHardwareModuleName_LargeSerial at tcg_oids_test.go |
| coverage_boost11 | TestMarshalPermanentIdentifier_Success_B11 | duplicate of TestMarshalPermanentIdentifier_EmptyIdentifier at tcg_oids_test.go |
| coverage_boost11 | TestPrivateKey_Success_B11 | duplicate of TestPrivateKey_Success_B10 at coverage_boost10_test.go |
| coverage_boost11 | TestSigner_NotInitialized_B11 | duplicate of TestSigner_NotInitialized at session1_extensions_test.go |
| coverage_boost11 | TestSigner_Success_B11 | duplicate of TestSigner_ReturnsSigner at session1_extensions_test.go |
| coverage_boost11 | TestVerify_NilCert_B11 | duplicate of TestVerify_NilCertWithXSigner at session1_extensions_test.go |
| coverage_boost11 | TestVerify_Revoked_B11 | duplicate of TestCA_Verify_RevokedCert at coverage_boost_test.go |
| coverage_boost12 | TestAddSANsExtension_HardwareModuleName_B12 | duplicate of TestAddSANsExtension_HardwareModuleName at csr_test.go |
| coverage_boost12 | TestCABundle_EmptyBundle_B12 | duplicate of TestCABundle_EmptyBundle_B9 at coverage_boost9_test.go |
| coverage_boost12 | TestCreateRootCertificate_WithCRLAndOCSP_B12 | duplicate of TestCreateRootCertificate_WithSANsAndURLs_B9 at coverage_boost9_test.go |
| coverage_boost12 | TestGenerateCRL_NilIssuingCert_B12 | duplicate of TestGenerateCRL_NoIssuingCert_B9 at coverage_boost9_test.go |
| coverage_boost12 | TestGetOrGenerateCAKey_CachedKey_B12 | duplicate of TestCA_GetOrGenerateCAKey_ExistingKey at coverage_boost_test.go |
| coverage_boost12 | TestListRevocationBlobs_RevocationStore_B12 | duplicate of TestListRevocationBlobs_RevocationStoreScan_B11 at coverage_boost11_test.go |
| coverage_boost13 | TestEncodeCertsToPEM_Empty_B13 | duplicate of TestEncodeCertsToPEM_EmptyInput at bundle_test.go |
| coverage_boost13 | TestLoad_AlreadyInitialized_B13 | duplicate of TestCA_Load_AlreadyInitialized at ca_core_test.go |
| coverage_boost13 | TestPubKey_NilAttrs_B13 | duplicate of TestPubKey_NilAttributes at session1_extensions_test.go |
| coverage_boost14 | TestCAKeyAttributes_StoreTypeMismatch_B14 | duplicate of TestCAKeyAttributes_WrongStoreType at session1_extensions_test.go |
| coverage_boost14 | TestCrossSignedPEM_NilAttrs_B14 | duplicate of TestCrossSignedPEM_EmptyCN at cross_signing_test.go |
| coverage_boost14 | TestCrossSignedPEM_NoObjectStore_B14 | duplicate of TestCrossSignedPEM_NoObjectStore_B9 at coverage_boost9_test.go |
| coverage_boost14 | TestOIDToQuantumAlgorithm_UnknownOID_B14 | duplicate of TestOIDToQuantumAlgorithm at quantum_test.go |
| coverage_boost14 | TestOSTrustStore_B14 | duplicate of TestOSTrustStore_Linux at coverage_boost4_test.go |
| coverage_boost14 | TestQuantumAlgorithmOID_UnknownAlgo_B14 | duplicate of TestQuantumAlgorithmOID at quantum_test.go |
| coverage_boost15 | TestInitializeAsIntermediate_AlreadyInitialized_B15 | duplicate of TestInitializeAsIntermediate_AlreadyInitialized_B10 at coverage_boost10_test.go |
| coverage_boost15 | TestOCSPCheckCertificateStatus_ColdPathRevoked_B15 | duplicate of TestOCSPCheckCertificateStatus_ColdPath_RevocationStore at ocsp_revocationstore_test.go |
| coverage_boost15 | TestVerifyHybridCertificate_NoAltSigAlgExt_B15 | duplicate of TestVerifyHybridCertificate_MissingExtensions at hybrid_test.go |
| coverage_boost15 | TestVerifyPeerCertificate_IntermediateIsRevokedError_B15 | duplicate of TestVerifyPeerCertificate_IsRevokedError_B15 at coverage_boost15_test.go |
| coverage_boost18 | TestNewHierarchicalCA_NilConfig_B18 | duplicate of TestNewHierarchicalCA_NilParams_B18 at coverage_boost18_test.go |
| coverage_boost18 | TestNewHierarchicalCA_WithBackendForStore_B18 | duplicate of TestNewHierarchicalCA_PreservesFullTopology_B18 at coverage_boost18_test.go |
| coverage_boost2 | TestBlob_NoObjectStore | duplicate of TestBlob_WithoutObjectStore at session1_extensions_test.go |
| coverage_boost2 | TestBlob_RoundTrip | duplicate of TestBlob_RoundTripAndMissing at object_store_test.go |
| coverage_boost2 | TestBuildCertPool_Empty | duplicate of TestBuildCertPool at verification_test.go |
| coverage_boost2 | TestCABundleCertPool_Success_B2 | duplicate of TestCABundleCertPool_RootOnly_B11 at coverage_boost11_test.go |
| coverage_boost2 | TestCABundleFiltered_ECDSAFilter | duplicate of TestCABundleFiltered_AlgorithmFilter at session1_extensions_test.go |
| coverage_boost2 | TestCABundleFiltered_NoFilter_B2 | duplicate of TestCABundleFiltered_NoFilter at session1_extensions_test.go |
| coverage_boost2 | TestCABundleFiltered_NotInitialized_B2 | duplicate of TestCABundleFiltered_NotInitialized_B10 at coverage_boost10_test.go |
| coverage_boost2 | TestCABundleFiltered_RSAFilter_NoCerts | duplicate of TestCABundleFiltered_NoMatch at session1_extensions_test.go |
| coverage_boost2 | TestCAKeyAttributes_StoreTypeMismatch | duplicate of TestCAKeyAttributes_WrongStoreType at session1_extensions_test.go |
| coverage_boost2 | TestCASigner_UnknownAlgo_Matches | duplicate of TestCASigner_MatchingAlgorithm at session1_extensions_test.go |
| coverage_boost2 | TestCASigner_UnknownAlgo_Mismatch | duplicate of TestCASigner_MismatchedAlgorithm at session1_extensions_test.go |
| coverage_boost2 | TestCertificateFingerprint_NilCert | duplicate of TestCertificateFingerprint at verification_test.go |
| coverage_boost2 | TestCertificateFingerprint_ValidCert | duplicate of TestCertificateFingerprint at verification_test.go |
| coverage_boost2 | TestDaysUntilExpiration_NilCert | duplicate of TestDaysUntilExpiration at verification_test.go |
| coverage_boost2 | TestDaysUntilExpiration_ValidCert | duplicate of TestDaysUntilExpiration at verification_test.go |
| coverage_boost2 | TestDefaultKeyAlgorithm_ECDSA | duplicate of TestDefaultKeyAlgorithm at session1_extensions_test.go |
| coverage_boost2 | TestDefaultKeyAlgorithm_NilIssuing_B2 | duplicate of TestDefaultKeyAlgorithm_NoIssuing at coverage_gap_test.go |
| coverage_boost2 | TestDefaultSignatureAlgorithm_NilIssuing_B2 | duplicate of TestDefaultSignatureAlgorithm_NilIssuing at coverage_gap_test.go |
| coverage_boost2 | TestDefaultValidityPeriod_FromCAConfig | duplicate of TestDefaultValidityPeriod at session1_extensions_test.go |
| coverage_boost2 | TestDefaultValidityPeriod_FromMultiConfig | duplicate of TestDefaultValidityPeriod_ZeroCaConfigDays at coverage_gap_test.go |
| coverage_boost2 | TestExists_Found | duplicate of TestExists_WrongAlgo at coverage_boost2_test.go |
| coverage_boost2 | TestExists_NilCN | duplicate of TestExists_EmptyCN_B7 at coverage_boost7_test.go |
| coverage_boost2 | TestHash_ECDSA | duplicate of TestHash_ECDSAReturnsSHA256 at session1_extensions_test.go |
| coverage_boost2 | TestImportBlob_NoObjectStore | duplicate of TestImportBlob_WithoutObjectStore at session1_extensions_test.go |
| coverage_boost2 | TestIsAutoImportingIssuerCAs_True | duplicate of TestIsAutoImportingIssuerCAs_DefaultFalse at session1_extensions_test.go |
| coverage_boost2 | TestIsIssuedBy_WithMatchingAKID | duplicate of TestIsIssuedBy at verification_test.go |
| coverage_boost2 | TestIssueAKCertificateRaw_InvalidDER_B2 | duplicate of TestIssueAKCertificateRaw_InvalidDER at coverage_gap_test.go |
| coverage_boost2 | TestIssueEKCertificateRaw_InvalidDER_B2 | duplicate of TestIssueEKCertificateRaw_InvalidDER at coverage_gap_test.go |
| coverage_boost2 | TestIssuingIdentity_NoInputIdentity | duplicate of TestIssuingIdentity_ReturnsConfiguredIdentity at session2_5_extensions_test.go |
| coverage_boost2 | TestLoadPersistedRevocations_WithObjectStore_Empty | duplicate of TestLoadPersistedRevocations_WithObjectStore_ValidRecord at coverage_boost2_test.go |
| coverage_boost2 | TestOSTrustStore_Success_B2 | duplicate of TestOSTrustStore_Linux at coverage_boost4_test.go |
| coverage_boost2 | TestPathLength_CACertWithConstraint | duplicate of TestPathLength at verification_test.go |
| coverage_boost2 | TestPathLength_NilCert_B2 | duplicate of TestPathLength at verification_test.go |
| coverage_boost2 | TestPathLength_NonCA | duplicate of TestPathLength at verification_test.go |
| coverage_boost2 | TestRecordRevocation_AlreadyRevoked | duplicate of TestRecordRevocation_TwoNodes_LoserGetsAlreadyRevoked_WinnerRecordPreserved at revocation_race_1131_test.go |
| coverage_boost2 | TestRemainingValidity_NilCert | duplicate of TestRemainingValidity at verification_test.go |
| coverage_boost2 | TestRemainingValidity_ValidCert | duplicate of TestRemainingValidity at verification_test.go |
| coverage_boost2 | TestRevokeCert_DeleteKeys_B2 | duplicate of TestRevokeCert_DeleteKeys at session1_extensions_test.go |
| coverage_boost2 | TestRevokeCert_NilCert | duplicate of TestRevokeCert_NilRejected at session1_extensions_test.go |
| coverage_boost2 | TestRevokeCert_Success | duplicate of TestRevokeCert_NoObjectStore at session2_5_extensions_test.go |
| coverage_boost2 | TestTLSBundle_NilAttrs_B2 | duplicate of TestTLSBundle_NilAttrs at session1_extensions_test.go |
| coverage_boost2 | TestTrustedIntermediateCertPool_WithIntermediate | duplicate of TestTrustedIntermediateCertPool_WithIntermediate_B4 at coverage_boost4_test.go |
| coverage_boost2 | TestValidityPeriod_NilCert | duplicate of TestValidityPeriod at verification_test.go |
| coverage_boost2 | TestValidityPeriod_ValidCert | duplicate of TestValidityPeriod at verification_test.go |
| coverage_boost2 | TestVerifyWithOptions_RevocationCheck_NilCert | duplicate of TestVerifyWithOptions at verification_test.go |
| coverage_boost2 | TestVerify_ValidCert | duplicate of TestVerify_IssuedCertificate at coverage_boost3_test.go |
| coverage_boost3 | TestCABundleCertPool_WithObjectStore | duplicate of TestCABundleCertPool_RootOnly_B11 at coverage_boost11_test.go |
| coverage_boost3 | TestCABundleFiltered_WithObjectStore | duplicate of TestCABundleFiltered_NoFilter at session1_extensions_test.go |
| coverage_boost3 | TestCheckCertificateStatus_Good_NoObjectStore | duplicate of TestCheckCertificateStatus_ObjectStore_NotFound at coverage_boost4_test.go |
| coverage_boost3 | TestCreateCSRWithKey_NilSigner_B3 | duplicate of TestCreateCSRWithKey_NilSigner at csr_test.go |
| coverage_boost3 | TestCreateCSRWithKey_RSA_B3 | duplicate of TestCreateCSRWithKey_FullFlow_RSA at csr_test.go |
| coverage_boost3 | TestCreateCSR_DefaultKeyAttributes | duplicate of TestCreateCSR_NilKeyAttributes_DefaultsToECDSA at coverage_boost5_test.go |
| coverage_boost3 | TestCreateCSR_WithExplicitSigner | duplicate of TestCreateCSR_WithEmailSAN at coverage_boost4_test.go |
| coverage_boost3 | TestCreateTPFIPS140Extension_BothValues | duplicate of TestCreateTPFIPS140Extension_False at tcg_oids_test.go |
| coverage_boost3 | TestCreateTPIssuerKeyStoreExtension_Variants | duplicate of TestCreateTPIssuerKeyStoreExtension_EmptyString at tcg_oids_test.go |
| coverage_boost3 | TestCreateTPKeyStoreExtension_Variants | duplicate of TestCreateTPKeyStoreExtension_EmptyString at tcg_oids_test.go |
| coverage_boost3 | TestEnrollDevice_InvalidPackedCSR_B3 | duplicate of TestEnrollDevice_NoTPM_B3 at coverage_boost3_test.go |
| coverage_boost3 | TestGetXSignedCertificates_EmptyStore_B3 | duplicate of TestGetXSignedCertificates_WithStoredCert at coverage_gap_test.go |
| coverage_boost3 | TestHashCRLURL_Deterministic_B3 | duplicate of TestHashCRLURL_DifferentURLs at coverage_gap_test.go |
| coverage_boost3 | TestHashCRLURL_DifferentURLs_B3 | duplicate of TestHashCRLURL_DifferentURLs at coverage_gap_test.go |
| coverage_boost3 | TestImportAttestationKeyCertificate_EmptyDER | duplicate of TestImportAttestationKeyCertificate_EmptyCertificate at attestation_test.go |
| coverage_boost3 | TestImportAttestationKeyCertificate_InvalidDER_B3 | duplicate of TestImportAttestationKeyCertificate_InvalidDER at attestation_test.go |
| coverage_boost3 | TestImportAttestationKeyCertificate_NilAttrs_B3 | duplicate of TestImportAttestationKeyCertificate_NilAttrs at attestation_test.go |
| coverage_boost3 | TestImportDistributionCRLs_NilCert_B3 | duplicate of TestImportDistributionCRLs_NilCert at session1_extensions_test.go |
| coverage_boost3 | TestImportDistributionCRLs_NoCRLDP_B3 | duplicate of TestImportDistributionCRLs_NoCRLDPs at session1_extensions_test.go |
| coverage_boost3 | TestImportIssuingCAs_NoAIA_B3 | duplicate of TestImportIssuingCAs_NoAIA at session1_extensions_test.go |
| coverage_boost3 | TestImportLocalAttestation_NilQuote_B3 | duplicate of TestImportLocalAttestation_NilQuote at attestation_test.go |
| coverage_boost3 | TestIssueCertificate_RSAKey | duplicate of TestIssueCertificate_WithRSASigner_Verifies at coverage_boost3_test.go |
| coverage_boost3 | TestListRevocationBlobs_WithObjectStore_Empty_B3 | duplicate of TestListRevocationBlobs_RevocationStorePath at coverage_gap_test.go |
| coverage_boost3 | TestLookupRevocation_NotFound | duplicate of TestLookupRevocation_IgnoresObjectStore at coverage_boost6_test.go |
| coverage_boost3 | TestNewIntermediateCA_NilParams | duplicate of TestNewIntermediateCA_NilParams_B9 at coverage_boost9_test.go |
| coverage_boost3 | TestNewIntermediateCA_NilParent | duplicate of TestNewIntermediateCA_RequiresParent at constructors_test.go |
| coverage_boost3 | TestProfileRegistry_CaseInsensitive | duplicate of TestCA_ProfileRegistry_Register at ca_core_test.go |
| coverage_boost3 | TestProfileRegistry_RegisterAndGet | duplicate of TestCA_ProfileRegistry_Register at ca_core_test.go |
| coverage_boost3 | TestSign_NotInitialized | duplicate of TestSign_NotInitialized_B15 at coverage_boost15_test.go |
| coverage_boost3 | TestSign_Success | duplicate of TestCA_Sign at ca_core_test.go |
| coverage_boost3 | TestTLSBundleWithCrossSigner_NilXSigner_B3 | duplicate of TestTLSBundleWithCrossSigner_NilXSigner_ReturnsBase at coverage_boost2_test.go |
| coverage_boost3 | TestTLSConfigWithOptions_ClientMode_B3 | duplicate of TestTLSConfigWithOptions_NilOpts_B3 at coverage_boost3_test.go |
| coverage_boost3 | TestTLSConfigWithXSigner_NilXSigner_B3 | duplicate of TestTLSConfigWithXSigner_NilXSigner_ReturnsCfg at coverage_boost2_test.go |
| coverage_boost3 | TestTryLoadOpenSSLDefaults_NilSubject_B3 | duplicate of TestTryLoadOpenSSLDefaults at openssl_test.go |
| coverage_boost3 | TestVerifyTCG_CSR_IDevIDBytes_NoTPM | duplicate of TestVerifyTCG_CSR_IDevIDBytes_NoTPMRequired at session1_extensions_test.go |
| coverage_boost3 | TestVerify_WithNilXSigner | duplicate of TestVerify_IssuedCertificate at coverage_boost3_test.go |
| coverage_boost4 | TestCABundleCertPool_Initialized | duplicate of TestCABundleCertPool_RootOnly_B11 at coverage_boost11_test.go |
| coverage_boost4 | TestCABundle_WithIntermediate | duplicate of TestCABundle_WithIntermediate_B12 at coverage_boost12_test.go |
| coverage_boost4 | TestImportLocalAttestation_ValidQuote_B4 | duplicate of TestImportLocalAttestation_WithEventLog_B4 at coverage_boost4_test.go |
| coverage_boost4 | TestProfileRegistry_List | duplicate of TestCA_ProfileRegistry_List at ca_core_test.go |
| coverage_boost4 | TestSign_NilRandReader | duplicate of TestCA_Sign at ca_core_test.go |
| coverage_boost4 | TestVerifyWithOptions_SelfSignedLeaf_B4 | duplicate of TestVerifyWithOptions at verification_test.go |
| coverage_boost5 | TestCABundleFiltered_ECDSA_WithIntermediate | duplicate of TestCABundleFiltered_WithIntermediate_ECDSAFilter at coverage_boost7_test.go |
| coverage_boost5 | TestMarshalHardwareModuleName_DirectCall | duplicate of TestMarshalHardwareModuleName_LargeSerial at tcg_oids_test.go |
| coverage_boost5 | TestMarshalHardwareModuleName_EmptySerial | duplicate of TestMarshalHardwareModuleName_LargeSerial at tcg_oids_test.go |
| coverage_boost5 | TestOCSPHandleRequest_UnknownSerial | duplicate of TestOCSPHandleRequest_WithCAIssuedCert at coverage_boost6_test.go |
| coverage_boost5 | TestSign_WithIntermediate | duplicate of TestSign_IntermediateCA_DifferentKey at coverage_boost6_test.go |
| coverage_boost5 | TestTLSConfigWithXSigner_WithIntermediate_EmptyStore | duplicate of TestTLSConfigWithXSigner_WithIntermediateAndXSignedCerts_B8 at coverage_boost8_test.go |
| coverage_boost5 | TestVerify_NilCert | duplicate of TestVerify_NilCertWithXSigner at session1_extensions_test.go |
| coverage_boost6 | TestGetXSignedCertificates_WithStoredCert_B6 | duplicate of TestGetXSignedCertificates_WithStoredCert at coverage_gap_test.go |
| coverage_boost6 | TestImportDistributionCRLs_HTTPSuccess | duplicate of TestImportDistributionCRLs_AlreadyImported at coverage_boost6_test.go |
| coverage_boost7 | TestBlob_ImportRoundtrip_B7 | duplicate of TestBlob_RoundTripAndMissing at object_store_test.go |
| coverage_boost7 | TestBlob_NotFound_B7 | duplicate of TestBlob_RoundTripAndMissing at object_store_test.go |
| coverage_boost7 | TestCABundleFiltered_AlgorithmFilter_ECDSA_B7 | duplicate of TestCABundleFiltered_AlgorithmFilter at session1_extensions_test.go |
| coverage_boost7 | TestCABundleFiltered_AlgorithmFilter_RSA_NoMatch | duplicate of TestCABundleFiltered_NoMatch at session1_extensions_test.go |
| coverage_boost7 | TestCABundleFiltered_NoFilters_B7 | duplicate of TestCABundleFiltered_NoFilter at session1_extensions_test.go |
| coverage_boost7 | TestCABundle_ContainsValidPEM_B7 | duplicate of TestCA_CABundle at ca_core_test.go |
| coverage_boost7 | TestCAKeyAttributes_EmptyStoreType | duplicate of TestCAKeyAttributes_MatchesConfigured at session1_extensions_test.go |
| coverage_boost7 | TestCAKeyAttributes_StoreTypeMismatch_B7 | duplicate of TestCAKeyAttributes_WrongStoreType at session1_extensions_test.go |
| coverage_boost7 | TestCASigner_AlgorithmMismatch_B7 | duplicate of TestCASigner_MismatchedAlgorithm at session1_extensions_test.go |
| coverage_boost7 | TestCASigner_UnknownAlgorithmSucceeds | duplicate of TestCASigner_MatchingAlgorithm at session1_extensions_test.go |
| coverage_boost7 | TestCreateTenantIDExtension_LargeID_B7 | duplicate of TestCreateTenantIDExtension_Success at tcg_oids_test.go |
| coverage_boost7 | TestDefaultSignatureAlgorithm_NilIdentity_B7 | duplicate of TestDefaultSignatureAlgorithm_NilIssuing at coverage_gap_test.go |
| coverage_boost7 | TestDefaultSignatureAlgorithm_Success_B7 | duplicate of TestDefaultSignatureAlgorithm at session1_extensions_test.go |
| coverage_boost7 | TestExists_AlgorithmMatch_B7 | duplicate of TestExists_AlgorithmMismatch_B7 at coverage_boost7_test.go |
| coverage_boost7 | TestImportCertificatePEM_EmptyCNArg_B7 | duplicate of TestImportCertificatePEM_Roundtrip at session1_extensions_test.go |
| coverage_boost7 | TestImportCertificatePEM_Success_B7 | duplicate of TestImportCertificatePEM_Roundtrip at session1_extensions_test.go |
| coverage_boost7 | TestParseBundle_Success_B7 | duplicate of TestParseBundle_HappyPath at session1_extensions_test.go |
| coverage_boost7 | TestParseTPMSpecificationExtension_GarbageData_B7 | duplicate of TestParseTPMSpecificationExtension_EmptyData at tcg_oids_test.go |
| coverage_boost7 | TestPubKey_NilAttrs_B7 | duplicate of TestPubKey_NilAttributes at session1_extensions_test.go |
| coverage_boost7 | TestRevokeCert_WithObjectStore_RoundTrip_B7 | duplicate of TestRevokeCert_NoObjectStore at session2_5_extensions_test.go |
| coverage_boost7 | TestRootCertificate_NilInput_B7 | duplicate of TestRootCertificate_NilCert at session1_extensions_test.go |
| coverage_boost7 | TestTLSBundleWithCrossSigner_WithSigner_NoXCerts_B7 | duplicate of TestTLSBundleWithCrossSigner_NilXSigner_ReturnsBase at coverage_boost2_test.go |
| coverage_boost7 | TestTrustedIntermediateCertPool_IssuedByRoot_B7 | duplicate of TestTrustedIntermediateCertPool_NoIntermediate at coverage_boost2_test.go |
| coverage_boost7 | TestTrustedIntermediate_Success_B7 | duplicate of TestTrustedIntermediate_Present at session1_extensions_test.go |
| coverage_boost7 | TestTrustedRoot_Success_B7 | duplicate of TestTrustedRoot_ReturnsRoot at session1_extensions_test.go |
| coverage_boost7 | TestVerifyCertificateAgainstPublicKey_UnsupportedKey_B7 | duplicate of TestVerifyCertificateAgainstPublicKey_UnsupportedKeyType at verification_test.go |
| coverage_boost7 | TestVerifyChain_Success | duplicate of TestVerifyChain at verification_test.go |
| coverage_boost7 | TestVerifyRSASignature_PSS_Success | duplicate of TestVerifyRSASignature_PSS_SelfSigned at coverage_boost2_test.go |
| coverage_boost7 | TestVerifyWithOptions_NilOpts_ErrorExpected | duplicate of TestVerifyWithOptions at verification_test.go |
| coverage_boost7 | TestVerifyWithOptions_RevocationPath | duplicate of TestVerifyWithOptions_WithCRLRevocationCheck at revocation_test.go |
| coverage_boost8 | TestImportAttestationKeyCertificate_Success_B8 | duplicate of TestImportAttestationKeyCertificate_Happy at session1_extensions_test.go |
| coverage_boost8 | TestPutRevocationBlob_RevocationStorePath_B8 | duplicate of TestPutRevocationBlob_PersistsThroughRevocationStore at coverage_gap_test.go |
| coverage_boost8 | TestRecordRevocation_NilSerial_B8 | duplicate of TestRecordRevocation_NilSerial at coverage_boost2_test.go |
| coverage_boost8 | TestSignedBlob_NotInitialized_B8 | duplicate of TestSignedBlob_NotInitialized at session1_extensions_test.go |
| coverage_boost8 | TestSignedBlob_Success_B8 | duplicate of TestSignedBlob_ProducesSignature at session1_extensions_test.go |
| coverage_boost9 | TestCABundle_WithIntermediate_B9 | duplicate of TestCABundle_WithIntermediate_B12 at coverage_boost12_test.go |
| coverage_boost9 | TestCAKeyAttributes_StoreTypeMismatch_B9 | duplicate of TestCAKeyAttributes_WrongStoreType at session1_extensions_test.go |
| coverage_boost9 | TestCASigner_AlgorithmMismatch_B9 | duplicate of TestCASigner_MismatchedAlgorithm at session1_extensions_test.go |
| coverage_boost9 | TestCrossSignedPEM_Found_B9 | duplicate of TestCrossSignedPEM_AggregatesAcrossIssuers at cross_signing_test.go |
| coverage_boost9 | TestCrossSignedPEM_NilAttrs_B9 | duplicate of TestCrossSignedPEM_EmptyCN at cross_signing_test.go |
| coverage_boost9 | TestCrossSignedPEM_NotFound_B9 | duplicate of TestCrossSignedPEM_NotFound at session1_extensions_test.go |
| coverage_boost9 | TestImportXSignedCertificate_EmptyIssuer_B9 | duplicate of TestImportXSignedCertificate_EmptyIssuerCN at cross_signing_test.go |
| coverage_boost9 | TestImportXSignedCertificate_NilCert_B9 | duplicate of TestImportXSignedCertificate_NilCert at session1_extensions_test.go |
| coverage_boost9 | TestImportXSignedCertificate_NoObjectStore_B9 | duplicate of TestImportXSignedCertificate_OperationFailure_DoesNotReachAuditGate at audit_test.go |
| coverage_boost9 | TestImportXSignedCertificate_Success_B9 | duplicate of TestImportXSignedCertificate_EmitsAuditEvent_OnSuccess at audit_test.go |
| coverage_boost9 | TestNewCA_NilParams_B9 | duplicate of TestNewCA_NilParams at constructors_test.go |
| coverage_boost9 | TestNewCA_NoIdentity_B9 | duplicate of TestNewCA_EmptyIdentity at constructors_test.go |
| coverage_boost9 | TestNewParentCA_NilParams_B9 | duplicate of TestNewParentCA_NilParams at constructors_test.go |
| coverage_boost9 | TestNewParentCA_NoIdentity_B9 | duplicate of TestNewParentCA_ValidatesIdentity at constructors_test.go |
| coverage_boost9 | TestSign_NotInitialized_B9 | duplicate of TestCA_Sign_NotInitialized at ca_core_test.go |
| coverage_boost9 | TestSign_Success_B9 | duplicate of TestCA_Sign at ca_core_test.go |
| coverage_boost9 | TestXSignedIntermediateCertificates_Empty_B9 | duplicate of TestXSignedIntermediateCertificates_BrokenChain at cross_signing_test.go |
| coverage_boost9 | TestXSignedRootCertificate_SelfSigned_B9 | duplicate of TestXSignedRootCertificate_SelfSignedReturnsSelf at cross_signing_test.go |
| coverage_boost | TestCAProfile_Apply_NilRequest | duplicate of TestCAProfile_Apply at coverage_boost_test.go |
| coverage_boost | TestCA_BuildCAPool_NilCerts | duplicate of TestCA_BuildCAPool at tls_test.go |
| coverage_boost | TestCA_CreateIntermediateCertificates_Success | duplicate of TestCA_CreateIntermediateCertificates_SelectedCA at coverage_boost_test.go |
| coverage_boost | TestCA_GenerateCRL_MultipleReasons | duplicate of TestCA_GenerateCRL at ca_core_test.go |
| coverage_boost | TestCA_GetCAKeyAttributes_NilIdentity | duplicate of TestGetCAKeyAttributes_NilIdentity_B10 at coverage_boost10_test.go |
| coverage_boost | TestCA_GetIssuingCertificate_NilBoth | duplicate of TestCA_GetIssuingCertificate_FallsBackToRoot at coverage_boost_test.go |
| coverage_boost | TestCA_GetSigner_NilIssuingIdentity | duplicate of TestGetSigner_GetCAKeyAttributesError_B11 at coverage_boost11_test.go |
| coverage_boost | TestCA_Init_AlreadyInitialized | duplicate of TestInit_AlreadyInitialized_B10 at coverage_boost10_test.go |
| coverage_boost | TestCA_IntermediateCA_IssueCertificate | duplicate of TestCA_IntermediateCA_Verify at coverage_boost_test.go |
| coverage_boost | TestCA_IsRevoked_NotRevoked | duplicate of TestIsRevoked_CachesStoreHitButNotMiss at revocation_cluster_test.go |
| coverage_boost | TestCA_Load_RootCertNotFound | duplicate of TestCA_Load_NeverInitialized_ReturnsErrCertificateNotFound at ca_reload_793_test.go |
| coverage_boost | TestCA_Load_WithIntermediate | duplicate of TestLoad_WithIntermediate_B9 at coverage_boost9_test.go |
| coverage_boost | TestCA_VerifySignature_NilCert | duplicate of TestVerifySignature_NilCert at coverage_boost7_test.go |
| coverage_boost | TestCA_VerifySignature_NotInitialized | duplicate of TestVerifySignature_NotInitialized at coverage_boost7_test.go |
| coverage_boost | TestCA_VerifySignature_ValidCert | duplicate of TestVerifySignature_Success_B8 at coverage_boost8_test.go |
| coverage_boost | TestCA_Verify_NilCert | duplicate of TestVerify_NilCertWithXSigner at session1_extensions_test.go |
| coverage_boost | TestCA_Verify_NotInitialized | duplicate of TestVerify_NotInitialized at coverage_boost2_test.go |
| coverage_boost | TestCA_Verify_ValidCert | duplicate of TestVerify_IssuedCertificate at coverage_boost3_test.go |
| coverage_boost | TestCaConfigToMultiIdentity_EmptySubject | duplicate of TestCaConfigToMultiIdentity_EmptyStoreType at coverage_boost_test.go |
| coverage_boost | TestCaConfigToMultiIdentity_WithPolicyAndCRL | duplicate of TestCaConfigToMultiIdentity_IntermediateDefaults at coverage_boost_test.go |
| coverage_boost | TestDetermineSignatureAlgorithm_ECDSAP224 | duplicate of TestDetermineSignatureAlgorithm_ECDSAP256 at coverage_boost_test.go |
| coverage_boost | TestDetermineSignatureAlgorithm_RSA | duplicate of TestDetermineSignatureAlgorithm_RSA_B11 at coverage_boost11_test.go |
| coverage_boost | TestDetermineSignatureAlgorithm_Unknown | duplicate of TestDetermineSignatureAlgorithm_Unknown_B11 at coverage_boost11_test.go |
| coverage_boost | TestMergeSubjects_AllFieldsOverridden | duplicate of TestMergeSubjects_AllFields_B11 at coverage_boost11_test.go |
| coverage_boost | TestNewFromMultiIdentityConfig_NilConfig | duplicate of TestNewFromMultiIdentityConfig_NilConfigField_B10 at coverage_boost10_test.go |
| coverage_boost | TestParams_Validate_NilConfig | duplicate of TestParams_Validate_NilConfig_B10 at coverage_boost10_test.go |
| coverage_boost | TestParams_Validate_NilKeyAttributes | duplicate of TestParams_Validate_NilKeyAttributes_B11 at coverage_boost11_test.go |
| coverage_gap | TestCABundleCertPool_Success | duplicate of TestCABundleCertPool_RootOnly_B11 at coverage_boost11_test.go |
| coverage_gap | TestCABundleCertPool_WithIntermediate | duplicate of TestCABundleCertPool_WithIntermediate_B11 at coverage_boost11_test.go |
| coverage_gap | TestCABundleFiltered_NotInitialized | duplicate of TestCABundleFiltered_NotInitialized_B10 at coverage_boost10_test.go |
| coverage_gap | TestCAKeyAttributes_NilIssuing | duplicate of TestCAKeyAttributes_NoIssuingIdentity_B8 at coverage_boost8_test.go |
| coverage_gap | TestCASigner_UnknownAlgoPassthrough | duplicate of TestCASigner_MatchingAlgorithm at session1_extensions_test.go |
| coverage_gap | TestCA_ObjectStore_Nil | duplicate of TestCA_ObjectStore_NotNil at coverage_gap_test.go |
| coverage_gap | TestDefaultValidityPeriod_FromCaConfig | duplicate of TestDefaultValidityPeriod at session1_extensions_test.go |
| coverage_gap | TestGetXSignedCertificates_EmptyStore | duplicate of TestGetXSignedCertificates_WithStoredCert at coverage_gap_test.go |
| coverage_gap | TestGetXSignedCertificates_NilObjectStore | duplicate of TestGetXSignedCertificates_NilObjectStore_B3 at coverage_boost3_test.go |
| coverage_gap | TestHashCRLURL_DeterministicOutput | duplicate of TestHashCRLURL_DifferentURLs at coverage_gap_test.go |
| coverage_gap | TestImportEndorsementKeyCertificate_WithEKOID | duplicate of TestImportEndorsementKeyCertificate_WithoutEKOID at coverage_gap_test.go |
| coverage_gap | TestImportIssuingCAs_NilCert | duplicate of TestImportIssuingCAs_NilCert_B3 at coverage_boost3_test.go |
| coverage_gap | TestImportIssuingCAs_NoAIAUrls | duplicate of TestImportIssuingCAs_NoAIA at session1_extensions_test.go |
| coverage_gap | TestImportLocalAttestation_NilQuoteCoverage | duplicate of TestImportLocalAttestation_NilQuote at attestation_test.go |
| coverage_gap | TestImportLocalAttestation_WithEventLog | duplicate of TestImportLocalAttestation_WithEventLog_B4 at coverage_boost4_test.go |
| coverage_gap | TestImportLocalAttestation_WithoutEventLog | duplicate of TestImportLocalAttestation_WithEventLog_B4 at coverage_boost4_test.go |
| coverage_gap | TestIsAutoImportingIssuerCAs_TrueWhenSet | duplicate of TestIsAutoImportingIssuerCAs_DefaultFalse at session1_extensions_test.go |
| coverage_gap | TestIsIssuedBy_NilCert | duplicate of TestIsIssuedBy at verification_test.go |
| coverage_gap | TestIsIssuedBy_NilIssuer | duplicate of TestIsIssuedBy at verification_test.go |
| coverage_gap | TestIssueAKCertificateRaw_Success | duplicate of TestIssueAKCertificateRaw_Success_B2 at coverage_boost2_test.go |
| coverage_gap | TestIssueEKCertificateRaw_Success | duplicate of TestIssueEKCertificateRaw_Success_B2 at coverage_boost2_test.go |
| coverage_gap | TestListRevocationBlobs_EmptyStores | duplicate of TestListRevocationBlobs_RevocationStorePath at coverage_gap_test.go |
| coverage_gap | TestOSTrustStore_Success | duplicate of TestOSTrustStore_Linux at coverage_boost4_test.go |
| coverage_gap | TestPEM_NilAttrs | duplicate of TestPEM_NilAttrs_B2 at coverage_boost2_test.go |
| coverage_gap | TestPathLength_MaxPathLenZero | duplicate of TestPathLength at verification_test.go |
| coverage_gap | TestPathLength_NilCert | duplicate of TestPathLength at verification_test.go |
| coverage_gap | TestPrivateKey_Success | duplicate of TestPrivateKey_Success_B10 at coverage_boost10_test.go |
| coverage_gap | TestPubKey_KeyNotFound | duplicate of TestPubKey_KeyNotSigner_B8 at coverage_boost8_test.go |
| coverage_gap | TestPubKey_Success | duplicate of TestPubKey_Success_B13 at coverage_boost13_test.go |
| coverage_gap | TestRevokeCert_NotInitialized | duplicate of TestRevokeCert_NotInitialized_B2 at coverage_boost2_test.go |
| coverage_gap | TestRootCertificate_IssuerNotFound | duplicate of TestRootCertificate_ResolvesARemoteIssuerOnceItsChainIsImported at remote_issuer_resolution_test.go |
| coverage_gap | TestRootCertificate_NonCAFails | duplicate of TestRootCertificate_SelfSignedNonCA_B8 at coverage_boost8_test.go |
| coverage_gap | TestSerialNumbersMatch_Match | duplicate of TestSerialNumbersMatch at verification_test.go |
| coverage_gap | TestSerialNumbersMatch_NilA | duplicate of TestSerialNumbersMatch at verification_test.go |
| coverage_gap | TestSerialNumbersMatch_NilB | duplicate of TestSerialNumbersMatch at verification_test.go |
| coverage_gap | TestTLSCertificate_NotInitialized | duplicate of TestCA_TLSCertificate_NotInitialized at tls_test.go |
| coverage_gap | TestTLSConfigWithOptions_NotInitialized | duplicate of TestCA_TLSConfigWithOptions_NotInitialized at tls_test.go |
| coverage_gap | TestTLSConfigWithXSigner_NilXSignerNoAttrError | duplicate of TestTLSConfigWithXSigner_NilAttrs at session1_extensions_test.go |
| coverage_gap | TestVerifyChain_NilCert | duplicate of TestVerifyChain at verification_test.go |
| coverage_gap | TestVerifyChain_NilRoots | duplicate of TestVerifyChain at verification_test.go |
| coverage_gap | TestVerifyOCSPResponse_EmptyBytes | duplicate of TestVerifyOCSPResponse_EmptyInput_B3 at coverage_boost3_test.go |
| coverage_gap | TestVerifyOCSPResponse_InvalidBytes | duplicate of TestVerifyOCSPResponse_InvalidBytes_B3 at coverage_boost3_test.go |
| coverage_gap | TestVerifyWithOptions_NilCert | duplicate of TestVerifyWithOptions at verification_test.go |

## Gates (slice 2)

All with TEST_TAGS and the DS-7500 module env.

- `go test -count=1 -cover ./pkg/ca/`: pass, 91.7% before and after
- race: `go test -race -count=1 ./pkg/ca/` pass
- vet: `go vet ./pkg/ca/` clean
- make lint: pass, 0 issues
- production code: `git diff --stat` against the merge base with main shows
  no non-test file under `pkg/ca/`
- the table above has 277 rows; each removed test is absent and each named
  superset test is still present
