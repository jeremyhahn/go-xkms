# TPM equivalence: go-xkms enclave provider vs go-enclave `backends/tpm`

This proof is PARTIAL: 7 rows are GAP. go-enclave PR #504 deletes go-enclave's
`backends/tpm` module. Owner ruling 1234 (Tenant order DS-10492) allows that
deletion only once go-xkms gives written proof that its provider has
equivalent behaviour and tests. This document is that proof. Rows marked
EQUIVALENT or N/A are covered below; the deletion must not rely on any row
marked GAP (rows 7, 14, 15, 16, 19, 20, 22).

## Import path

The replacement is `github.com/jeremyhahn/go-xkms/pkg/enclaveprovider`.

## Construction

- [`enclaveprovider.NewKeyProtector(sealer, attrs)`](../../pkg/enclaveprovider/provider.go)
  (provider.go:50) returns an `enclave.KeyProtector`; `NewRootUnsealer`
  (provider.go:110) and `ProvisionRoot` (provider.go:137) serve
  `enclave.ModeRootKey`.
- `sealer` is a `types.Sealer`. For a TPM it is the
  [`pkg/backend/tpm2`](../../pkg/backend/tpm2/sealer.go) `Backend`
  (CanSeal sealer.go:30, Seal :56, Unseal :135), which delegates to
  [`pkg/tpm2`](../../pkg/tpm2/sealer.go) `(*TPM2).Seal` (sealer.go:131) and
  `(*TPM2).Unseal` (sealer.go:318).

```go
p, err := enclaveprovider.NewKeyProtector(backend, &types.KeyAttributes{
	CN:       "enclave-provider",
	Parent:   backend.SRKAttributes(),
	Password: objectAuth,
})
blob, err := p.Protect(ctx, key) // key is enclave.RootKeyBytes long
err = p.Unprotect(ctx, blob, dst)
```

This is the construction
[`TestEnclaveProvider_Conformance_Simulator`](../../pkg/backend/tpm2/enclave_provider_simulator_test.go)
runs.

## Design differences that are not gaps

- **Parent binding.** go-enclave seals under a transient primary whose
  `unique.x` is SHA-256 of a label. go-xkms seals under a persistent SRK and
  binds the purpose in two places: an AAD sealed with the secret
  (`bindSealAAD`, pkg/tpm2/sealed_data_authentication.go:118, purpose AAD
  envelope.go:82) and an HMAC envelope tag keyed from the sealed key
  (`envelopeTag`, envelope.go:241). Cross-purpose use is refused (row 6).
- **Key size.** The seam protects `enclave.RootKeyBytes` keys only; any other
  length is `ErrInvalidKeyLength` (row 10).
- **Unseal authorization failures.** TPM BAD_AUTH, AUTH_FAIL and POLICY_FAIL
  on TPM2_Unseal are not sealed-data authentication in go-xkms: its sealed
  objects carry caller-held UserAuth or a PCR policy, so these codes mean the
  environment changed, not that the blob was forged
  (pkg/tpm2/sealer.go:297-317; row 13).

## Inventory

go-enclave columns are copied from the Tenant inventory (go-enclave is not
readable from go-xkms). go-xkms columns are from code read and tests run on
this branch. Every go-xkms test cited ran green under the gates in the last
line.

| # | go-enclave item (backends/tpm file:line) | go-enclave test | go-xkms code (file:line) | go-xkms test (name, file) | status | reason |
|---|---|---|---|---|---|---|
| 1 | Blob format: tpmBlobVersion=1 blob.go:12, label blob.go:26, encodeBlob blob.go:89 | TestBlob_RoundTrip blob_test.go:50 | envelope.go:49-50 magic "XKEP" v1, encodeEnvelope envelope.go:103 | TestEnvelope_RoundTripKeepsEveryField envelope_test.go:50; TestEnvelope_EmptyFieldsDecodeAsNil :61 | EQUIVALENT | versioned self-describing envelope, round trip tested |
| 2 | parseBlob refusals (bad version, size past end, trailing bytes, private > maxPrivateBytes=254) blob.go:103, sized blob.go:129, maxPrivateBytes blob.go:22 | TestBlob_Truncation :83, TestBlob_Refused :93, TestBlob_PrivateAtBound :118, TestSized blob_fields_test.go:13 | decodeEnvelope envelope.go:136, maxEnvelopeSize envelope.go:54, checkLoadAreaSizes pkg/tpm2/sealed_data_authentication.go:91 | TestDecodeEnvelope_RefusesWhatEncodeNeverWrites envelope_test.go:118; TestCheckLoadAreaSizes pkg/tpm2/sealed_data_authentication_test.go:138; TestUnseal_OversizedAndForeignObjects_Simulator pkg/tpm2/sealed_data_authentication_simulator_test.go:349 | EQUIVALENT | malformed or oversized input is refused before the TPM |
| 3 | checkPublic: KeyedHash type, 32-byte unique, exact template blob.go:142 | TestCheckPublic blob_fields_test.go:48, TestBlob_TemplateFieldChanged :129 | TPM Load plus unsealRejectsObject pkg/tpm2/sealed_data_authentication.go:203 | TestUnseal_OversizedAndForeignObjects_Simulator :349 (AES key reported as sealed-data authentication) | EQUIVALENT | different mechanism: the TPM refuses, then go-xkms classifies; a foreign object is still authentication |
| 4 | parseBlob aliases and never writes the blob | TestBlob_ParseDoesNotWriteTheBlob blob_test.go:72 | decodeEnvelope copies envelope.go:136 | TestEnvelope_DecodeDoesNotAliasBlob envelope_test.go:70; FuzzDecodeEnvelope envelope_fuzz_test.go:19 (input unchanged) | EQUIVALENT | go-xkms is stricter: it copies |
| 5 | Fuzzed blob parser | FuzzParseBlob blob_fuzz_test.go:28 | decodeEnvelope envelope.go:136 | FuzzDecodeEnvelope pkg/enclaveprovider/envelope_fuzz_test.go:19 | EQUIVALENT | never panics, never writes its input, refuses only with ErrMalformedEnvelope/ErrEnvelopeTooLarge/ErrWrongPurpose, accepted input re-encodes to the same body; 30 s of fuzzing found nothing |
| 6 | Label-bound parent: parentTemplate unique.x = SHA-256(label) blob.go:30 | TestBlob_ParentTemplateBindsTheLabel blob_test.go:166 | purpose AAD envelope.go:82 bound through bindSealAAD pkg/tpm2/sealed_data_authentication.go:118; envelope tag envelope.go:241 | TestKeyProtector_Unprotect_BackendBindsThePurpose provider_test.go:283; TestEnvelope_TagRejectsAnotherKey envelope_test.go:89 | EQUIVALENT | design difference: persistent SRK plus purpose binding instead of a label-bound transient primary; cross-purpose use is refused |
| 7 | Sealed object attributes FixedTPM/FixedParent/UserWithAuth/NoDA, sealedTemplate blob.go:70 | TestBlob_TemplateFieldChanged :129 | KeyedHashTemplate pkg/tpm2/types.go:831 (FixedTPM, FixedParent, UserWithAuth; no NoDA), applied in sealKeyInternal pkg/tpm2/seal.go:24; requireSealProtection seal.go:256 | none | GAP | no test pins the template attributes, and NoDA is not set, so dictionary-attack lockout applies to go-xkms sealed objects |
| 8 | Ended ctx refused before any device work protector.go:131/177 | TestKeyProtector_RefusesBeforeDeviceWork protector_test.go:742 | sealBox.seal provider.go:221, sealBox.open provider.go:241, backend Unseal pkg/backend/tpm2/sealer.go:135 | TestKeyProtector_Protect_EndedContext provider_test.go:152; TestKeyProtector_Unprotect_EndedContextTouchesNothing :177 | EQUIVALENT | ctx checked at entry |
| 9 | Malformed blob refused before the device (parseBlob first in Unprotect) protector.go:177 | TestKeyProtector_RefusesBeforeDeviceWork :742 | decodeEnvelope before sealer.Unseal provider.go:241; NewRootUnsealer decodes up front provider.go:110 | TestKeyProtector_Unprotect_BackendVerdicts provider_test.go:224; TestNewRootUnsealer_RefusesUnusableInputs :355 | EQUIVALENT | decode precedes the sealer call |
| 10 | Key size 1..128 bytes, KeySizeError errors.go:90-104, maxKeyBytes blob.go:15 | TestKeyProtector_RefusesBeforeDeviceWork :742 (empty/129) | Protect requires enclave.RootKeyBytes provider.go:67, ErrInvalidKeyLength errors.go:59 | TestKeyProtector_Protect_RefusesWrongLengthKey provider_test.go:141 | N/A | the seam protects RootKeyBytes keys only; any other length is refused |
| 11 | Length mismatch is authentication; key written only on success, last | TestKeyProtector_LengthMismatchIsAuthentication protector_test.go:793 | sealBox.open provider.go:241, ErrKeyLengthMismatch errors.go:80 | TestKeyProtector_Unprotect_WrongLengthDestination provider_test.go:192; _SealedKeyOfAnotherLength :207 | EQUIVALENT | same verdict and write-last rule |
| 12 | Tampered or foreign blob is ErrSealedAuthentication: authError errors.go:115, classify Load errors.go:179 | TestErrorContract_Sentinels errors_contract_test.go:172; TestMapResult errors_test.go:32; TestProviderConformance_OnSWTPM conformance_swtpm_test.go:50 | classifyLoadError pkg/tpm2/sealed_data_authentication.go:233, authenticationError pkg/enclaveprovider/errors.go:90 | TestEnclaveProvider_AuthenticationFailure_Simulator pkg/tpm2/enclave_provider_equivalence_simulator_test.go:125; TestUnseal_SealedDataAuthentication_Simulator pkg/tpm2/sealed_data_authentication_simulator_test.go:59, _FromStorage :173 | EQUIVALENT | through the provider on a TPM: a flipped byte in the envelope's sealed private area, and a private area spliced from a second sealed key, are refused by TPM2_Load (types.ErrSealedDataAuthentication, before the envelope tag is checked) as ErrSealedAuthentication, dst untouched, no handle left; the harness has one SRK, so there is no second-parent case |
| 13 | Unseal BAD_AUTH/AUTH_FAIL/POLICY_FAIL classified as authentication, classify errors.go:179 | TestMapResult errors_test.go:32 | pkg/tpm2/sealer.go:297-317 doc, classifyUnsealError pkg/tpm2/sealed_data_authentication.go:223 | TestUnseal_EnvironmentFailuresAreNotAuthentication_Simulator pkg/tpm2/sealed_data_authentication_simulator_test.go:203; TestUnsealRejectsObject pkg/tpm2/sealed_data_authentication_test.go:151 | N/A | deliberate: go-xkms sealed objects carry caller-held UserAuth/PCR policy, so these codes mean the environment changed, not the blob was forged |
| 14 | RETRY/YIELDED/TESTING retried, LOCKOUT a failure: WithRetry protector.go:90, call.do :324, defaults :27-30 | TestKeyProtector_Retry protector_test.go:823 | not found for Create/Load/Unseal; flushSessionWithRetry pkg/tpm2/auth.go:204 covers auth-session flush only | TestFlushSessionWithRetry_* auth_flush_retry_test.go:27-60 (flush only) | GAP | no retry of TPM_RC_RETRY on seal/unseal commands |
| 15 | Locked transients: key in and out in mlock + MADV_DONTDUMP + MADV_DONTFORK memory, wiped then freed: lockedAllocator transport_linux.go:90-135, free protector.go:307 | TestLockedAllocator_ExcludesFromDumpAndFork alloc_linux_test.go:22, _FailsClosedWhenAnExclusionIsRefused :43, _TransientNotInForkedChild :112, TestLockedAllocator_Free transport_linux_test.go:234 | only ProvisionRoot uses enclave.ProcessAllocator provider.go:137; per-call key and plaintext are heap slices wiped by enclave.Wipe (provider.go:252, pkg/tpm2/seal.go:96) | TestKeyProtector_RoundTripWipesThePlaintext provider_test.go:126 (wipe only, sealer double) | GAP | Codex-named; wiped but not locked, dump-excluded or fork-excluded |
| 16 | No plaintext copy left in process memory: hand-marshalled TPM2_Create/TPM2_Unseal in locked buffers unseal.go:15-108 | TestTPMDevice_UnsealLeavesNoCopy residue_linux_test.go:291, _CreateLeavesNoCopy :311 | tpm2.Create/tpm2.Unseal via go-tpm in sealKeyInternal pkg/tpm2/seal.go:24 and unsealFromBlobs seal.go:376; returns go-tpm's unseal.OutData.Buffer | none; residue sweep skipped pkg/tpm2/enclave_provider_simulator_test.go:37 | GAP | Codex-named; the secret passes through go-tpm heap and transport buffers below pkg/tpm2 |
| 17 | No handle residue: cleanup flushes every held handle newest-first protector.go:408 | TestReclaimAfterInterrupt_OnSWTPM conformance_swtpm_test.go:185; TestKeyProtector_CancelMidCommand protector_test.go:323 (no loaded handles) | Flush pkg/tpm2/seal.go:193 (seal, before SaveKeyPair), defer Flush seal.go:424 (unseal), session closers | TestEnclaveProvider_NoHandleResidue_Simulator pkg/tpm2/enclave_provider_equivalence_simulator_test.go:89; TestEnclaveProvider_CancelBetweenCommands_Simulator :194 | EQUIVALENT | transient objects and loaded sessions return to baseline after Protect, Unprotect, a tampered Unprotect, a wrong-length Unprotect, and a cancel after every command |
| 18 | Cancellation between commands: ctx error returned, key untouched, transients wiped and flushed: protect protector.go:142, call.do :324 | TestKeyProtector_CancelMidCommand protector_test.go:323 | ctx checked after each TPM step in sealKeyInternal pkg/tpm2/seal.go:44-195 (before SaveKeyPair :218) and unsealFromBlobs seal.go:401-471 (unsealed secret wiped :472), and after the call in Unseal pkg/tpm2/sealer.go:392/408 | TestEnclaveProvider_CancelBetweenCommands_Simulator pkg/tpm2/enclave_provider_equivalence_simulator_test.go:194; TestUnseal_EnvironmentFailuresAreNotAuthentication_Simulator pkg/tpm2/sealed_data_authentication_simulator_test.go:203 | EQUIVALENT | a cancel after any command but the last returns context.Canceled (not authentication), dst untouched, no blob and no persisted key pair, no handle left; the storage-blob path (unsealKeyInternal seal.go:270) is checked only after the call; a command already in flight is row 19 |
| 19 | Interrupt of an in-flight command on a silent TPM; Close interrupts a stuck call: send via context.AfterFunc protector.go:634, interrupt :674, reopen :684, Close :234 | TestKeyProtector_ContextEndsOnSilentTPM cancel_linux_test.go:118, _CloseInterruptsStuckCall :154 | none: go-tpm transport.TPM Send has no ctx | none | GAP | a call blocked inside a TPM command cannot be cancelled |
| 20 | A refused flush fails the call; handle kept in p.left and flushed by the next call: cleanup protector.go:408, flushLeft :457 | TestKeyProtector_FlushFailsAfterUnseal protector_test.go:383, _FlushLostAfterUnseal :482, _ReclaimAfterLostResponse :530 | Flush pkg/tpm2/tpm.go:2337 logs and drops the error; closeSession pkg/tpm2/session.go:358 logs only | none | GAP | a failed flush can leave a transient loaded while the call reports success |
| 21 | Handle baseline and reclaim: begin recover.go:28, reclaim :46, listType :128, maxListedHandles :24 | TestListType response_test.go:220, TestBeginBaselineKeepsHandles :393, FuzzListType :560 | none | none | N/A | mechanism of row 20; go-xkms has no reclaim path to test; the gap is recorded in row 20 |
| 22 | Calls serialized by a one-slot semaphore; a waiting call honours ctx: KeyProtector protector.go:53, acquire :273 | TestKeyProtector_WaitingCallHonorsContext protector_test.go:809 | not confirmed in pkg/tpm2.TPM2 | none | GAP | serialization and ctx-aware waiting not shown |
| 23 | Call after Close refused (ErrClosed errors.go:111); second Close nil: Close protector.go:234 | TestKeyProtector_CloseRefusesQueuedCall cancel_linux_test.go:187, _CloseAndHealth protector_test.go:840 | Backend closed checks pkg/backend/tpm2/sealer.go:30/135 | TestCanSeal_WhenClosed pkg/backend/tpm2/sealer_test.go:69; TestUnseal_NilSealedDataCheckedBeforeClosedCheck :206 | EQUIVALENT | calls after Close are refused; in-flight interruption is row 19 |
| 24 | Health returns nil protector.go:221 | TestKeyProtector_CloseAndHealth :840 | Health provider.go:90 | TestEnclaveProvider_Conformance_Simulator pkg/tpm2/enclave_provider_simulator_test.go:32 (providertest) | EQUIVALENT | |
| 25 | Salted session with AES-128 parameter encryption: parentAndSession protector.go:381 | TestProviderConformance_OnSWTPM :50 | encryptionSession(encryptIn) in sealKeyInternal pkg/tpm2/seal.go:111, encryptionSession(encryptOut) in unsealFromBlobs seal.go:450 | TestSealUnseal pkg/tpm2/seal_test.go:15 | EQUIVALENT | sensitive in and out are parameter-encrypted |
| 26 | Hand-written response parser: execute unseal.go:108, cut2B :175, putSize16 :166, readResponse protector.go:705, streamTransport :598, maxResponseBytes :24 | TestExecute_MalformedResponses response_test.go:115, _WellFormedResponse :162, TestSend_GuaranteesHeader :184, TestReadResponse read_response_test.go:87, TestStreamTransport protector_test.go:881, FuzzExecuteResponse :434, FuzzCut2B :474, FuzzReadResponse read_response_test.go:129 | none: go-tpm transport and unmarshalling | none | N/A | go-xkms has no hand parser; go-tpm's parser is not fuzzed by go-xkms |
| 27 | Device open: DefaultPath protector.go:20, openDevice transport_linux.go:20, resourceManaged :38, dialDevice :48, openCharDevice :61 | TestOpenDevice_RefusesPath transport_linux_test.go:20, _CharacterDevice :54, TestResourceManaged :66, TestDialDevice :127, TestOpenCharDevice :188 | transport opened by pkg/tpm2 config | pkg/tpm2 config tests (not enumerated) | N/A | device opening is outside the provider seam |
| 28 | ErrUnsupportedPlatform/PlatformError errors.go:14-28, transport_other.go | TestErrors_Match errors_test.go:118 | none | none | N/A | pkg/tpm2 is not platform-gated this way |
| 29 | Typed errors DeviceError/CommandError/KeySizeError errors.go:32-104, command String :134-161, mapResult :216 | TestErrorContract_Types errors_contract_test.go:119, _Complete :242, TestErrors_Contract errors_test.go:138, _Unwrap :213, TestCommand_String :242, TestMapResult_KeepsTheResponseCode :107 | sentinels pkg/enclaveprovider/errors.go:27-85; TPM response code kept reachable (classifyLoadError) | TestKeyProtector_Protect_BackendFailures provider_test.go:163; TestKeyProtector_Unprotect_BackendVerdicts :224; TestUnseal_SealedDataAuthentication_Simulator :59 | N/A | go-xkms exports sentinels, not these types; the auth/non-auth contract is covered in rows 12-13 |
| 30 | Provider conformance on a real TPM | TestProviderConformance_OnSWTPM conformance_swtpm_test.go:50, TestBlobLength_OnSWTPM :65 | pkg/tpm2.(*TPM2) as Sealer | TestEnclaveProvider_Conformance_Simulator pkg/tpm2/enclave_provider_simulator_test.go:32 | EQUIVALENT | residue sweep skipped (l.37 reason; see row 16) |
| 31 | Conformance over the construction shipped to callers | TestProviderConformance_OnSWTPM :50 | pkg/backend/tpm2 Backend Sealer sealer.go:30-135 | TestEnclaveProvider_Conformance_Simulator pkg/backend/tpm2/enclave_provider_simulator_test.go:18 | EQUIVALENT | the provider conformance suite runs over the Backend wrapper on the simulator (newSimBackend); residue sweep skipped for the row 16 reason |

Unprefixed go-xkms paths are in `pkg/enclaveprovider/`.

EQUIVALENT: 17, GAP: 7, N/A: 7

Last verified: 2026-11-24 at 91d7a2b4c, gates: make lint, go build, tagged go test -race of pkg/enclaveprovider/..., pkg/backend/tpm2/..., pkg/tpm2 (pkg/tpm2/tpmdev guard red on confidentialvm device opens, outside this proof), FuzzDecodeEnvelope 30 s.
