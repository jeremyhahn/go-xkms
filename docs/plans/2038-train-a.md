# Train #2038 (8184-a-fixes) on current heads

- Merges: 92e60972b9 (main d55b1b73c into the train), c8a8e93196 (#2004 head b91b38b3d).
- Checks: build + vet (tags codec_cbor codec_json codec_msgpack tpm_simulator frost) in root, sdk/go, xkey; race unit tests of pkg/tpm2, pkg/ca, pkg/xkms, pkg/backend/tpm2, pkg/acme/client, pkg/fido2/authenticator, test/mocks, pkg/acme/server/handlers; xkey pkg/gui/services, pkg/pairing, cmd/xkey/cmd; sdk/go root package.
- Results: to follow, one line per run.

## Results

- build + vet (tags above): root pass, sdk/go pass, xkey pass.
- root tests: pkg/tpm2, pkg/ca, pkg/xkms, pkg/backend/tpm2, pkg/fido2/authenticator, test/mocks, pkg/acme/server/handlers pass; pkg/acme/client FAIL in 5 TestDeviceAttestDICE* tests only (first: pkg/acme/client/device_attest_dice_e2e_test.go:274, tfwsim-atecc608a binary not built in the trusted-firmware module cache). Environment, not a member: the test comes from main (#1997), no member touches it. The rest of pkg/acme/client passes with -skip TestDeviceAttestDICE.
- xkey tests: pkg/gui/services, pkg/pairing, cmd/xkey/cmd pass.
- sdk/go tests: pass.
- No member conflict found; no fix commits.
