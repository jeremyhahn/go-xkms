Merges: #2066 (6cda86a265dd, row/2540-authenticator-test-memory) into F3 tip da1e34a29ff9; so_pin.go keeps #2027's per-manager SO PIN derivation lock and #2066's configurable Argon2id memory cost.
Checks: go build ./...; go vet ./pkg/fido2/... ./pkg/ca/... ./pkg/acme/...; go test -race -count=1 -tags "codec_cbor codec_json codec_msgpack" on the same packages; make lint.
Results to follow.
- Merge #2066 (5789bd6c1e12): so_pin.go conflict resolved; deriveMu lock (#2027) wraps the configurable argon2IDKey call (#2066).
- go build ./...: pass.
- go vet fido2/ca/acme: pass.
- go test -race (fido2/ca/acme): pass except pkg/acme/client TestDeviceAttestDICE* (device_attest_dice_e2e_test.go:274,299,313,329,346): tfwsim-atecc608a simulator binary not built in the lane container (environment, not the merge).
- make lint: pass (0 issues on every module and tag set).
