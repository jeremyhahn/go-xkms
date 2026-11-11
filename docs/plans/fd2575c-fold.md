Merges: #2066 (6cda86a265dd, row/2540-authenticator-test-memory) into F3 tip da1e34a29ff9; so_pin.go keeps #2027's per-manager SO PIN derivation lock and #2066's configurable Argon2id memory cost.
Checks: go build ./...; go vet ./pkg/fido2/... ./pkg/ca/... ./pkg/acme/...; go test -race -count=1 -tags "codec_cbor codec_json codec_msgpack" on the same packages; make lint.
Results to follow.
