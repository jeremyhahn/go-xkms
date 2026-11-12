# Train #2039 (8184-b-ci-deps): rebuild on current member heads (CA m2565)

- Merge #2033 head 0f25923a03ed into train/8184-b-ci-deps; resolve go.mod/go.sum in root, sdk/go, xkey, web/desktop (higher version wins, go mod tidy).
- Checks: build + vet (tags codec_cbor codec_json codec_msgpack tpm_simulator frost) in root, sdk/go, xkey; build in web/desktop; race unit tests in pkg/acme/server/handlers, pkg/api/rest, pkg/apimodule, pkg/encoding/jwe, pkg/webauthn/http, internal/buildgates.
- Results to follow.
- Merge a7c67a176 (parents 1b92c51fb, 0f25923a03ed): go.mod conflicts resolved to the higher version (go-luks2 v1.0.1-rc.4 from the train, all others from #2033); go.sum from the train side, then go mod tidy clean in root, sdk/go, xkey, web/desktop.
- Build + vet (codec_cbor codec_json codec_msgpack tpm_simulator frost): pass in root, sdk/go, xkey; go build ./... pass in web/desktop.
- go test -race -p 2 (same tags): pkg/acme/server/handlers, pkg/api/rest, pkg/apimodule, pkg/encoding/jwe, pkg/webauthn/http, internal/buildgates: all pass.
