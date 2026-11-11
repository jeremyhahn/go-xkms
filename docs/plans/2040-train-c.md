Merges: main d55b1b73c (f645e8c3cd), #1956 head f4376b78cc73 (8514076d32), #1958 head 3a4af9c28227 (0ee36246f7) onto train/8184-c-features.
Checks: go build + go vet (tags codec_cbor codec_json codec_msgpack tpm_simulator frost) in root, sdk/go, xkey; go test -count=1 -race -p 2 in root (pkg/api/..., pkg/xkms, pkg/attestation/..., pkg/types, pkg/fido2/authenticator), xkey (cmd/xkey/cmd, pkg/attestation/...), sdk/go (.).
Results to follow.
