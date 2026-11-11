# Lane fd2575d: F4 fold, conflicting members (CA m2575)

- Merges, in order: #2000 9b7c6eabbf86, #1957 c432df9acea7, #2002 850d8052ea1b, #1974 7142fb23f9e7, #2003 23a7d74b1587, #1964 509231d39e9e; .pb.go regenerated from xkms.proto inside each merge that touches it.
- Checks: go build + go vet in root, sdk/go, xkey; root tests (api, apimodule, attestation, pairingproto, backend, fido2, ca; codec tags); xkey tests (attestation, phone); sdk/go tests; make lint once.
- Results to follow.
