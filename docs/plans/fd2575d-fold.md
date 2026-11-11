# Lane fd2575d: F4 fold, conflicting members (CA m2575)

- Merges, in order: #2000 9b7c6eabbf86, #1957 c432df9acea7, #2002 850d8052ea1b, #1974 7142fb23f9e7, #2003 23a7d74b1587, #1964 509231d39e9e; .pb.go regenerated from xkms.proto inside each merge that touches it.
- Checks: go build + go vet in root, sdk/go, xkey; root tests (api, apimodule, attestation, pairingproto, backend, fido2, ca; codec tags); xkey tests (attestation, phone); sdk/go tests; make lint once.
- Results to follow.
- Merge #2000 c4349ee86: union of the authz/scope tables; appraisal.go and its test take #2000's side (duplicate nil-TrustedRoots check dropped); pb.go regenerated; SPEC.md held back. The subject line is wrong (message file lost its first part); not amended.
- Merge #1957 e246e87f6: #2000's side on all 12 overlaps; kept #1957's REST decodedPathMiddleware, appraisal store dot-names and tests, two changelogs; duplicate MCP rpcMethods and golden entries removed; SPEC.md held back.
- Merge #2002 e68eb10b3: #2002's side for pairingproto, userverify, phone, keybackend, attesttest; #1958's Android status list, android verifier, phone config and sdk/go revocation test kept; two #1958 tests kept (host-cancel fix ported to verifyUserExchange); SPEC.md held back.
- Merge #1974 8e7a5a3a5: architecture.md keeps the shipped hook text; no tree change; SPEC.md held back.
- Merge #2003 a2df57640: references README keeps both sides; pb.go regenerated; SPEC.md held back.
- Merge #1964 cfe62ad13: routes.go keeps Verifier and tlog routes; go-qrdb v0.58 bumps come in; pb.go regenerated; SPEC.md held back.
- Check go build + go vet (root, sdk/go, xkey): pass.
- Check root tests with codec tags: pass.
- Check xkey tests (attestation, phone): pass.
- Check sdk/go go test ./...: fails without codec tags (first: TestServiceModule_HostCompositionThroughSDK, sdk/go/apimodule_host_test.go:44, codec json not in build); passes with -tags "codec_cbor codec_json codec_msgpack".
- Check make lint: pass.
- Conflict markers: none.
