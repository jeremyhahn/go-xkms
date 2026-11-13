# 8473: make vuln, modverify and deps-check on main d55b1b73c

- Cause: on main d55b1b73c the Devcontainer image job never got past make coverage (runner lost or timeout), so make security (gosec vuln modverify trivy) and make deps-check have not run on main's tree; once #2042 fixes coverage they decide whether main goes green.
- Targets: make vuln, make modverify, make deps-check (XKMS_NATIVE_BUILD=1, fresh GOMODCACHE as CI). Out of scope: gosec (lane dv2042a), trivy (needs Docker images); a code cause gets a test commit then a fix commit, an outside cause is a finding here.
- Results:
  - make vuln (d55b1b73c): FAIL, GO-2026-6911 (mcp-go SSRF/credential leak via Location header, Fixed in: N/A), reachable from pkg/mcptool/client.go:280 Client.Connect. Outside cause: no fixed release; no exclusion (the finding applies).
  - make modverify (d55b1b73c): PASS, all modules verified.
  - make deps-check (d55b1b73c): FAIL, 13 root, 4 sdk/go and 7 xkey direct deps behind a release 7+ days old.
  - Fix: build(deps) bump of those deps in root, sdk/go and xkey (web/desktop tidied); builds of all four modules, test-mcp, test-grpc, test-sdk-go, test-sdk-transport, test-frost, test-xkey and test-go on mcptool, quic transport and acme api: PASS.
  - make deps-check (after bump): FAIL, only github.com/jeremyhahn/go-truststrap v0.6.0-alpha -> v0.7.1-alpha (root, sdk/go). Outside cause: v0.7.1-alpha needs go-enclave v0.10.0-alpha (undefined: enclave.ByteAccess under the v0.8.0-alpha replace), and go-enclave is held at v0.8.0-alpha for go-qrdb v0.51.0-alpha; the qrdb/enclave bump (#1995) is frozen.
  - make vuln (after bump, mcp-go v1.5.0): FAIL, GO-2026-6911 unchanged.
  - make modverify (after bump): PASS. make lint: PASS.

## m2616 (11-12)

- make deps-check (887b2c450, go-jose v4.1.9, x/oauth2 v0.38.0, x/sys v0.50.0, kin-openapi v0.153.0, sqlite v1.62.0, go-truststrap held in go.mod and sdk/go/go.mod): PASS.
- go build ./... with -mod=readonly in root, xkey, sdk/go, web/desktop: PASS.
- make lint: FAIL, staticcheck SA1019: go-jose v4.1.9 deprecates ParseSigned (pkg/acme/server/handlers/key_change.go:100, service.go:1249, tenant_auth.go:70) and ParseEncrypted (pkg/encoding/jwe/jwe.go:373). Needs a .go change (ParseSignedJSON/Compact, ParseEncryptedJSON/Compact) or a go-jose hold at v4.1.6.
- Slice 2 fix (4f8045e7b, tests first in c2e5ff550): ACME sites use jose.ParseSignedJSON (RFC 8555 section 6.2 flattened JSON; a compact JWS is now rejected), jwe.Decrypt uses jose.ParseEncryptedCompact.
- go test -tags codec_json ./pkg/acme/... ./pkg/encoding/jwe/: PASS except 5 TestDeviceAttestDICE* in pkg/acme/client, which need the tfwsim-atecc608a binary (make tfwsim-atecc608a or TFWSIM_DIR), not built in the lane; environmental, unrelated.
- make lint: PASS (0 issues, all modules and tag sets).
- scripts/deps-check.sh: exit 0 (go-truststrap held).
- go build ./... with -mod=readonly in root, xkey, sdk/go, web/desktop: PASS.
