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
