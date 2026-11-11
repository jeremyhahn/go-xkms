# 8473: make vuln, modverify and deps-check on main d55b1b73c

- Cause: on main d55b1b73c the Devcontainer image job never got past make coverage (runner lost or timeout), so make security (gosec vuln modverify trivy) and make deps-check have not run on main's tree; once #2042 fixes coverage they decide whether main goes green.
- Targets: make vuln, make modverify, make deps-check (XKMS_NATIVE_BUILD=1, fresh GOMODCACHE as CI). Out of scope: gosec (lane dv2042a), trivy (needs Docker images); a code cause gets a test commit then a fix commit, an outside cause is a finding here.
- Results to follow.
