# 2042: Devcontainer image job steps after make coverage

- Cause: on main d55b1b73c and every PR since 11:50Z the Devcontainer image job never got past `make coverage` (lost runner or timeout), so `make security` (gosec, vuln, modverify, trivy) and `make deps-check` have not run on main's tree.
- Targets: `make gosec`, `make vuln`, `make modverify`, `make deps-check` with `XKMS_NATIVE_BUILD=1` on #2042's tree; trivy is not run here (needs Docker images), CI runs it.
- Results to follow.
