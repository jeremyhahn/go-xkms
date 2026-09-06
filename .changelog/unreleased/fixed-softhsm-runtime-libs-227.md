- **The `test/docker/softhsm` image shipped without the C++ runtime, so
  `libsofthsm2.so` and `softhsm2-util` could not load inside it -- and its
  healthcheck could not detect that** (#227). `test/docker/softhsm/Dockerfile`,
  `docker-compose.yml`, `.devcontainer/docker-compose.yml`.

  SoftHSMv2 is C++, but the runtime stage installed only
  `openssl sqlite-libs p11-kit p11-kit-server` while copying `/usr/local` from
  the builder -- `libstdc++.so.6`/`libgcc_s.so.1` live in the builder's
  `/usr/lib` (pulled by `build-base`) and were never carried across, so every
  load ended in `Error loading shared library libstdc++.so.6` plus ~250
  relocation failures. Latent on every base version (reproduced identically on
  the pre-#177 `alpine:3.22.1`), and invisible because the healthcheck was
  `test -f` on the .so -- a check that cannot fail the way the container was
  broken. The fix adds `libstdc++` and `libgcc` to the runtime `apk add` and
  replaces the healthcheck (Dockerfile and both compose overrides) with
  `softhsm2-util --show-slots`, which links the same runtime and opens the
  token store, so it fails whenever the library would. Verified by building
  the image before and after: `ldd libsofthsm2.so` goes from two
  "Error loading shared library" lines to fully resolved, and
  `softhsm2-util --show-slots` from RC=127 to RC=0 listing slot 0.
  `test/docker/swtpm` was checked for the same gap and does not have it: swtpm
  and libtpms are C, their runtime deps are installed explicitly, and its
  healthcheck (`nc -z` on the command port) exercises the running daemon.

