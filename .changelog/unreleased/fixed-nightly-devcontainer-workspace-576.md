- **Nightly `Integration Tests` now actually runs, instead of failing
  `integration-test-software` with `[setup failed]` on every scheduled
  run.** `.devcontainer/docker-compose.yml`'s `devcontainer` service
  bind-mounts `..:/workspace:cached`, which a Gitea Actions job resolves
  against the RUNNER HOST's filesystem (the daemon), not the job
  container's own checkout, so `/workspace` came up empty or unrelated and
  every `run_in_devcontainer` / `run_with_server` target died before
  compiling a package. A new CI-only overlay,
  `.devcontainer/docker-compose.ci.yml`, replaces that one bind mount with a
  named volume (Compose merges `volumes:` by container target path, so
  every other mount is untouched); the Makefile's
  `ci_sync_devcontainer_workspace` (wired into `run_in_devcontainer` and
  `run_with_server`) then populates it once per run with `docker compose
  cp`, which streams the tree over the Docker API connection rather than
  depending on a shared filesystem, so it lands correctly regardless of
  which host the daemon runs on. The overlay is layered on only when
  `COMPOSE_RUN_ID != local` (i.e. `GITHUB_RUN_ID` is set); local development
  keeps the plain bind mount unchanged. Files: `Makefile`,
  `.devcontainer/docker-compose.ci.yml`.
