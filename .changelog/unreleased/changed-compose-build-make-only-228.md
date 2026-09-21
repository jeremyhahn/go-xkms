- **`docker-compose.production.yml` no longer builds its own images; it runs
  the ones the `docker-build-*` Make targets produce (#228).** The compose
  file's `build:` blocks pointed at the real Dockerfiles with no secret
  injection, so a bare `docker compose build` (or an accidental `docker
  compose up` before the images existed) failed on the first private
  `github.com/jeremyhahn/*` module with an opaque authentication error — the
  in-house Go module credential is staged to a gitignored file by
  `stage-gomodauth` and passed to BuildKit only as a build secret
  (`--secret id=gomodauth`) by `make docker-build-*`, and compose has no
  equivalent step. Each service's `build:` now points at
  `Dockerfile.compose-build-unsupported`, a stub that fails immediately with a
  message naming the correct `docker-build-*` target, so the failure is
  actionable instead of opaque. The `image:` tags were also corrected to match
  what the Make targets actually tag (`go-xkms-server:${VERSION:-latest}`,
  etc. — they previously read `go-xkms/server:...`, a name nothing ever
  built), so `docker compose up` picks up a Make-built image once one exists.
  Files: `docker-compose.production.yml`, `Dockerfile.compose-build-unsupported`,
  `docs/deployment/docker.md`. Verified with `docker compose -f
  docker-compose.production.yml config` (parses) and `docker compose -f
  docker-compose.production.yml build` (fails, naming the per-service
  `docker-build-*` target).
