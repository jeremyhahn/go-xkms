### Fixed

- The Makefile's compose macro uses the host's Compose: the `docker compose` plugin first, else the standalone `docker-compose` binary. A host with neither stops at once with `docker compose plugin or docker-compose is required`, instead of failing at the devcontainer's tar step with `unknown shorthand flag: 'p' in -p` (CI run 42881658762).
