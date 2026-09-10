- **`make build` no longer needs a Gitea token on a host with a warm module
  cache.** The builder container mounted the host module cache at
  `/root/go/pkg/mod`, but the golang base image keeps its cache at
  `/go/pkg/mod`, so the mount sat unused and every `xkmsd` and `xkey` build
  refetched the whole module graph from Gitea. A checkout without
  `.devcontainer/.env` then failed on the first private module (`go-codec
  v1.4.0: Failed to authenticate user`) even though the host had every module
  cached. The container's `GOMODCACHE` is now pinned to the mount path for the root
  builder containers (`build-server`, `build-xkey`, `lib`, `docker-ci`), so a
  host cache that already holds the graph serves the build with no fetch and
  no token; `docker-run` and `docker-test`, which run as `testuser`, keep
  resolving modules inside the image.
