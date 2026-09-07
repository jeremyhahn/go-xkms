- **In-house Go module resolution follows the Gitea move.** The `insteadOf`
  rewrite that resolves `github.com/jeremyhahn/*` against the internal Gitea
  instance was pinned to the old host in eleven places — the root `Makefile`
  (both the container env block and the generated runner export), the
  devcontainer compose file, and eight `test/integration/*/docker-compose.yml`
  files. Every devcontainer build and integration-test target that fetches an
  in-house module failed to reach the server. The review workflow's
  `OLLAMA_URL` is deliberately unchanged: that service did not move.
