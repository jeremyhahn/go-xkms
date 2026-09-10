- **`make test` no longer fails on a loaded runner because the release-assets
  stub server was slow to start.** `test/scripts/release-assets.test.sh` gave
  its stub Gitea API 5 s to publish a port; past that, an empty `PORT` silently
  became port 80 and every assertion failed with `Failed to connect to
  127.0.0.1 port 80`. The wait is now 60 s, and a server that never binds
  fails the suite by name with its own stderr instead of by side effect.
