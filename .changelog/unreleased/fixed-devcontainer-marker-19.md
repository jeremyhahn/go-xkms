- **The integration harness identified the devcontainer by `/.dockerenv`, so
  any containerised caller — including the Gitea act_runner job container —
  impersonated it and the devcontainer was never started** (#19). That is why
  Integration Tests was red on 39 of 40 CI runs: `run_with_server` skipped the
  start-the-devcontainer branch, built nothing, and `devcontainer-server-wait`
  then probed for the socket inside a devcontainer that did not exist while
  the server was serving perfectly well. Devcontainer identity is now a
  positive marker: `XKMS_DEVCONTAINER=1` is baked into the devcontainer image
  (`.devcontainer/Dockerfile`) and set in its compose environment
  (`.devcontainer/docker-compose.yml`), and all four Makefile probe sites
  (`run_in_devcontainer`, both branches of `run_with_server`,
  `integration-test-xkey-ssh`) test that marker instead of the ambient
  `/.dockerenv` / `$DEVCONTAINER` side effects. Verified by evaluating both
  predicates in all three contexts — host shell, marker-carrying container,
  and a plain container standing in for the act_runner job: the old predicate
  wrongly selects run-in-place inside the plain container, the new one selects
  start-the-devcontainer there and on the host, and run-in-place only when the
  marker is present — plus `make -n` renders and shell syntax checks of every
  changed target. `test/integration/api/testutil.go`'s `isRunningInDocker` is
  untouched: it genuinely asks "am I in any container" (and has no callers).

