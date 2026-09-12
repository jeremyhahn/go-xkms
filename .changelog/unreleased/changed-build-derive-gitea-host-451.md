- **No host literal in the build system.** The in-house Gitea server was
  written into the Makefile, the devcontainer and every integration compose
  file, so a server move broke all of them at once. `scripts/gitea-host.sh`
  now derives `GITEA_HOST` from the environment, from `.devcontainer/.env`,
  or from the checkout's own origin remote (an SSH origin maps its port to
  the HTTP port), the Makefile exports it so every compose file interpolates
  `${GITEA_HOST}` (failing with the variable's name when it is unset), and a
  GitHub origin with no override takes the public resolution path with no
  `insteadOf` rewrite at all. `make gitea-host` prints the resolved value.
  The review workflow's model endpoint is likewise a knob (the `OLLAMA_URL`
  Actions variable or a runner-injected value) that fails naming itself
  when neither is configured.
