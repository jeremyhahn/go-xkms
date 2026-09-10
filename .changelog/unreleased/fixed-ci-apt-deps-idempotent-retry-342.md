### Fixed

- CI's nine per-job `apt-get install` steps now go through one script that skips packages the runner image already carries, fetches only what is missing over IPv4 with a bounded retry, and fails naming any package dpkg still lacks. An archive outage no longer reddens a pull request that had no defect, and baking a package into the runner image makes its step a no-op without a workflow edit.
