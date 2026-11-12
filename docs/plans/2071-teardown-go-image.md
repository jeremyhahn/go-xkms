# 2071: Integration teardown sets GO_IMAGE for compose down

## Cause

Main d55b1b73c Integration prints "GO_IMAGE is unset" (DS-8630, Infra 199917).
The teardown steps in `.github/workflows/ci.yml` run
`docker compose -f build/docker/devcontainer/compose.yaml ... down --volumes || true`
outside make. `build/docker/devcontainer/compose.yaml:87` requires
`${GO_IMAGE:?...}`, so compose refuses to parse the file, the `down` fails,
`|| true` hides the failure, and the integration containers and volumes are
never removed.

## Change

On the three teardown lines (ci.yml:1619, :1721, :1748), set
`GO_IMAGE="$(. scripts/tool-pins.sh && printf '%s' "$GO_IMAGE")"` before
`GO_QUICRAFT_IT_IMAGE=`, the same pin source ci.yml already uses at :999.
`|| true` and the rest of each line stay.

## Checks

- `actionlint .github/workflows/ci.yml`
- `GO_IMAGE=... GO_QUICRAFT_IT_IMAGE=x docker compose -f build/docker/devcontainer/compose.yaml config -q` prints rc=0, no "GO_IMAGE is unset"
- `git grep -n 'devcontainer/compose.yaml.*down' .github/workflows/ci.yml` shows GO_IMAGE on all three lines

## Results

- actionlint on ci.yml: pass, no findings.
- compose config check: not run; docker is not installed in the lane
  container (`docker: command not found`). The GO_IMAGE expression itself
  yields a non-empty value from scripts/tool-pins.sh. CI's Integration job
  exercises the teardown.
- The three teardown lines (ci.yml:1619, :1721, :1748) all set GO_IMAGE.
