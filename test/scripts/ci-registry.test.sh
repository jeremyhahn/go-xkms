#!/bin/bash
# Shell-level tests for scripts/ci-registry.sh (ruling 169; the go-qrdb #1135
# pattern): the CI image handoff from the ci-images job to every consumer.
#
# These pin what the script may do with a registry and a credential: the
# registry is the forge's (or GHCR on GitHub), a forge push reads the release
# runner's RELEASE_REGISTRY* names alone (ruling 173), a read degrades to
# anonymous and then to a local build, a consumer never rebuilds an image main
# published, every reference is a digest, and no credential is ever printed.
#
# No Docker daemon or registry is involved: a fake `docker` and a fake `make`
# on PATH record every invocation and answer from FAKE_* variables. DOCKER_HOST
# points at a closed port, so a PATH mistake fails loudly.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_UNDER_TEST="$REPO_ROOT/scripts/ci-registry.sh"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

FAKE_BIN="$WORK_DIR/bin"
CALL_LOG="$WORK_DIR/calls.log"
mkdir -p "$FAKE_BIN" "$WORK_DIR/home" "$WORK_DIR/tmp"

DIGEST="sha256:$(printf '%064d' 7)"
IMAGE_ID="sha256:$(printf 'a%.0s' {1..64})"
TOOLCHAIN_TAG="go-xkms-toolchain:0123456789abcdef"
IT_TAG="go-xkms-ci-it:fedcba9876543210"
FORGE="forge.invalid:3000"
SECRET="s3cr3t-run-token"
RELEASE_SECRET="s3cr3t-release-token"

cat >"$FAKE_BIN/docker" <<'FAKE'
#!/bin/bash
# Fake docker: record each invocation and answer from FAKE_* variables.
echo "docker $*" >>"$FAKE_LOG"
case "$1" in
  login)
    stdin=$(cat)
    echo "login-stdin-bytes ${#stdin}" >>"$FAKE_LOG"
    exit "${FAKE_LOGIN_RC:-0}"
    ;;
  buildx)
    case "${FAKE_INSPECT:-found}" in
      found) printf 'Name:      %s\nMediaType: application/vnd.oci.image.index.v1+json\nDigest:    %s\n' "$4" "$FAKE_DIGEST" ;;
      missing) echo "ERROR: $4: not found" >&2; exit 1 ;;
      *) echo "ERROR: unexpected status from HEAD request: 401 Unauthorized" >&2; exit 1 ;;
    esac
    ;;
  image)
    case "$4" in
      *RepoDigests*) echo "${5%:*}@$FAKE_DIGEST" ;;
      *) echo "$FAKE_IMAGE_ID" ;;
    esac
    ;;
  pull) exit "${FAKE_PULL_RC:-0}" ;;
  create) exit "${FAKE_CREATE_RC:-0}" ;;
esac
exit 0
FAKE

cat >"$FAKE_BIN/make" <<'FAKE'
#!/bin/bash
# Fake make: the content-hash tags as the Makefile prints them (a caller's
# TOOLCHAIN_IMAGE or IT_IMAGE overrides them, as on the real Makefile), and
# the image builds, which record the module file's mode and contents' names.
case " $* " in
  *" toolchain-image "*) echo "${TOOLCHAIN_IMAGE:-$FAKE_TOOLCHAIN_TAG}"; exit 0 ;;
  *" it-image "*) echo "${IT_IMAGE:-$FAKE_IT_TAG}"; exit 0 ;;
esac
echo "make $*" >>"$FAKE_LOG"
for a in "$@"; do
  case $a in
    MODULE_ENV_FILE=*)
      f=${a#MODULE_ENV_FILE=}
      echo "modauth-mode $(stat -c %a "$f")" >>"$FAKE_LOG"
      echo "modauth-names $(cut -d= -f1 "$f" | tr '\n' ' ')" >>"$FAKE_LOG"
      echo "$f" >"$FAKE_MODAUTH_PATH"
      ;;
  esac
done
exit "${FAKE_BUILD_RC:-0}"
FAKE
chmod +x "$FAKE_BIN/docker" "$FAKE_BIN/make"

FAILURES=0

start_case() { echo "--- $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "    ok: $1"; }

# run_script <expected-exit> <args...> [-- VAR=VALUE ...]
# Runs the script on a forge run of a pull request by default; VAR=VALUE
# pairs after -- override or add to that environment.
run_script() {
  local expected_exit="$1"
  shift
  local args=() envs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do args+=("$1"); shift; done
  [ $# -eq 0 ] || { shift; envs=("$@"); }
  : >"$CALL_LOG"
  (
    cd "$REPO_ROOT" || exit 99
    env -i \
      PATH="$FAKE_BIN:/usr/bin:/bin" \
      HOME="$WORK_DIR/home" \
      DOCKER_HOST="tcp://127.0.0.1:1" \
      RUNNER_TEMP="$WORK_DIR/tmp" \
      GITHUB_SERVER_URL="https://$FORGE" \
      GITHUB_REPOSITORY_OWNER=JeremyHahn \
      GITHUB_RUN_ID=42 \
      GITHUB_RUN_ATTEMPT=1 \
      CI_STACK_PREFIX=go-xkms-ci- \
      CI_REGISTRY_BACKOFF=0 \
      GOPRIVATE=github.com/jeremyhahn \
      FAKE_LOG="$CALL_LOG" \
      FAKE_DIGEST="$DIGEST" \
      FAKE_IMAGE_ID="$IMAGE_ID" \
      FAKE_TOOLCHAIN_TAG="$TOOLCHAIN_TAG" \
      FAKE_IT_TAG="$IT_TAG" \
      FAKE_MODAUTH_PATH="$WORK_DIR/modauth-path" \
      "${envs[@]}" \
      bash "$SCRIPT_UNDER_TEST" "${args[@]}" >"$WORK_DIR/stdout" 2>"$WORK_DIR/stderr"
  )
  local actual=$?
  if [ "$actual" -ne "$expected_exit" ]; then
    fail "expected exit $expected_exit, got $actual"
    sed 's/^/      /' "$WORK_DIR/stderr" >&2
  fi
}

stdout_is() {
  if [ "$(cat "$WORK_DIR/stdout")" = "$1" ]; then
    pass "prints '$1'"
  else
    fail "printed '$(cat "$WORK_DIR/stdout")', want '$1'"
  fi
}

stderr_has() {
  if grep -qF -- "$1" "$WORK_DIR/stderr"; then
    pass "says '$1'"
  else
    fail "stderr lacks '$1'"
    sed 's/^/      /' "$WORK_DIR/stderr" >&2
  fi
}

called() {
  if grep -qF -- "$1" "$CALL_LOG"; then
    pass "ran '$1'"
  else
    fail "never ran '$1'"
  fi
}

not_called() {
  if grep -qF -- "$1" "$CALL_LOG"; then
    fail "ran '$1'"
  else
    pass "never ran '$1'"
  fi
}

no_secret_printed() {
  if grep -qF -e "$SECRET" -e "$RELEASE_SECRET" "$WORK_DIR/stdout" "$WORK_DIR/stderr" "$CALL_LOG"; then
    fail "a credential value reached the output or a command line"
  else
    pass "no credential value printed or passed as an argument"
  fi
}

RUN_TOKEN=(CI_REGISTRY_USER=runner "CI_REGISTRY_TOKEN=$SECRET")
RELEASE=(CI_PUBLISH=true "RELEASE_REGISTRY=$FORGE" RELEASE_REGISTRY_USER=releaser "RELEASE_REGISTRY_TOKEN=$RELEASE_SECRET")
TOOLCHAIN_REPO="$FORGE/jeremyhahn/go-xkms-ci-toolchain"

# --------------------------------------------------------------------------
start_case "resolve: main's image of the same content, by digest, from the forge's registry"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}"
stdout_is "$TOOLCHAIN_REPO@$DIGEST"
called "docker login $FORGE -u runner --password-stdin"
called "docker buildx imagetools inspect $TOOLCHAIN_REPO:0123456789abcdef-main"
no_secret_printed

start_case "resolve: GHCR on GitHub"
run_script 0 resolve it -- "${RUN_TOKEN[@]}" GITHUB_SERVER_URL=https://github.com
stdout_is "ghcr.io/jeremyhahn/go-xkms-ci-it@$DIGEST"
called "docker buildx imagetools inspect ghcr.io/jeremyhahn/go-xkms-ci-it:fedcba9876543210-main"

start_case "resolve: the content tag ignores a caller's TOOLCHAIN_IMAGE"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" TOOLCHAIN_IMAGE=other:tag
stdout_is "$TOOLCHAIN_REPO@$DIGEST"

start_case "resolve: main has not published this content"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_INSPECT=missing
stdout_is ""
stderr_has "main has not published $TOOLCHAIN_REPO:0123456789abcdef-main"

start_case "resolve: an unreadable registry names the pull-credential gap"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_INSPECT=denied
stdout_is ""
stderr_has "::warning::ci-registry: cannot read"
stderr_has "neither the run's token nor an anonymous pull"

start_case "resolve: a refused run token falls back to an anonymous read"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_LOGIN_RC=1
stdout_is "$TOOLCHAIN_REPO@$DIGEST"
stderr_has "the Gitea registry refused the run's token"
no_secret_printed

start_case "resolve: no run token reads anonymously"
run_script 0 resolve toolchain
stdout_is "$TOOLCHAIN_REPO@$DIGEST"
not_called "docker login"

start_case "resolve: an empty credential name fails naming the variable, not the value"
run_script 1 resolve toolchain -- "CI_REGISTRY_TOKEN=$SECRET"
stderr_has "CI_REGISTRY_USER is empty"
not_called "docker login"
no_secret_printed
run_script 1 resolve toolchain -- CI_REGISTRY_USER=runner
stderr_has "CI_REGISTRY_TOKEN is empty"

start_case "resolve: an unknown family"
run_script 1 resolve debian -- "${RUN_TOKEN[@]}"
stderr_has "family 'debian' is neither toolchain nor it"

start_case "resolve: no forge URL, no registry"
run_script 1 resolve toolchain -- GITHUB_SERVER_URL=
stderr_has "GITHUB_SERVER_URL is empty"

# --------------------------------------------------------------------------
start_case "publish: only on a push to main"
run_script 1 publish toolchain -- "${RUN_TOKEN[@]}"
stderr_has "CI_PUBLISH is not true"
not_called "docker login"

start_case "publish: the forge push builds, pushes and prints the digest with the release runner's credential"
run_script 0 publish toolchain -- "${RELEASE[@]}" "${RUN_TOKEN[@]}" FAKE_INSPECT=missing
stdout_is "$TOOLCHAIN_REPO@$DIGEST"
called "docker login $FORGE -u releaser --password-stdin"
not_called "-u runner"
called "make --no-print-directory docker-build-toolchain MODULE_ENV_FILE="
called "docker tag $TOOLCHAIN_TAG $TOOLCHAIN_REPO:0123456789abcdef-main"
called "docker push $TOOLCHAIN_REPO:0123456789abcdef-main"
called "modauth-mode 600"
called "modauth-names GOPRIVATE"
if [ -e "$(cat "$WORK_DIR/modauth-path")" ]; then
  fail "the staged module credential file outlived the script"
else
  pass "the staged module credential file is removed"
fi
no_secret_printed

start_case "publish: content main published already is not rebuilt"
run_script 0 publish toolchain -- "${RELEASE[@]}"
stdout_is "$TOOLCHAIN_REPO@$DIGEST"
not_called "make "
not_called "docker push"

start_case "publish: the integration image builds under its content tag"
run_script 0 publish it -- "${RELEASE[@]}" FAKE_INSPECT=missing
called "docker-build-it IT_IMAGE=$IT_TAG"

start_case "publish: GHCR pushes with the run's token"
run_script 0 publish toolchain -- CI_PUBLISH=true "${RUN_TOKEN[@]}" GITHUB_SERVER_URL=https://github.com FAKE_INSPECT=missing
called "docker login ghcr.io -u runner --password-stdin"
called "docker push ghcr.io/jeremyhahn/go-xkms-ci-toolchain:0123456789abcdef-main"

start_case "publish: a missing release credential names its source"
run_script 1 publish toolchain -- CI_PUBLISH=true "RELEASE_REGISTRY=$FORGE" "RELEASE_REGISTRY_TOKEN=$RELEASE_SECRET" "${RUN_TOKEN[@]}"
stderr_has "RELEASE_REGISTRY_USER is empty: the release runner's credential is not in the job's environment"
not_called "docker login"
no_secret_printed
run_script 1 publish toolchain -- CI_PUBLISH=true "${RUN_TOKEN[@]}"
stderr_has "RELEASE_REGISTRY is empty"

start_case "publish: a refused login names the registry"
run_script 1 publish toolchain -- "${RELEASE[@]}" FAKE_LOGIN_RC=1
stderr_has "the Gitea registry refused the login: the release runner's credential cannot push jeremyhahn's container packages"
not_called "docker push"
no_secret_printed

start_case "publish: a failed build pushes nothing"
run_script 1 publish toolchain -- "${RELEASE[@]}" FAKE_INSPECT=missing FAKE_BUILD_RC=2
stderr_has "cannot build $TOOLCHAIN_TAG"
not_called "docker push"

# --------------------------------------------------------------------------
start_case "use: pulls the digest and holds it until the teardown"
run_script 0 use toolchain "$TOOLCHAIN_REPO@$DIGEST" -- "${RUN_TOKEN[@]}"
called "docker pull --quiet $TOOLCHAIN_REPO@$DIGEST"
called "docker create --pull never --name go-xkms-ci-hold-42-1-toolchain-"
if grep -qE "^TOOLCHAIN_IMAGE=$TOOLCHAIN_REPO@$DIGEST\$" "$WORK_DIR/stdout" &&
  grep -qE '^TOOLCHAIN_HOLD=go-xkms-ci-hold-42-1-toolchain-[0-9a-f]{8}$' "$WORK_DIR/stdout"; then
  pass "prints TOOLCHAIN_IMAGE and TOOLCHAIN_HOLD for \$GITHUB_ENV"
else
  fail "printed '$(cat "$WORK_DIR/stdout")'"
fi
not_called "make "
no_secret_printed

start_case "use: a bad digest reference is refused before any pull"
run_script 1 use toolchain "$TOOLCHAIN_REPO:latest" -- "${RUN_TOKEN[@]}"
stderr_has "is not a digest reference"
not_called "docker pull"
run_script 1 use toolchain "$TOOLCHAIN_REPO@sha256:abc" -- "${RUN_TOKEN[@]}"
stderr_has "is not a digest reference"

start_case "use: a reference in another registry is refused"
run_script 1 use toolchain "ghcr.io/jeremyhahn/go-xkms-ci-toolchain@$DIGEST" -- "${RUN_TOKEN[@]}"
stderr_has "is not in this run's registry, $FORGE"
not_called "docker pull"

start_case "use: a failed pull fails after three attempts and never rebuilds"
run_script 1 use toolchain "$TOOLCHAIN_REPO@$DIGEST" -- "${RUN_TOKEN[@]}" FAKE_PULL_RC=1
stderr_has "cannot pull $TOOLCHAIN_REPO@$DIGEST after 3 attempts"
if [ "$(grep -c '^docker pull ' "$CALL_LOG")" -eq 3 ]; then
  pass "three pull attempts"
else
  fail "$(grep -c '^docker pull ' "$CALL_LOG") pull attempts, want 3"
fi
not_called "make "

start_case "use: an empty credential name fails before the pull"
run_script 1 use toolchain "$TOOLCHAIN_REPO@$DIGEST" -- "CI_REGISTRY_TOKEN=$SECRET"
stderr_has "CI_REGISTRY_USER is empty"
not_called "docker pull"
no_secret_printed

start_case "use: no reference on a pull request builds locally, with no push, held by image ID"
run_script 0 use it "" -- "${RUN_TOKEN[@]}"
called "docker-build-it IT_IMAGE=$IT_TAG"
called "docker create --pull never --name go-xkms-ci-hold-42-1-it-"
not_called "docker push"
not_called "docker login"
if grep -qx "IT_IMAGE=$IMAGE_ID" "$WORK_DIR/stdout" && grep -q '^IT_HOLD=go-xkms-ci-hold-42-1-it-' "$WORK_DIR/stdout"; then
  pass "prints IT_IMAGE as the image ID and IT_HOLD"
else
  fail "printed '$(cat "$WORK_DIR/stdout")'"
fi

start_case "use: no reference on a push to main fails rather than rebuild"
run_script 1 use toolchain "" -- CI_PUBLISH=true
stderr_has "a consumer runs the image ci-images published and never builds its own"
not_called "make "

start_case "use: no CI_STACK_PREFIX, no hold name"
run_script 1 use toolchain "$TOOLCHAIN_REPO@$DIGEST" -- CI_STACK_PREFIX=
stderr_has "CI_STACK_PREFIX does not name"
not_called "docker pull"

# --------------------------------------------------------------------------
start_case "release: removes each hold and skips an empty name"
run_script 0 release go-xkms-ci-hold-42-1-toolchain-0a0b0c0d ""
called "docker rm -f go-xkms-ci-hold-42-1-toolchain-0a0b0c0d"
if [ "$(grep -c '^docker rm' "$CALL_LOG")" -eq 1 ]; then
  pass "one removal"
else
  fail "$(grep -c '^docker rm' "$CALL_LOG") removals, want 1"
fi

start_case "an unknown command"
run_script 1 push toolchain
stderr_has "unknown command 'push'"

# --------------------------------------------------------------------------
if [ "$FAILURES" -eq 0 ]; then
  echo "PASS: ci-registry.sh hands the CI images over by digest"
  exit 0
fi
echo "FAILED: $FAILURES assertion(s)" >&2
exit 1
