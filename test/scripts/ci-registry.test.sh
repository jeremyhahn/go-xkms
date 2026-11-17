#!/bin/bash
# Shell-level tests for scripts/ci-registry.sh (ruling 169; the go-qrdb #1135
# pattern): the CI image handoff from the ci-images job to every consumer.
#
# These pin what the script may do with a registry and a credential: the
# registry is the forge's (or GHCR on GitHub), a forge push reads the release
# runner's RELEASE_REGISTRY* names alone (ruling 173), a forge read is
# anonymous, a GHCR read takes the run's token, a failed read degrades to a
# local build, a consumer never rebuilds an image main
# published, every reference is a digest, and no credential is ever printed.
#
# No Docker daemon or registry is involved: a fake `docker`, a fake `make` and
# a fake `curl` on PATH record every invocation and answer from FAKE_*
# variables. The fake curl is the registry: it serves the registry API (OCI
# Distribution Spec v1.1.1, the Distribution token flow) on one scheme,
# FAKE_SERVES, as a forge does. DOCKER_HOST points at a closed port, so a
# PATH mistake fails loudly.

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
BEARER_SECRET="s3cr3t-bearer-token"
# The manifest the fake registry serves, ending in a newline: its digest is
# the sha256 of these exact bytes, the newline included.
MANIFEST=$'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}\n'
MANIFEST_DIGEST="sha256:$(printf '%s' "$MANIFEST" | sha256sum | cut -d' ' -f1)"

cat >"$FAKE_BIN/docker" <<'FAKE'
#!/bin/bash
# Fake docker: record each invocation and answer from FAKE_* variables.
echo "docker $*" >>"$FAKE_LOG"
# The Docker config each pull and push ran with (#2243 P1-2): its directory and
# the names in it, never their contents.
case "$1" in
  pull | push) echo "docker-cfg $1 ${*: -1} ${DOCKER_CONFIG:-unset} files=$(ls -A "${DOCKER_CONFIG:-/nonexistent}" 2>/dev/null | tr '\n' ' ')" >>"$FAKE_LOG" ;;
esac
case "$1" in
  login)
    stdin=$(cat)
    echo "login-stdin-bytes ${#stdin}" >>"$FAKE_LOG"
    case "${FAKE_LOGIN:-ok}" in
      ok) echo "Login Succeeded" ;;
      refused) echo "Error response from daemon: login attempt to https://$2/v2/ failed with status: 401 Unauthorized" >&2; exit 1 ;;
      unreachable) echo "Error response from daemon: Get \"https://$2/v2/\": dial tcp: lookup $2: no such host" >&2; exit 1 ;;
      *) echo "Error response from daemon: something went wrong" >&2; exit 1 ;;
    esac
    ;;
  image)
    case "$4" in
      *RepoDigests*)
        case "${FAKE_REPO_DIGEST:-pushed}" in
          pushed)
            # FAKE_LAN_DIGEST: the digest an image pulled from FAKE_LAN reports.
            d=$FAKE_DIGEST
            if [ -n "${FAKE_LAN:-}" ]; then
              case "$5" in "$FAKE_LAN/"*) d=${FAKE_LAN_DIGEST:-$FAKE_DIGEST} ;; esac
            fi
            echo "${5%:*}@$d"
            ;;
          elsewhere) echo "elsewhere.invalid/jeremyhahn/go-xkms-ci-toolchain@$FAKE_DIGEST" ;;
          short) echo "${5%:*}@sha256:abc" ;;
        esac
        ;;
      *Created*)
        case " ${FAKE_INSPECT_FAIL:-} " in *" $5 "*) echo "Error: No such image: $5" >&2; exit 1 ;; esac
        printf '%s\n' "${FAKE_IMAGES:-}" | while read -r _ _ i c; do
          [ "$i" != "$5" ] || { echo "$c"; break; }
        done
        ;;
      *)
        # FAKE_RETAG_ID: a tag (not a digest-pinned ref) now names another
        # image, as after a concurrent push or rebuild of the content tag.
        case "${*: -1}" in
          *@sha256:*) echo "$FAKE_IMAGE_ID" ;;
          *) echo "${FAKE_RETAG_ID:-$FAKE_IMAGE_ID}" ;;
        esac
        ;;
    esac
    ;;
  # FAKE_IMAGES: one "<repository> <tag> <id> <created>" line per name.
  images) printf '%s\n' "${FAKE_IMAGES:-}" | cut -d' ' -f1-3 ;;
  ps) case " ${FAKE_IN_USE:-} " in *" ${4#ancestor=} "*) echo c0ffee000000 ;; esac ;;
  rmi)
    case " ${FAKE_RMI_FAIL:-} " in *" $2 "*) echo "Error response from daemon: conflict: unable to remove $2" >&2; exit 1 ;; esac
    echo "Untagged: $2"
    ;;
  pull)
    # FAKE_LAN: the CI_IMAGE_REGISTRY a case sets; its pulls answer FAKE_LAN_PULL_RC.
    if [ -n "${FAKE_LAN:-}" ]; then
      case "$*" in *" $FAKE_LAN/"*) exit "${FAKE_LAN_PULL_RC:-0}" ;; esac
    fi
    exit "${FAKE_PULL_RC:-0}"
    ;;
  push) exit "${FAKE_PUSH_RC:-0}" ;;
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
cat >"$FAKE_BIN/curl" <<'FAKE'
#!/bin/bash
# The CI_IMAGE_REGISTRY probe (#2243): FAKE_LAN_CURL_RC answers it (7 = closed port).
if [ -n "${FAKE_LAN:-}" ]; then
  case " $* " in *" http://$FAKE_LAN/v2/ "*) echo "curl $*" >>"$FAKE_LOG"; exit "${FAKE_LAN_CURL_RC:-0}" ;; esac
fi
# Fake curl: a registry on every host, served over FAKE_SERVES (https by
# default). It records each request with the credential it carried named,
# never its value, and answers from FAKE_* variables:
#   FAKE_AUTH      the manifest endpoint's challenge: bearer (default), basic, none
#   FAKE_REALM     the Bearer challenge's realm: served (default), http, none
#   FAKE_TOKEN     the token service: ok (default), access, refused, forbidden, error, notoken
#   FAKE_MANIFEST  the tag: found (default), missing, denied, forbidden, error, html
#   FAKE_CTYPE     the found manifest's Content-Type
#   FAKE_DCD       the found manifest's Docker-Content-Digest: its digest
#                  (default), none, or this value
#   FAKE_DOWN      "<manifest|token> <curl exit code>": that endpoint gives no answer
# The Authorization header comes from a curl config on stdin (-K -) alone.
out="" dump="" write="" url="" header="" query="" accept="" method=GET
while [ $# -gt 0 ]; do
  case $1 in
    -sS | --get) ;;
    -I) method=HEAD ;;
    -K)
      [ "$2" = - ] || { echo "curl: config '$2' is not stdin" >&2; exit 2; }
      while IFS= read -r line; do
        case $line in
          'header = "'*'"') header=${line#'header = "'} header=${header%'"'} ;;
          *) echo "curl: unexpected config line" >&2; exit 2 ;;
        esac
      done
      shift
      ;;
    --max-time) shift ;;
    -o) out=$2; shift ;;
    -D) dump=$2; shift ;;
    -w) write=$2; shift ;;
    --data-urlencode) query+="&$2"; shift ;;
    -H)
      case $2 in
        Accept:*) accept=${2#Accept: } ;;
        *) echo "curl: header '$2' outside the pipe" >&2; exit 2 ;;
      esac
      shift
      ;;
    -*) echo "curl: unexpected option $1" >&2; exit 2 ;;
    *) url=$1 ;;
  esac
  shift
done
scheme=${url%%://*} rest=${url#*://}
host=${rest%%/*} path=/${rest#*/}

# Who the request is: none, "basic <user>" (a credential this run holds) or
# "basic <user> wrong", "bearer" (the token this registry issued) or
# "bearer wrong".
who=none
case $header in
  "Authorization: Basic "*)
    pair=$(printf '%s' "${header#Authorization: Basic }" | base64 -d)
    who="basic ${pair%%:*}"
    if [ "$pair" != "${CI_REGISTRY_USER:-}:${CI_REGISTRY_TOKEN:-}" ] &&
      [ "$pair" != "${RELEASE_REGISTRY_USER:-}:${RELEASE_REGISTRY_TOKEN:-}" ]; then
      who+=" wrong"
    fi
    ;;
  "Authorization: Bearer "*)
    who=bearer
    [ "${header#Authorization: Bearer }" = "$FAKE_BEARER" ] || who+=" wrong"
    ;;
esac
echo "curl $method $url${query:+?${query#&}} auth=$who" >>"$FAKE_LOG"
[ -z "$accept" ] || echo "curl-accept $accept" >>"$FAKE_LOG"

# respond <status> <content-type> <body> [header...]
respond() {
  local status=$1 ctype=$2 body=$3 h w
  shift 3
  if [ -n "$dump" ]; then
    {
      printf 'HTTP/1.1 %s Fake\r\n' "$status"
      [ -z "$ctype" ] || printf 'Content-Type: %s\r\n' "$ctype"
      for h in "$@"; do printf '%s\r\n' "$h"; done
      printf '\r\n'
    } >"$dump"
  fi
  if [ -n "$out" ]; then printf '%s' "$body" >"$out"; else printf '%s' "$body"; fi
  w=${write//\\n/$'\n'}
  printf '%s' "${w//'%{http_code}'/$status}"
  exit 0
}

# fail <exit code> <message>: no HTTP answer. Like curl, the message goes to
# stderr and the write-out still prints, with status 000.
fail() {
  local w=${write//\\n/$'\n'}
  echo "curl: ($1) $2" >&2
  printf '%s' "${w//'%{http_code}'/000}"
  exit "$1"
}

endpoint=manifest
[ "$path" != /v2/token ] || endpoint=token
case ${FAKE_DOWN:-} in
  "$endpoint "*)
    case ${FAKE_DOWN#* } in
      6) fail 6 "Could not resolve host: $host" ;;
      28) fail 28 "Operation timed out after 60001 milliseconds with 0 bytes received" ;;
      *) fail 7 "Failed to connect to ${host%:*} port 3000 after 0 ms: Couldn't connect to server" ;;
    esac
    ;;
esac
served=${FAKE_SERVES:-https}
if [ "$scheme" != "$served" ]; then
  [ "$scheme" = https ] || respond 400 text/html "The plain HTTP request was sent to HTTPS port"
  fail 35 "OpenSSL/3.0.13: error:0A00010B:SSL routines::wrong version number"
fi

if [ "$endpoint" = token ]; then
  case ${FAKE_TOKEN:-ok} in
    forbidden) respond 403 application/json '{"errors":[{"code":"DENIED"}]}' ;;
    error) respond 500 text/plain "internal error" ;;
    notoken) respond 200 application/json '{"expires_in":60}' ;;
    refused) [ "$who" = none ] || respond 401 application/json '{"errors":[{"code":"UNAUTHORIZED"}]}' ;;
  esac
  case $who in *wrong) respond 401 application/json '{"errors":[{"code":"UNAUTHORIZED"}]}' ;; esac
  field=token
  [ "${FAKE_TOKEN:-ok}" != access ] || field=access_token
  respond 200 application/json "{\"$field\": \"$FAKE_BEARER\", \"expires_in\": 60}"
fi

name=${path#/v2/}
name=${name%/manifests/*}
case ${FAKE_AUTH:-bearer} in
  bearer)
    if [ "$who" != bearer ]; then
      case ${FAKE_REALM:-served} in
        served) realm="realm=\"$served://$host/v2/token\"," ;;
        http) realm="realm=\"http://$host/v2/token\"," ;;
        none) realm="" ;;
      esac
      respond 401 application/json '{"errors":[{"code":"UNAUTHORIZED"}]}' \
        "Www-Authenticate: Bearer ${realm}service=\"container_registry\",scope=\"repository:$name:pull\""
    fi
    ;;
  basic)
    case $who in
      "basic "*wrong | none | bearer*) respond 401 application/json '{"errors":[{"code":"UNAUTHORIZED"}]}' 'WWW-Authenticate: Basic realm="registry"' ;;
    esac
    ;;
esac
case ${FAKE_MANIFEST:-found} in
  missing) respond 404 application/json '{"errors":[{"code":"MANIFEST_UNKNOWN"}]}' ;;
  denied) respond 401 application/json '{"errors":[{"code":"UNAUTHORIZED"}]}' ;;
  forbidden) respond 403 application/json '{"errors":[{"code":"DENIED"}]}' ;;
  error) respond 500 text/plain "internal error" ;;
  html) respond 200 "text/html; charset=utf-8" "<html>sign in</html>" ;;
esac
dcd="Docker-Content-Digest: ${FAKE_DCD:-$FAKE_MANIFEST_DIGEST}"
[ "${FAKE_DCD:-}" != none ] || dcd=""
respond 200 "${FAKE_CTYPE:-application/vnd.oci.image.index.v1+json}" "$FAKE_MANIFEST_BODY" ${dcd:+"$dcd"}
FAKE
chmod +x "$FAKE_BIN/docker" "$FAKE_BIN/make" "$FAKE_BIN/curl"

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
      FAKE_BEARER="$BEARER_SECRET" \
      FAKE_MANIFEST_BODY="$MANIFEST" \
      FAKE_MANIFEST_DIGEST="$MANIFEST_DIGEST" \
      CI_REGISTRY_OWNER=example-ci-images \
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
  if grep -qF -e "$SECRET" -e "$RELEASE_SECRET" -e "$BEARER_SECRET" "$WORK_DIR/stdout" "$WORK_DIR/stderr" "$CALL_LOG"; then
    fail "a credential value reached the output or a command line"
  else
    pass "no credential value printed or passed as an argument"
  fi
}

# warnings_are <n>: the run printed exactly n ::warning:: lines.
warnings_are() {
  local n
  n=$(grep -c '^::warning::' "$WORK_DIR/stderr")
  if [ "$n" -eq "$1" ]; then
    pass "$1 warning line(s)"
  else
    fail "$n warning lines, want $1"
    sed 's/^/      /' "$WORK_DIR/stderr" >&2
  fi
}

# stdout_is_digest_ref: what the script printed is one digest reference, the
# shape ci.yml's Validate step and `use` accept.
stdout_is_digest_ref() {
  if grep -qxE '[^@ ]+@sha256:[0-9a-f]{64}' "$WORK_DIR/stdout" && [ "$(wc -l <"$WORK_DIR/stdout")" -eq 1 ]; then
    pass "prints one digest reference"
  else
    fail "printed '$(cat "$WORK_DIR/stdout")', not one digest reference"
  fi
}

RUN_TOKEN=(CI_REGISTRY_USER=runner "CI_REGISTRY_TOKEN=$SECRET")
RELEASE=(CI_PUBLISH=true "RELEASE_REGISTRY=$FORGE" RELEASE_REGISTRY_USER=releaser "RELEASE_REGISTRY_TOKEN=$RELEASE_SECRET")
TOOLCHAIN_REPO="$FORGE/example-ci-images/go-xkms-ci-toolchain"

# --------------------------------------------------------------------------
MANIFEST_PATH="example-ci-images/go-xkms-ci-toolchain/manifests/0123456789abcdef-main"
TOKEN_QUERY="service=container_registry&scope=repository:example-ci-images/go-xkms-ci-toolchain:pull"
ACCEPT="application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json"
HTTP_FORGE=("GITHUB_SERVER_URL=http://$FORGE" FAKE_SERVES=http)

start_case "resolve: main's image of the same content, by digest, read anonymously from example-ci-images over https"
run_script 0 resolve toolchain
stdout_is "$TOOLCHAIN_REPO@$MANIFEST_DIGEST"
called "curl GET https://$FORGE/v2/token?$TOKEN_QUERY auth=none"
called "curl HEAD https://$FORGE/v2/$MANIFEST_PATH auth=bearer"
called "curl-accept $ACCEPT"
not_called "curl GET https://$FORGE/v2/$MANIFEST_PATH"
stderr_has "==> main published $TOOLCHAIN_REPO:0123456789abcdef-main as $MANIFEST_DIGEST; the consumers pull it"
warnings_are 0
not_called "docker login"
not_called "docker buildx"
no_secret_printed

start_case "resolve: a forge served over plain http is read over http"
run_script 0 resolve toolchain -- "${HTTP_FORGE[@]}"
stdout_is "$TOOLCHAIN_REPO@$MANIFEST_DIGEST"
called "curl GET http://$FORGE/v2/token?$TOKEN_QUERY auth=none"
called "curl HEAD http://$FORGE/v2/$MANIFEST_PATH auth=bearer"
not_called "https://"
warnings_are 0
no_secret_printed

start_case "resolve: the namespace is CI_REGISTRY_OWNER, else the repository's owner"
run_script 0 resolve toolchain -- CI_REGISTRY_OWNER=Other-Org
stdout_is "$FORGE/other-org/go-xkms-ci-toolchain@$MANIFEST_DIGEST"
run_script 0 resolve toolchain -- CI_REGISTRY_OWNER=
stdout_is "$FORGE/jeremyhahn/go-xkms-ci-toolchain@$MANIFEST_DIGEST"
run_script 1 resolve toolchain -- "CI_REGISTRY_OWNER=-bad/owner"
stderr_has "CI_REGISTRY_OWNER does not name a registry owner"
run_script 1 resolve toolchain -- CI_REGISTRY_OWNER= GITHUB_REPOSITORY_OWNER=
stderr_has "GITHUB_REPOSITORY_OWNER does not name a registry owner"

start_case "resolve: GHCR on GitHub answers the registry's challenge with the run's token, since a GHCR package is private"
run_script 0 resolve it -- "${RUN_TOKEN[@]}" GITHUB_SERVER_URL=https://github.com CI_REGISTRY_OWNER=
stdout_is "ghcr.io/jeremyhahn/go-xkms-ci-it@$MANIFEST_DIGEST"
called "curl GET https://ghcr.io/v2/jeremyhahn/go-xkms-ci-it/manifests/fedcba9876543210-main auth=none"
called "curl GET https://ghcr.io/v2/token?service=container_registry&scope=repository:jeremyhahn/go-xkms-ci-it:pull auth=basic runner"
called "curl GET https://ghcr.io/v2/jeremyhahn/go-xkms-ci-it/manifests/fedcba9876543210-main auth=bearer"
not_called "auth=basic runner wrong"
warnings_are 0
no_secret_printed

start_case "resolve: GHCR with no run token in the step reads anonymously"
run_script 0 resolve it -- GITHUB_SERVER_URL=https://github.com CI_REGISTRY_OWNER=
stdout_is "ghcr.io/jeremyhahn/go-xkms-ci-it@$MANIFEST_DIGEST"
called "curl GET https://ghcr.io/v2/token?service=container_registry&scope=repository:jeremyhahn/go-xkms-ci-it:pull auth=none"
not_called "auth=basic"
stderr_has "==> no run token in the step's environment; reading GHCR anonymously"

start_case "resolve: a GHCR read with half the run's token fails naming the missing half"
run_script 1 resolve it -- CI_REGISTRY_USER=runner GITHUB_SERVER_URL=https://github.com CI_REGISTRY_OWNER=
stderr_has "CI_REGISTRY_TOKEN is empty: the run's token is not in the job's environment"
not_called "curl"
run_script 1 resolve it -- "CI_REGISTRY_TOKEN=$SECRET" GITHUB_SERVER_URL=https://github.com CI_REGISTRY_OWNER=
stderr_has "CI_REGISTRY_USER is empty: the run's token is in the job's environment without its user"
not_called "curl"
no_secret_printed

start_case "resolve: the content tag ignores a caller's TOOLCHAIN_IMAGE"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" TOOLCHAIN_IMAGE=other:tag
stdout_is "$TOOLCHAIN_REPO@$MANIFEST_DIGEST"

GHCR=(GITHUB_SERVER_URL=https://github.com CI_REGISTRY_OWNER=)
start_case "resolve: the forge's public namespace is read anonymously, never with the run's token"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}"
stdout_is "$TOOLCHAIN_REPO@$MANIFEST_DIGEST"
called "curl GET https://$FORGE/v2/token?$TOKEN_QUERY auth=none"
not_called "auth=basic"
warnings_are 0
no_secret_printed

start_case "resolve: a GHCR Basic challenge is answered with the run's token, and refused without it"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" "${GHCR[@]}" FAKE_AUTH=basic
stdout_is "ghcr.io/jeremyhahn/go-xkms-ci-toolchain@$MANIFEST_DIGEST"
called "curl GET https://ghcr.io/v2/jeremyhahn/go-xkms-ci-toolchain/manifests/0123456789abcdef-main auth=basic runner"
warnings_are 0
no_secret_printed
run_script 0 resolve toolchain -- "${GHCR[@]}" FAKE_AUTH=basic
stdout_is ""
stderr_has "::warning::ci-registry: resolve: GHCR refused an anonymous pull's read of ghcr.io/jeremyhahn/go-xkms-ci-toolchain:0123456789abcdef-main (401/403): HTTP 401"
not_called "auth=basic"
warnings_are 1

start_case "resolve: an open registry is read with no challenge"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" "${GHCR[@]}" FAKE_AUTH=none
stdout_is "ghcr.io/jeremyhahn/go-xkms-ci-toolchain@$MANIFEST_DIGEST"
not_called "/v2/token"
not_called "auth=basic"

start_case "resolve: a token under access_token, and a Content-Type with parameters"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_TOKEN=access
stdout_is "$TOOLCHAIN_REPO@$MANIFEST_DIGEST"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" "FAKE_CTYPE=application/vnd.docker.distribution.manifest.list.v2+json; charset=utf-8"
stdout_is "$TOOLCHAIN_REPO@$MANIFEST_DIGEST"

start_case "resolve: the forge's digest is the one its answer names"
run_script 0 resolve toolchain -- "FAKE_DCD=$DIGEST"
stdout_is "$TOOLCHAIN_REPO@$DIGEST"

PENDING="$TOOLCHAIN_REPO:0123456789abcdef-main"
BUILDS="each consumer builds the toolchain image on its runner"

# Each case resolves to "" (the consumers build) and says why in one warning.
start_case "resolve: main has not published this content (404)"
for over in "" "${HTTP_FORGE[*]}"; do
  # shellcheck disable=SC2086 # $over is a list of VAR=VALUE words
  run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_MANIFEST=missing $over
  stdout_is ""
  stderr_has "::warning::ci-registry: resolve: main has not published $PENDING (not found); $BUILDS"
  warnings_are 1
done

start_case "resolve: a refused read (401/403) names the reader"
for manifest in denied forbidden; do
  run_script 0 resolve toolchain -- FAKE_MANIFEST=$manifest
  stdout_is ""
  stderr_has "::warning::ci-registry: resolve: the Gitea registry refused an anonymous pull's read of $PENDING (401/403): HTTP"
  stderr_has "$BUILDS"
  warnings_are 1
done
stderr_has "(401/403): HTTP 403"
run_script 0 resolve toolchain -- FAKE_TOKEN=forbidden
stdout_is ""
stderr_has "::warning::ci-registry: resolve: the Gitea registry refused an anonymous pull's read of $PENDING (401/403): the token service answered HTTP 403"
warnings_are 1

start_case "resolve: a registry or token service that does not answer"
for down in "manifest 7" "manifest 28" "manifest 6" "token 7"; do
  run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" "FAKE_DOWN=$down"
  stdout_is ""
  stderr_has "::warning::ci-registry: resolve: the Gitea registry did not answer the read of $PENDING (curl: ("
  stderr_has "$BUILDS"
  warnings_are 1
done
stderr_has "(curl: (7) Failed to connect to ${FORGE%:*} port 3000 after 0 ms: Couldn't connect to server)"

start_case "resolve: an unexpected reply"
UNEXPECTED="::warning::ci-registry: resolve: the Gitea registry gave an unexpected reply to the read of $PENDING"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_MANIFEST=error
stdout_is ""
stderr_has "$UNEXPECTED (HTTP 500); $BUILDS"
warnings_are 1
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_MANIFEST=html
stdout_is ""
stderr_has "$UNEXPECTED (an answer that is not a manifest (Content-Type 'text/html'))"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_TOKEN=error
stdout_is ""
stderr_has "$UNEXPECTED (the token service answered HTTP 500)"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_TOKEN=notoken
stdout_is ""
stderr_has "$UNEXPECTED (a token service answer that names no token)"
not_called "curl HEAD"
for dcd in none sha256:abc; do
  run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" "FAKE_DCD=$dcd"
  stdout_is ""
  stderr_has "$UNEXPECTED (an answer that names no digest)"
  warnings_are 1
done
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" "${GHCR[@]}" FAKE_REALM=none
stdout_is ""
stderr_has "GHCR gave an unexpected reply to the read of ghcr.io/jeremyhahn/go-xkms-ci-toolchain:0123456789abcdef-main (a challenge that names no token service)"
warnings_are 1

start_case "resolve: an https forge is never read over plain http"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" FAKE_SERVES=http
stdout_is ""
stderr_has "$UNEXPECTED (curl: (35) OpenSSL/3.0.13: error:0A00010B:SSL routines::wrong version number)"
not_called "http://"
warnings_are 1

start_case "resolve: an https registry's token service is never asked over plain http"
run_script 0 resolve toolchain -- "${RUN_TOKEN[@]}" "${GHCR[@]}" FAKE_REALM=http
stdout_is ""
stderr_has "(a challenge that sends the credential to a token service over plain http)"
not_called "/v2/token"
warnings_are 1
no_secret_printed

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
run_script 0 publish toolchain -- "${RELEASE[@]}" "${RUN_TOKEN[@]}" FAKE_MANIFEST=missing
stdout_is "$TOOLCHAIN_REPO@$DIGEST"
stdout_is_digest_ref
if [ "$(grep -c '^docker login ' "$CALL_LOG")" -eq 1 ] && grep -qx "docker login $FORGE -u releaser --password-stdin" "$CALL_LOG"; then
  pass "one login, exactly 'docker login <RELEASE_REGISTRY> -u <RELEASE_REGISTRY_USER> --password-stdin'"
else
  fail "the login is not the one stdin-fed login: $(grep '^docker login' "$CALL_LOG")"
fi
called "login-stdin-bytes ${#RELEASE_SECRET}"
stderr_has "==> logged in to the Gitea registry at $FORGE with the release runner's credential"
called "curl GET https://$FORGE/v2/token?$TOKEN_QUERY auth=basic releaser"
stderr_has "==> main has not published $TOOLCHAIN_REPO:0123456789abcdef-main (not found); building and pushing it"
stderr_has "==> pushed $TOOLCHAIN_REPO:0123456789abcdef-main as $DIGEST"
warnings_are 0
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
stdout_is "$TOOLCHAIN_REPO@$MANIFEST_DIGEST"
stderr_has "==> $TOOLCHAIN_REPO:0123456789abcdef-main is published already as $MANIFEST_DIGEST; nothing to build"
not_called "make "
not_called "docker push"

start_case "publish: the integration image builds under its content tag"
run_script 0 publish it -- "${RELEASE[@]}" FAKE_MANIFEST=missing
called "docker-build-it IT_IMAGE=$IT_TAG"

start_case "publish: GHCR pushes with the run's token"
run_script 0 publish toolchain -- CI_PUBLISH=true "${RUN_TOKEN[@]}" "${GHCR[@]}" FAKE_MANIFEST=missing
called "docker login ghcr.io -u runner --password-stdin"
called "curl GET https://ghcr.io/v2/token?service=container_registry&scope=repository:jeremyhahn/go-xkms-ci-toolchain:pull auth=basic runner"
called "docker push ghcr.io/jeremyhahn/go-xkms-ci-toolchain:0123456789abcdef-main"

start_case "publish: a missing release credential names its source"
run_script 1 publish toolchain -- CI_PUBLISH=true "RELEASE_REGISTRY=$FORGE" "RELEASE_REGISTRY_TOKEN=$RELEASE_SECRET" "${RUN_TOKEN[@]}"
stderr_has "RELEASE_REGISTRY_USER is empty: the release runner's credential is not in the job's environment"
not_called "docker login"
no_secret_printed
run_script 1 publish toolchain -- CI_PUBLISH=true "RELEASE_REGISTRY=$FORGE" RELEASE_REGISTRY_USER=releaser "${RUN_TOKEN[@]}"
stderr_has "RELEASE_REGISTRY_TOKEN is empty: the release runner's credential is not in the job's environment"
not_called "docker login"
no_secret_printed
run_script 1 publish toolchain -- CI_PUBLISH=true "${RUN_TOKEN[@]}"
stderr_has "RELEASE_REGISTRY is empty"
not_called "docker login"
run_script 1 publish toolchain -- CI_PUBLISH=true "RELEASE_REGISTRY=https://$FORGE" RELEASE_REGISTRY_USER=releaser "RELEASE_REGISTRY_TOKEN=$RELEASE_SECRET"
stderr_has "RELEASE_REGISTRY does not name a registry host"
not_called "docker login"
no_secret_printed

start_case "publish: a refused login names the registry"
run_script 1 publish toolchain -- "${RELEASE[@]}" FAKE_LOGIN=refused
stderr_has "the Gitea registry refused the login: the release runner's credential cannot push example-ci-images's container packages"
not_called "docker push"
no_secret_printed

start_case "publish: a login that gets no answer, or an unexpected one, names the case"
run_script 1 publish toolchain -- "${RELEASE[@]}" FAKE_LOGIN=unreachable
stderr_has "the Gitea registry did not answer the login with the release runner's credential"
not_called "docker push"
run_script 1 publish toolchain -- "${RELEASE[@]}" FAKE_LOGIN=odd
stderr_has "the Gitea registry gave an unexpected reply to the login with the release runner's credential"
not_called "docker push"
no_secret_printed

start_case "publish: a lookup that fails other than not-found says so, then pushes"
run_script 0 publish toolchain -- "${RELEASE[@]}" FAKE_MANIFEST=forbidden
stderr_has "::warning::ci-registry: publish: the Gitea registry refused the release runner's credential's read of $TOOLCHAIN_REPO:0123456789abcdef-main (401/403): HTTP 403"
called "docker push $TOOLCHAIN_REPO:0123456789abcdef-main"
stdout_is_digest_ref

start_case "publish: a release registry other than the forge's warns that pull requests will not find the image"
run_script 0 publish toolchain -- "${RELEASE[@]}" RELEASE_REGISTRY=registry.invalid:5000
stderr_has "::warning::ci-registry: publish: RELEASE_REGISTRY (registry.invalid:5000) is not the forge's registry ($FORGE), which pull requests resolve against"
stdout_is "registry.invalid:5000/example-ci-images/go-xkms-ci-toolchain@$MANIFEST_DIGEST"
warnings_are 1

start_case "publish: a forge served over plain http is looked up over http; any other registry over https"
run_script 0 publish toolchain -- "${RELEASE[@]}" "${HTTP_FORGE[@]}"
stdout_is "$TOOLCHAIN_REPO@$MANIFEST_DIGEST"
called "curl GET http://$FORGE/v2/token?$TOKEN_QUERY auth=basic releaser"
not_called "https://"
run_script 0 publish toolchain -- "${RELEASE[@]}" RELEASE_REGISTRY=registry.invalid:5000 "GITHUB_SERVER_URL=http://$FORGE"
stdout_is "registry.invalid:5000/example-ci-images/go-xkms-ci-toolchain@$MANIFEST_DIGEST"
called "curl GET https://registry.invalid:5000/v2/example-ci-images/go-xkms-ci-toolchain/manifests/0123456789abcdef-main auth=bearer"
not_called "http://"
no_secret_printed

start_case "publish: a push that reports no digest fails"
for repo_digest in none elsewhere; do
  run_script 1 publish toolchain -- "${RELEASE[@]}" FAKE_MANIFEST=missing FAKE_REPO_DIGEST=$repo_digest
  stderr_has "the push of $TOOLCHAIN_REPO:0123456789abcdef-main reported no digest"
  stdout_is ""
done
run_script 1 publish toolchain -- "${RELEASE[@]}" FAKE_MANIFEST=missing FAKE_REPO_DIGEST=short
stderr_has "'$TOOLCHAIN_REPO@sha256:abc' is not a digest reference"
stdout_is ""

start_case "publish: a failed build pushes nothing"
run_script 1 publish toolchain -- "${RELEASE[@]}" FAKE_MANIFEST=missing FAKE_BUILD_RC=2
stderr_has "cannot build $TOOLCHAIN_TAG"
not_called "docker push"

# --------------------------------------------------------------------------
start_case "use: on the forge, pulls the digest anonymously, with no login, and holds it until the teardown"
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
not_called "docker login"
no_secret_printed
run_script 0 use toolchain "$TOOLCHAIN_REPO@$DIGEST" -- "${HTTP_FORGE[@]}"
called "docker pull --quiet $TOOLCHAIN_REPO@$DIGEST"
not_called "docker login"

GHCR_REPO=ghcr.io/jeremyhahn/go-xkms-ci-toolchain
start_case "use: on GHCR, logs in with the run's token before the pull, since a GHCR package is private"
run_script 0 use toolchain "$GHCR_REPO@$DIGEST" -- "${RUN_TOKEN[@]}" "${GHCR[@]}"
called "docker login ghcr.io -u runner --password-stdin"
called "docker pull --quiet $GHCR_REPO@$DIGEST"
if grep -qx "TOOLCHAIN_IMAGE=$GHCR_REPO@$DIGEST" "$WORK_DIR/stdout"; then
  pass "prints the GHCR TOOLCHAIN_IMAGE"
else
  fail "printed '$(cat "$WORK_DIR/stdout")'"
fi
warnings_are 0
no_secret_printed

start_case "use: a refused GHCR login is a warning, and the pull goes on anonymously"
run_script 0 use toolchain "$GHCR_REPO@$DIGEST" -- "${RUN_TOKEN[@]}" "${GHCR[@]}" FAKE_LOGIN=refused
called "docker pull --quiet $GHCR_REPO@$DIGEST"
stderr_has "::warning::ci-registry: GHCR refused the run's token (packages: read); reading anonymously"
warnings_are 1
no_secret_printed

start_case "use: a GHCR pull with no run token in the step is anonymous"
run_script 0 use toolchain "$GHCR_REPO@$DIGEST" -- "${GHCR[@]}"
called "docker pull --quiet $GHCR_REPO@$DIGEST"
not_called "docker login"
stderr_has "==> no run token in the step's environment; reading GHCR anonymously"

start_case "use: a GHCR pull with the token's user and no token fails before any login or pull"
run_script 1 use toolchain "$GHCR_REPO@$DIGEST" -- CI_REGISTRY_USER=runner "${GHCR[@]}"
stderr_has "CI_REGISTRY_TOKEN is empty: the run's token is not in the job's environment"
not_called "docker login"
not_called "docker pull"

start_case "use: a reference outside example-ci-images is refused before any pull"
run_script 1 use toolchain "$FORGE/jeremyhahn/go-xkms-ci-toolchain@$DIGEST"
stderr_has "'$FORGE/jeremyhahn/go-xkms-ci-toolchain@$DIGEST' is not under $FORGE/example-ci-images/, where main publishes"
not_called "docker pull"
run_script 1 use toolchain "$FORGE/example-ci-images-x/go-xkms-ci-toolchain@$DIGEST"
stderr_has "is not under $FORGE/example-ci-images/"
not_called "docker pull"

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

start_case "use: a failed pull tries three times, then builds on this runner (DS-9239)"
run_script 0 use toolchain "$TOOLCHAIN_REPO@$DIGEST" -- "${RUN_TOKEN[@]}" FAKE_PULL_RC=1
stderr_has "failed (attempt 2 of 3)"
stderr_has "cannot pull $TOOLCHAIN_REPO@$DIGEST; building it on this runner"
called "docker-build-toolchain"
if [ "$(grep -c '^docker pull ' "$CALL_LOG")" -eq 3 ]; then
  pass "three pull attempts"
else
  fail "$(grep -c '^docker pull ' "$CALL_LOG") pull attempts, want 3"
fi
called "make --no-print-directory docker-build-toolchain"

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

# DS-9239 (ruling 752): a consumer never turns a job red because no image of
# main's can be had; a missing ref on a push to main, or a forge pull that
# fails every attempt, falls back to a build on this runner.
FB_LAN=lan.invalid:5000
FB_REF="$TOOLCHAIN_REPO@sha256:$(printf '%064d' 0 | tr 0 a)"

start_case "use (e): CI_PUBLISH=true, empty ref, no CI_IMAGE_REGISTRY: builds on this runner"
run_script 0 use toolchain "" -- CI_PUBLISH=true
called "docker-build-toolchain"
stderr_has "building it on this runner"
not_called "docker push"

start_case "use (f): CI_PUBLISH=true, empty ref, CI_IMAGE_REGISTRY misses: builds on this runner"
run_script 0 use toolchain "" -- CI_PUBLISH=true CI_IMAGE_REGISTRY="$FB_LAN" FAKE_LAN="$FB_LAN" FAKE_LAN_PULL_RC=1
called "docker pull --quiet $FB_LAN/go-xkms-toolchain:"
called "docker-build-toolchain"

start_case "use (g): the forge pull fails every attempt: builds on this runner"
run_script 0 use toolchain "$FB_REF" -- "GITHUB_SERVER_URL=https://$FORGE" CI_REGISTRY_BACKOFF=0 FAKE_PULL_RC=1
stderr_has "cannot pull $FB_REF; building it on this runner"
called "docker-build-toolchain"

start_case "use (h): CI_IMAGE_REGISTRY misses and the forge pull fails: builds on this runner"
run_script 0 use toolchain "$FB_REF" -- "GITHUB_SERVER_URL=https://$FORGE" CI_REGISTRY_BACKOFF=0 FAKE_PULL_RC=1 CI_IMAGE_REGISTRY="$FB_LAN" FAKE_LAN="$FB_LAN" FAKE_LAN_PULL_RC=1
stderr_has "cannot pull $FB_REF; building it on this runner"
called "docker-build-toolchain"

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

# --------------------------------------------------------------------------
# retain (#1789): four IT generations, each under its local and registry
# names, one older toolchain generation and an unrelated image.
gen_id() { printf 'sha256:%064d' "$1"; }
IT_REPO="$FORGE/example-ci-images/go-xkms-ci-it"
RETAIN_IMAGES=""
for g in 1 2 3 4; do
  RETAIN_IMAGES+="go-xkms-ci-it ${g}${g}${g}${g}000000000000 $(gen_id "$g") 2026-10-2${g}T10:00:00.5Z"$'\n'
  RETAIN_IMAGES+="$IT_REPO ${g}${g}${g}${g}000000000000-main $(gen_id "$g") 2026-10-2${g}T10:00:00.5Z"$'\n'
done
RETAIN_IMAGES+="go-xkms-toolchain 0123456789abcdef $(gen_id 5) 2026-01-01T00:00:00Z"$'\n'
RETAIN_IMAGES+="$FORGE/example-ci-images/go-xkms-ci-toolchain 0123456789abcdef-main $(gen_id 5) 2026-01-01T00:00:00Z"$'\n'
RETAIN_IMAGES+="postgres 16 $(gen_id 6) 2025-01-01T00:00:00Z"

start_case "retain: removes all but the newest two generations, by every name"
run_script 0 retain it -- CI_PUBLISH=true FAKE_IMAGES="$RETAIN_IMAGES"
for g in 1 2; do
  called "docker rmi go-xkms-ci-it:${g}${g}${g}${g}000000000000"
  called "docker rmi $IT_REPO:${g}${g}${g}${g}000000000000-main"
done
for g in 3 4; do
  not_called "docker rmi go-xkms-ci-it:${g}${g}${g}${g}"
  not_called "docker rmi $IT_REPO:${g}${g}${g}${g}"
done
not_called "docker rmi -f"
not_called "docker rmi sha256:"
not_called "docker rmi go-xkms-toolchain"
not_called "docker rmi $FORGE/example-ci-images/go-xkms-ci-toolchain"
not_called "docker rmi postgres"
not_called "docker login"
stdout_is ""
warnings_are 0

start_case "retain: keeps an old generation a container uses"
run_script 0 retain it -- CI_PUBLISH=true FAKE_IMAGES="$RETAIN_IMAGES" FAKE_IN_USE="$(gen_id 1)"
called "docker ps -aq --filter ancestor=$(gen_id 1)"
not_called "docker rmi go-xkms-ci-it:1111"
not_called "docker rmi $IT_REPO:1111"
called "docker rmi go-xkms-ci-it:2222000000000000"
stderr_has "($(gen_id 1)) is used by a container; it is kept"

start_case "retain: a failed removal warns and retain goes on"
run_script 0 retain it -- CI_PUBLISH=true FAKE_IMAGES="$RETAIN_IMAGES" FAKE_RMI_FAIL="go-xkms-ci-it:1111000000000000"
stderr_has "cannot remove go-xkms-ci-it:1111000000000000"
called "docker rmi $IT_REPO:1111000000000000-main"
called "docker rmi go-xkms-ci-it:2222000000000000"
warnings_are 1

start_case "retain: an image it cannot inspect is kept"
run_script 0 retain it -- CI_PUBLISH=true FAKE_IMAGES="$RETAIN_IMAGES" FAKE_INSPECT_FAIL="$(gen_id 1)"
not_called "docker rmi go-xkms-ci-it:1111"
called "docker rmi go-xkms-ci-it:2222000000000000"
warnings_are 1

start_case "retain: the other family's generations are its own"
run_script 0 retain toolchain -- CI_PUBLISH=true FAKE_IMAGES="$RETAIN_IMAGES"
not_called "docker rmi"

start_case "retain: refuses unless CI_PUBLISH is true"
run_script 1 retain it -- FAKE_IMAGES="$RETAIN_IMAGES"
stderr_has "CI_PUBLISH is not true"
not_called "docker"

start_case "retain: an unknown family"
run_script 1 retain bogus -- CI_PUBLISH=true FAKE_IMAGES="$RETAIN_IMAGES"
stderr_has "family 'bogus' is neither toolchain nor it"
not_called "docker"

start_case "an unknown command"
run_script 1 push toolchain
stderr_has "unknown command 'push'"

# #2243 (ruling 752): CI_IMAGE_REGISTRY, a LAN registry with no auth, serves
# the content-hash tag; a hit is pulled instead of built, a miss is built and
# pushed, and neither a failed pull nor a failed push turns the job red.
LAN=lan.invalid:5000
LAN_TC="$LAN/$TOOLCHAIN_TAG"

start_case "use: CI_IMAGE_REGISTRY hit pulls the content tag, tags it locally, builds nothing"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN"
stderr_has "pulled $LAN_TC $DIGEST"
called "docker pull --quiet $LAN_TC"
called "docker tag $LAN_TC $TOOLCHAIN_TAG"
not_called "docker-build-toolchain"
not_called "docker push"
not_called "docker login"
if grep -qx "TOOLCHAIN_IMAGE=$IMAGE_ID" "$WORK_DIR/stdout" && grep -q '^TOOLCHAIN_HOLD=go-xkms-ci-hold-42-1-toolchain-' "$WORK_DIR/stdout"; then
  pass "prints TOOLCHAIN_IMAGE as the image ID and TOOLCHAIN_HOLD"
else
  fail "printed '$(cat "$WORK_DIR/stdout")'"
fi

start_case "use: with no ref, a CI_IMAGE_REGISTRY hit needs no GITHUB_SERVER_URL and skips the forge pull"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" GITHUB_SERVER_URL=
stderr_has "pulled $LAN_TC $DIGEST"
not_called "docker pull --quiet $FORGE"
not_called "docker-build-toolchain"
# Codex round 2 P1-1: a ref is checked against GITHUB_SERVER_URL's registry
# before the CI_IMAGE_REGISTRY path, so with no GITHUB_SERVER_URL it is refused.
start_case "use: a ref with no GITHUB_SERVER_URL is refused before any CI_IMAGE_REGISTRY pull"
run_script 1 use toolchain "$FORGE/example-ci-images/go-xkms-ci-toolchain@$DIGEST" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" GITHUB_SERVER_URL=
stderr_has "GITHUB_SERVER_URL is empty"
not_called "docker pull"

start_case "use: CI_IMAGE_REGISTRY miss builds, tags and pushes the content tag"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" FAKE_LAN_PULL_RC=1
called "docker pull --quiet $LAN_TC"
called "docker-build-toolchain"
called "docker tag $TOOLCHAIN_TAG $LAN_TC"
called "docker push $LAN_TC"
stderr_has "miss, built and pushed $LAN_TC"
not_called "docker login"

start_case "use: CI_IMAGE_REGISTRY push failure is one line and the job stays green"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" FAKE_LAN_PULL_RC=1 FAKE_PUSH_RC=1
called "docker-build-toolchain"
called "docker push $LAN_TC"
stderr_has "miss, built, push failed"
if grep -qx "TOOLCHAIN_IMAGE=$IMAGE_ID" "$WORK_DIR/stdout"; then
  pass "prints TOOLCHAIN_IMAGE after a failed push"
else
  fail "printed '$(cat "$WORK_DIR/stdout")'"
fi

start_case "use: CI_IMAGE_REGISTRY unset builds as before, with no pull and no push"
run_script 0 use toolchain "" -- FAKE_LAN="$LAN"
called "docker-build-toolchain"
not_called "docker pull"
not_called "docker push"
not_called "$LAN"

start_case "use: CI_IMAGE_REGISTRY on a closed port builds as before, with no pull and no push"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" FAKE_LAN_CURL_RC=7
called "docker-build-toolchain"
not_called "docker pull"
not_called "docker push"

# #2243 Codex P1-1: a LAN image is accepted for a ref only when its digest is
# the ref's; otherwise use pulls the ref from the forge (and builds, DS-9239).
OTHER_DIGEST="sha256:$(printf '%064d' 9)"
LAN_REF="$TOOLCHAIN_REPO@$DIGEST"
start_case "use: a CI_IMAGE_REGISTRY hit whose digest is not the ref's is refused; the forge pull of the ref is used"
run_script 0 use toolchain "$LAN_REF" -- "${RUN_TOKEN[@]}" CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" FAKE_LAN_DIGEST="$OTHER_DIGEST"
called "docker pull --quiet $LAN_TC"
stderr_has "$LAN_TC is $OTHER_DIGEST, not the digest of $LAN_REF; not used"
not_called "docker tag $LAN_TC $TOOLCHAIN_TAG"
called "docker pull --quiet $LAN_REF"
not_called "docker-build-toolchain"
if grep -qx "TOOLCHAIN_IMAGE=$LAN_REF" "$WORK_DIR/stdout"; then
  pass "prints the ref as TOOLCHAIN_IMAGE"
else
  fail "printed '$(cat "$WORK_DIR/stdout")', want TOOLCHAIN_IMAGE=$LAN_REF"
fi
called "docker push $LAN_TC"

start_case "use: a refused CI_IMAGE_REGISTRY hit and a failed forge pull build on this runner (DS-9239)"
run_script 0 use toolchain "$LAN_REF" -- "${RUN_TOKEN[@]}" CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" FAKE_LAN_DIGEST="$OTHER_DIGEST" FAKE_PULL_RC=1
stderr_has "not the digest of $LAN_REF; not used"
not_called "docker tag $LAN_TC $TOOLCHAIN_TAG"
called "docker-build-toolchain"
if grep -qx "TOOLCHAIN_IMAGE=$IMAGE_ID" "$WORK_DIR/stdout"; then
  pass "prints the local build's image ID"
else
  fail "printed '$(cat "$WORK_DIR/stdout")'"
fi

start_case "use: a CI_IMAGE_REGISTRY hit whose digest is the ref's is used"
run_script 0 use toolchain "$LAN_REF" -- "${RUN_TOKEN[@]}" CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN"
stderr_has "pulled $LAN_TC $DIGEST"
called "docker tag $LAN_TC $TOOLCHAIN_TAG"
not_called "docker pull --quiet $LAN_REF"
not_called "docker-build-toolchain"

# #2243 Codex P1-2: every CI_IMAGE_REGISTRY pull and push runs with an empty
# private Docker config, never the runner's (its auths and credsStore).
RUNNER_CFG="$WORK_DIR/runner-docker"
mkdir -p "$RUNNER_CFG"
printf '{"auths":{"%s":{"auth":"%s"}},"credsStore":"desktop"}\n' "$LAN" "$(printf 'runner:%s' "$SECRET" | base64)" >"$RUNNER_CFG/config.json"
# lan_cfg_private <pull|push>: each LAN <op> ran with a private, empty config.
lan_cfg_private() {
  local lines line bad=0
  lines=$(grep -F "docker-cfg $1 $LAN/" "$CALL_LOG")
  [ -n "$lines" ] || { fail "no CI_IMAGE_REGISTRY $1 recorded"; return; }
  while IFS= read -r line; do
    case $line in
      *" $RUNNER_CFG files="* | *" unset files="* | *config.json*) bad=1 ;;
      *" files=" | *" files=cli-plugins ") ;;
      *) bad=1 ;;
    esac
  done <<<"$lines"
  if [ "$bad" = 0 ]; then
    pass "every CI_IMAGE_REGISTRY $1 ran with an empty private DOCKER_CONFIG"
  else
    fail "a CI_IMAGE_REGISTRY $1 saw the runner's Docker config: $lines"
  fi
}
start_case "use: a CI_IMAGE_REGISTRY pull never sees the runner's Docker config"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" DOCKER_CONFIG="$RUNNER_CFG"
lan_cfg_private pull
not_called "docker login"
start_case "use: a CI_IMAGE_REGISTRY miss's pull and push never see the runner's Docker config"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" FAKE_LAN_PULL_RC=1 DOCKER_CONFIG="$RUNNER_CFG"
lan_cfg_private pull
lan_cfg_private push
start_case "use: after a forge pull, the CI_IMAGE_REGISTRY push never sees the run's login config"
run_script 0 use toolchain "$LAN_REF" -- "${RUN_TOKEN[@]}" CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" FAKE_LAN_PULL_RC=1 DOCKER_CONFIG="$RUNNER_CFG"
called "docker pull --quiet $LAN_REF"
lan_cfg_private push
no_secret_printed

# #2243 Codex round 2, P1-1: a CI_IMAGE_REGISTRY hit is no way around the ref
# checks; a ref pull_ref would refuse is refused before any LAN pull.
start_case "use: a ':latest' ref with a CI_IMAGE_REGISTRY hit is refused before any pull"
run_script 1 use toolchain "$TOOLCHAIN_REPO:latest" -- "${RUN_TOKEN[@]}" CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN"
stderr_has "is not a digest reference"
not_called "docker pull"
not_called "docker tag $LAN_TC"
start_case "use: a ref outside the publishing namespace with a CI_IMAGE_REGISTRY hit is refused before any pull"
run_script 1 use toolchain "$FORGE/jeremyhahn/go-xkms-ci-toolchain@$DIGEST" -- "${RUN_TOKEN[@]}" CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN"
stderr_has "is not under $FORGE/example-ci-images/, where main publishes"
not_called "docker pull"
not_called "docker tag $LAN_TC"
start_case "use: a ref in another registry with a CI_IMAGE_REGISTRY hit is refused before any pull"
run_script 1 use toolchain "ghcr.io/jeremyhahn/go-xkms-ci-toolchain@$DIGEST" -- "${RUN_TOKEN[@]}" CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN"
stderr_has "is not in this run's registry, $FORGE"
not_called "docker pull"
not_called "docker tag $LAN_TC"

# P1-2: with no private config dir (mktemp fails), no LAN docker call runs.
start_case "use: no private Docker config for CI_IMAGE_REGISTRY: no LAN pull or push, builds on this runner"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" DOCKER_CONFIG="$RUNNER_CFG" TMPDIR="$WORK_DIR/no-such-tmp"
not_called "docker pull --quiet $LAN/"
not_called "docker push"
called "docker-build-toolchain"
if grep -F "$LAN/" "$CALL_LOG" | grep -q '^docker-cfg'; then
  fail "a CI_IMAGE_REGISTRY call ran: $(grep -F "docker-cfg" "$CALL_LOG")"
else
  pass "no CI_IMAGE_REGISTRY docker call ran without a private config"
fi

# P1-3: a single-label CI_IMAGE_REGISTRY would be read by Docker as a Docker Hub
# namespace; it is rejected with a warning and treated as unset.
start_case "use: a single-label CI_IMAGE_REGISTRY is rejected and treated as unset"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY=registry FAKE_LAN=registry
stderr_has "CI_IMAGE_REGISTRY is a single-label name"
not_called "registry/go-xkms-toolchain"
not_called "docker pull"
not_called "docker push"
called "docker-build-toolchain"
start_case "use: CI_IMAGE_REGISTRY=localhost is a registry host"
run_script 0 use toolchain "" -- CI_IMAGE_REGISTRY=localhost FAKE_LAN=localhost
called "docker pull --quiet localhost/$TOOLCHAIN_TAG"
not_called "docker-build-toolchain"

# #2243 Codex round 3 P1-1: pull_ref runs inside an if, where errexit is off;
# a failed private config must stop it before any login or pull, which would
# otherwise read the runner's Docker config.
start_case "use: no private Docker config for the forge pull: no pull, no login, builds on this runner"
run_script 0 use toolchain "$LAN_REF" -- "${RUN_TOKEN[@]}" DOCKER_CONFIG="$RUNNER_CFG" TMPDIR="$WORK_DIR/no-such-tmp"
not_called "docker pull"
not_called "docker login"
called "docker-build-toolchain"
start_case "use: no private Docker config for a GHCR pull: no login, no pull, builds on this runner"
run_script 0 use toolchain "$GHCR_REPO@$DIGEST" -- "${RUN_TOKEN[@]}" "${GHCR[@]}" DOCKER_CONFIG="$RUNNER_CFG" TMPDIR="$WORK_DIR/no-such-tmp"
not_called "docker login"
not_called "docker pull"
called "docker-build-toolchain"
no_secret_printed

# Round 3 P1-2: the image whose digest was checked is the one held and run;
# a retag of the content tag after the check changes nothing.
RETAG_ID="sha256:$(printf '%064d' 0 | tr 0 b)"
start_case "use: a CI_IMAGE_REGISTRY hit is held by the checked digest's image ID, never re-read from a tag"
run_script 0 use toolchain "$LAN_REF" -- "${RUN_TOKEN[@]}" CI_IMAGE_REGISTRY="$LAN" FAKE_LAN="$LAN" FAKE_RETAG_ID="$RETAG_ID"
called "docker image inspect -f {{.Id}} $LAN/go-xkms-toolchain@$DIGEST"
called "docker tag $IMAGE_ID $TOOLCHAIN_TAG"
called "docker create --pull never --name go-xkms-ci-hold-42-1-toolchain-"
not_called "$RETAG_ID"
if grep -qx "TOOLCHAIN_IMAGE=$IMAGE_ID" "$WORK_DIR/stdout"; then
  pass "prints the checked image's ID as TOOLCHAIN_IMAGE"
else
  fail "printed '$(cat "$WORK_DIR/stdout")', want TOOLCHAIN_IMAGE=$IMAGE_ID"
fi

# --------------------------------------------------------------------------
if [ "$FAILURES" -eq 0 ]; then
  echo "PASS: ci-registry.sh hands the CI images over by digest"
  exit 0
fi
echo "FAILED: $FAILURES assertion(s)" >&2
exit 1
