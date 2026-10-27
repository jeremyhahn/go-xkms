#!/usr/bin/env bash
# ci-registry.sh hands the CI images from the ci-images job to every job that
# runs a stage in them. CUSTOMIZE (go-xkms, ruling 169; the go-qrdb #1135
# pattern, handbook ci-standard.md §9).
#
#   ci-registry.sh publish toolchain|it    push to main: prints <registry>/<namespace>/<name>@sha256:<hex>
#   ci-registry.sh resolve toolchain|it    any other event: prints main's digest reference, or ""
#   ci-registry.sh use toolchain|it <ref>  prints <FAMILY>_IMAGE= and <FAMILY>_HOLD= for $GITHUB_ENV
#   ci-registry.sh release <hold>...       removes the holds
#
# Each image is named by its content: the Makefile's tag (`make -s
# toolchain-image`, `make -s it-image`) carries a hash of its inputs, and the
# registry copy is <registry>/<namespace>/go-xkms-ci-<family>:<hash>-main.
#
#   - A push to main (CI_PUBLISH=true): ci-images runs on the release runner
#     and publishes each image, building and pushing it only when main has
#     not published that hash yet. Every consumer pulls the printed digest; a
#     consumer that cannot pull it fails rather than rebuild.
#   - Any other event (a pull request, the schedule, a dispatch): ci-images
#     resolves <hash>-main to a digest. When main published the same content,
#     every consumer pulls it by digest; when it did not, or the registry
#     cannot be read, the reference is empty and each consumer builds the
#     image on its own runner with no push.
#
# The registry is the forge the run belongs to, derived from GITHUB_SERVER_URL:
# ghcr.io on GitHub, the forge's own host[:port] on Gitea; no address is
# written here or in ci.yml. The namespace is CI_REGISTRY_OWNER, which
# ci.yml's workflow env sets on the forge to agent-ci-images, the release
# runner's public user: Gitea 1.27 lets only a user namespace's owner or an
# admin write it (go-xkms #1730, ruling 217). On GHCR, where the run's token
# pushes, it is GITHUB_REPOSITORY_OWNER. A lookup speaks the registry API
# with curl on GITHUB_SERVER_URL's scheme, so it reaches a forge registry
# served over plain http; docker reaches it through the daemon's own
# registry configuration.
#
# Credentials. No new identity or token exists for this (ruling 169):
#   - A push to the forge's registry runs on the release runner alone and
#     reads that runner's credential contract and nothing else (ruling 173):
#     RELEASE_REGISTRY (host[:port]), RELEASE_REGISTRY_USER and
#     RELEASE_REGISTRY_TOKEN. A push to GHCR uses the run's token.
#   - A read (resolve, use) on the forge is anonymous: the namespace is
#     public (ruling 217). resolve asks the forge's token endpoint for an
#     anonymous pull token (Gitea 1.27 refuses an Actions task token there),
#     and use runs `docker pull` by digest with no login.
#   - A read on GHCR, where a package is private when published, takes the
#     run's token, CI_REGISTRY_USER and CI_REGISTRY_TOKEN, under the job's
#     `packages: read`: resolve answers GHCR's challenge with it and use logs
#     in before `docker pull`. A step with no token, or a refused login,
#     reads anonymously.
# No credential value is ever printed: an empty name fails naming the
# variable. Every docker call lives in a private DOCKER_CONFIG deleted on
# exit, so a login reaches no other job on the same Docker host, and the
# host's own credentials are never used.
#
# A hold is a container created from the image and never started, named
# <CI_STACK_PREFIX>hold-<run>-<attempt>-<family>-<random>: `docker image rm`
# refuses an image a container uses, and the reaper keeps any image a
# container uses, so neither it nor a concurrent job's cache trim can remove
# the image before the job's teardown releases the hold. A hold a dead job
# leaves is a stale container, which the reaper removes like any other. A
# locally built image is held, and run, by its image ID.
#
# CI_REGISTRY_BACKOFF is the seconds between pull attempts, times the attempt
# number (default 10: at most 10 s + 20 s of waiting across 3 attempts).
set -euo pipefail

readonly attempts=3
readonly ref_re='^[^@ ]+@sha256:[0-9a-f]{64}$'
readonly host_re='^[A-Za-z0-9.-]+(:[0-9]+)?$'
# forge_service is the service the forge's registry issues its tokens for
# (Gitea's "container_registry").
readonly forge_service=container_registry

# Temporary files and directories, removed on exit. Nothing that adds to it
# runs in a subshell, or its entry would be lost.
cleanup=()
trap '[ "${#cleanup[@]}" -eq 0 ] || rm -rf -- "${cleanup[@]}"' EXIT

die() {
  echo "::error::ci-registry: $*" >&2
  exit 1
}

warn() {
  echo "::warning::ci-registry: $*" >&2
}

# registry_host prints the registry of the forge at GITHUB_SERVER_URL: GHCR on
# GitHub; on Gitea the registry shares the web UI's host[:port].
registry_host() {
  local url=${GITHUB_SERVER_URL:-} host
  [ -n "$url" ] || die "GITHUB_SERVER_URL is empty: the registry is derived from it, never written down"
  host=${url#*://}
  host=${host%%/*}
  [[ $host =~ $host_re ]] || die "GITHUB_SERVER_URL does not name a registry host"
  host=${host,,}
  case $host in github.com) host=ghcr.io ;; esac
  printf '%s\n' "$host"
}

# push_host prints the registry a push goes to: GHCR on GitHub; on the forge,
# RELEASE_REGISTRY, the release runner's own (ruling 173).
push_host() {
  local host
  host=$(registry_host)
  if [ "$host" = ghcr.io ]; then
    printf '%s\n' "$host"
    return 0
  fi
  host=${RELEASE_REGISTRY:-}
  [ -n "$host" ] || die "RELEASE_REGISTRY is empty: the release runner's credential is not in the job's environment"
  [[ $host =~ $host_re ]] || die "RELEASE_REGISTRY does not name a registry host"
  printf '%s\n' "${host,,}"
}

# registry_scheme prints the scheme that reaches registry host $1. The
# forge's own registry answers on GITHUB_SERVER_URL's scheme, plain http on
# a forge served over http; any other registry, a RELEASE_REGISTRY
# elsewhere, is https. An https registry's certificate is always verified.
registry_scheme() {
  local scheme=${GITHUB_SERVER_URL:-}
  scheme=${scheme%%://*}
  if [ "$1" != "$(registry_host)" ]; then
    printf 'https\n'
    return 0
  fi
  case ${scheme,,} in
    http | https) printf '%s\n' "${scheme,,}" ;;
    *) die "GITHUB_SERVER_URL's scheme is neither http nor https" ;;
  esac
}

# registry_name names the registry at host $1 in a message.
registry_name() {
  case $1 in
    ghcr.io) printf 'GHCR\n' ;;
    *) printf 'the Gitea registry\n' ;;
  esac
}

# registry_owner prints the namespace main's images live under:
# CI_REGISTRY_OWNER when the workflow sets it (agent-ci-images on the
# forge), else GITHUB_REPOSITORY_OWNER.
registry_owner() {
  local var=GITHUB_REPOSITORY_OWNER owner
  [ -z "${CI_REGISTRY_OWNER:-}" ] || var=CI_REGISTRY_OWNER
  owner=${!var:-}
  owner=${owner,,}
  [[ $owner =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die "$var does not name a registry owner"
  printf '%s\n' "$owner"
}

check_ref() {
  [[ $1 =~ $ref_re ]] || die "'$1' is not a digest reference (<registry>/<owner>/<name>@sha256:<64 hex>)"
}

check_family() {
  case $1 in
    toolchain | it) ;;
    *) die "family '$1' is neither toolchain nor it" ;;
  esac
}

# content_tag prints family $1's content-hash tag, the name the Makefile
# builds it under.
content_tag() {
  local tag tag_re
  case $1 in
    toolchain) tag_re='^go-xkms-toolchain:[0-9a-f]{16}$' ;;
    it) tag_re='^go-xkms-ci-it:[0-9a-f]{16}$' ;;
  esac
  tag=$(env -u TOOLCHAIN_IMAGE -u IT_IMAGE make -s --no-print-directory "$1-image")
  [[ $tag =~ $tag_re ]] || die "'$tag' is not a content-hash tag of the $1 family"
  printf '%s\n' "$tag"
}

# main_repo prints family $1's repository at registry host $2. Its caller's
# command substitution does not inherit errexit, so a namespace that does not
# resolve exits here.
main_repo() {
  local namespace
  namespace=$(registry_owner) || exit 1
  printf '%s/%s/go-xkms-ci-%s\n' "$2" "$namespace" "$1"
}

# private_config points DOCKER_CONFIG at a new directory removed on exit, so
# a login reaches no other job and the host's credentials are never read.
# The CLI plugins, buildx among them, stay reachable.
private_config() {
  local plugins=${DOCKER_CONFIG:-${HOME:-/nonexistent}/.docker}/cli-plugins
  DOCKER_CONFIG=$(mktemp -d)
  export DOCKER_CONFIG
  cleanup+=("$DOCKER_CONFIG")
  [ ! -d "$plugins" ] || ln -s "$plugins" "$DOCKER_CONFIG/cli-plugins"
}

# push_login logs in to host $1 to push: the release runner's credential on
# the forge (ruling 173), the run's token on GHCR. It sets writer to the
# credential's name and user and token to the names of its variables, and a
# failed login fails naming its case; the output of `docker login` is never
# printed.
push_login() {
  local host=$1 out
  user=RELEASE_REGISTRY_USER token=RELEASE_REGISTRY_TOKEN writer="the release runner's credential"
  if [ "$host" = ghcr.io ]; then
    user=CI_REGISTRY_USER token=CI_REGISTRY_TOKEN writer="the run's token"
  fi
  [ -n "${!user:-}" ] || die "$user is empty: $writer is not in the job's environment"
  [ -n "${!token:-}" ] || die "$token is empty: $writer is not in the job's environment"
  if ! out=$(printf '%s' "${!token}" | docker login "$host" -u "${!user}" --password-stdin 2>&1); then
    case $(failure_case "$out") in
      refused) die "$(registry_name "$host") refused the login: $writer cannot push $(registry_owner)'s container packages" ;;
      unreachable) die "$(registry_name "$host") did not answer the login with $writer" ;;
      *) die "$(registry_name "$host") gave an unexpected reply to the login with $writer" ;;
    esac
  fi
  echo "==> logged in to $(registry_name "$host") at $host with $writer" >&2
}

# read_credential sets user and token to the names of the run's token
# variables for a read of host $1, or to "" for an anonymous read. The
# forge's namespace is public (ruling 217), so a forge read is anonymous. A
# GHCR package is private when published, so a GHCR read takes the run's
# token under the job's `packages: read`, and only a step with no token at
# all reads it anonymously.
read_credential() {
  local host=$1
  user="" token=""
  [ "$host" = ghcr.io ] || return 0
  if [ -z "${CI_REGISTRY_USER:-}" ] && [ -z "${CI_REGISTRY_TOKEN:-}" ]; then
    echo "==> no run token in the step's environment; reading $(registry_name "$host") anonymously" >&2
    return 0
  fi
  [ -n "${CI_REGISTRY_USER:-}" ] || die "CI_REGISTRY_USER is empty: the run's token is in the job's environment without its user"
  [ -n "${CI_REGISTRY_TOKEN:-}" ] || die "CI_REGISTRY_TOKEN is empty: the run's token is not in the job's environment"
  user=CI_REGISTRY_USER token=CI_REGISTRY_TOKEN
}

# read_login logs in to host $1 to read with the credential read_credential
# names, and does nothing for an anonymous read. When the registry refuses
# the run's token, the read is anonymous.
read_login() {
  local host=$1 user token
  read_credential "$host"
  [ -n "$user" ] || return 0
  if ! printf '%s' "${!token}" | docker login "$host" -u "${!user}" --password-stdin >/dev/null; then
    warn "$(registry_name "$host") refused the run's token (packages: read); reading anonymously"
  fi
}

# failure_case names why a `docker login` failed, from its output $1:
# refused (401/403), unreachable (the registry did not answer) or
# unexpected (any other reply).
failure_case() {
  case ${1,,} in
    *"connection refused"* | *"connection reset"* | *"no such host"* | *"no route to host"* | *"network is unreachable"* | *timeout* | *"deadline exceeded"*)
      printf 'unreachable\n' ;;
    *unauthorized* | *forbidden* | *denied*) printf 'refused\n' ;;
    *) printf 'unexpected\n' ;;
  esac
}

# lookup_rc is remote_digest's return code for each failure case.
declare -rA lookup_rc=([missing]=1 [refused]=2 [unreachable]=3 [unexpected]=4)

# manifest_types are the manifests a lookup accepts: an OCI index or
# manifest, a Docker manifest list or v2 manifest.
declare -ra manifest_types=(
  application/vnd.oci.image.index.v1+json
  application/vnd.oci.image.manifest.v1+json
  application/vnd.docker.distribution.manifest.list.v2+json
  application/vnd.docker.distribution.manifest.v2+json
)

# request_failure prints remote_digest's code for curl's exit code $1: no
# answer (6 the host does not resolve, 7 no connection, 28 a timeout, 52 an
# empty reply, 55/56 a broken connection), or an unexpected reply for any
# other failure, a TLS failure among them.
request_failure() {
  case $1 in
    6 | 7 | 28 | 52 | 55 | 56) printf '%s\n' "${lookup_rc[unreachable]}" ;;
    *) printf '%s\n' "${lookup_rc[unexpected]}" ;;
  esac
}

# request_error sets reply to the last line curl wrote to $dir/error. A
# failed request's stdout carries only the write-out's "000", not the cause.
request_error() {
  reply=$(<"$dir/error")
  reply=${reply##*$'\n'}
}

# auth_config prints the Authorization header of a registry request as a
# curl config line, for curl to read with `-K -` from a pipe, so no
# credential reaches a command line (printf is a builtin). The caller
# declares authorization: "Basic <user:token>", "Bearer <token>" or "" for
# none. Neither a base64 credential nor a token (token_re) holds a quote.
auth_config() {
  [ -z "$authorization" ] || printf 'header = "Authorization: %s"\n' "$authorization"
}

# header_value prints the value of response header $1 (lowercase) from the
# headers remote_digest saved.
header_value() {
  local line
  while IFS= read -r line; do
    line=${line%$'\r'}
    case ${line,,} in
      "$1:"*)
        line=${line#*:}
        printf '%s\n' "${line#"${line%%[! ]*}"}"
        return 0
        ;;
    esac
  done <"$dir/headers"
}

# manifest_get GETs manifest URL $1 (OCI Distribution Spec v1.1.1, "Pulling
# manifests"), or HEADs it when $2 is -I ("Checking if content exists in the
# registry"), into $dir/manifest, its headers into $dir/headers, and sets
# status. When no answer comes it sets reply to curl's error and returns
# remote_digest's code for it.
manifest_get() {
  local url=$1 accept out rc=0
  shift
  accept=$(IFS=,; printf '%s' "${manifest_types[*]}")
  out=$(auth_config | curl -sS --max-time 60 "$@" -o "$dir/manifest" -D "$dir/headers" -H "Accept: $accept" -K - -w '%{http_code}' "$url" 2>"$dir/error") || rc=$?
  if [ "$rc" -ne 0 ]; then
    request_error
    return "$(request_failure "$rc")"
  fi
  status=$out
}

# token_get answers Bearer challenge $1 (Distribution "Token Authentication
# Specification", "How to authenticate"): it asks the challenge's realm for a
# token for its service and scopes with token_request.
token_get() {
  local challenge=${1#* } realm="" service="" scope=""
  local param_re='([A-Za-z_]+)="([^"]*)"'
  while [[ $challenge =~ $param_re ]]; do
    case ${BASH_REMATCH[1],,} in
      realm) realm=${BASH_REMATCH[2]} ;;
      service) service=${BASH_REMATCH[2]} ;;
      scope) scope=${BASH_REMATCH[2]} ;;
    esac
    challenge=${challenge#*"${BASH_REMATCH[0]}"}
  done
  token_request "$realm" "$service" "${scope:-repository:$name:pull}"
}

# token_request asks token service $1 for a token for service $2 and the
# space-separated scopes $3 ("Requesting a Token"), with the basic credential
# when there is one, and sets authorization to it ("Using the Bearer
# token"). The token is never printed or written. A token service reached
# over plain http serves an http registry alone.
token_request() {
  local realm=$1 service=$2 scopes s answer code rc=0 args=(--get)
  local token_re='"(access_)?token"[[:space:]]*:[[:space:]]*"([^"]+)"'
  case $realm in
    https://*) ;;
    http://*)
      if [ "$scheme" != http ]; then
        reply="a challenge that sends the credential to a token service over plain http"
        return "${lookup_rc[unexpected]}"
      fi
      ;;
    *)
      reply="a challenge that names no token service"
      return "${lookup_rc[unexpected]}"
      ;;
  esac
  [ -z "$service" ] || args+=(--data-urlencode "service=$service")
  read -ra scopes <<<"$3"
  for s in "${scopes[@]}"; do
    args+=(--data-urlencode "scope=$s")
  done
  authorization=${basic:+"Basic $basic"}
  answer=$(auth_config | curl -sS --max-time 60 -K - -w '\n%{http_code}' "${args[@]}" "$realm" 2>"$dir/error") || rc=$?
  if [ "$rc" -ne 0 ]; then
    request_error
    return "$(request_failure "$rc")"
  fi
  code=${answer##*$'\n'}
  case $code in
    200) ;;
    401 | 403)
      reply="the token service answered HTTP $code"
      return "${lookup_rc[refused]}"
      ;;
    *)
      reply="the token service answered HTTP $code"
      return "${lookup_rc[unexpected]}"
      ;;
  esac
  if [[ $answer =~ $token_re ]]; then
    authorization="Bearer ${BASH_REMATCH[2]}"
    return 0
  fi
  reply="a token service answer that names no token"
  return "${lookup_rc[unexpected]}"
}

# remote_digest looks up reference $1 (<host>/<name>:<tag>) over scheme $2
# with the credential in the variables named $3 (user) and $4 (token), or
# anonymously when they are absent. It speaks the registry API (OCI
# Distribution Spec v1.1.1) rather than `docker buildx imagetools`, which
# speaks https alone and so never reaches a forge registry served over
# http. An anonymous read on the forge is forge_digest. Any other GETs the
# tag's manifest ("Pulling manifests") anonymously; a 401 carrying a Bearer
# challenge is answered with a token, a Basic one with the credential, and
# the GET is retried once. Its digest is the sha256 of the manifest
# returned, since the Docker-Content-Digest header is optional.
# It sets digest and returns 0, or sets reply to what the registry said and
# returns lookup_rc's code: 404 not published, 401/403 refused, no answer,
# or anything else unexpected. The caller declares digest and reply.
remote_digest() {
  local host=${1%%/*} name=${1#*/} tag scheme=$2 basic="" authorization="" dir status challenge
  tag=${name##*:} name=${name%:*}
  digest="" reply=""
  dir=$(mktemp -d)
  cleanup+=("$dir")
  if [ $# -eq 2 ] && [ "$host" != ghcr.io ]; then
    forge_digest "$scheme://$host"
    return
  fi
  [ $# -eq 2 ] || basic=$(printf '%s:%s' "${!3}" "${!4}" | base64 | tr -d '\n')
  manifest_get "$scheme://$host/v2/$name/manifests/$tag" || return $?
  if [ "$status" = 401 ]; then
    challenge=$(header_value www-authenticate)
    case ${challenge,,} in
      "bearer "*) token_get "$challenge" || return $? ;;
      *) authorization=${basic:+"Basic $basic"} ;;
    esac
    if [ -n "$authorization" ]; then
      manifest_get "$scheme://$host/v2/$name/manifests/$tag" || return $?
    fi
  fi
  manifest_status || return $?
  digest=$(sha256sum "$dir/manifest")
  digest=sha256:${digest%% *}
}

# forge_digest is remote_digest's anonymous read of the forge's registry at
# base URL $1, the flow Infrastructure verified on the runners (go-xkms
# #1727, ruling 217). Gitea 1.27 refuses an Actions task token at
# /v2/token, and its challenge's realm is the forge's configured URL, so it
# asks the registry's own token endpoint for an anonymous pull token
# ("Requesting a Token"; the namespace is public) and HEADs the tag with it
# (OCI Distribution Spec v1.1.1, "Checking if content exists in the
# registry"). The digest is the answer's Docker-Content-Digest header.
forge_digest() {
  token_request "$1/v2/token" "$forge_service" "repository:$name:pull" || return $?
  manifest_get "$1/v2/$name/manifests/$tag" -I || return $?
  manifest_status || return $?
  digest=$(header_value docker-content-digest)
  if [[ ! $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
    digest=""
    reply="an answer that names no digest"
    return "${lookup_rc[unexpected]}"
  fi
}

# manifest_status checks the answer manifest_get recorded: a 200 carrying a
# manifest, or reply and lookup_rc's code for anything else.
manifest_status() {
  local ctype
  case $status in
    200) ;;
    404)
      reply="HTTP 404"
      return "${lookup_rc[missing]}"
      ;;
    401 | 403)
      reply="HTTP $status"
      return "${lookup_rc[refused]}"
      ;;
    *)
      reply="HTTP $status"
      return "${lookup_rc[unexpected]}"
      ;;
  esac
  # The client SHOULD ignore Content-Type parameters ("Pulling manifests").
  ctype=$(header_value content-type)
  ctype=${ctype%%;*}
  ctype=${ctype,,}
  case " ${manifest_types[*]} " in
    *" $ctype "*) ;;
    *)
      reply="an answer that is not a manifest (Content-Type '$ctype')"
      return "${lookup_rc[unexpected]}"
      ;;
  esac
}

# lookup_failure names failed lookup $1 (remote_digest's code) of reference
# $2 at host $3 by reader $4, from the registry's reply $5.
lookup_failure() {
  local registry
  registry=$(registry_name "$3")
  case $1 in
    "${lookup_rc[missing]}") printf 'main has not published %s (not found)\n' "$2" ;;
    "${lookup_rc[refused]}") printf "%s refused %s's read of %s (401/403): %s\n" "$registry" "$4" "$2" "$5" ;;
    "${lookup_rc[unreachable]}") printf '%s did not answer the read of %s (%s)\n' "$registry" "$2" "$5" ;;
    *) printf '%s gave an unexpected reply to the read of %s (%s)\n' "$registry" "$2" "$5" ;;
  esac
}

# stage_modauth writes the module credentials the image build reads as its
# gomodauth BuildKit secret to the private file $1. Nothing prints it.
stage_modauth() {
  (
    umask 077
    : >"$1"
    local v
    for v in GOPRIVATE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; do
      [ -z "${!v:-}" ] || printf '%s=%s\n' "$v" "${!v}" >>"$1"
    done
  )
}

# build_local builds family $1's image under its content-hash tag $2 on this
# runner's daemon, unless the daemon holds it already. It never pushes.
build_local() {
  local family=$1 tag=$2 modauth
  modauth=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gomodauth.XXXXXX")
  cleanup+=("$modauth")
  stage_modauth "$modauth"
  case $family in
    toolchain) env -u TOOLCHAIN_IMAGE make --no-print-directory docker-build-toolchain MODULE_ENV_FILE="$modauth" >&2 ;;
    it) env -u IT_IMAGE make --no-print-directory docker-build-it IT_IMAGE="$tag" MODULE_ENV_FILE="$modauth" >&2 ;;
  esac || die "cannot build $tag on this runner"
}

publish() {
  [ $# -eq 1 ] || die "usage: publish toolchain|it"
  check_family "$1"
  [ "${CI_PUBLISH:-}" = true ] || die "publish runs on a push to main alone, and CI_PUBLISH is not true"
  local family=$1 tag host scheme repo target writer user token digest reply d rc=0
  tag=$(content_tag "$family")
  host=$(push_host)
  repo=$(main_repo "$family" "$host")
  target=$repo:${tag##*:}-main
  if [ "$host" != "$(registry_host)" ]; then
    warn "publish: RELEASE_REGISTRY ($host) is not the forge's registry ($(registry_host)), which pull requests resolve against: they will not find this image and build their own"
  fi
  scheme=$(registry_scheme "$host")
  private_config
  push_login "$host"
  remote_digest "$target" "$scheme" "$user" "$token" || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "==> $target is published already as $digest; nothing to build" >&2
  else
    # Anything but not-found is a warning, and the push goes on: the push
    # itself shows whether the credential can write the package.
    if [ "$rc" -eq "${lookup_rc[missing]}" ]; then
      echo "==> $(lookup_failure "$rc" "$target" "$host" "$writer" "$reply"); building and pushing it" >&2
    else
      warn "publish: $(lookup_failure "$rc" "$target" "$host" "$writer" "$reply"); building and pushing it"
    fi
    build_local "$family" "$tag"
    docker tag "$tag" "$target" || die "cannot tag $tag as $target"
    docker push "$target" >&2 || die "$(registry_name "$host") refused the push of $target"
    digest=""
    while IFS= read -r d; do
      case $d in "$repo@"*) digest=${d#"$repo@"} ;; esac
    done < <(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$target")
    [ -n "$digest" ] || die "the push of $target reported no digest"
    echo "==> pushed $target as $digest" >&2
  fi
  check_ref "$repo@$digest"
  printf '%s@%s\n' "$repo" "$digest"
}

resolve() {
  [ $# -eq 1 ] || die "usage: resolve toolchain|it"
  check_family "$1"
  local family=$1 tag host scheme repo target user token reader="an anonymous pull" digest reply rc=0
  tag=$(content_tag "$family")
  host=$(registry_host)
  scheme=$(registry_scheme "$host")
  repo=$(main_repo "$family" "$host")
  target=$repo:${tag##*:}-main
  read_credential "$host"
  if [ -n "$user" ]; then
    reader="the run's token"
    remote_digest "$target" "$scheme" "$user" "$token" || rc=$?
  else
    remote_digest "$target" "$scheme" || rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    warn "resolve: $(lookup_failure "$rc" "$target" "$host" "$reader" "$reply"); each consumer builds the $family image on its runner, with no push"
    printf '\n'
    return 0
  fi
  check_ref "$repo@$digest"
  echo "==> main published $target as $digest; the consumers pull it" >&2
  printf '%s@%s\n' "$repo" "$digest"
}

# hold_name prints a hold's name for family $1, unique to this job.
hold_name() {
  local prefix=${CI_STACK_PREFIX:-} run=${GITHUB_RUN_ID:-} attempt=${GITHUB_RUN_ATTEMPT:-1}
  [[ $prefix =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "CI_STACK_PREFIX does not name this repository's CI resources"
  [[ $run =~ ^[0-9]+$ ]] || die "GITHUB_RUN_ID is not a run id"
  [[ $attempt =~ ^[0-9]+$ ]] || die "GITHUB_RUN_ATTEMPT is not a run attempt"
  printf '%shold-%s-%s-%s-%s\n' "$prefix" "$run" "$attempt" "$1" "$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
}

# pull_ref pulls digest reference $1 from main's namespace in this run's
# registry, with the run's token on GHCR and anonymously on the forge
# (read_login), and holds it as $2, in at most $attempts attempts.
pull_ref() {
  local ref=$1 hold=$2 host repos backoff=${CI_REGISTRY_BACKOFF:-10} n
  check_ref "$ref"
  [[ $backoff =~ ^[0-9]+$ ]] || die "CI_REGISTRY_BACKOFF is not a number of seconds"
  host=$(registry_host)
  [ "${ref%%/*}" = "$host" ] || die "'$ref' is not in this run's registry, $host"
  repos=$host/$(registry_owner)/
  [[ $ref == "$repos"* ]] || die "'$ref' is not under $repos, where main publishes"
  private_config
  read_login "$host"
  for ((n = 1; n <= attempts; n++)); do
    if docker pull --quiet "$ref" >/dev/null; then
      docker rm -f "$hold" >/dev/null 2>&1 || true
      # A concurrent reap can remove the image between the pull and the
      # hold; the next attempt pulls it again.
      if docker create --pull never --name "$hold" "$ref" true >/dev/null; then
        echo "==> $hold holds $ref until the job's teardown" >&2
        return 0
      fi
    fi
    [ "$n" -lt "$attempts" ] || break
    echo "==> pull of $ref failed (attempt $n of $attempts); retrying" >&2
    sleep $((n * backoff))
  done
  die "cannot pull $ref after $attempts attempts; a consumer never rebuilds an image main published"
}

# hold_local builds or reuses family $1's image on this runner, holds it as
# $2 by its image ID and sets image to that ID.
hold_local() {
  local family=$1 hold=$2 tag id n
  tag=$(content_tag "$family")
  for ((n = 1; n <= 2; n++)); do
    build_local "$family" "$tag"
    # A concurrent reap or trim can drop the tag before the hold; the next
    # attempt builds it again.
    id=$(docker image inspect -f '{{.Id}}' "$tag" 2>/dev/null) || continue
    [[ $id =~ ^sha256:[0-9a-f]{64}$ ]] || die "$tag has no image ID ('$id')"
    docker rm -f "$hold" >/dev/null 2>&1 || true
    if docker create --pull never --name "$hold" "$id" true >/dev/null; then
      echo "==> $hold holds $tag ($id) until the job's teardown" >&2
      image=$id
      return 0
    fi
  done
  die "$tag was removed before $hold could hold it"
}

use() {
  [ $# -eq 2 ] || die "usage: use toolchain|it <ref>"
  check_family "$1"
  local family=$1 ref=$2 hold var=TOOLCHAIN
  [ "$family" = toolchain ] || var=IT
  hold=$(hold_name "$family")
  image=""
  if [ -n "$ref" ]; then
    pull_ref "$ref" "$hold"
    image=$ref
  elif [ "${CI_PUBLISH:-}" = true ]; then
    die "no $family image reference on a push to main: a consumer runs the image ci-images published and never builds its own"
  else
    echo "==> no $family image of main's for this content; building it on this runner, with no push" >&2
    hold_local "$family" "$hold"
  fi
  printf '%s_IMAGE=%s\n%s_HOLD=%s\n' "$var" "$image" "$var" "$hold"
}

release() {
  local hold
  for hold in "$@"; do
    [ -z "$hold" ] || docker rm -f "$hold" >/dev/null 2>&1 || true
  done
}

main() {
  [ $# -ge 1 ] || die "usage: ci-registry.sh publish|resolve|use|release ..."
  local cmd=$1
  shift
  case $cmd in
    publish) publish "$@" ;;
    resolve) resolve "$@" ;;
    use) use "$@" ;;
    release) release "$@" ;;
    *) die "unknown command '$cmd'" ;;
  esac
}

main "$@"
