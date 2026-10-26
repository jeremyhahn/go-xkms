#!/usr/bin/env bash
# ci-registry.sh hands the CI images from the ci-images job to every job that
# runs a stage in them. CUSTOMIZE (go-xkms, ruling 169; the go-qrdb #1135
# pattern, handbook ci-standard.md §9).
#
#   ci-registry.sh publish toolchain|it    push to main: prints <registry>/<owner>/<name>@sha256:<hex>
#   ci-registry.sh resolve toolchain|it    any other event: prints main's digest reference, or ""
#   ci-registry.sh use toolchain|it <ref>  prints <FAMILY>_IMAGE= and <FAMILY>_HOLD= for $GITHUB_ENV
#   ci-registry.sh release <hold>...       removes the holds
#
# Each image is named by its content: the Makefile's tag (`make -s
# toolchain-image`, `make -s it-image`) carries a hash of its inputs, and the
# registry copy is <registry>/<owner>/go-xkms-ci-<family>:<hash>-main.
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
# written here or in ci.yml. The owner is GITHUB_REPOSITORY_OWNER.
#
# Credentials. No new identity or token exists for this (ruling 169):
#   - A push to the forge's registry runs on the release runner alone and
#     reads that runner's credential contract and nothing else (ruling 173):
#     RELEASE_REGISTRY (host[:port]), RELEASE_REGISTRY_USER and
#     RELEASE_REGISTRY_TOKEN. A push to GHCR uses the run's token.
#   - A read (resolve, use) logs in with the run's token, CI_REGISTRY_USER
#     and CI_REGISTRY_TOKEN, under the job's `packages: read`. A refused
#     login is a warning and the read goes on anonymously.
# No credential value is ever printed: an empty name fails naming the
# variable. Every login lives in a private DOCKER_CONFIG deleted on exit, so
# it reaches no other job on the same Docker host, and the host's own
# credentials are never used.
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
readonly digest_re='^Digest:[[:space:]]+(sha256:[0-9a-f]{64})[[:space:]]*$'

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

# registry_name names the registry at host $1 in a message.
registry_name() {
  case $1 in
    ghcr.io) printf 'GHCR\n' ;;
    *) printf 'the Gitea registry\n' ;;
  esac
}

registry_owner() {
  local owner=${GITHUB_REPOSITORY_OWNER:-}
  owner=${owner,,}
  [[ $owner =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die "GITHUB_REPOSITORY_OWNER does not name a registry owner"
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

# main_repo prints family $1's repository at registry host $2.
main_repo() {
  local owner
  owner=$(registry_owner)
  printf '%s/%s/go-xkms-ci-%s\n' "$2" "$owner" "$1"
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
# the forge (ruling 173), the run's token on GHCR.
push_login() {
  local host=$1 user=RELEASE_REGISTRY_USER token=RELEASE_REGISTRY_TOKEN src="the release runner's credential"
  if [ "$host" = ghcr.io ]; then
    user=CI_REGISTRY_USER token=CI_REGISTRY_TOKEN src="the run's token"
  fi
  [ -n "${!user:-}" ] || die "$user is empty: $src is not in the job's environment"
  [ -n "${!token:-}" ] || die "$token is empty: $src is not in the job's environment"
  if ! printf '%s' "${!token}" | docker login "$host" -u "${!user}" --password-stdin >/dev/null; then
    die "$(registry_name "$host") refused the login: $src cannot push $(registry_owner)'s container packages"
  fi
}

# read_login logs in to host $1 to read, with the run's token when the step
# supplies it. Without one, or when the registry refuses it, the read is
# anonymous.
read_login() {
  local host=$1 user=${CI_REGISTRY_USER:-} token=${CI_REGISTRY_TOKEN:-}
  if [ -z "$user" ] && [ -z "$token" ]; then
    echo "==> no run token in the step's environment; reading $(registry_name "$host") anonymously" >&2
    return 0
  fi
  [ -n "$user" ] || die "CI_REGISTRY_USER is empty: the run's token is in the job's environment without its user"
  [ -n "$token" ] || die "CI_REGISTRY_TOKEN is empty: the run's token is not in the job's environment"
  if ! printf '%s' "$token" | docker login "$host" -u "$user" --password-stdin >/dev/null; then
    warn "$(registry_name "$host") refused the run's token (packages: read); reading anonymously"
  fi
}

# remote_digest prints the digest of the manifest at reference $1. It
# returns 1 when the registry has no such tag, and 2 when it cannot be read.
remote_digest() {
  local out line
  if ! out=$(docker buildx imagetools inspect "$1" 2>&1); then
    case $out in
      *"not found"* | *"manifest unknown"* | *MANIFEST_UNKNOWN* | *NAME_UNKNOWN*) return 1 ;;
    esac
    printf '%s\n' "${out##*$'\n'}" >&2
    return 2
  fi
  while IFS= read -r line; do
    if [[ $line =~ $digest_re ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"
      return 0
    fi
  done <<<"$out"
  echo "==> the registry's answer for $1 names no digest" >&2
  return 2
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
  local family=$1 tag host repo target digest="" d rc=0
  tag=$(content_tag "$family")
  host=$(push_host)
  repo=$(main_repo "$family" "$host")
  target=$repo:${tag##*:}-main
  private_config
  push_login "$host"
  digest=$(remote_digest "$target") || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "==> $target is published already; nothing to build" >&2
  else
    build_local "$family" "$tag"
    docker tag "$tag" "$target" || die "cannot tag $tag as $target"
    docker push "$target" >&2 || die "$(registry_name "$host") refused the push of $target"
    digest=""
    while IFS= read -r d; do
      case $d in "$repo@"*) digest=${d#"$repo@"} ;; esac
    done < <(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$target")
    [ -n "$digest" ] || die "the push of $target reported no digest"
  fi
  check_ref "$repo@$digest"
  printf '%s@%s\n' "$repo" "$digest"
}

resolve() {
  [ $# -eq 1 ] || die "usage: resolve toolchain|it"
  check_family "$1"
  local family=$1 tag host repo target digest="" rc=0
  tag=$(content_tag "$family")
  host=$(registry_host)
  repo=$(main_repo "$family" "$host")
  target=$repo:${tag##*:}-main
  private_config
  read_login "$host"
  digest=$(remote_digest "$target") || rc=$?
  case $rc in
    0)
      check_ref "$repo@$digest"
      echo "==> main published $target as $digest; the consumers pull it" >&2
      printf '%s@%s\n' "$repo" "$digest"
      ;;
    1)
      echo "::notice::ci-registry: main has not published $target; each consumer builds the $family image on its runner, with no push" >&2
      printf '\n'
      ;;
    *)
      warn "cannot read $target: neither the run's token nor an anonymous pull can read $(registry_owner)'s container packages on $(registry_name "$host"); each consumer builds the $family image on its runner"
      printf '\n'
      ;;
  esac
}

# hold_name prints a hold's name for family $1, unique to this job.
hold_name() {
  local prefix=${CI_STACK_PREFIX:-} run=${GITHUB_RUN_ID:-} attempt=${GITHUB_RUN_ATTEMPT:-1}
  [[ $prefix =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "CI_STACK_PREFIX does not name this repository's CI resources"
  [[ $run =~ ^[0-9]+$ ]] || die "GITHUB_RUN_ID is not a run id"
  [[ $attempt =~ ^[0-9]+$ ]] || die "GITHUB_RUN_ATTEMPT is not a run attempt"
  printf '%shold-%s-%s-%s-%s\n' "$prefix" "$run" "$attempt" "$1" "$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
}

# pull_ref pulls digest reference $1 from this run's registry and holds it
# as $2, in at most $attempts attempts.
pull_ref() {
  local ref=$1 hold=$2 host backoff=${CI_REGISTRY_BACKOFF:-10} n
  check_ref "$ref"
  [[ $backoff =~ ^[0-9]+$ ]] || die "CI_REGISTRY_BACKOFF is not a number of seconds"
  host=$(registry_host)
  [ "${ref%%/*}" = "$host" ] || die "'$ref' is not in this run's registry, $host"
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
