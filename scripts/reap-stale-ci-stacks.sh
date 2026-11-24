#!/usr/bin/env bash
# Remove this repository's stopped CI leftovers on the runner host.
set -u

prefix=${1:-}
min_age=${2:-11100}
case $prefix in
  '' | *[!A-Za-z0-9_.-]*) echo "usage: $0 <prefix [A-Za-z0-9_.-]> [min-age-seconds]" >&2; exit 2 ;;
esac
case $min_age in
  '' | *[!0-9]*) echo "min-age-seconds must be a number: $min_age" >&2; exit 2 ;;
esac
image_min_age=${REAP_IMAGE_MIN_AGE:-7200}
case $image_min_age in
  '' | *[!0-9]*) echo "REAP_IMAGE_MIN_AGE must be a number: $image_min_age" >&2; exit 2 ;;
esac

now=$(date +%s)

# run <command...>: the command, or only its echo under REAP_DRY_RUN=1.
run() {
  if [ "${REAP_DRY_RUN:-0}" = 1 ]; then echo "dry   $*"; else "$@" >/dev/null; fi
}

# stale <container>: 0 when the container is stale (as above), 1 otherwise.
stale() {
  local state finished created t
  read -r state finished created < <(docker inspect -f '{{.State.Status}} {{.State.FinishedAt}} {{.Created}}' "$1" 2>/dev/null) || return 1
  case $state in
    exited | dead) t=$finished ;;
    created) t=$created ;;
    *) return 1 ;;
  esac
  t=$(date -d "$t" +%s 2>/dev/null) || return 1
  [ $((now - t)) -ge "$min_age" ]
}

# in_use <image>: 0, with a keep line, when a container (a job's hold or
# lease included) uses the image, or when the containers cannot be listed;
# 1 otherwise.
in_use() {
  local users
  if ! users=$(docker ps -aq --filter "ancestor=$1" 2>/dev/null); then
    echo "keep  image $1 (cannot list the containers that use it)"
    return 0
  fi
  [ -n "$users" ] || return 1
  echo "keep  image $1 (used by a container)"
}

reaped=0

# Compose projects.
for project in $(docker ps -a --filter label=com.docker.compose.project \
    --format '{{.Label "com.docker.compose.project"}}' | sort -u); do
  case $project in "$prefix"*) ;; *) continue ;; esac
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project")
  keep=0
  for id in $ids; do stale "$id" || { keep=1; break; }; done
  if [ "$keep" = 1 ]; then
    echo "keep  $project (a container is live or stopped within ${min_age}s)"
    continue
  fi
  # shellcheck disable=SC2086 # one id per word
  set -- $ids
  echo "reap  $project: $# container(s)"
  run docker rm -v "$@" || echo "warn  $project: container removal failed"
  for net in $(docker network ls -q --filter "label=com.docker.compose.project=$project"); do
    run docker network rm "$net" || echo "warn  $project: network $net not removed"
  done
  for vol in $(docker volume ls -q --filter "label=com.docker.compose.project=$project"); do
    run docker volume rm "$vol" || echo "warn  $project: volume $vol not removed"
  done
  reaped=$((reaped + 1))
done

# Containers outside compose.
docker ps -a --filter "name=^$prefix" \
    --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.project"}}' |
  while read -r id name project; do
    [ -z "$project" ] || continue
    case $name in "$prefix"*) ;; *) continue ;; esac
    if stale "$id"; then
      echo "reap  container $name"
      run docker rm -v "$id" || echo "warn  container $name not removed"
    fi
  done

# Content-addressed integration images (v2, above).
images=0
for ref in $(docker images --filter "reference=${prefix}it" --format '{{.Repository}}:{{.Tag}}'); do
  case $ref in "${prefix}it:"*) ;; *) continue ;; esac
  read -r created tagged < <(docker image inspect -f '{{.Created}} {{.Metadata.LastTagTime.Unix}}' "$ref" 2>/dev/null) || continue
  t=$(date -d "$created" +%s 2>/dev/null) || continue
  # A never-tagged image reports the zero time, a large negative number.
  case $tagged in ''|*[!0-9]*) ;; *) [ "$tagged" -le "$t" ] || t=$tagged ;; esac
  if [ $((now - t)) -lt "$image_min_age" ]; then
    echo "keep  image $ref (created or tagged within ${image_min_age}s)"
    continue
  fi
  in_use "$ref" && continue
  echo "reap  image $ref"
  if run docker image rm "$ref"; then images=$((images + 1)); else echo "warn  image $ref not removed (in use?)"; fi
done

# v4, CUSTOMIZE (go-xkms, ruling 169; the go-qrdb #1135 pattern): the CI
# images in the forge's registry are <registry>/<owner>/<prefix>toolchain
# and <registry>/<owner>/<prefix>it (scripts/ci-registry.sh), named by tag
# on the release runner that pushed them and by digest alone where a job
# pulled them. The same age rule applies to each name, and an image a job's
# hold (a created, never-started container) uses keeps every name: in_use is
# asked before any of them is removed, because `docker image rm` of one of
# several names only untags it, in use or not, and the name it drops can be
# the digest reference the holding job runs. A pull by digest records no tag
# time, so an unheld pulled image ages from its build; a job holds what it
# pulls, and its pull retries if a reap wins the race between the two.
while read -r repo tag digest; do
  case $repo in */"${prefix}it" | */"${prefix}toolchain") ;; *) continue ;; esac
  refs=()
  [ "$tag" = '<none>' ] || refs+=("$repo:$tag")
  [ "$digest" = '<none>' ] || refs+=("$repo@$digest")
  [ "${#refs[@]}" -gt 0 ] || continue
  read -r created tagged < <(docker image inspect -f '{{.Created}} {{.Metadata.LastTagTime.Unix}}' "${refs[0]}" 2>/dev/null) || continue
  t=$(date -d "$created" +%s 2>/dev/null) || continue
  case $tagged in ''|*[!0-9]*) ;; *) [ "$tagged" -le "$t" ] || t=$tagged ;; esac
  if [ $((now - t)) -lt "$image_min_age" ]; then
    echo "keep  image ${refs[0]} (created or tagged within ${image_min_age}s)"
    continue
  fi
  in_use "${refs[0]}" && continue
  for ref in "${refs[@]}"; do
    # Removing the tag can remove the image, and its digest name with it.
    docker image inspect "$ref" >/dev/null 2>&1 || continue
    echo "reap  image $ref"
    if run docker image rm "$ref"; then images=$((images + 1)); else echo "warn  image $ref not removed (in use?)"; fi
  done
done < <(docker images --digests --format '{{.Repository}} {{.Tag}} {{.Digest}}')

if [ "${REAP_DRY_RUN:-0}" = 1 ]; then done_as="would be removed"; else done_as=removed; fi
echo "reaper: $reaped compose project(s) and $images image(s) $done_as for prefix '$prefix'"
exit 0
