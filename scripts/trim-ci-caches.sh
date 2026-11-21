#!/usr/bin/env bash
# Bound the size of this repo's CI cache volumes on the runner host.
#
#   usage: scripts/trim-ci-caches.sh <prefix> <image> [max-gib]
#   e.g.   scripts/trim-ci-caches.sh go-enclave-ci- "$TOOLCHAIN_IMAGE"
#
# v1 (ci-template v1.22, Company Agent m616 item 2). in-toolchain-image.sh v2
# keeps the build, golangci-lint and module caches in named volumes,
# <prefix>cache-<class>-{gobuild,golangci,gomod}, on the Docker host the job
# talks to (ci-standard.md §6). Go trims its build cache of entries unused for
# five days, but nothing trims the module cache, so the volumes would grow
# without bound. This measures them and, while their total is over <max-gib>,
# removes the largest one no container is using. A removed volume comes back
# empty at the next stage, which costs one cold build, never a wrong one.
#
# Sizes are measured by `du` in <image> (the toolchain image the job just
# built: it has du, and it is already on the host), run as IN_IMAGE_UID (the
# volumes' owner, default 10001) with no network, no capability and the volume
# read-only. A volume any container (running or
# stopped) mounts is never removed; `docker volume rm` refuses one in use in any
# case.
#
# When the total is still over the bound with only in-use volumes left (Tenant
# Agent ruling 966 (4): one host's gobuild volume reached 57G), they are
# trimmed inside, largest first, by a one-shot <image> container with the same
# limits mounting the volume read-write, by whole cache entries:
#   gobuild   the entry files inside the xx/ hash buckets, oldest file mtime
#             first across all buckets, until under the bound (buckets stay);
#             `go clean -cache` when the volume alone is over the bound;
#   golangci  emptied whole, as `golangci-lint cache clean` does;
#   gomod     never trimmed inside (no per-file age trims of the module cache):
#             reported, and removed whole only once no container uses it.
#
# <max-gib> defaults to CI_CACHE_MAX_GIB, else 32: the bound for this repo's
# volumes, both trust classes together, on one host.
#
# A failed measurement or removal is reported and skipped: this never fails
# the job. REAP_DRY_RUN=1 prints what would be removed and removes nothing.
set -u

prefix=${1:-}
image=${2:-}
max_gib=${3:-${CI_CACHE_MAX_GIB:-32}}
case $prefix in
  '' | *[!A-Za-z0-9_.-]*) echo "usage: $0 <prefix [A-Za-z0-9_.-]> <image> [max-gib]" >&2; exit 2 ;;
esac
if [ -z "$image" ]; then
  echo "usage: $0 <prefix> <image> [max-gib]" >&2
  exit 2
fi
case $max_gib in
  '' | *[!0-9]*) echo "max-gib must be a number: $max_gib" >&2; exit 2 ;;
esac
max_kib=$((max_gib * 1024 * 1024))
uid=${IN_IMAGE_UID:-10001}
case $uid in
  "" | 0 | *[!0-9]*) echo "IN_IMAGE_UID must be a non-root numeric uid: $uid" >&2; exit 2 ;;
esac

# size <volume>: the volume's size in KiB, or nothing when it cannot be read.
size() {
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
    --user "$uid:$uid" -v "$1:/c:ro" --entrypoint du "$image" -sk /c 2>/dev/null | awk '{print $1}'
}

list=$(mktemp)
trap 'rm -f "$list"' EXIT
total=0
for vol in $(docker volume ls -q --filter "name=${prefix}cache-"); do
  case $vol in "${prefix}cache-"*) ;; *) continue ;; esac
  kib=$(size "$vol")
  case $kib in
    '' | *[!0-9]*) echo "warn  $vol: size not read"; continue ;;
  esac
  echo "$kib $vol" >> "$list"
  total=$((total + kib))
done
echo "caches: $((total / 1024 / 1024)) GiB of ${max_gib} GiB for prefix '$prefix'"

dry=${REAP_DRY_RUN:-0}
removed=0
inuse=$(mktemp)
trap 'rm -f "$list" "$inuse"' EXIT
while read -r kib vol; do
  [ "$total" -gt "$max_kib" ] || break
  if [ -n "$(docker ps -aq --filter "volume=$vol")" ]; then
    echo "$kib $vol" >> "$inuse"
    continue
  fi
  if [ "$dry" = 1 ]; then
    echo "dry   docker volume rm $vol ($((kib / 1024)) MiB)"
  elif docker volume rm "$vol" >/dev/null 2>&1; then
    echo "trim  $vol ($((kib / 1024)) MiB)"
  else
    echo "warn  $vol not removed"
    continue
  fi
  total=$((total - kib))
  removed=$((removed + 1))
done < <(sort -rn "$list")

# In-use volumes (ruling 966 (4)): a volume a container mounts cannot be
# removed, so while the total is still over the bound trim inside it, through a
# one-shot container of <image> mounting it read-write, by whole cache entries.

# Delete build-cache entries, the files inside the xx/ hash buckets (two hex
# digits), oldest file mtime first across all buckets, until <need> KiB are
# freed. A bucket holds many unrelated entries and reading an entry does not
# touch the bucket's mtime, so a bucket's own mtime never decides; the bucket
# directories stay, so a concurrent build can still write into them. Prints
# the KiB freed.
# shellcheck disable=SC2016 # expanded by the in-volume shell, not here
gobuild_trim='dir=$1 need=$2
cd "$dir" || exit 1
buckets=
for d in [0-9a-f][0-9a-f]; do [ -d "$d" ] && buckets="$buckets $d"; done
[ -n "$buckets" ] || { echo 0; exit 0; }
find $buckets -type f -exec stat -c "%Y %s %n" {} + | sort -n | {
  freed=0
  while read -r _ bytes f; do
    [ "$freed" -lt "$need" ] || break
    rm -f "$f" || continue
    freed=$((freed + (bytes + 1023) / 1024))
  done
  echo "$freed"
}'
# golangci-lint cache clean: the whole cache directory's content goes.
# shellcheck disable=SC2016
golangci_clean='find "$1" -mindepth 1 -maxdepth 1 -exec rm -rf {} + && echo cleaned'

# in_volume <volume> <args...>: run <args> in <image> with <volume> on /c, read-write.
in_volume() {
  local vol=$1
  shift
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
    --user "$uid:$uid" -v "$vol:/c" "$@" 2>/dev/null
}

trimmed=0
while read -r kib vol; do
  [ "$total" -gt "$max_kib" ] || break
  need=$((total - max_kib))
  case $vol in
    *-gobuild)
      if [ "$kib" -gt "$max_kib" ]; then
        if [ "$dry" = 1 ]; then
          echo "dry   go clean -cache in $vol ($((kib / 1024)) MiB, in use)"
          freed=$kib
        elif in_volume "$vol" -e GOCACHE=/c --entrypoint go "$image" clean -cache >/dev/null; then
          echo "trim  go clean -cache in $vol ($((kib / 1024)) MiB, in use)"
          freed=$kib
        else
          echo "warn  go clean -cache in $vol failed"
          continue
        fi
      elif [ "$dry" = 1 ]; then
        echo "dry   trim oldest entries in $vol ($((need / 1024)) MiB of $((kib / 1024)) MiB, in use)"
        freed=$need
      else
        freed=$(in_volume "$vol" --entrypoint sh "$image" -c "$gobuild_trim" trim-ci-cache /c "$need")
        case $freed in
          '' | *[!0-9]*) echo "warn  $vol: trim inside failed"; continue ;;
        esac
        echo "trim  oldest entries in $vol ($((freed / 1024)) MiB freed, in use)"
      fi
      ;;
    *-golangci)
      if [ "$dry" = 1 ]; then
        echo "dry   golangci-lint cache clean in $vol ($((kib / 1024)) MiB, in use)"
      elif [ "$(in_volume "$vol" --entrypoint sh "$image" -c "$golangci_clean" trim-ci-cache /c)" = cleaned ]; then
        echo "trim  golangci-lint cache clean in $vol ($((kib / 1024)) MiB, in use)"
      else
        echo "warn  $vol: cache clean failed"
        continue
      fi
      freed=$kib
      ;;
    *)
      # The module cache is never trimmed per file: only removed whole, unused.
      echo "keep  $vol ($((kib / 1024)) MiB, in use; not trimmed inside)"
      continue
      ;;
  esac
  total=$((total - freed))
  trimmed=$((trimmed + 1))
done < <(sort -rn "$inuse")

echo "trim: $removed volume(s) removed, $trimmed trimmed inside, $((total / 1024 / 1024)) GiB left for prefix '$prefix'"
exit 0
