#!/usr/bin/env bash
# apk-index-sum: v3. One checksum of the Alpine package indexes the devcontainer build resolves against.
set -euo pipefail

dockerfile=${1:-${APK_DOCKERFILE:-build/docker/devcontainer/Dockerfile}}

fail() {
  echo "::error::apk-index-sum: $*" >&2
  exit 1
}

bases=()
if [ -n "${APK_BASE_IMAGES:-}" ]; then
  read -r -a bases <<< "$APK_BASE_IMAGES"
else
  [ -f "$dockerfile" ] || fail "no Dockerfile at $dockerfile"
  declare -A arg=() stage=() seen=()
  # shellcheck disable=SC2016 # a regex, not an expansion
  ref='\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)'
  from=0
  # Join continuation lines, drop comments, then read one instruction a line.
  while read -r kw rest; do
    case ${kw^^} in
      ARG)
        # Only a global ARG (before the first FROM) can name a base image.
        [ "$from" = 0 ] || continue
        read -r -a kvs <<< "$rest"
        for kv in "${kvs[@]}"; do
          case $kv in
            *=*) v=${kv#*=}; v=${v#\"}; v=${v%\"}; arg[${kv%%=*}]=$v ;;
          esac
        done
        ;;
      FROM)
        from=1
        read -r -a w <<< "$rest"
        i=0
        while [ "$i" -lt "${#w[@]}" ] && [ "${w[$i]#--}" != "${w[$i]}" ]; do i=$((i + 1)); done
        img=${w[$i]:-}
        [ -n "$img" ] || fail "a FROM line in $dockerfile names no image"
        # ${NAME}, ${NAME:-default} and $NAME from the global ARG defaults.
        while [[ $img =~ $ref ]]; do
          n=${BASH_REMATCH[1]:-${BASH_REMATCH[4]}}
          v=${arg[$n]:-${BASH_REMATCH[3]}}
          [ -n "$v" ] || fail "FROM $img in $dockerfile names \$$n, which has no global ARG default; set APK_BASE_IMAGES"
          img=${img/"${BASH_REMATCH[0]}"/$v}
        done
        if [ "${w[$((i + 1))]:-}" != "" ] && [ "${w[$((i + 1))],,}" = as ]; then
          stage[${w[$((i + 2))],,}]=1
        fi
        [ "${img,,}" = scratch ] && continue
        [ -n "${stage[${img,,}]:-}" ] && continue
        [ -n "${seen[$img]:-}" ] && continue
        seen[$img]=1
        bases+=("$img")
        ;;
    esac
  done < <(sed -e ':a' -e '/\\$/N; s/\\\n/ /; ta' -e 's/^[[:space:]]*#.*//' "$dockerfile")
fi

[ "${#bases[@]}" -gt 0 ] || fail "no base image found in $dockerfile"

mirror_script=$(cd "$(dirname "$0")" && pwd)/apk-mirror.sh
[ -f "$mirror_script" ] || fail "no apk-mirror.sh beside $0"

# Runs in the base image, with apk-mirror.sh on its stdin. A base without apk
# contributes `none`. The repository list is printed before apk-mirror
# rewrites it (and restores it).
# shellcheck disable=SC2016 # expanded by the container's shell
probe='command -v apk >/dev/null 2>&1 || { echo none; exit 0; }
cat > /tmp/apk-mirror || exit 5
sed "s/[[:space:]]*$//" /etc/apk/repositories | grep -v "^#" | grep . | sort
sh /tmp/apk-mirror update --quiet >/dev/null || exit 3
set -- /var/cache/apk/APKINDEX.*.tar.gz
[ -f "$1" ] || exit 4
sha256sum "$@" | cut -d" " -f1 | sort'

sum_input=
alpine=0
for img in "${bases[@]}"; do
  out=$(docker run -i --rm --pull missing --network bridge --user 0 \
          --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
          --security-opt no-new-privileges -e APK_MIRROR="${DEVCACHE_APK_MIRROR:-}" \
          --entrypoint /bin/sh "$img" -c "$probe" < "$mirror_script") ||
    fail "reading the Alpine package index of $img failed (exit $?)"
  [ "$out" = none ] || alpine=1
  echo "apk-index-sum: $img: $(printf '%s\n' "$out" | grep -cE '^[0-9a-f]{64}$' || true) index file(s)" >&2
  sum_input+="$img"$'\n'"$out"$'\n'
done

if [ "$alpine" = 0 ]; then
  echo none
else
  printf '%s' "$sum_input" | sha256sum | cut -d' ' -f1
fi
