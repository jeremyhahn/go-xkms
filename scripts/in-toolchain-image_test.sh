#!/usr/bin/env bash
# Tests scripts/in-toolchain-image.sh's environment forwarding with a stub
# `docker` that records its arguments: a bridge stage carries the Trivy
# database repositories the runner sets, and never TRIVY_INSECURE (it would
# turn off TLS verification for the security gate's database downloads).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir "$tmp/bin"
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$DOCKER_STUB_LOG"
case $1 in
  info) echo 4 ;;
  cp) cat >/dev/null ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/docker"

fail=0
log="$tmp/docker.log"
(
  cd "$repo"
  PATH="$tmp/bin:$PATH" DOCKER_STUB_LOG="$log" \
    IN_IMAGE_NETWORK=bridge CI_CACHE=off \
    TRIVY_DB_REPOSITORY=mirror.example/trivy-db \
    TRIVY_JAVA_DB_REPOSITORY=mirror.example/trivy-java-db \
    TRIVY_INSECURE=true \
    scripts/in-toolchain-image.sh toolchain:test true >/dev/null 2>"$tmp/err"
) || { echo "FAIL: in-toolchain-image.sh exited non-zero: $(cat "$tmp/err")"; exit 1; }

create=$(while IFS= read -r l; do case $l in create*) echo "$l" ;; esac; done <"$log")
[ -n "$create" ] || { echo "FAIL: no docker create call"; exit 1; }

case " $create " in
  *" --env TRIVY_DB_REPOSITORY "*) ;;
  *) echo "FAIL: TRIVY_DB_REPOSITORY not forwarded"; fail=1 ;;
esac
case " $create " in
  *" --env TRIVY_JAVA_DB_REPOSITORY "*) ;;
  *) echo "FAIL: TRIVY_JAVA_DB_REPOSITORY not forwarded"; fail=1 ;;
esac
case " $create " in
  *TRIVY_INSECURE*) echo "FAIL: TRIVY_INSECURE forwarded into the stage"; fail=1 ;;
esac

[ "$fail" = 0 ] && echo "PASS: in-toolchain-image.sh forwards the Trivy repositories, not TRIVY_INSECURE"
exit "$fail"
