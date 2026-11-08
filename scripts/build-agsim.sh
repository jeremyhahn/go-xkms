#!/usr/bin/env bash
#
# build-agsim.sh -- build the trusted-firmware host simulators (tfwsim and
# tfwsim-atecc608a) at the version go.mod pins, into DIR.
#
# Usage:
#	scripts/build-agsim.sh DIR
#
# Why this exists (go-xkms#737). The device-attest-01 DICE end-to-end test
# (pkg/acme/client) enrolls the REAL trusted-firmware firmware, compiled for the
# host, through the ACME server. The simulators are C programs, so the Go
# module cache holds their source but not a binary; the sdk/go/tfwsim launcher
# finds them in $TFWSIM_DIR, and a missing binary FAILS the test rather than
# skipping it.
#
# The source is the trusted-firmware repository at the same version as the
# sdk/go dependency. It is fetched with git, not the Go module machinery: the
# repository root has no go.mod, so proxy.golang.org and sum.golang.org serve
# no version of github.com/jeremyhahn/trusted-firmware (only sdk/go resolves).
# The version is read from go.mod, so bumping the dependency is the only step
# that changes what is simulated, and a bump with no pin line fails here.
#
# The source is compiled and executed, so it is pinned: scripts/agsim.sum names
# the repository, the commit and its tree for each version. The script fetches
# that commit (never the tag name, which can move) into a fresh repository,
# where git hashes every object it receives, and checks the commit and tree
# against the pin before anything is built.
#
# An offline image pre-fetches the pinned commit into $AGSIM_SRC/<version>
# (default /opt/agsim-src, build/docker/devcontainer/Dockerfile); when that
# directory exists the commit is fetched from it instead, and checked the same
# way, so a pre-fetched source at another commit fails too.
#
# A DIR already built for this version is left alone.
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: build-agsim.sh DIR" >&2
	exit 2
fi
dir=$1
module=github.com/jeremyhahn/trusted-firmware
binaries=(tfwsim tfwsim-atecc608a)

if ! version=$(go list -m -f '{{.Version}}' "${module}/sdk/go"); then
	echo "build-agsim.sh: go list -m ${module}/sdk/go failed: cannot read the version go.mod pins (go's error is above)" >&2
	exit 1
fi
stamp="${dir}/.version"

built=1
for binary in "${binaries[@]}"; do
	[ -x "${dir}/${binary}" ] || built=0
done
if [ "${built}" -eq 1 ] && [ "$(cat "${stamp}" 2>/dev/null)" = "${version}" ]; then
	echo "tfwsim ${version} already built in ${dir}"
	exit 0
fi

pins=$(dirname "$0")/agsim.sum
url='' commit='' tree=''
while read -r p_url p_version p_commit p_tree _; do
	case "${p_url}" in '' | '#'*) continue ;; esac
	if [ "${p_version}" = "${version}" ]; then
		url=${p_url} commit=${p_commit} tree=${p_tree}
	fi
done <"${pins}"
if [ -z "${tree}" ]; then
	echo "build-agsim.sh: trusted-firmware ${version} has no pin in ${pins}; add it (see that file)" >&2
	exit 1
fi
src=${url}
safe=()
prefetched="${AGSIM_SRC:-/opt/agsim-src}/${version}"
if [ -d "${prefetched}" ]; then
	src=$(cd "${prefetched}" && pwd -P)
	# The image's pre-fetched source belongs to root, and git refuses a
	# repository another user owns unless safe.directory names it.
	safe=(-c "safe.directory=${src}")
fi

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
git -c init.defaultBranch=main init -q "${work}"
if ! git "${safe[@]}" -C "${work}" fetch -q --depth 1 "${src}" "${commit}"; then
	echo "build-agsim.sh: git fetch ${src} ${commit} failed: the source does not hold the pinned commit (git's error is above)" >&2
	exit 1
fi
git -C "${work}" -c advice.detachedHead=false checkout -q FETCH_HEAD
got=$(git -C "${work}" rev-parse 'HEAD^{commit}')
if [ "${got}" != "${commit}" ]; then
	echo "build-agsim.sh: ${src} gave commit '${got}', ${pins} pins '${commit}'" >&2
	exit 1
fi
got=$(git -C "${work}" rev-parse 'HEAD^{tree}')
if [ "${got}" != "${tree}" ]; then
	echo "build-agsim.sh: commit ${commit} has tree '${got}', ${pins} pins '${tree}'" >&2
	exit 1
fi

make -C "${work}" "${binaries[@]}"

mkdir -p "${dir}"
for binary in "${binaries[@]}"; do
	install -m 0755 "${work}/build/host/${binary}" "${dir}/${binary}"
done
echo "${version}" >"${stamp}"
echo "tfwsim ${version} built in ${dir}"
