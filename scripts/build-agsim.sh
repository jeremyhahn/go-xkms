#!/usr/bin/env bash
#
# build-agsim.sh: build the trusted-firmware host simulators at the version go.mod pins into DIR.
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
