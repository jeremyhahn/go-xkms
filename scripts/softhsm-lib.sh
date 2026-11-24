#!/bin/sh
#
# softhsm-lib.sh: print the libsofthsm2.so the PKCS#11 suites should load.
set -eu

MIN_VERSION=2.7.0
here=$(cd "$(dirname "$0")" && pwd)
build=${SOFTHSM_BUILD_SCRIPT:-${here}/build-softhsm.sh}
pinned=$(sed -n 's/^SOFTHSM_VERSION=//p' "${build}")
if [ -z "${pinned}" ]; then
	echo "softhsm-lib.sh: no SOFTHSM_VERSION in ${build}" >&2
	exit 1
fi
cache=${SOFTHSM_CACHE:-${HOME}/.cache/go-xkms/softhsm-${pinned}}

# at_least VERSION -- VERSION is MIN_VERSION or newer.
at_least() {
	[ "$(printf '%s\n%s\n' "$1" "${MIN_VERSION}" | sort -V | head -n 1)" = "${MIN_VERSION}" ]
}

if util=$(command -v softhsm2-util 2>/dev/null); then
	version=$("${util}" --version 2>/dev/null || true)
	if [ -n "${version}" ] && at_least "${version}"; then
		# Only the module of the utility's own installation matches its
		# version: follow symlinks to that installation and look inside its
		# prefix, never in unrelated system library directories.
		prefix=$(dirname "$(dirname "$(readlink -f "${util}")")")
		for dir in "${prefix}/lib/softhsm" "${prefix}/lib64/softhsm" "${prefix}"/lib/*-linux-gnu/softhsm; do
			if [ -f "${dir}/libsofthsm2.so" ]; then
				echo "$(cd "${dir}" && pwd -P)/libsofthsm2.so"
				exit 0
			fi
		done
		echo "softhsm-lib.sh: no module in the installation of ${util}; using the pinned build" >&2
	fi
fi

# Resolve the cache to an absolute path first: the build script changes
# directory before it installs into DESTDIR, and Go test processes load the
# printed module from their own package directories.
mkdir -p "$(dirname "${cache}")"
cache="$(cd "$(dirname "${cache}")" && pwd)/$(basename "${cache}")"
lib="${cache}/usr/lib/softhsm/libsofthsm2.so"
cached_util="${cache}/usr/bin/softhsm2-util"

# cached -- the cache holds a complete build of the pinned release.
cached() {
	[ -f "${lib}" ] && [ -x "${cached_util}" ] && [ "$("${cached_util}" --version 2>/dev/null || true)" = "${pinned}" ]
}

if cached; then
	echo "${lib}"
	exit 0
fi

# Hold a lock beside the cache across the recheck, build and publication, so
# invocations sharing a cache build it once and never remove one another's
# published cache; a cache published while this one waited is reused.
exec 9>"${cache}.lock"
flock 9
if cached; then
	echo "${lib}"
	exit 0
fi

# Build into a sibling directory and rename it into place, so a failed or
# interrupted build never leaves a cache that looks complete.
tmp=$(mktemp -d "${cache}.tmp.XXXXXX")
trap 'rm -rf "${tmp}"' EXIT INT TERM
echo "softhsm-lib.sh: SoftHSM ${MIN_VERSION}+ not installed; building ${pinned} into ${cache}" >&2
DESTDIR="${tmp}" sh "${build}" /usr >&2
rm -rf "${cache}"
mv "${tmp}" "${cache}"
echo "${lib}"
