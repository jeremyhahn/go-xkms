#!/bin/sh
#
# build-softhsm.sh: build and install SoftHSM v2 from its pinned, checksum-verified release.
set -eu

SOFTHSM_VERSION=2.7.0
SOFTHSM_SHA256=be14a5820ec457eac5154462ffae51ba5d8a643f6760514d4b4b83a77be91573
SOFTHSM_URL="https://github.com/softhsm/SoftHSMv2/archive/refs/tags/${SOFTHSM_VERSION}.tar.gz"

if [ "$#" -gt 1 ]; then
	echo "usage: build-softhsm.sh [PREFIX]" >&2
	exit 2
fi
prefix=${1:-/usr}
destdir=${DESTDIR:-}

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT INT TERM
archive="${work}/softhsm-${SOFTHSM_VERSION}.tar.gz"

if [ -n "${SOFTHSM_ARCHIVE:-}" ]; then
	cp "${SOFTHSM_ARCHIVE}" "${archive}"
elif command -v curl >/dev/null 2>&1; then
	curl -fsSL --retry 3 -o "${archive}" "${SOFTHSM_URL}"
else
	wget -q -O "${archive}" "${SOFTHSM_URL}"
fi

if ! echo "${SOFTHSM_SHA256}  ${archive}" | sha256sum -c - >/dev/null 2>&1; then
	echo "build-softhsm.sh: SoftHSM ${SOFTHSM_VERSION} archive hashes to $(sha256sum "${archive}" | cut -d' ' -f1), pinned ${SOFTHSM_SHA256}" >&2
	exit 1
fi

tar -xzf "${archive}" -C "${work}"
src="${work}/SoftHSMv2-${SOFTHSM_VERSION}"
cd "${src}"
sh autogen.sh
./configure \
	--prefix="${prefix}" \
	--sysconfdir=/etc/softhsm \
	--localstatedir=/var \
	--with-crypto-backend=openssl \
	--disable-gost
make -j"$(nproc 2>/dev/null || echo 2)"
# install-strip and no libtool archives: the images carry the module and the
# utilities, not debug symbols or link-time artifacts nothing links against.
make install-strip DESTDIR="${destdir}"
rm -f "${destdir}${prefix}"/lib/softhsm/*.la "${destdir}${prefix}"/lib/softhsm/*.a

installed=$("${destdir}${prefix}/bin/softhsm2-util" --version)
if [ "${installed}" != "${SOFTHSM_VERSION}" ]; then
	echo "build-softhsm.sh: installed softhsm2-util reports '${installed}', want ${SOFTHSM_VERSION}" >&2
	exit 1
fi
echo "SoftHSM ${SOFTHSM_VERSION} installed under ${destdir}${prefix}"
