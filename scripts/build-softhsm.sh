#!/bin/sh
#
# build-softhsm.sh -- build and install SoftHSM v2 from its pinned,
# checksum-verified upstream release.
#
# Usage:
#	scripts/build-softhsm.sh [PREFIX]
#
# PREFIX defaults to /usr, which installs the module where Debian's
# libsofthsm2 package puts it (/usr/lib/softhsm/libsofthsm2.so) and
# softhsm2-util in /usr/bin, so every path the tests, configs and
# documentation already name keeps working. The configuration file is read
# from /etc/softhsm/softhsm2.conf and tokens default to /var/lib/softhsm/tokens,
# again Debian's layout. Set DESTDIR to stage the install under another root
# (a multi-stage image copies that tree into its runtime stage).
#
# Why this exists (go-xkms#1418). Every distribution this repository builds
# on ships SoftHSM 2.6.1, whose C_Decrypt answers an AES-GCM tag mismatch
# with CKR_GENERAL_ERROR -- the code PKCS#11 reserves for an unrecoverable
# token error. pkg/backend/pkcs11 never treats that ambiguous code as
# tampering (#1414), so on 2.6.1 a tampered sealed value cannot be reported as
# types.ErrSealedDataAuthentication. SoftHSM 2.7.0 answers
# CKR_ENCRYPTED_DATA_INVALID, which names the ciphertext, and is classified.
# 2.7.0 is therefore the minimum SoftHSM version for PKCS#11 tamper
# classification, and this script is the one place it is pinned.
#
# The source is compiled and executed, so it is pinned: the archive must hash
# to SOFTHSM_SHA256 below, checked before anything is extracted. A moved tag
# or a changed upstream archive fails here. SOFTHSM_ARCHIVE may name a local
# copy of the archive (an offline build, or the script's own tests); it is
# held to the same checksum.
#
# Build dependencies (installed by the caller, so each image keeps its own
# package manager and minimal package set):
#	Debian/Ubuntu: build-essential autoconf automake libtool pkg-config
#	               libssl-dev curl ca-certificates
#	Alpine:        build-base autoconf automake libtool pkgconf openssl-dev
#	               curl
# Runtime dependencies of the installed module: libssl3 (OpenSSL 3), the C++
# runtime (libstdc++6 / libstdc++, libgcc).
#
# To bump: set SOFTHSM_VERSION, download
# https://github.com/softhsm/SoftHSMv2/archive/refs/tags/<version>.tar.gz,
# take its sha256sum as SOFTHSM_SHA256, and confirm the new release still
# answers a GCM tag mismatch with a code ciphertextRejections lists
# (pkg/backend/pkcs11/ciphertext_rejection.go).
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
