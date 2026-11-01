#!/usr/bin/env bash
#
# build-agsim.sh -- build the arduino-generic host simulators (agsim and
# agsim-atecc608a) at the version go.mod pins, into DIR.
#
# Usage:
#	scripts/build-agsim.sh DIR
#
# Why this exists (go-xkms#737). The device-attest-01 DICE end-to-end test
# (pkg/acme/client) enrolls the REAL arduino-generic firmware, compiled for the
# host, through the ACME server. The simulators are C programs, so the Go
# module cache holds their source but not a binary; the sdk/go/agsim launcher
# finds them in $AGSIM_DIR, and a missing binary FAILS the test rather than
# skipping it.
#
# The source is the arduino-generic module at the same version as the
# sdk/go dependency, fetched through the Go module machinery (so it uses the
# same private-module credentials `go mod download` does) and copied out of the
# read-only module cache before it is built. The version is read from go.mod, so
# bumping the dependency is the only step that changes what is simulated.
#
# The source is compiled and executed, so it is pinned: its module hash must
# match scripts/agsim.sum (the root arduino-generic module is not in go.mod, so
# go.sum does not cover it, and first-party modules skip the checksum database).
# A moved tag or a changed upstream fails here, before anything is built.
#
# A DIR already built for this version is left alone.
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: build-agsim.sh DIR" >&2
	exit 2
fi
dir=$1
module=github.com/jeremyhahn/arduino-generic
binaries=(agsim agsim-atecc608a)

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
	echo "agsim ${version} already built in ${dir}"
	exit 0
fi

pins=$(dirname "$0")/agsim.sum
want=$(awk -v m="${module}" -v v="${version}" '$1 == m && $2 == v { print $3 }' "${pins}")
if [ -z "${want}" ]; then
	echo "build-agsim.sh: ${module} ${version} has no hash in ${pins}; add it (see that file)" >&2
	exit 1
fi
# `go mod download -json` reports a failure in the JSON's Error field on
# stdout, not on stderr, so the result is kept and the error reported here.
# Offline (GOPROXY=off) this module resolves only from the module cache and
# only with GOPRIVATE covering it: it is not in go.sum, so without GOPRIVATE
# Go asks the checksum database, which cannot vouch for a first-party module.
if ! download=$(go mod download -json "${module}@${version}"); then
	reason=$(printf '%s\n' "${download}" | sed -n 's/^[[:space:]]*"Error": "\(.*\)",\{0,1\}$/\1/p')
	echo "build-agsim.sh: go mod download ${module}@${version} failed: ${reason:-no error reported}" >&2
	echo "build-agsim.sh: offline, it needs the module in the module cache and GOPRIVATE covering ${module}" >&2
	exit 1
fi
got=$(printf '%s\n' "${download}" | sed -n 's/^[[:space:]]*"Sum": "\(.*\)",\{0,1\}$/\1/p')
if [ "${got}" != "${want}" ]; then
	echo "build-agsim.sh: ${module} ${version} hashes to '${got}', ${pins} pins '${want}'" >&2
	exit 1
fi

if ! src=$(go list -m -f '{{.Dir}}' "${module}@${version}"); then
	echo "build-agsim.sh: go list -m ${module}@${version} failed: cannot locate its source in the module cache (go's error is above)" >&2
	exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
cp -r "${src}/." "${work}/"
chmod -R u+w "${work}"

make -C "${work}" "${binaries[@]}"

mkdir -p "${dir}"
for binary in "${binaries[@]}"; do
	install -m 0755 "${work}/build/host/${binary}" "${dir}/${binary}"
done
echo "${version}" >"${stamp}"
echo "agsim ${version} built in ${dir}"
