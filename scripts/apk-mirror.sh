#!/bin/sh
# apk-mirror: v1. Runs apk through a package cache when the build has one.
set -eu

repos=${APK_REPOSITORIES:-/etc/apk/repositories}
mirror=${APK_MIRROR:-}
if [ -z "$mirror" ]; then
	exec apk "$@"
fi
case $mirror in
http://* | https://*) ;;
*)
	echo "apk-mirror: APK_MIRROR '$mirror' is not an http(s) URL" >&2
	exit 2
	;;
esac
mirror=${mirror%/}
saved=$(mktemp)
cp "$repos" "$saved"
restore() { cat "$saved" >"$repos" && rm -f "$saved"; }
trap restore EXIT
sed -i "s#https\{0,1\}://dl-cdn\.alpinelinux\.org/alpine#$mirror#" "$repos"
apk "$@"
