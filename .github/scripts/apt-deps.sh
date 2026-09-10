#!/bin/sh
# apt-deps.sh — make a set of Debian packages present in the job container, or
# fail the job naming the ones that are not. Called from
# .github/workflows/ci.yml, as root (the workflow prefixes it with sudo).
#
#   apt-deps.sh <package>...
#
# WHY THIS EXISTS (go-xkms #342)
#
# Nine jobs per pull request ran `apt-get install` against the public Ubuntu
# archive before compiling anything. Every one of them was an independent
# chance for an archive outage to redden a build that had no defect: measured
# on #304 and #319, the install step died after eighteen minutes of
# "Cannot initiate the connection ... Network is unreachable" on every IPv6
# mirror address and timeouts on the IPv4 ones, and the Build/Vet/Test steps
# showed `skipped`, not `failure`, because nothing had run.
#
# The fix the issue prefers is to bake the packages into the runner image, as
# #249 did for the Go analysis tools. That image is owner infrastructure, so
# this script is written to make that change safe to land INCREMENTALLY:
#
#   - A package the image already carries is never reinstalled. dpkg is asked
#     first, and when nothing is missing apt is not touched at all, so the
#     network is out of the picture the moment the image catches up.
#   - What IS missing is fetched with the doomed IPv6 attempts skipped
#     (Acquire::ForceIPv4 -- every host in this fleet resolves AAAA records
#     and none has a default IPv6 route, see require-tool.sh) and with a
#     bounded retry, so a stalled mirror costs seconds per attempt instead of
#     the eighteen minutes measured above.
#   - After apt reports success, dpkg is asked AGAIN. apt's exit status is not
#     the property this job needs; the package being installed is, and a step
#     that trusted the former would report success for a package that is not
#     there. That is the same fail-closed shape as require-tool.sh.
#
# Knobs, all optional, read from the environment:
#   APT_DEPS_ATTEMPTS  how many times to try the install (default 5)
#   APT_DEPS_BACKOFF   seconds to wait after the first failure; doubles each
#                      attempt (default 2; the tests set 0)

set -eu

if [ "$#" -eq 0 ]; then
	echo "usage: apt-deps.sh <package>..." >&2
	exit 2
fi

attempts="${APT_DEPS_ATTEMPTS:-5}"
backoff="${APT_DEPS_BACKOFF:-2}"

installed() { # installed <package>: true when dpkg says it is fully installed
	[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" = "install ok installed" ]
}

missing_of() { # missing_of <package>...: prints the ones dpkg does not have
	for pkg in "$@"; do
		installed "$pkg" || printf '%s\n' "$pkg"
	done
}

missing="$(missing_of "$@")"
if [ -z "$missing" ]; then
	echo "apt-deps: all present, apt not touched: $*"
	exit 0
fi

echo "apt-deps: missing, installing: $(printf '%s' "$missing" | tr '\n' ' ')"
export DEBIAN_FRONTEND=noninteractive

attempt=1
delay="$backoff"
while :; do
	# shellcheck disable=SC2086  # $missing is a whitespace-separated package list
	if apt-get -o Acquire::ForceIPv4=true update \
		&& apt-get -o Acquire::ForceIPv4=true install -y $missing; then
		break
	fi
	if [ "$attempt" -ge "$attempts" ]; then
		echo "apt-deps: giving up after ${attempts} attempt(s); still missing:" >&2
		printf '  %s\n' $missing >&2
		exit 1
	fi
	echo "apt-deps: attempt ${attempt} of ${attempts} failed; retrying in ${delay}s" >&2
	sleep "$delay"
	attempt=$((attempt + 1))
	delay=$((delay * 2))
done

# apt said yes; dpkg decides.
still="$(missing_of "$@")"
if [ -n "$still" ]; then
	echo "apt-deps: apt reported success but dpkg does not have:" >&2
	printf '%s\n' "$still" | sed 's/^/  /' >&2
	exit 1
fi
echo "apt-deps: present: $*"
