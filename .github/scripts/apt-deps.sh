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
#     bounded retry.
#   - Every apt-get call is BOUNDED (go-xkms #1587). apt's own
#     Acquire::http::Timeout covers a connection that stops sending, and
#     `timeout` covers everything else: main run 55255 sat in `apt-get update`
#     after "Get:15 ... noble-backports InRelease" for hours, because the
#     retry above only ever starts once an attempt returns. A call that hits
#     the bound is a failed attempt like any other, so the retry and backoff
#     apply and the step still ends naming what is missing.
#   - After apt reports success, dpkg is asked AGAIN. apt's exit status is not
#     the property this job needs; the package being installed is, and a step
#     that trusted the former would report success for a package that is not
#     there. That is the same fail-closed shape as require-tool.sh.
#
# Knobs, all optional, read from the environment:
#   APT_DEPS_ATTEMPTS  how many times to try the install (default 5)
#   APT_DEPS_BACKOFF   seconds to wait after the first failure; doubles each
#                      attempt (default 2; the tests set 0)
#   APT_DEPS_ATTEMPT_SECONDS
#                      the bound on each call: apt-get update, apt-get
#                      install, and the dpkg --configure -a that opens every
#                      retry (default 40)
#
# THE DEFAULT BOUND (#1587). The script must give up, naming the packages,
# before the job's own timeout-minutes kills it silently. The smallest bound
# of a job that runs it is Security Scan's 15m, and its worst case is every
# call hitting the bound: 2 calls on attempt 1, 3 on each of the 4 retries,
# 14 calls x (40s + timeout's 10s kill grace) + 30s of backoff = 730s, about
# 12m, leaving 3m for checkout and Go setup. A cut-off attempt is not wasted:
# the .debs it fetched stay in apt's cache and dpkg --configure -a finishes
# what it unpacked, so the next attempt resumes instead of starting over.

set -eu

if [ "$#" -eq 0 ]; then
	echo "usage: apt-deps.sh <package>..." >&2
	exit 2
fi

attempts="${APT_DEPS_ATTEMPTS:-5}"
backoff="${APT_DEPS_BACKOFF:-2}"
attempt_seconds="${APT_DEPS_ATTEMPT_SECONDS:-40}"

installed() { # installed <package>: true when dpkg says it is fully installed
	[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" = "install ok installed" ]
}

bounded() { # bounded <command...>: runs the command, cut off at the bound
	timeout --kill-after=10 "$attempt_seconds" "$@"
}

apt_get() { # apt_get <args...>: one apt-get call, bounded in time and on the wire
	bounded apt-get \
		-o Acquire::http::Timeout=30 \
		-o Acquire::https::Timeout=30 \
		-o Acquire::Retries=3 \
		-o Acquire::ForceIPv4=true \
		"$@"
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
	# A previous attempt cut off mid-install leaves dpkg interrupted, and apt
	# refuses every later install until it is finished.
	if [ "$attempt" -gt 1 ] && ! bounded dpkg --configure -a; then
		echo "apt-deps: dpkg --configure -a failed before attempt ${attempt}" >&2
	fi
	# shellcheck disable=SC2086  # $missing is a whitespace-separated package list
	if apt_get update && apt_get install -y $missing; then
		break
	else
		status=$?
	fi
	# 124: timeout stopped the call; 137: it ignored TERM and was killed.
	if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
		echo "apt-deps: attempt ${attempt} timed out after ${attempt_seconds}s" >&2
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
