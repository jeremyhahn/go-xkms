#!/usr/bin/env bash
# touched-packages.sh <base> <tip>
#
# Prints the packages whose unit tests a diff requires, as repo-relative
# directories (pkg/acme/admin), sorted, one per line: the input of
# `make test-pkg PKG=<dir>` (Tenant rulings 1170/1171, handbook
# testing-guidelines.md section 4). That is each changed Go package of the
# root module plus its direct importers there, test imports included
# (go list -f on ./...). A changed non-Go file counts for the nearest package
# directory above it (pkg/x/testdata/in.json -> pkg/x). A package of a nested
# module (sdk/go, xkey, web/desktop) is not printed itself, but its
# root-module importers are; test/integration/ is touched-features.sh's.
#
# Renames count on both sides. Imports come from the working tree, under the
# tags `make test-pkg` passes (read from `make -n`). A package of ./... that
# does not load (Error or DepsErrors) hides its imports, so the script prints
# only ALL: run every package. A docs-only change (*.md, docs/, .changelog/)
# or an empty diff prints nothing. Exit 2 on a bad argument or revision.
set -euo pipefail

usage() {
	echo "usage: $0 <base> <tip>" >&2
	exit 2
}
[ "$#" -eq 2 ] || usage
base=$1
tip=$2

if ! top=$(git rev-parse --show-toplevel 2>/dev/null); then
	echo "$0: not inside a git repository" >&2
	exit 2
fi
top=$(cd "$top" && pwd -P)
cd "$top"

for rev in "$base" "$tip"; do
	if ! git rev-parse --verify --quiet "${rev}^{commit}" >/dev/null; then
		echo "$0: bad revision: $rev" >&2
		exit 2
	fi
done

difftmp=$(mktemp)
pkgs=
trap 'rm -f "$difftmp" ${pkgs:+"$pkgs"}' EXIT
# -z: NUL-delimited records with paths unquoted (core.quotePath quotes a
# non-ASCII path otherwise); a rename or copy record holds two paths.
if ! git diff --name-status -z -M "$base" "$tip" >"$difftmp"; then
	echo "$0: git diff $base $tip failed" >&2
	exit 2
fi
files=()
while IFS= read -r -d '' st; do
	n=1
	case "$st" in R* | C*) n=2 ;; esac
	for ((i = 0; i < n; i++)); do
		IFS= read -r -d '' p || break
		files+=("$p")
	done
done <"$difftmp"

candidates=()
for f in ${files[@]+"${files[@]}"}; do
	[ -n "$f" ] || continue
	case "$f" in
	*.md | docs/* | .changelog/* | test/integration/*) continue ;;
	*/*) ;;
	*) continue ;; # a top-level file (Makefile, go.mod) is no package
	esac
	candidates+=("$f")
done
[ "${#candidates[@]}" -gt 0 ] || exit 0

# recipe_tags <make args>: the -tags of the first go test line `make -n`
# prints, comma-separated, so the tags are the recipe's after every +=.
recipe_tags() {
	local out line re_dq re_sq re_bare
	out=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -n -s --no-print-directory "$@" 2>/dev/null) || return 1
	re_dq='-tags[= ]+"([^"]*)"'
	re_sq="-tags[= ]+'([^']*)'"
	re_bare='-tags[= ]+([^[:space:]]+)'
	while IFS= read -r line; do
		case "$line" in *" test "*) ;; *) continue ;; esac
		if [[ $line =~ $re_dq ]] || [[ $line =~ $re_sq ]] || [[ $line =~ $re_bare ]]; then
			printf '%s\n' "${BASH_REMATCH[1]}" | tr -s ' ,' '\n' | awk 'NF && !seen[$0]++' | paste -sd, -
			return 0
		fi
	done <<<"$out"
	return 1
}

# The unit-test tags make test-pkg passes.
if ! tags=$(recipe_tags test-pkg PKG=.); then
	echo "$0: no go test -tags line in make -n test-pkg; reading imports without tags" >&2
	tags=
fi

pkgs=$(mktemp)
# <dir> TAB <import path> TAB <imports, test imports, xtest imports> TAB E
# when the package or a dependency does not load
if ! go list -e -tags "$tags" \
	-f '{{.Dir}}{{"\t"}}{{.ImportPath}}{{"\t"}}{{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}{{"\t"}}{{if or .Error .DepsErrors}}E{{end}}' \
	./... >"$pkgs" 2>/dev/null; then
	echo "$0: go list ./... failed" >&2
	exit 2
fi
# A package that does not load hides its imports, so its importers are
# unknown: every package runs.
if bad=$(awk -F'\t' '$4 == "E" { print $2; found = 1; exit } END { exit !found }' "$pkgs"); then
	echo "$0: $bad does not load completely; every package runs" >&2
	echo ALL
	exit 0
fi
rel_pkgs=$(awk -F'\t' -v top="$top/" 'substr($1, 1, length(top)) == top { print substr($1, length(top) + 1) "\t" $2 }' "$pkgs")

# import_path <dir>: the import path of <dir> from the nearest go.mod (a
# deleted package or one of a nested module).
import_path() {
	local d=$1 mod
	while :; do
		if [ -f "$d/go.mod" ]; then
			mod=$(sed -n 's/^module[[:space:]]\{1,\}//p' "$d/go.mod" | head -1)
			if [ "$d" = "$1" ]; then
				printf '%s\n' "$mod"
			elif [ "$d" = . ]; then
				printf '%s/%s\n' "$mod" "$1"
			else
				printf '%s/%s\n' "$mod" "${1#"$d"/}"
			fi
			return 0
		fi
		[ "$d" != . ] || return 1
		d=$(dirname "$d")
	done
}
root_ip() { # root_ip <dir>: the import path of a root-module package dir
	printf '%s\n' "$rel_pkgs" | d=$1 awk -F'\t' '$1 == ENVIRON["d"] { print $2; exit }'
}

out=()
changed_ips=()
for f in "${candidates[@]}"; do
	dir=$(dirname "$f")
	if [ "${f%.go}" = "$f" ]; then
		# A non-Go file: the nearest root-module package at or above it.
		while [ "$dir" != . ] && [ -z "$(root_ip "$dir")" ]; do
			dir=$(dirname "$dir")
		done
		[ "$dir" != . ] || continue
	fi
	ip=$(root_ip "$dir")
	if [ -n "$ip" ]; then
		out+=("$dir")
	elif ! ip=$(import_path "$dir"); then
		continue
	fi
	changed_ips+=("$ip")
done

if [ "${#changed_ips[@]}" -gt 0 ]; then
	while IFS= read -r d; do
		[ -n "$d" ] && out+=("$d")
	done < <(awk -F'\t' -v top="$top/" -v ips="${changed_ips[*]}" '
		BEGIN { n = split(ips, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
		substr($1, 1, length(top)) == top {
			m = split($3, imp, " ")
			for (i = 1; i <= m; i++) if (imp[i] in want) { print substr($1, length(top) + 1); break }
		}' "$pkgs")
fi

[ "${#out[@]}" -gt 0 ] || exit 0
printf '%s\n' "${out[@]}" | grep -v '^test/integration/' | LC_ALL=C sort -u || true
