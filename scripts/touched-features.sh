#!/usr/bin/env bash
# touched-features.sh <base> <tip>
#
# Prints the features whose `make integration-test-<feature>` a diff requires,
# sorted, one per line (Tenant rulings 1170/1171, handbook
# testing-guidelines.md section 4). A feature is a directory
# test/integration/<feature>/ holding _test.go files: the Makefile's
# integration-test-% pattern runs it, and internal/buildgates checks that
# every such directory resolves. There is no second feature list.
#
#   - a changed file under test/integration/<feature>/ names that feature;
#   - a changed Go package (or a file inside one, such as testdata) names
#     every feature whose integration tests import it, directly or
#     transitively (go list -deps -test -tags integration);
#   - a change outside every feature prints only ALL: the Makefile,
#     .github/, go.mod/go.sum, test/integration/common/ or another shared
#     helper no feature imports, or any non-docs file no feature reaches;
#   - a docs-only change (*.md, docs/, .changelog/) or an empty diff prints
#     nothing.
#
# Renames count on both sides. Package imports come from the working tree.
# Exit 2 on a bad argument or revision.
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

# Every path of the diff, both sides of a rename or copy.
if ! status=$(git diff --name-status -M "$base" "$tip"); then
	echo "$0: git diff $base $tip failed" >&2
	exit 2
fi
files=$(printf '%s\n' "$status" | cut -f2- | tr '\t' '\n' | LC_ALL=C sort -u)

is_feature() { # is_feature <name>: test/integration/<name> holds _test.go files
	[ -d "test/integration/$1" ] &&
		[ -n "$(find "test/integration/$1" -name '*_test.go' -print -quit)" ]
}

features=()
pending=()
while IFS= read -r f; do
	[ -n "$f" ] || continue
	case "$f" in
	*.md | docs/* | .changelog/*) continue ;;
	Makefile | .github/* | go.mod | go.sum | test/integration/common/*)
		echo ALL
		exit 0
		;;
	test/integration/*/*)
		name=${f#test/integration/}
		name=${name%%/*}
		if is_feature "$name"; then
			features+=("$name")
			continue
		fi
		;;
	esac
	pending+=("$f")
done <<<"$files"

if [ "${#pending[@]}" -gt 0 ]; then
	# The integration tags: integration plus the Makefile's BUILD_TAGS, read
	# from the Makefile itself.
	tags=integration
	if [ -f Makefile ]; then
		bt=$(sed -n 's/^BUILD_TAGS[[:space:]]*:\{0,1\}=[[:space:]]*//p' Makefile | head -1)
		[ -z "$bt" ] || tags="integration,$(printf '%s' "$bt" | tr -s ' ' ',')"
	fi
	deps=$(mktemp)
	trap 'rm -f "$deps"' EXIT
	# One line per package of the integration tree and its dependencies:
	# <dir> TAB <import path> TAB <deps>. A feature reaches the directories
	# of its own packages' deps.
	if ! go list -e -deps -test -tags "$tags" \
		-f '{{if not .Standard}}{{.Dir}}{{"\t"}}{{.ImportPath}}{{"\t"}}{{join .Deps " "}}{{end}}' \
		./test/integration/... >"$deps" 2>/dev/null; then
		echo "$0: go list ./test/integration/... failed; every feature runs" >&2
		echo ALL
		exit 0
	fi
	# reach: lines "<repo-relative dir> TAB <feature>".
	reach=$(awk -F'\t' -v top="$top/" '
		$1 == "" { next }
		{
			ip = $2; sub(/ \[.*\]$/, "", ip)
			if (substr($1, 1, length(top)) == top) dir[ip] = substr($1, length(top) + 1)
			rows[NR] = $0
		}
		END {
			for (r in rows) {
				split(rows[r], c, "\t")
				if (substr(c[1], 1, length(top)) != top) continue
				rel = substr(c[1], length(top) + 1)
				if (rel !~ /^test\/integration\/[^\/]+/) continue
				feat = rel; sub(/^test\/integration\//, "", feat); sub(/\/.*/, "", feat)
				print rel "\t" feat
				n = split(c[3], d, " ")
				for (i = 1; i <= n; i++) {
					ip = d[i]; sub(/ \[.*\]$/, "", ip)
					if (ip in dir) print dir[ip] "\t" feat
				}
			}
		}' "$deps" | LC_ALL=C sort -u)
	for f in "${pending[@]}"; do
		dir=$(dirname "$f")
		hits=()
		while :; do
			while IFS= read -r h; do
				if [ -n "$h" ] && is_feature "$h"; then
					hits+=("$h")
				fi
			done < <(printf '%s\n' "$reach" | awk -F'\t' -v d="$dir" '$1 == d { print $2 }')
			# A Go file names its own package; any other file the nearest
			# package directory above it (pkg/x/testdata/in.json -> pkg/x).
			if [ "${#hits[@]}" -gt 0 ] || [ "${f%.go}" != "$f" ] || [ "$dir" = . ]; then
				break
			fi
			dir=$(dirname "$dir")
		done
		if [ "${#hits[@]}" -eq 0 ]; then
			echo ALL
			exit 0
		fi
		features+=("${hits[@]}")
	done
fi

[ "${#features[@]}" -gt 0 ] || exit 0
printf '%s\n' "${features[@]}" | LC_ALL=C sort -u
