#!/usr/bin/env bash
# touched-features.sh <base> <tip>
#
# Prints the features (scripts/features.tsv) whose `paths` prefixes match a
# file changed between <base> and <tip>, sorted, one per line. When any
# changed file matches no feature (Makefile, .github/, go.mod, a shared
# package outside every row), it prints only ALL: the caller then runs every
# gate. An empty diff prints nothing. Exit 2 on a bad argument or revision.
#
# A prefix ending in `/` matches every file under that directory; any other
# prefix matches that one file. FEATURES_TSV overrides the table (tests).
# The factory's local verify calls it as FEATURES_CMD (Tenant ruling 1170).
set -euo pipefail

usage() {
	echo "usage: $0 <base> <tip>" >&2
	exit 2
}
[ "$#" -eq 2 ] || usage
base=$1
tip=$2

tsv=${FEATURES_TSV:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/features.tsv}
if [ ! -r "$tsv" ]; then
	echo "$0: cannot read $tsv" >&2
	exit 2
fi

for rev in "$base" "$tip"; do
	if ! git rev-parse --verify --quiet "${rev}^{commit}" >/dev/null; then
		echo "$0: bad revision: $rev" >&2
		exit 2
	fi
done

if ! changed=$(git diff --name-only "$base" "$tip"); then
	echo "$0: git diff $base $tip failed" >&2
	exit 2
fi
[ -n "$changed" ] || exit 0

# Load the table: parallel arrays of feature names and their prefixes.
names=()
prefixes=()
first=1
while IFS=$'\t' read -r feature paths _; do
	if [ "$first" -eq 1 ]; then
		first=0
		continue
	fi
	[ -n "$feature" ] || continue
	names+=("$feature")
	prefixes+=("$paths")
done <"$tsv"

matched=()
while IFS= read -r file; do
	[ -n "$file" ] || continue
	hit=0
	for i in "${!names[@]}"; do
		for p in ${prefixes[$i]}; do
			case "$p" in
			*/) case "$file" in "$p"*) ;; *) continue ;; esac ;;
			*) [ "$file" = "$p" ] || continue ;;
			esac
			matched+=("${names[$i]}")
			hit=1
			break
		done
	done
	if [ "$hit" -eq 0 ]; then
		echo ALL
		exit 0
	fi
done <<<"$changed"

printf '%s\n' "${matched[@]}" | LC_ALL=C sort -u
