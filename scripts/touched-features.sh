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
#     transitively, under the tags the integration-test-% recipe passes
#     (read from `make -n`, so += tags count);
#   - it also names every feature whose suite builds and runs a binary that
#     is, or depends on, that package: a quoted .../cmd/<name> path in the
#     suite's own Go files, or a Makefile recipe line that builds
#     ./cmd/<name> (after any cd, so a nested module's binary counts) and
#     tests ./test/integration/<feature>;
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

# bin_dir <path>: the package directory of a binary named by a quoted path
# (./cmd/x, ../../../cmd/x, <module>/xkey/cmd/x/...): its longest suffix that
# is an existing directory with Go files under a cmd/ directory.
bin_dir() {
	local p=${1%/...}
	while :; do
		case "$p" in
		./*) p=${p#./} ;;
		../*) p=${p#../} ;;
		/*) p=${p#/} ;;
		*) break ;;
		esac
	done
	while [[ $p == */* ]]; do
		case "/$p" in */cmd/*) ;; *) return 1 ;; esac
		if [ -d "$p" ] && [ -n "$(find "$p" -maxdepth 1 -name '*.go' ! -name '*_test.go' -print -quit)" ]; then
			printf '%s\n' "$p"
			return 0
		fi
		p=${p#*/}
	done
	return 1
}

# module_root <dir>: the nearest directory at or above <dir> with a go.mod.
module_root() {
	local d=$1
	while [ "$d" != . ] && [ ! -f "$d/go.mod" ]; do
		d=$(dirname "$d")
	done
	printf '%s\n' "$d"
}

# recipe_binaries <integration tags>: lines "<feature> TAB <binary dir> TAB
# <tags>" for each Makefile recipe line that builds ./.../cmd/<name> and
# tests ./test/integration/<feature>; the tags add the build's literal ones.
recipe_binaries() {
	awk -v tags="$1" '
	function resolve(cwd, p,   n, parts, out, i, k, r) {
		sub(/\/\.\.\.$/, "", p)
		if (p ~ /^\//) return ""
		if (cwd != "") p = cwd "/" p
		n = split(p, parts, "/"); k = 0
		for (i = 1; i <= n; i++) {
			if (parts[i] == "" || parts[i] == ".") continue
			if (parts[i] == "..") { if (k > 0) k--; continue }
			out[++k] = parts[i]
		}
		r = ""
		for (i = 1; i <= k; i++) r = r (i > 1 ? "/" : "") out[i]
		return r
	}
	function clean(t) {
		gsub(/^["'\''(]+/, "", t); gsub(/["'\''),]+$/, "", t)
		return t
	}
	function build_tags(s,   v, n, w, i, r) {
		if (!match(s, /-tags[= ]*["'\''][^"'\'']*["'\'']/) && !match(s, /-tags[= ]*[^[:space:]]+/)) return ""
		v = substr(s, RSTART, RLENGTH)
		sub(/^-tags[= ]*/, "", v)
		gsub(/["'\'']/, "", v)
		gsub(/\$\(comma\)/, ",", v)
		gsub(/\$\(call go_tags,/, "", v)
		n = split(v, w, /[ ,]+/); r = ""
		for (i = 1; i <= n; i++) {
			gsub(/\)+$/, "", w[i])
			if (w[i] ~ /^[A-Za-z0-9_.]+$/) r = r "," w[i]
		}
		return r
	}
	{
		line = cont $0
		if (line ~ /\\$/) { sub(/\\$/, "", line); cont = line " "; next }
		cont = ""
		if (line !~ /^\t/) next
		nseg = split(line, seg, /&&|;/)
		cwd = ""; saved = ""; insub = 0; nb = 0; nf = 0
		for (s = 1; s <= nseg; s++) {
			nt = split(seg[s], tok, /[[:space:]]+/)
			first = 0
			for (i = 1; i <= nt; i++) if (tok[i] != "") { first = i; break }
			if (first == 0) continue
			if (clean(tok[first]) == "cd" && first < nt) {
				if (tok[first] ~ /^\(/) { saved = cwd; insub = 1 }
				dest = clean(tok[first + 1])
				cwd = (dest ~ /^[$\/]/) ? "" : resolve(cwd, dest)
				continue
			}
			isbuild = seg[s] ~ /(^|[^A-Za-z0-9_])(go|GO\))[[:space:]]+build([[:space:]]|$)/
			istest = seg[s] ~ /(^|[^A-Za-z0-9_])(go|GO\))[[:space:]]+test([[:space:]]|$)/
			btags = isbuild ? build_tags(seg[s]) : ""
			for (i = first; i <= nt; i++) {
				t = clean(tok[i])
				if (isbuild && t ~ /^\.\.?\// && t ~ /(^|\/)cmd\/[^\/]/) {
					bins[++nb] = resolve(cwd, t); btag[nb] = btags
				}
				if (istest && t ~ /^(\.\/)?test\/integration\/[^\/]/) {
					r = resolve(cwd, t)
					if (r ~ /^test\/integration\/[^\/]+/) {
						split(r, rp, "/"); feats[++nf] = rp[3]
					}
				}
			}
			if (insub && seg[s] ~ /\)[[:space:]]*$/) { cwd = saved; insub = 0 }
		}
		for (i = 1; i <= nf; i++) for (j = 1; j <= nb; j++) if (bins[j] != "")
			print feats[i] "\t" bins[j] "\t" tags btag[j]
	}' Makefile
}

if [ "${#pending[@]}" -gt 0 ]; then
	# The tags the integration-test-% recipe passes, from make itself, on
	# the first feature no explicit rule overrides (the recipe needs its
	# directory to exist).
	tags=
	for fd in test/integration/*/; do
		feat=$(basename "$fd")
		is_feature "$feat" || continue
		if [ -f Makefile ] && grep -qE "^([^:#=]*[[:space:]])?integration-test-${feat}([[:space:]][^:#=]*)?::?([^=]|$)" Makefile; then
			continue
		fi
		tags=$(recipe_tags "integration-test-$feat") || tags=
		break
	done
	if [ -z "$tags" ]; then
		echo "$0: no go test -tags line in make -n integration-test-%; every feature runs" >&2
		echo ALL
		exit 0
	fi
	deps=$(mktemp)
	bins=$(mktemp)
	trap 'rm -f "$deps" "$bins"' EXIT
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

	# The binaries each feature's suite builds and runs: "<feature> TAB
	# <binary dir> TAB <tags>", from the suite's own files and the recipes.
	for fd in test/integration/*/; do
		feat=$(basename "$fd")
		is_feature "$feat" || continue
		while IFS= read -r lit; do
			[ -n "$lit" ] || continue
			if b=$(bin_dir "$lit"); then
				printf '%s\t%s\t%s\n' "$feat" "$b" "$tags"
			fi
		done < <(grep -rhoE --include='*.go' '"[^"[:space:]]*cmd/[A-Za-z0-9_.-]+(/\.\.\.)?"' "$fd" 2>/dev/null | tr -d '"' | LC_ALL=C sort -u)
	done >"$bins"
	if [ -f Makefile ]; then
		recipe_binaries "$tags" >>"$bins"
	fi
	# Each binary reaches its own directory and its deps' directories.
	bin_reach=$(while IFS=$'\t' read -r bin btags; do
		mod=$(module_root "$bin")
		rel=./${bin#"$mod"/}
		[ "$mod" != . ] || rel=./$bin
		while IFS= read -r d; do
			case "$d" in
			"$top"/*) awk -F'\t' -v b="$bin" -v t="$btags" -v d="${d#"$top"/}" \
				'$2 == b && $3 == t { print d "\t" $1 }' "$bins" ;;
			esac
		done < <(cd "$mod" && go list -e -deps -tags "$btags" \
			-f '{{if not .Standard}}{{.Dir}}{{end}}' "$rel" 2>/dev/null || true)
	done < <(cut -f2,3 "$bins" | LC_ALL=C sort -u))
	reach=$(printf '%s\n' "$reach" "$bin_reach" | LC_ALL=C sort -u)

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
