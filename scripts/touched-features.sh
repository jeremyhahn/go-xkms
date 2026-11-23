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
#   - a changed file under test/integration/<feature>/ names that feature; a
#     non-test Go file there is also a package other features may import, so
#     it goes through the rules below as well;
#   - a changed Go package (or a file inside one, such as testdata) names
#     every feature whose integration tests import it, directly or
#     transitively, under that suite's own tags: the -tags of the go test
#     lines for ./test/integration/<feature> in the recipe of
#     integration-test-<feature> or its prerequisites (an explicit rule such
#     as integration-test-clusterca adding tpm_simulator), expanded by make,
#     else the tags of the integration-test-% recipe (from `make -n`, so +=
#     tags count). A suite none of whose tests builds under its tags, or any
#     package of the graphs that does not load (Error or DepsErrors), prints
#     ALL for any such change;
#   - it also names every feature whose suite builds and runs a binary that
#     is, or depends on, that package: a quoted .../cmd/<name> path in the
#     suite's own Go files, or a Makefile recipe line that builds
#     ./cmd/<name> (after any cd, so a nested module's binary counts) and
#     tests ./test/integration/<feature>. A binary that does not load prints
#     ALL;
#   - a feature whose explicit integration-test-<feature> recipe runs no go
#     test of it the script can read (it hands the suite to Compose, whose
#     Dockerfile builds what it runs) is named by every change that names
#     any feature;
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
			# A helper Go file may be imported by other features' suites:
			# its package also goes through the dependency analysis.
			case "$f" in
			*_test.go) continue ;;
			*.go) ;;
			*) continue ;;
			esac
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

# recipe_binaries <integration tags> <suites file>: lines "<feature> TAB
# <binary dir> TAB <tags>" for each Makefile recipe line that builds
# ./.../cmd/<name> and tests ./test/integration/<feature>; the tags add the
# build's literal ones. Each go test line that runs ./test/integration/<feature>
# also appends "<target> TAB <feature> TAB <its -tags as written, or empty>" to
# <suites file>, for each target of the rule it belongs to; <rules file> gets
# "H TAB <target> TAB <prerequisites>" per rule header and "R TAB <target>"
# per recipe line.
recipe_binaries() {
	awk -v tags="$1" -v suites="$2" -v rules="$3" '
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
	# raw_tags <segment>: the -tags value as written, unexpanded; "" when it
	# has no -tags or its parentheses do not balance.
	function raw_tags(s,   v, o, c, i, ch, d) {
		if (match(s, /-tags[= ]*["'\''][^"'\'']*["'\'']/)) {
			v = substr(s, RSTART, RLENGTH)
			sub(/^-tags[= ]*/, "", v)
		} else if (match(s, /-tags[= ]*[^[:space:]"'\'']/)) {
			# A bare value runs to the first blank outside $( ).
			s = substr(s, RSTART + RLENGTH - 1); v = ""; d = 0
			for (i = 1; i <= length(s); i++) {
				ch = substr(s, i, 1)
				if (d == 0 && ch ~ /[[:space:]]/) break
				if (ch == "(") d++
				else if (ch == ")") { if (d == 0) break; d-- }
				v = v ch
			}
		} else return ""
		gsub(/["'\'']/, "", v)
		o = gsub(/\(/, "(", v); c = gsub(/\)/, ")", v)
		if (o != c || v ~ /\$[*@<]/) return ""
		return v
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
		if (line !~ /^\t/) {
			# A rule header (not a variable or target-specific variable)
			# starts the recipe of its targets; a define body has none.
			if (line ~ /^define[[:space:]]/) { curt = ""; next }
			if (line !~ /^[[:space:]]*(#|$)/ && match(line, /^[^:=#\t]+::?/)) {
				head = substr(line, 1, RLENGTH); rest = substr(line, RLENGTH + 1)
				if (rest !~ /=/) {
					sub(/::?$/, "", head); sub(/;.*/, "", rest)
					curt = head
					nh = split(head, tg, /[[:space:]]+/)
					for (i = 1; i <= nh; i++) if (tg[i] != "") print "H\t" tg[i] "\t" rest > rules
				}
			}
			next
		}
		nct = split(curt, ct, /[[:space:]]+/)
		for (i = 1; i <= nct; i++) if (ct[i] != "") print "R\t" ct[i] > rules
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
			texpr = istest ? raw_tags(seg[s]) : ""
			for (i = first; i <= nt; i++) {
				t = clean(tok[i])
				if (isbuild && t ~ /^\.\.?\// && t ~ /(^|\/)cmd\/[^\/]/) {
					bins[++nb] = resolve(cwd, t); btag[nb] = btags
				}
				if (istest && t ~ /^(\.\/)?test\/integration\/[^\/]/) {
					r = resolve(cwd, t)
					if (r ~ /^test\/integration\/[^\/]+/) {
						split(r, rp, "/"); feats[++nf] = rp[3]
						for (k = 1; k <= nct; k++) if (ct[k] != "") print ct[k] "\t" rp[3] "\t" texpr > suites
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
	suites=$(mktemp)
	rules=$(mktemp)
	evalmk=$(mktemp)
	binreach=$(mktemp)
	trap 'rm -f "$deps" "$bins" "$suites" "$rules" "$evalmk" "$binreach"' EXIT
	# The binaries each suite builds, the -tags of every go test line that
	# runs a suite (with its rule's targets), and the rules' prerequisites.
	if [ -f Makefile ]; then
		recipe_binaries "$tags" "$suites" "$rules" >"$bins"
	fi
	featlist=$(for fd in test/integration/*/; do
		feat=$(basename "$fd")
		if is_feature "$feat"; then printf '%s ' "$feat"; fi
	done)
	# plan: per feature "<feature> TAB P" (no explicit rule with a recipe:
	# the integration-test-% tags), "<feature> TAB E TAB <tags as written>"
	# for each go test line of it in integration-test-<feature> or its
	# prerequisites, or "<feature> TAB U" when that recipe runs none (it
	# delegates, to Compose say) or one whose tags cannot be read: such a
	# suite's tests and binaries are unknown, so it is selected by any
	# change that selects a feature.
	plan=$(awk -F'\t' -v feats="$featlist" '
		FILENAME == ARGV[1] {
			if ($1 == "H") { has[$2] = 1; pre[$2] = pre[$2] " " $3 }
			else if ($1 == "R") rec[$2] = 1
			next
		}
		{ n++; lt[n] = $1; lf[n] = $2; le[n] = $3 }
		END {
			m = split(feats, fs, " ")
			for (i = 1; i <= m; i++) {
				f = fs[i]; root = "integration-test-" f
				split("", in_); in_[root] = 1; q[1] = root; h = 1; tl = 1
				while (h <= tl) {
					t = q[h++]; k = split(pre[t], ps, /[[:space:]]+/)
					for (j = 1; j <= k; j++) if (ps[j] != "" && ps[j] != "|" && !(ps[j] in in_)) { in_[ps[j]] = 1; q[++tl] = ps[j] }
				}
				found = 0; bad = 0
				for (j = 1; j <= n; j++) if (lf[j] == f && (lt[j] in in_)) {
					found = 1
					if (le[j] == "") bad = 1; else print f "\tE\t" le[j]
				}
				if (found && !bad) continue
				if (!found && !((root in has) && (root in rec))) print f "\tP"
				else print f "\tU"
			}
		}' "$rules" "$suites")
	unresolved=$(printf '%s\n' "$plan" | awk -F'\t' '$2 == "U" { print $1 }')
	# suite_tags: "<feature> TAB <tags>", each E suite's tags expanded by make
	# itself (union over its go test lines); P and U suites run under the
	# integration-test-% tags.
	suite_tags=
	if printf '%s\n' "$plan" | grep -q $'\tE\t'; then
		{
			printf '__touched_suite_tags:\n\t@:\n'
			while IFS=$'\t' read -r feat kind expr; do
				[ "$kind" = E ] || continue
				# shellcheck disable=SC2016 # a make $(info), written literally
				printf '$(info __TS__ %s %s)\n' "$feat" "$expr"
			done <<<"$plan"
		} >"$evalmk"
		if ! out=$(env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -s --no-print-directory \
			-f Makefile -f "$evalmk" __touched_suite_tags 2>/dev/null); then
			echo "$0: make could not expand the suites' -tags; every feature runs" >&2
			echo ALL
			exit 0
		fi
		suite_tags=$(printf '%s\n' "$out" | awk '
			$1 == "__TS__" {
				f = $2
				for (i = 3; i <= NF; i++) {
					n = split($i, w, ",")
					for (j = 1; j <= n; j++) if (w[j] != "" && !seen[f, w[j]]++) t[f] = t[f] (t[f] == "" ? "" : ",") w[j]
				}
			}
			END { for (f in t) print f "\t" t[f] }')
	fi
	# One go list per tag set, over the suites that run under it. Each line:
	# <dir> TAB <import path> TAB <deps> TAB T when it holds tests. A feature
	# reaches the directories of its own packages' deps.
	groups=$(for fd in test/integration/*/; do
		feat=$(basename "$fd")
		is_feature "$feat" || continue
		t=$(printf '%s\n' "$suite_tags" | awk -F'\t' -v f="$feat" '$1 == f { print $2; exit }')
		printf '%s\t%s\n' "${t:-$tags}" "$feat"
	done | LC_ALL=C sort | awk -F'\t' '
		$1 != p { if (NR > 1) print p "\t" l; p = $1; l = $2; next }
		{ l = l " " $2 }
		END { if (NR) print p "\t" l }')
	: >"$deps"
	while IFS=$'\t' read -r t flist; do
		[ -n "$flist" ] || continue
		pats=()
		for feat in $flist; do
			pats+=("./test/integration/$feat/...")
		done
		if ! go list -e -deps -test -tags "$t" \
			-f '{{if not .Standard}}{{.Dir}}{{"\t"}}{{.ImportPath}}{{"\t"}}{{join .Deps " "}}{{"\t"}}{{if or .TestGoFiles .XTestGoFiles}}T{{end}}{{"\t"}}{{if or .Error .DepsErrors}}E{{end}}{{end}}' \
			"${pats[@]}" >>"$deps" 2>/dev/null; then
			echo "$0: go list -tags $t failed; every feature runs" >&2
			echo ALL
			exit 0
		fi
	done <<<"$groups"
	# A package that does not load (a missing import, a parse error) hides
	# its imports: the graph is incomplete, so every feature runs.
	if bad=$(awk -F'\t' '$5 == "E" { print $2; found = 1; exit } END { exit !found }' "$deps"); then
		echo "$0: $bad does not load completely; every feature runs" >&2
		echo ALL
		exit 0
	fi
	# A suite none of whose tests builds under its tags has unknown imports:
	# every feature runs rather than that suite being dropped.
	tested=$(awk -F'\t' -v top="$top/" '
		$4 == "T" && substr($1, 1, length(top)) == top {
			rel = substr($1, length(top) + 1)
			if (rel ~ /^test\/integration\/[^\/]+/) { sub(/^test\/integration\//, "", rel); sub(/\/.*/, "", rel); print rel }
		}' "$deps" | LC_ALL=C sort -u)
	while IFS=$'\t' read -r t flist; do
		for feat in $flist; do
			if ! printf '%s\n' "$tested" | grep -qxF -- "$feat"; then
				echo "$0: no test of test/integration/$feat builds under -tags $t; every feature runs" >&2
				echo ALL
				exit 0
			fi
		done
	done <<<"$groups"
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
	done >>"$bins"
	# Each binary reaches its own directory and its deps' directories; a
	# binary whose graph does not load completely makes every feature run.
	while IFS=$'\t' read -r bin btags; do
		[ -n "$bin" ] || continue
		mod=$(module_root "$bin")
		rel=./${bin#"$mod"/}
		[ "$mod" != . ] || rel=./$bin
		if ! bl=$(cd "$mod" && go list -e -deps -tags "$btags" \
			-f '{{if not .Standard}}{{.Dir}}{{"\t"}}{{if or .Error .DepsErrors}}E{{end}}{{end}}' "$rel" 2>/dev/null); then
			echo "$0: go list $bin failed; every feature runs" >&2
			echo ALL
			exit 0
		fi
		if printf '%s\n' "$bl" | grep -q $'\tE$'; then
			echo "$0: $bin does not load completely under -tags $btags; every feature runs" >&2
			echo ALL
			exit 0
		fi
		while IFS=$'\t' read -r d _; do
			case "$d" in
			"$top"/*) awk -F'\t' -v b="$bin" -v t="$btags" -v d="${d#"$top"/}" \
				'$2 == b && $3 == t { print d "\t" $1 }' "$bins" ;;
			esac
		done <<<"$bl" >>"$binreach"
	done < <(cut -f2,3 "$bins" | LC_ALL=C sort -u)
	reach=$(printf '%s\n' "$reach" | cat - "$binreach" | LC_ALL=C sort -u)

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
		# A suite whose recipe the script cannot follow may reach it too.
		while IFS= read -r u; do
			[ -n "$u" ] && features+=("$u")
		done <<<"$unresolved"
	done
fi

[ "${#features[@]}" -gt 0 ] || exit 0
printf '%s\n' "${features[@]}" | LC_ALL=C sort -u
