#!/bin/sh
# pr-scope-test.sh -- the test suite for pr-scope.sh.
#
# Real git, in a throwaway repo under $TMPDIR: git has no network mode and
# every operation here is local, so faking it would only make the test
# trust its own fake instead of the tool the workflow actually runs. Each
# case is a way pr-scope.sh could report success while classifying the run
# wrong:
#
#   1. A docs-only diff must report docs_only=true, so a docs PR is not
#      blocked on Go jobs that never had anything to check.
#   2. A single non-doc path in an otherwise-docs diff must flip docs_only
#      to false -- the dangerous direction is mislabeling a code change as
#      docs-only, not the reverse.
#   3. Tier selection: train/* head ref -> full_tier=true; anything else on
#      a pull_request -> false; push/dispatch -> true regardless of ref.
#   4. Every "no usable base" path (empty BASE_SHA, all-zero BEFORE_SHA, a
#      base sha this clone cannot reach) fails OPEN: docs_only=false.
#
# No network, no mutation outside the temp dir, well under a second.
set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
subject="${here}/pr-scope.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

git() { command git -c user.email=t@example.com -c user.name=t -c commit.gpgsign=false "$@"; }

repo="$work/repo"
mkdir -p "$repo"
(
	cd "$repo"
	git init -q -b main
	mkdir -p docs xkey/docs .changelog/unreleased pkg/foo cmd/bar
	echo one >README.md
	echo one >docs/index.md
	git add -A
	git commit -q -m base
)
base_sha="$(cd "$repo" && git rev-parse HEAD)"

pass=0
fail=0
check() { # check <label> <condition...>
	label="$1"
	shift
	if "$@"; then
		printf '  PASS  %-62s\n' "$label"
		pass=$((pass + 1))
	else
		printf '  FAIL  %-62s\n' "$label"
		fail=$((fail + 1))
	fi
}

# run <event> <base_sha> <before_sha> <head_ref> -- checks out a fresh
# working copy at $repo's current HEAD plus whatever the caller committed
# since, and runs the subject against it.
run() {
	event="$1"
	b="$2"
	before="$3"
	href="$4"
	out="$work/out"
	rm -f "$out"
	# set -e means a compound command's own nonzero status would abort this
	# whole test script, so the failure has to be caught inside an if/else
	# rather than read from $? after the fact.
	if (
		cd "$repo"
		GITHUB_OUTPUT="$out" EVENT_NAME="$event" BASE_SHA="$b" BEFORE_SHA="$before" HEAD_REF="$href" \
			sh "$subject" >"$work/log" 2>&1
	); then
		rc=0
	else
		rc=$?
	fi
}
outval() { grep "^$1=" "$work/out" | tail -1 | cut -d= -f2-; }

echo "== docs-only diff =="
(
	cd "$repo"
	git checkout -q -b docs-pr
	echo two >>docs/index.md
	echo new >xkey/docs/newthing.md
	echo entry >.changelog/unreleased/123.md
	echo more >>README.md
	git add -A
	git commit -q -m docs
)
run pull_request "$base_sha" "" "docs-pr"
check "exit 0" [ "$rc" -eq 0 ]
check "docs_only=true" [ "$(outval docs_only)" = true ]
check "full_tier=false (ordinary PR)" [ "$(outval full_tier)" = false ]
check "merge_base is the base sha" [ "$(outval merge_base)" = "$base_sha" ]
(cd "$repo" && git checkout -q main && git branch -q -D docs-pr)

echo "== one non-doc file flips docs_only to false =="
(
	cd "$repo"
	git checkout -q -b mixed-pr
	echo two >>docs/index.md
	echo 'package foo' >pkg/foo/foo.go
	git add -A
	git commit -q -m mixed
)
run pull_request "$base_sha" "" "mixed-pr"
check "exit 0" [ "$rc" -eq 0 ]
check "docs_only=false" [ "$(outval docs_only)" = false ]
(cd "$repo" && git checkout -q main && git branch -q -D mixed-pr)

echo "== train/* head ref forces the full tier even on a docs-only diff =="
(
	cd "$repo"
	git checkout -q -b "train/7"
	echo three >>docs/index.md
	git add -A
	git commit -q -m docs-on-train
)
run pull_request "$base_sha" "" "train/7"
check "exit 0" [ "$rc" -eq 0 ]
check "full_tier=true" [ "$(outval full_tier)" = true ]
check "docs_only still true (independent axis)" [ "$(outval docs_only)" = true ]
(cd "$repo" && git checkout -q main && git branch -q -D "train/7")

echo "== push and workflow_dispatch are always full tier =="
run push "$base_sha" "$base_sha" ""
check "push: full_tier=true" [ "$(outval full_tier)" = true ]
run workflow_dispatch "" "" ""
check "workflow_dispatch: full_tier=true" [ "$(outval full_tier)" = true ]

echo "== no usable base fails open =="
run pull_request "" "" "some-branch"
check "empty BASE_SHA: exit 0" [ "$rc" -eq 0 ]
check "empty BASE_SHA: docs_only=false" [ "$(outval docs_only)" = false ]

run push "" "0000000000000000000000000000000000000000" ""
check "all-zero BEFORE_SHA: docs_only=false" [ "$(outval docs_only)" = false ]

run pull_request "0123456789012345678901234567890123456789" "" "some-branch"
check "unreachable base sha: exit 0" [ "$rc" -eq 0 ]
check "unreachable base sha: docs_only=false" [ "$(outval docs_only)" = false ]

echo "== push diffed against the previous commit =="
prev_sha="$(cd "$repo" && git rev-parse HEAD)"
(
	cd "$repo"
	echo four >>docs/index.md
	git add -A
	git commit -q -m "docs on main"
)
run push "" "$prev_sha" ""
check "push docs-only: docs_only=true" [ "$(outval docs_only)" = true ]
check "push docs-only: full_tier=true regardless" [ "$(outval full_tier)" = true ]

echo ""
echo "passed ${pass}, failed ${fail}"
[ "$fail" -eq 0 ] || exit 1
