#!/usr/bin/env bash
# Tests for scripts/touched-features.sh (Tenant rulings 1170/1171): the
# test/integration/<feature> directories whose `make integration-test-<feature>`
# a diff requires, read from the tree and `go list`, or ALL when a change is
# outside every feature. Needs git and go; no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/touched-features.sh"
# shellcheck source=test/scripts/touched-lib.sh
. "$ROOT/test/scripts/touched-lib.sh"

run() { (cd "$REPO" && bash "$SCRIPT" "$@"); }
two() { printf '%s\n%s' "$1" "$2"; }

FA=$(commit_file test/integration/alpha/alpha_test.go '// alpha')
PA=$(commit_file pkg/a/a.go '// a')
PC=$(commit_file pkg/c/c.go '// c')
MK=$(commit_file Makefile '# make')
CM=$(commit_file test/integration/common/common.go '// common')
PD=$(commit_file pkg/d/d.go '// d')
put docs/guide.md '# guide'
put .changelog/unreleased/added-x.md '- x'
printf 'more\n' >>"$REPO/README.md"
DOC=$(commit_all docs)
RN=$(move_file test/integration/beta/extra_test.go test/integration/alpha/extra_test.go)
# The moved file still says package beta, which breaks alpha's package in the
# tree every case reads (a load error is ALL): give it alpha's clause.
put test/integration/alpha/extra_test.go '//go:build integration

package alpha'
FX=$(commit_all "extra_test.go in package alpha")

echo "touched-features.sh"
if [ -x "$SCRIPT" ]; then ok "the script is executable"; else no "the script is executable"; fi
eq "a feature-only diff prints that feature" "alpha" "$(run "$BASE" "$FA")"
eq "a package a feature imports transitively prints that feature" "alpha" "$(run "$FA" "$PA")"
eq "a package a second feature imports prints that feature" "beta" "$(run "$PA" "$PC")"
eq "a two-feature diff prints both, sorted" "$(two alpha beta)" "$(run "$BASE" "$PC")"
eq "a Makefile change prints ALL" "ALL" "$(run "$PC" "$MK")"
eq "a Makefile change among feature changes prints only ALL" "ALL" "$(run "$BASE" "$MK")"
eq "a test/integration/common change prints ALL" "ALL" "$(run "$MK" "$CM")"
eq "a package no feature reaches prints ALL" "ALL" "$(run "$CM" "$PD")"
eq "a docs-only change prints nothing" "" "$(run "$PD" "$DOC")"
eq "an empty diff prints nothing" "" "$(run "$DOC" "$DOC")"
eq "a rename between features prints both sides" "$(two alpha beta)" "$(run "$DOC" "$RN")"

# The integration-test-% recipe's full tag set, += lines included.
G=$(commit_file pkg/g/g.go '// g')
eq "a package only tag-gated feature tests import prints that feature" "gamma" "$(run "$FX" "$G")"
# A binary the suite builds and runs counts with its package deps.
T=$(commit_file pkg/t/t.go '// t')
eq "a dep of a binary the suite's own files build prints that feature" "delta" "$(run "$G" "$T")"
CT=$(commit_file cmd/tool/main.go '// tool')
eq "the binary the suite's own files build prints that feature" "delta" "$(run "$T" "$CT")"
S=$(commit_file pkg/s/s.go '// s')
eq "a dep of a binary the feature's recipe builds prints that feature" "eps" "$(run "$CT" "$S")"
U=$(commit_file pkg/u/u.go '// u')
eq "a dep of a nested-module binary the recipe builds prints that feature" "zeta" "$(run "$S" "$U")"
# Each explicit suite's graph under its own recipe's tags.
K=$(commit_file pkg/k/k.go '// k')
eq "a package a suite imports under its explicit rule's extra tag prints that suite" "$(two alpha kappa)" "$(run "$U" "$K")"
# A helper inside one feature's directory that another feature imports.
MH=$(commit_file test/integration/mu/help.go '// help')
eq "a feature's helper another feature imports prints both" "$(two mu nu)" "$(run "$K" "$MH")"
# The tags are those of integration-test-<feature> itself, not of a similarly
# named target that tests the same directory.
O=$(commit_file pkg/o/o.go '// o')
eq "a suite's graph uses its own target's tags" "omicron" "$(run "$MH" "$O")"
# xi's target delegates to Compose, whose Dockerfile builds ./cmd/tool: a
# suite whose binaries the script cannot resolve is selected (or ALL).
put test/integration/xi/compose.yml 'services:
  harness:
    build:
      context: ../../..
      dockerfile: test/integration/xi/Dockerfile.test'
put test/integration/xi/Dockerfile.test 'FROM golang:1.22
COPY . /src
WORKDIR /src
RUN go build -o /usr/local/bin/tool ./cmd/tool
CMD ["go", "test", "-tags", "integration", "./test/integration/xi/..."]'
put test/integration/xi/xi_test.go '//go:build integration

package xi

import (
	"os/exec"
	"testing"
)

func TestXi(t *testing.T) { _ = exec.Command("tool").Run() }'
XT=$(commit_all xi)
XC=$(commit_file cmd/tool/main.go '// xi')
case "$(run "$XT" "$XC")" in
"$(two delta xi)" | ALL) ok "a suite whose target delegates to Compose is selected with its binary" ;;
*) no "a suite whose target delegates to Compose is selected with its binary: got [$(run "$XT" "$XC")]" ;;
esac
# pi's tests import a package that does not exist: its graph is incomplete,
# so a change to a package another suite reaches is ALL, not a narrowed list.
put test/integration/pi/pi_test.go '//go:build integration

package pi

import (
	"testing"

	"example.com/m/pkg/c"
	"example.com/m/pkg/nosuch"
)

func TestPi(t *testing.T) { _ = c.C() + nosuch.N() }'
PT=$(commit_all pi)
PC2=$(commit_file pkg/c/c.go '// pi')
eq "a package-load error in a suite's graph prints ALL" "ALL" "$(run "$PT" "$PC2")"
g rm -rq test/integration/pi
PR=$(commit_all "drop pi")
eq "the load-error case leaves no trace" "beta" "$(run "$PR" "$(commit_file pkg/c/c.go '// pi gone')" | grep -v '^xi$')"
# rho's target tests only ./test/integration/rho, not its nested sub suite
# (the pkcs11/module shape): a change only the nested suite sees is ALL, not
# rho. sigma's pattern target runs ./test/integration/sigma/..., nested
# suites included.
cat >>"$REPO/Makefile" <<'EOF'

integration-test-rho:
	go test -tags "integration $(BUILD_TAGS)" ./test/integration/rho
EOF
put pkg/r/r.go 'package r

func R() int { return 16 }'
put test/integration/rho/rho_test.go '//go:build integration

package rho

import "testing"

func TestRho(t *testing.T) {}'
put test/integration/rho/sub/sub_test.go '//go:build integration

package sub

import (
	"testing"

	"example.com/m/pkg/r"
)

func TestSub(t *testing.T) { _ = r.R() }'
put test/integration/sigma/sigma_test.go '//go:build integration

package sigma

import "testing"

func TestSigma(t *testing.T) {}'
put test/integration/sigma/inner/inner_test.go '//go:build integration

package inner

import "testing"

func TestInner(t *testing.T) {}'
RT=$(commit_all "rho and sigma")
RS=$(commit_file test/integration/rho/sub/sub_test.go '// sub')
eq "a nested suite its feature's target does not run prints ALL" "ALL" "$(run "$RT" "$RS")"
RP=$(commit_file pkg/r/r.go '// r')
eq "a package only a nested suite the target skips imports prints ALL" "ALL" "$(run "$RS" "$RP")"
SI=$(commit_file test/integration/sigma/inner/inner_test.go '// inner')
eq "a nested suite its feature's target runs prints that feature" "sigma" "$(run "$RP" "$SI")"
XS=$(commit_file test/integration/xi/sub/sub_test.go '//go:build integration

package sub')
eq "a nested suite under a Compose-delegated target prints ALL" "ALL" "$(run "$SI" "$XS")"
# tau's test builds ./cmd/cli with its working directory in the nested module
# sub (the oidccredentials/xkey shape); the root has no cmd/cli.
put test/integration/tau/tau_test.go '//go:build integration

package tau

import (
	"os/exec"
	"testing"
)

func TestTau(t *testing.T) {
	c := exec.Command("go", "build", "-o", t.TempDir()+"/cli", "./cmd/cli")
	c.Dir = "../../../sub"
	_ = c.Run()
}'
TT=$(commit_all tau)
TC=$(commit_file sub/cmd/cli/main.go '// tau')
eq "a nested-module binary a suite builds from its module prints that suite" "$(printf 'tau\nxi\nzeta')" "$(run "$TT" "$TC")"
TU=$(commit_file pkg/u/u.go '// tau')
eq "a dep of a nested-module binary a suite builds prints that suite" "$(printf 'tau\nxi\nzeta')" "$(run "$TC" "$TU")"
# upsilon's target runs its suite through the with_server define, which builds
# and starts ./cmd/server (the run_with_server/logins shape); phi's test names
# ./cmd/server itself. A change to the server is selected with upsilon (or ALL).
cat >>"$REPO/Makefile" <<'EOF'

define with_server
	go build -o build/server ./cmd/server && build/server &
	$(1)
endef

integration-test-upsilon:
	$(call with_server,go test -tags "integration $(BUILD_TAGS)" ./test/integration/upsilon/...)
EOF
put cmd/server/main.go 'package main

func main() {}'
put test/integration/upsilon/upsilon_test.go '//go:build integration

package upsilon

import "testing"

func TestUpsilon(t *testing.T) {}'
put test/integration/phi/phi_test.go '//go:build integration

package phi

import (
	"os/exec"
	"testing"
)

func TestPhi(t *testing.T) { _ = exec.Command("go", "build", "./cmd/server").Run() }'
UT=$(commit_all "upsilon and phi")
UC=$(commit_file cmd/server/main.go '// upsilon')
got=$(run "$UT" "$UC")
case "$got" in
ALL | *upsilon*) ok "a binary a define helper of a suite's recipe builds selects that suite" ;;
*) no "a binary a define helper of a suite's recipe builds selects that suite: got [$got]" ;;
esac
# omega's target wraps go test in the in_box define (the run_in_devcontainer
# shape) with an explicit omega tag its test file needs. The helper hides its
# binaries, not its -tags: a change to a package omega imports selects a
# list holding omega, not ALL.
cat >>"$REPO/Makefile" <<'EOF'

define in_box
	$(1)
endef

integration-test-omega:
	$(call in_box,go test -tags "integration omega" ./test/integration/omega/...,integration-test-omega)
EOF
put pkg/w/w.go 'package w

func W() {}'
put test/integration/omega/omega_test.go '//go:build integration && omega

package omega

import (
	"testing"

	"example.com/m/pkg/w"
)

func TestOmega(t *testing.T) { w.W() }'
OT=$(commit_all omega)
OC=$(commit_file pkg/w/w.go '// omega')
got=$(run "$OT" "$OC")
case "$got" in
ALL) no "a suite a define helper wraps keeps its explicit tags: got ALL" ;;
*omega*) ok "a suite a define helper wraps keeps its explicit tags" ;;
*) no "a suite a define helper wraps keeps its explicit tags: got [$got]" ;;
esac
# Git quotes a non-ASCII path under the default core.quotePath: a change to
# such a file below beta's package pkg/c, and a rename onto such a name, each
# still select beta, never an empty or narrowed list, nor ALL: the path is
# an ordinary file of a package beta imports.
QA=$(commit_file "pkg/c/testdata/$(printf '\303\251').json" '{}')
QB=$(move_file "pkg/c/testdata/$(printf '\303\251').json" "pkg/c/testdata/$(printf '\303\274').json")
for qc in "$OC $QA a change to a file Git quotes" "$QA $QB a rename onto a name Git quotes"; do
	read -r qf qt qd <<<"$qc"
	got=$(run "$qf" "$qt")
	case "$got" in
	beta | beta$'\n'* | *$'\n'beta | *$'\n'beta$'\n'*) ok "$qd selects the suite importing its package" ;;
	*) no "$qd selects the suite importing its package: got [$got]" ;;
	esac
done
# lambda's only test file is gated on a tag no recipe passes (last, since
# from here on every package change prints ALL).
put test/integration/lambda/lambda_test.go '//go:build integration && neverset

package lambda

import (
	"testing"

	"example.com/m/pkg/l"
)

func TestLambda(t *testing.T) { _ = l.L() }'
LT=$(commit_all lambda)
L=$(commit_file pkg/l/l.go '// l')
eq "a suite whose tests no recipe's tags build makes any package change ALL" "ALL" "$(run "$LT" "$L")"

OUT=$(run "$BASE" no-such-revision 2>&1)
RC=$?
eq "a bad revision exits 2" "2" "$RC"
case "$OUT" in
ALL | alpha* | beta*) no "a bad revision prints no feature: [$OUT]" ;;
*) ok "a bad revision prints no feature" ;;
esac
run "$BASE" >/dev/null 2>&1
eq "a missing argument exits 2" "2" "$?"

finish
