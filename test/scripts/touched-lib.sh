#!/usr/bin/env bash
# Shared fixture for touched-features.test.sh and touched-packages.test.sh
# (Tenant rulings 1170/1171): a throwaway git repository holding a small Go
# module laid out like go-xkms, so both scripts run against a real
# `go list` without the network.
#
#   pkg/a          leaf package
#   pkg/b          imports pkg/a
#   pkg/c          leaf package
#   pkg/d          leaf package no integration test reaches
#   test/integration/alpha   feature: its tests import pkg/b (pkg/a transitively)
#   test/integration/beta    feature: its tests import pkg/c
#   test/integration/common  shared helper
#
# Sourcing it defines REPO, g, commit_file, move_file and the eq/ok/no
# counters; the caller prints the summary with finish.

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
eq() { # eq <name> <want> <got>
	if [ "$2" = "$3" ]; then ok "$1"; else no "$1: want [$2] got [$3]"; fi
}
finish() {
	printf '%d passed, %d failed\n' "$PASS" "$FAIL"
	[ "$FAIL" -eq 0 ]
}

export GOWORK=off GOFLAGS=-mod=mod GOTOOLCHAIN=local GOPROXY=off

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
REPO="$WORK/repo"

g() { git -C "$REPO" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }

put() { # put <file> <content>
	mkdir -p "$REPO/$(dirname "$1")"
	printf '%s\n' "$2" >"$REPO/$1"
}
commit_all() { # commit_all <msg>: commit everything, print the commit id
	g add -A >/dev/null && g commit -q -m "$1" && g rev-parse HEAD
}
commit_file() { # commit_file <file> <line>: append a line, commit, print the id
	mkdir -p "$REPO/$(dirname "$1")"
	printf '%s\n' "$2" >>"$REPO/$1"
	commit_all "$1"
}
move_file() { # move_file <from> <to>: git mv, commit, print the id
	mkdir -p "$REPO/$(dirname "$2")"
	g mv "$1" "$2" && commit_all "move $1"
}

git init -q "$REPO"
put go.mod 'module example.com/m

go 1.22'
mkdir -p "$REPO"
# The tags come from conditional += lines, as in go-xkms; eps and zeta build
# the binary their tests run in the recipe (zeta from a nested module);
# integration-test-xi hands its suite to Compose, whose Dockerfile builds
# ./cmd/tool (touched-features.test.sh adds the xi directory late).
cat >"$REPO/Makefile" <<'EOF'
WITH_GAMMA ?= 1
BUILD_TAGS := codec_json
ifeq ($(WITH_GAMMA),1)
	BUILD_TAGS += gamma
endif
TEST_TAGS := codec_json
ifeq ($(WITH_GAMMA),1)
	TEST_TAGS += gamma
endif

test-pkg:
	go test -tags "$(TEST_TAGS)" ./$(PKG)

integration-test-eps:
	go build -o build/bin/srv ./cmd/srv && go test -tags "integration $(BUILD_TAGS)" ./test/integration/eps/...

integration-test-zeta:
	cd sub && go build -o ../build/bin/cli ./cmd/cli && cd .. && \
		go test -tags "integration $(BUILD_TAGS)" ./test/integration/zeta/...

integration-test-kappa:
	go test -v -tags "integration simx $(BUILD_TAGS)" ./test/integration/kappa/... -timeout 10m

integration-test-omicron-go:
	go test -tags "integration codec_only" ./test/integration/omicron/...

integration-test-xi:
	docker compose -f test/integration/xi/compose.yml run --build harness

integration-test-%:
	go test -v -tags "integration $(BUILD_TAGS)" ./test/integration/$*/...
EOF
put README.md '# m'
put pkg/a/a.go 'package a

func A() int { return 1 }'
put pkg/b/b.go 'package b

import "example.com/m/pkg/a"

func B() int { return a.A() }'
put pkg/c/c.go 'package c

func C() int { return 3 }'
put pkg/d/d.go 'package d

func D() int { return 4 }'
put test/integration/common/common.go 'package common

func Helper() {}'
put test/integration/alpha/alpha_test.go '//go:build integration

package alpha

import (
	"testing"

	"example.com/m/pkg/b"
	"example.com/m/pkg/k"
	"example.com/m/pkg/l"
)

func TestAlpha(t *testing.T) { _ = b.B() + k.K() + l.L() }'
put test/integration/beta/beta_test.go '//go:build integration

package beta

import (
	"testing"

	"example.com/m/pkg/c"
)

func TestBeta(t *testing.T) { _ = c.C() }'
put test/integration/beta/extra_test.go '//go:build integration

package beta'
put pkg/a/extra.go 'package a'
# gamma: only a gamma-tagged test file imports pkg/g; pkg/h imports pkg/g
# only from a gamma-tagged file.
put pkg/g/g.go 'package g

func G() int { return 7 }'
put pkg/h/h.go '//go:build gamma

package h

import "example.com/m/pkg/g"

func H() int { return g.G() }'
put test/integration/gamma/gamma_test.go '//go:build integration && gamma

package gamma

import (
	"testing"

	"example.com/m/pkg/g"
)

func TestGamma(t *testing.T) { _ = g.G() }'
# kappa: alpha imports pkg/k, and so does kappa's only test file, gated on
# simx, a tag only kappa's explicit rule adds (the clusterca/tpm_simulator
# shape). alpha also imports pkg/l, which touched-features.test.sh gives a
# suite (lambda) no recipe's tags build.
put pkg/k/k.go 'package k

func K() int { return 11 }'
put test/integration/kappa/kappa_test.go '//go:build integration && simx

package kappa

import (
	"testing"

	"example.com/m/pkg/k"
)

func TestKappa(t *testing.T) { _ = k.K() }'
put pkg/l/l.go 'package l

func L() int { return 12 }'
# delta: its test builds and runs ./cmd/tool, which imports pkg/t.
put pkg/t/t.go 'package t

func T() int { return 8 }'
put cmd/tool/main.go 'package main

import "example.com/m/pkg/t"

func main() { _ = t.T() }'
put test/integration/delta/delta_test.go '//go:build integration

package delta

import (
	"os/exec"
	"testing"
)

func TestDelta(t *testing.T) {
	bin := t.TempDir() + "/tool"
	if err := exec.Command("go", "build", "-o", bin, "./cmd/tool").Run(); err != nil {
		t.Fatal(err)
	}
}'
# eps: the Makefile recipe builds ./cmd/srv (imports pkg/s) for the tests.
put pkg/s/s.go 'package s

func S() int { return 9 }'
put cmd/srv/main.go 'package main

import "example.com/m/pkg/s"

func main() { _ = s.S() }'
put test/integration/eps/eps_test.go '//go:build integration

package eps

import "testing"

func TestEps(t *testing.T) {}'
# zeta: the recipe builds sub/cmd/cli, a nested module's binary importing
# the root module's pkg/u.
put pkg/u/u.go 'package u

func U() int { return 10 }'
put sub/go.mod 'module example.com/m/sub

go 1.22

require example.com/m v0.0.0

replace example.com/m => ../'
put sub/cmd/cli/main.go 'package main

import "example.com/m/pkg/u"

func main() { _ = u.U() }'
put test/integration/zeta/zeta_test.go '//go:build integration

package zeta

import "testing"

func TestZeta(t *testing.T) {}'
# mu: a feature whose directory also holds a helper package nu's tests import
# (the xkmsdtest shape).
put test/integration/mu/help.go 'package mu

func Help() int { return 13 }'
put test/integration/mu/mu_test.go '//go:build integration

package mu

import "testing"

func TestMu(t *testing.T) { _ = Help() }'
put test/integration/nu/nu_test.go '//go:build integration

package nu

import (
	"testing"

	"example.com/m/test/integration/mu"
)

func TestNu(t *testing.T) { _ = mu.Help() }'
# omicron: integration-test-omicron-go tests the directory without gamma, but
# the emitted omicron runs integration-test-omicron (the pattern, gamma set),
# and only its gamma-tagged file imports pkg/o.
put pkg/o/o.go 'package o

func O() int { return 15 }'
put test/integration/omicron/plain_test.go '//go:build integration

package omicron'
put test/integration/omicron/omicron_test.go '//go:build integration && gamma

package omicron

import (
	"testing"

	"example.com/m/pkg/o"
)

func TestOmicron(t *testing.T) { _ = o.O() }'
BASE=$(commit_all base)
export BASE
