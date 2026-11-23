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
put Makefile 'BUILD_TAGS := codec_json
TEST_TAGS := codec_json'
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
)

func TestAlpha(t *testing.T) { _ = b.B() }'
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
BASE=$(commit_all base)
export BASE
