// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package bad is a deliberately non-compliant fixture that
// `make secure-analyzer-selftest` drives through the real secure-analyzer
// binary to prove the gate goes RED on a known violation of each rule.
//
// It must never be reachable from any module's `./...`: the leading
// underscore on its parent directory (_fixtures) is what the Go toolchain
// uses to exclude a directory from wildcard package discovery (`go help
// packages`), so this package builds and vets only when addressed by its
// exact import path -- exactly what the selftest does, and nothing else in
// this repository's build, vet or lint targets ever will.
//
// Do not "fix" the violations below. They are the fixture.
package bad

import (
	"github.com/awnumar/memguard" // rule 1: raw memguard import outside pkg/secure

	"golang.org/x/crypto/ssh" // rule 2: paired with the banned call below
)

// holder is a rule-3 finding with no scope-clause cover: not generated, not
// a _test.go file, not codec-tagged, and its address never reaches a flag
// binder. Rule 3 must fire on it.
type holder struct {
	Password string
}

// useMemguard exercises rule 1: a raw memguard allocation outside
// pkg/secure.
func useMemguard() *memguard.LockedBuffer {
	return memguard.NewBuffer(32)
}

// useParsePrivateKey exercises rule 2: the banned parse call, regardless of
// what backs pemBytes.
func useParsePrivateKey(pemBytes []byte) (ssh.Signer, error) {
	return ssh.ParsePrivateKey(pemBytes)
}
