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

// Package clean is the compliant counterpart of the bad fixture beside it:
// same shape, none of the three secure-analyzer rules apply. Together the
// pair is what `make secure-analyzer-selftest` proves the gate can tell
// apart -- a sweep that cannot find a known violation, or that flags a
// compliant file, is measuring something other than this repository.
//
// See bad/bad.go for why this directory is never reached by `./...`.
package clean

import (
	"golang.org/x/crypto/ssh"

	sdksecure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// holder is the compliant shape for bad.holder: the sensitive-named field
// is backed by the SDK's secure wrapper instead of a raw string.
type holder struct {
	Password *sdksecure.Secret
}

// parseWithPassphrase is the compliant counterpart of bad.useParsePrivateKey:
// the only entry point rule 2 allows.
func parseWithPassphrase(pemBytes, passphrase []byte) (ssh.Signer, error) {
	return ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
}

// readBorrowed is the compliant counterpart of bad.readUnborrowed and
// bad.toString: the read happens inside a held borrow and no copy leaves it.
func readBorrowed(b *sdksecure.Buffer) (byte, error) {
	var first byte
	err := b.WithBytes(func(p []byte) error {
		first = p[0]
		return nil
	})
	return first, err
}

// copyWiped is the compliant counterpart of bad.copyUnwiped: the copy is
// wiped before the function returns.
func copyWiped(b *sdksecure.Buffer) error {
	return b.WithBytes(func(p []byte) error {
		cp := append([]byte(nil), p...)
		defer sdksecure.Wipe(cp)
		_ = len(cp)
		return nil
	})
}
