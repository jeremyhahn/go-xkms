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

package staticpw

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
)

// TestMain runs this package's tests with a cheap passphrase Argon2id cost:
// the vault tests enroll and unlock many times, and the production cost
// (64 MiB, t=3) would make every derivation dominate the suite. The cost is
// recorded on each factor, so the code path is the production one.
func TestMain(m *testing.M) {
	passphraseKDFParams = func() *kdf.KDFParams {
		return &kdf.KDFParams{Algorithm: kdf.AlgorithmArgon2id, Memory: 64, Time: 1, Threads: 1, KeyLength: 32}
	}
	os.Exit(m.Run())
}
