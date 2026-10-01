// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package luks

import (
	sdkluks "github.com/jeremyhahn/go-xkms/sdk/go/luks"
)

// KeyringError reports a failed kernel keyring preflight. It is
// go-xkms/pkg/luks's canonical KeyringError, re-exported here so existing
// xkey call sites and tests do not need to import sdk/go/luks directly.
type KeyringError = sdkluks.KeyringError

// ErrKeyringUnavailable is the identity of every KeyringError: the kernel
// keyring is not usable by this process, so no volume can be unlocked.
var ErrKeyringUnavailable = sdkluks.ErrKeyringUnavailable

// EnsureKeyringAvailable proves, before a volume key is handled, that this
// process can place one in the kernel keyring. The production Executor
// (go-xkms/pkg/luks.LibExecutor) already runs this preflight before every
// Create and Unlock; callers that want to probe readiness ahead of a longer
// operation (e.g. before staging a data migration, or before mounting USB
// media) can call it directly too.
func EnsureKeyringAvailable() error {
	return sdkluks.EnsureKeyringAvailable()
}
