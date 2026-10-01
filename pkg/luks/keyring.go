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

package luks

import (
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// checkKeyringAvailable is go-luks2's keyring preflight. It is a variable so
// tests can stand in for the kernel.
var checkKeyringAvailable = luks2.CheckKeyringAvailable

// EnsureKeyringAvailable proves, before a volume key is handled, that this
// process can place one in the kernel keyring. go-luks2 hands dm-crypt the
// volume key by keyring reference, so every unlock needs the add_key, keyctl
// and request_key syscalls; Docker's default seccomp profile blocks all three,
// and CAP_SYS_ADMIN does not lift that. Without this check the refusal arrives
// at the first volume attach and reads as a storage fault. With it, the
// refusal is a KeyringError naming the cause and the remedy, before a loop
// device is attached or a container file is created.
//
// The production Executor calls this before every Create and Unlock; callers
// that want to probe readiness ahead of a longer operation (e.g. before
// staging a data migration) can call it directly too.
//
// The probe runs before every operation and its result is never cached. A
// success proves only that the syscalls are reachable now: the per-user key
// quota can be exhausted between two operations of a long-lived process, and
// an operation that skipped the probe on the strength of an earlier success
// would fail at the key insertion, after the file, loop device or partition
// table it was meant to protect already existed. The probe is one add and one
// release of a 32-byte key, so running it per operation costs nothing that
// matters.
func EnsureKeyringAvailable() error {
	if err := checkKeyringAvailable(); err != nil {
		return &KeyringError{Err: err}
	}
	return nil
}
