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

package seal

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// CompareAndDelete overrides the method BarrierBackend would otherwise promote
// from the embedded barrier, to translate ONE sentinel.
//
// go-qrdb's barrier reads its base and turns a missing key into the refusal the
// guarded delete owes its caller -- but it recognises only its OWN
// ErrSecretNotFound. An xkms backend reports a missing key as
// storage.ErrNotFound, a different sentinel, so the absent case escaped as an
// error where storage.CompareAndDeleter requires deleted=false with a nil
// error. That is not cosmetic: a caller releasing a claim treats an error as
// "outcome unknown" and retries or escalates, where the truthful answer is the
// ordinary "someone else released it first".
//
// THE TRANSLATION IS DELIBERATELY CONFINED TO THIS METHOD. The obvious fix --
// translating on the Get that the barrier reads through -- would re-point the
// absent-key error for EVERY barrier read, and roughly fifty production call
// sites currently match on storage.ErrNotFound, including barrier-backed ones
// like platform_store.go and pkcs11/localseal's isUninitialized, which reads it
// as "no barrier yet". Overriding here fixes the verb that has the contract
// without touching the error contract of anything else.
//
// Only ErrNotFound is translated. Every other failure still surfaces as an
// error, because it genuinely leaves the outcome unknown, and the point of the
// distinction is that deleted=false must mean the guard was evaluated.
func (b *BarrierBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	deleted, err := b.Barrier.CompareAndDelete(ctx, key, expected)
	if err != nil && errors.Is(err, storage.ErrNotFound) {
		// The key was absent when the barrier read it: an ordinary refusal.
		return false, nil
	}
	return deleted, err
}
