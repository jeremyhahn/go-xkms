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

package pairing

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// NoiseKeySealedPrefix marks a PairedDevice.LocalNoisePrivateKey value that
// holds the host's Noise static private key sealed under the barrier (#42),
// as opposed to the pre-#42 raw-base64 plaintext form. A reader tells the two
// apart by this prefix alone: SealLocalNoiseKey always writes it, and a
// stored value that lacks it is the legacy form, kept working so an existing
// pairing is not broken by the fix that stops writing it. See
// UnsealLocalNoiseKey for how the legacy form is read and migrated.
const NoiseKeySealedPrefix = "xkey-noise-sealed-v1:"

// NoiseKeyBarrier is the minimal barrier surface sealing and unsealing the
// Noise static private key needs: encrypt and decrypt a blob under the
// barrier's master key. *sdk/go.Barrier (go-qrdb's StorageBarrier) satisfies
// it -- its own Put/Get call exactly these two methods to encrypt a value at
// rest, so a key sealed here is protected the same way every other secret
// this stack keeps under the barrier is, without this package depending on
// the full barrier type or its KV-store surface.
//
// A narrow interface also keeps this package testable without standing up a
// real barrier (password, strategy, on-disk root key) for every noise-key
// test.
type NoiseKeyBarrier interface {
	// Encrypt seals plaintext under the barrier's current master key.
	// Implementations return an error (not a fallback) when the barrier is
	// sealed.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt opens a blob Encrypt produced. Implementations return an error
	// (not a fallback) when the barrier is sealed.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// Noise key sealing errors (#42).
var (
	// ErrNoiseKeySealBarrierRequired is returned by SealLocalNoiseKey when no
	// barrier was supplied to seal under. The Noise static private key must
	// never be persisted unsealed, so there is no plaintext fallback here.
	ErrNoiseKeySealBarrierRequired = errors.New("pairing: sealing the local Noise private key requires an unsealed barrier")

	// ErrNoiseKeySealFailed wraps a failure from the barrier itself (sealed,
	// closed, or an underlying storage error) while sealing.
	ErrNoiseKeySealFailed = errors.New("pairing: failed to seal the local Noise private key")

	// ErrNoiseKeyUnsealFailed wraps a decode or decrypt failure while
	// unsealing, sealed or legacy.
	ErrNoiseKeyUnsealFailed = errors.New("pairing: failed to unseal the local Noise private key")

	// ErrNoiseKeyFormMismatch is returned by UnsealLocalNoiseKey when the
	// stored record's form does not match the barrier's current presence: a
	// barrier is open but the record is the legacy plaintext form, or no
	// barrier is available but the record is the sealed form. There is no
	// migration between the two forms (go-xkms compat cleanup PR5) -- the
	// operator must re-pair the device so a fresh record is written in the
	// form that matches this host's current barrier state.
	ErrNoiseKeyFormMismatch = errors.New("pairing: stored local Noise private key form does not match the barrier state; re-pair this device")

	// ErrNoiseKeyEmpty is returned when there is no stored value to seal or
	// unseal.
	ErrNoiseKeyEmpty = errors.New("pairing: no local Noise private key is stored")
)

// IsSealedNoiseKey reports whether stored is the barrier-sealed form
// SealLocalNoiseKey writes, as opposed to the legacy raw-base64 plaintext
// form. An empty string is not sealed.
func IsSealedNoiseKey(stored string) bool {
	return strings.HasPrefix(stored, NoiseKeySealedPrefix)
}

// SealLocalNoiseKey seals priv -- the raw Curve25519 private scalar, e.g.
// bootstrap.NoiseStaticKey.Private -- under barrier and returns the marker-prefixed,
// base64-encoded value to store in a PairedDevice's LocalNoisePrivateKey
// field. priv is the caller's: SealLocalNoiseKey neither mutates nor
// destroys it, so the caller wipes/destroys it (bootstrap.NoiseStaticKey.Destroy, or
// secure.Buffer.Destroy) once sealing returns, on every path.
func SealLocalNoiseKey(barrier NoiseKeyBarrier, priv []byte) (string, error) {
	if barrier == nil {
		return "", ErrNoiseKeySealBarrierRequired
	}
	if len(priv) == 0 {
		return "", ErrNoiseKeyEmpty
	}

	ciphertext, err := barrier.Encrypt(priv)
	if err != nil {
		return "", &pairingproto.SentinelCauseError{Sentinel: ErrNoiseKeySealFailed, Cause: err}
	}
	return NoiseKeySealedPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// UnsealLocalNoiseKey reads a PairedDevice's LocalNoisePrivateKey field into
// protected memory. The expected form is chosen by barrier presence, not by
// inspecting the stored value: a non-nil barrier means the record must be
// the barrier-sealed form (IsSealedNoiseKey); a nil barrier means it must be
// the legacy plaintext-base64 form. A record in the other form returns
// ErrNoiseKeyFormMismatch -- there is no migration between the two forms
// (go-xkms compat cleanup PR5); the operator must re-pair the device.
//
// The returned Buffer is the caller's to Destroy.
func UnsealLocalNoiseKey(barrier NoiseKeyBarrier, stored string) (*secure.Buffer, error) {
	if stored == "" {
		return nil, ErrNoiseKeyEmpty
	}

	sealed := IsSealedNoiseKey(stored)

	if barrier != nil {
		if !sealed {
			return nil, ErrNoiseKeyFormMismatch
		}
		ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, NoiseKeySealedPrefix))
		if err != nil {
			return nil, &pairingproto.SentinelCauseError{Sentinel: ErrNoiseKeyUnsealFailed, Cause: err}
		}
		plaintext, err := barrier.Decrypt(ciphertext)
		if err != nil {
			return nil, &pairingproto.SentinelCauseError{Sentinel: ErrNoiseKeyUnsealFailed, Cause: err}
		}
		// NewBufferFromBytes copies plaintext into protected memory and wipes
		// the caller's slice, so the barrier-decrypted heap copy above does
		// not outlive this call.
		buf, err := secure.NewBufferFromBytes(plaintext)
		if err != nil {
			return nil, &pairingproto.SentinelCauseError{Sentinel: ErrNoiseKeyUnsealFailed, Cause: err}
		}
		return buf, nil
	}

	if sealed {
		return nil, ErrNoiseKeyFormMismatch
	}

	// Legacy plaintext base64: the expected form when no barrier is open.
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: ErrNoiseKeyUnsealFailed, Cause: err}
	}
	buf, err := secure.NewBufferFromBytes(raw)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: ErrNoiseKeyUnsealFailed, Cause: err}
	}
	return buf, nil
}
