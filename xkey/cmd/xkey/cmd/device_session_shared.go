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

package cmd

import (
	"errors"
	"log/slog"
	"os"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// Not ble-gated: neither function touches Bluetooth, and go-xkms#1306 needs
// them from `xkey device relay` (TCP, no ble tag required) as well as from
// the ble-gated surfaces that reach a phone through openDeviceSession or
// newPairedDeviceBackendConfig (device_session.go). They used to live there
// only because every caller happened to be BLE at the time they were written.

// ErrSessionKeyDecode means the stored pairing keys will not decode, so
// the pairing record is unusable and re-pairing is the only fix.
var ErrSessionKeyDecode = errors.New("device: stored pairing key is malformed")

// unsealDeviceLocalKey resolves device's local Noise static private key for
// the surfaces that reach the phone through openDeviceSession or
// newPairedDeviceBackendConfig rather than through a device command with its
// own --barrier-password flags (#42): OATH sync, backup, sharing, attest,
// phone enrollment, and the FIDO2 phone backend.
//
// A legacy plaintext record (IsSealedNoiseKey false) is read with no barrier
// at all -- these surfaces predate #42 and must keep working unattended for
// an existing pairing with no barrier configured. A sealed record needs the
// barrier open, so this opens one from XKEY_BARRIER_PASSWORD -- the one
// source that does not need a *cobra.Command threaded through this whole call
// graph -- and closes it again immediately: nothing else in these flows needs
// it once the key is in hand. There is no fallback to reading a sealed record
// as plaintext: with no password available, this refuses via
// pairing.ErrNoiseKeyFormMismatch before ever calling UnsealLocalNoiseKey
// (which would refuse the same way, since it also has no barrier).
func unsealDeviceLocalKey(device *PairedDevice, logger *slog.Logger) (*secure.Buffer, error) {
	if !pairing.IsSealedNoiseKey(device.LocalNoisePrivateKey) {
		return pairing.UnsealLocalNoiseKey(nil, device.LocalNoisePrivateKey)
	}

	password := os.Getenv("XKEY_BARRIER_PASSWORD")
	if password == "" {
		return nil, &SentinelCauseError{Sentinel: ErrSessionKeyDecode, Cause: pairing.ErrNoiseKeyFormMismatch}
	}
	barrier, closeBarrier, err := openDeviceBarrierWithPassword(password)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSessionKeyDecode, Cause: err}
	}
	defer closeBarrier()

	return pairing.UnsealLocalNoiseKey(barrier, device.LocalNoisePrivateKey)
}

// loadLocalStaticKey copies the unsealed local Noise scalar in priv into a
// Noise static key's own protected memory, holding priv's borrow across the
// read so a concurrent shutdown wipe cannot unmap the pages mid-copy. priv
// stays the caller's to destroy.
func loadLocalStaticKey(priv *secure.Buffer) (*pairing.StaticKey, error) {
	var key *pairing.StaticKey
	err := priv.WithBytes(func(scalar []byte) error {
		var lerr error
		key, lerr = pairing.LoadStaticKey(scalar)
		return lerr
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

// newLiveAttestor builds the verifier the phone backend calls after its
// handshake, for surfaces that connect through PhoneKeyBackend rather than
// openDeviceSession (#129) -- and, since go-xkms#1306, the verifier
// TCPPairingConfig.LiveAttest and BLEPeripheralConfig.LiveAttest run on a
// phone-INITIATED connection.
//
// The trust loader is passed rather than a pool: attestation.NewLiveAttestor
// calls it per connection, so a root installed with `xkey trust` between
// connections takes effect instead of a stale pool refusing a device the
// machine now trusts.
func newLiveAttestor(device *PairedDevice, logger *slog.Logger) pairing.LiveAttestFunc {
	return attestation.NewLiveAttestor(
		attestation.DeviceBindingFor(*device), loadPairingAttestationTrust, logger)
}
