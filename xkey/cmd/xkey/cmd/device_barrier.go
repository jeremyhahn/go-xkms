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

//go:build ble

package cmd

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// Device barrier errors (#42). The Noise static private key is sealed under
// the barrier when this host has one initialized. It does not need one:
// a host that never ran `xkey barrier init` pairs and connects exactly as
// xkey always did, with the key stored as legacy plaintext base64 and one
// warning logged per operation (owner ruling on #42, recorded on the issue).
// What refuses is a barrier that DOES exist but cannot be opened -- the
// operator chose to protect this key, and a locked barrier is not consent to
// fall back to plaintext.
var (
	// ErrDeviceBarrierNotInitialized indicates no barrier has ever been set
	// up on this host. Only openDeviceBarrierWithPassword's callers, which
	// already know the record they are about to read is sealed, treat this
	// as a refusal; openDeviceBarrier itself never returns it.
	ErrDeviceBarrierNotInitialized = errors.New("device: barrier not initialized; run 'xkey barrier init' first")

	// ErrDeviceBarrierPasswordRequired indicates the barrier is initialized
	// but no password was supplied to unseal it.
	ErrDeviceBarrierPasswordRequired = errors.New("device: barrier password required (--barrier-password, --barrier-password-file, or XKEY_BARRIER_PASSWORD)")

	// ErrDeviceBarrierUnsealFailed indicates the barrier could not be
	// resolved or unsealed with the supplied password.
	ErrDeviceBarrierUnsealFailed = errors.New("device: failed to unseal barrier")

	// ErrDeviceBarrierSealFailed indicates the Noise static private key
	// could not be sealed under an already-open barrier.
	ErrDeviceBarrierSealFailed = errors.New("device: failed to seal the local Noise private key")
)

// noBarrierConfiguredWarning is logged, once per operation, by every device
// command that proceeds with the legacy plaintext form of the Noise static
// private key because no barrier is initialized on this host at all (#42
// owner ruling). It is a package-level format string so every call site logs
// identical wording.
const noBarrierConfiguredWarning = "pairing key stored unencrypted: no barrier is initialized on this host; run `xkey barrier init` to protect it"

// addDeviceBarrierFlags registers the --barrier-password[-file] flags shared
// by every device command that seals or unseals the Noise static private key.
func addDeviceBarrierFlags(cmd *cobra.Command) {
	cmd.Flags().String("barrier-password", "", "Barrier password (or XKEY_BARRIER_PASSWORD)")
	cmd.Flags().String("barrier-password-file", "", "Path to a file containing the barrier password")
}

// resolveDeviceBarrierPassword resolves the barrier password the same way
// FIDO2's barrier storage does (see createBarrierStorage in fido2.go):
// --barrier-password, then --barrier-password-file, then XKEY_BARRIER_PASSWORD.
func resolveDeviceBarrierPassword(cmd *cobra.Command) (string, error) {
	password, _ := cmd.Flags().GetString("barrier-password")
	if password == "" {
		if path, _ := cmd.Flags().GetString("barrier-password-file"); path != "" {
			raw, err := os.ReadFile(path)
			if err != nil {
				return "", &SentinelCauseError{Sentinel: ErrDeviceBarrierUnsealFailed, Cause: err}
			}
			password = strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
		}
	}
	if password == "" {
		password = os.Getenv("XKEY_BARRIER_PASSWORD")
	}
	return password, nil
}

// openDeviceBarrier opens the barrier that seals the phone pairing Noise
// static private key (#42) IF one is initialized on this host, resolving the
// data directory the way devices.yaml itself is resolved
// (resolveInvokingUserHome, which honours SUDO_USER so `sudo xkey device
// pair` and the user's own GUI session read the same files) and unsealing it
// with a password resolved from resolveDeviceBarrierPassword.
//
// Three outcomes, matching PhoneService.resolveNoiseKeyBarrier's on the GUI
// side:
//   - No barrier has ever been initialized on this host: (nil, no-op close,
//     nil). This is the owner ruling on #42 -- not a refusal. The caller is
//     responsible for logging noBarrierConfiguredWarning and falling back to
//     the legacy plaintext form (sealOrWarnLocalNoiseKey does this for the
//     write path; the read path's pairing.UnsealLocalNoiseKey already
//     accepts a nil barrier for a legacy record on its own).
//   - A barrier exists but could not be unsealed (missing/wrong password, or
//     any other resolution failure): (nil, nil, err) --
//     ErrDeviceBarrierPasswordRequired or a wrapped ErrDeviceBarrierUnsealFailed.
//     This DOES refuse: the operator chose to protect this key.
//   - A barrier exists and opened: (barrier, closeFn, nil).
//
// The returned close function seals the barrier again; call it via defer
// unconditionally after a nil error (it is a safe no-op in the first case).
func openDeviceBarrier(cmd *cobra.Command) (pairing.NoiseKeyBarrier, func(), error) {
	password, pwErr := resolveDeviceBarrierPassword(cmd)
	if pwErr != nil {
		return nil, nil, pwErr
	}
	return resolveDeviceBarrier(password, false)
}

// openDeviceBarrierWithPassword is openDeviceBarrier's password-only half,
// used directly by surfaces that reach the phone through openDeviceSession or
// newPairedDeviceBackendConfig (device_session.go) rather than through a
// command with its own --barrier-password flags -- OATH sync, backup,
// sharing, attest, phone enrollment, and the FIDO2 phone backend. Unlike
// openDeviceBarrier, an uninitialized barrier here IS refused
// (ErrDeviceBarrierNotInitialized): every call site already knows, from
// pairing.IsSealedNoiseKey, that the record it is about to read is sealed,
// so a barrier that was never initialized cannot be the reason -- something
// is actually inconsistent, and there is no legacy fallback to offer.
//
// It deliberately does not share fido2.go's createBarrierStorage: that helper
// resolves the data directory with plain xhome.Resolve(), which does not
// honour SUDO_USER, and would put the barrier it opens at a different path
// than the devices.yaml these commands read or write under sudo.
func openDeviceBarrierWithPassword(password string) (pairing.NoiseKeyBarrier, func(), error) {
	return resolveDeviceBarrier(password, true)
}

// resolveDeviceBarrier is the shared core of openDeviceBarrier and
// openDeviceBarrierWithPassword. When requireInitialized is false, a host
// with no barrier ever initialized returns (nil, no-op close, nil) rather
// than ErrDeviceBarrierNotInitialized.
func resolveDeviceBarrier(password string, requireInitialized bool) (pairing.NoiseKeyBarrier, func(), error) {
	home, homeErr := resolveInvokingUserHome()
	if homeErr != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrDeviceBarrierUnsealFailed, Cause: homeErr}
	}
	dataDir, dataDirErr := home.EnsureDataDir()
	if dataDirErr != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrDeviceBarrierUnsealFailed, Cause: dataDirErr}
	}

	if !barrierRootKeyExists(dataDir) {
		if requireInitialized {
			return nil, nil, ErrDeviceBarrierNotInitialized
		}
		return nil, func() {}, nil
	}
	if password == "" {
		return nil, nil, ErrDeviceBarrierPasswordRequired
	}

	strategy, strategyErr := readBarrierStrategy(dataDir)
	if strategyErr != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrDeviceBarrierUnsealFailed, Cause: strategyErr}
	}

	barrierSvc := services.NewBarrierService(home.Root, slog.Default())
	barrierSvc.SetDataDir(dataDir)
	if unsealErr := barrierSvc.Unseal(password, string(strategy)); unsealErr != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrDeviceBarrierUnsealFailed, Cause: unsealErr}
	}

	barrier := barrierSvc.GetBarrier()
	if barrier == nil {
		return nil, nil, &DetailError{Err: ErrDeviceBarrierUnsealFailed, Detail: ": barrier unavailable after unseal"}
	}

	return barrier, func() { _ = barrierSvc.Seal() }, nil
}

// sealOrWarnLocalNoiseKey mirrors PhoneService.sealOrWarnLocalNoiseKey for
// the CLI: seals priv under barrier when one is open, or logs
// noBarrierConfiguredWarning and returns the legacy plaintext form when
// barrier is nil. A nil barrier reaching this function is always because no
// barrier is initialized on this host at all -- openDeviceBarrier's callers
// never reach here with a nil barrier from any other cause, since every
// other resolution failure is a non-nil error they return before calling
// this.
func sealOrWarnLocalNoiseKey(logger *slog.Logger, deviceName string, barrier pairing.NoiseKeyBarrier, priv []byte) (string, error) {
	if barrier == nil {
		logger.Warn(noBarrierConfiguredWarning, "device", deviceName)
		return base64.StdEncoding.EncodeToString(priv), nil
	}
	sealed, err := pairing.SealLocalNoiseKey(barrier, priv)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrDeviceBarrierSealFailed, Cause: err}
	}
	return sealed, nil
}

// compile-time checks: *xkms.Barrier is what openDeviceBarrier actually
// returns behind the pairing.NoiseKeyBarrier interface.
var _ pairing.NoiseKeyBarrier = (*xkms.Barrier)(nil)
