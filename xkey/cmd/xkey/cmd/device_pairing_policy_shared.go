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

package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// Not ble-gated: none of this touches Bluetooth, and go-xkms#1306 needs
// resolvePairingPolicy and loadPairingAttestationTrust from `xkey device
// relay` (TCP, no ble tag required) as well as from `xkey device pair`/
// `listen` (BLE). It used to live in device_pair.go, a ble-tagged file, only
// because every caller happened to be BLE at the time it was written.

// unifiedConfigOrDefault returns GetConfig() when the CLI's normal
// initConfig() lifecycle has populated it, and xkeyconfig.DefaultConfig()
// otherwise -- the same fallback listenerConfig() (listen_config.go) already
// uses. resolvePairingPolicy's LoadVerifiedPolicy refuses a nil *Config
// outright, which initConfig() never produces when a command runs through
// RootCmd.Execute(), but a test that calls runDeviceListen/runDeviceRelay
// directly bypasses that lifecycle and would otherwise see GetConfig()
// return nil.
func unifiedConfigOrDefault() *xkeyconfig.Config {
	if cfg := GetConfig(); cfg != nil {
		return cfg
	}
	return xkeyconfig.DefaultConfig()
}

// loadPairingAttestationTrust builds this machine's Android hardware
// attestation trust material.
//
// It is the CLI's half of a decision whose other half is shared: WHICH store
// to open is per-surface, what to do with the pool is not.
func loadPairingAttestationTrust() (_ *attestation.Trust, err error) {
	store, err := openTrustStore()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: attestation.ErrDeviceAttestVerifyFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	return attestation.LoadTrust(store)
}

// ErrPairingPolicyRefused indicates the config directory is sealed, an SO
// PIN was supplied, and the policy section did not verify under it. The
// pairing is refused outright rather than continued under a policy that may
// have been edited: the cause (config.ErrPolicyUnverifiable joined with
// ErrPolicyHMACMismatch or ErrPolicyHMACLoadFailed) is reachable with
// errors.Is.
var ErrPairingPolicyRefused = errors.New("device pair: sealed enterprise policy could not be verified")

// resolvePairingPolicy resolves the enterprise plane for one pairing or
// listening/relay session.
//
// It returns the policy with its verification state when the plane can be
// trusted: unsealed (personal mode, the section is the user's own file) or
// sealed and verified under the SO PIN the operator supplied. It returns
// (nil, nil) when the directory is sealed and no SO PIN was supplied — the
// plane exists but is unknown, and allowUnattestablePairing/
// allowPhoneSyncExport fail closed on it. It returns ErrPairingPolicyRefused
// when an SO PIN was supplied and the section did not verify, because a
// sealed section that does not verify is a value anyone may have written and
// must not be consulted at all (#118).
//
// Where the SO PIN comes from is the same three sources as the user PIN
// (soPINUsage). It is never demanded: an ordinary pairing has no SO at the
// keyboard, and the price of not supplying it is the fail-closed answer.
func resolvePairingPolicy(cmd *cobra.Command, unified *xkeyconfig.Config, logger *slog.Logger) (*xkeyconfig.VerifiedPolicy, error) {
	soPIN, err := resolveSOPINInput(cmd)
	if err != nil {
		return nil, err
	}

	configDir := xkeyconfig.ConfigDir()
	if soPIN == "" && xkeyconfig.IsEnterpriseMode(configDir) {
		logger.Info("sealed enterprise policy not consulted: no SO PIN supplied",
			"config_dir", configDir)
		return nil, nil
	}

	policy, err := xkeyconfig.LoadVerifiedPolicy(unified, configDir, soPIN)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPairingPolicyRefused, Cause: err}
	}
	if policy.State == xkeyconfig.PolicySealedVerified {
		logger.Info("enterprise policy verified", "state", policy.State.String())
	}
	return policy, nil
}

// allowUnattestablePairing projects this command's two policy planes onto the
// shared decision, attestation.AllowUnattestablePairing.
//
// What is genuinely this command's is WHERE each plane comes from: the user
// plane is devices.yaml as this package reads it, the enterprise plane is the
// config.VerifiedPolicy resolvePairingPolicy produced, nil when the directory
// is sealed and no SO PIN was supplied. What is not this command's is how they
// combine -- the GUI pairs phones too, and a resolution that lived here alone
// was the #95 defect one level up (#115).
func allowUnattestablePairing(devices *DevicesConfig, policy *xkeyconfig.VerifiedPolicy) bool {
	userAllows := devices != nil && devices.AttestationPolicy != nil &&
		devices.AttestationPolicy.AllowUnattestableDevices
	return attestation.AllowUnattestablePairing(userAllows, policy)
}

// allowPhoneSyncExport decides whether THIS "xkey device listen"/"relay"
// session may serve remote.syncPasswords, remote.syncOATH and remote.syncAll
// -- the bridge methods that export the password vault or OATH secrets to
// the phone (go-xkms#1306).
//
// Mirrors allowUnattestablePairing's two-plane resolution exactly:
// sessionAllowed is the operator's own --allow-sync flag for this
// invocation, the "devices.yaml" plane's equivalent for a decision that has
// no persisted per-device setting to read. policy is what
// resolvePairingPolicy produced -- nil when the config directory is sealed
// and no SO PIN was supplied, in which case this fails closed exactly the
// way attestation.AllowUnattestablePairing does for a nil policy: the
// enterprise plane's answer is unknown, so it cannot be "yes".
//
// When the policy verified AND locks this decision
// (PolicySealedVerified && LockPhoneSyncPolicy), it governs outright and
// sessionAllowed is never consulted -- an operator cannot opt a session in
// (or out) of something the organization has locked. Otherwise the
// operator's own --allow-sync flag governs, matching the CLI contract
// go-xkms#1306 asks for: "refuse unless an explicit --allow-sync style flag
// was given for that session."
func allowPhoneSyncExport(sessionAllowed bool, policy *xkeyconfig.VerifiedPolicy) bool {
	if policy != nil && policy.State == xkeyconfig.PolicySealedVerified && policy.Policy.LockPhoneSyncPolicy {
		return policy.Policy.PhoneSyncAllowSecretExport
	}
	return sessionAllowed
}

// printUnattestablePairingWarning tells the operator what they now have, in the
// terms the record actually supports.
//
// It is deliberately not softened. The default is to refuse; reaching this
// point means someone chose to pair a device whose hardware claims could not be
// checked, and the one thing they must not take away is that the pairing
// carries a verified device identity. It does not carry any device identity.
func printUnattestablePairingWarning() {
	fmt.Println()
	fmt.Println("  WARNING: paired WITHOUT a verified attestation.")
	fmt.Println()
	fmt.Println("  Policy allows pairing an unattestable device, so this pairing")
	fmt.Println("  completed. Nothing about the device's hardware was verified, so")
	fmt.Println("  the record stores no security level, no boot state and no device")
	fmt.Println("  fingerprint -- there is nothing trustworthy to store.")
	fmt.Println()
	fmt.Println("  This device is NOT known to be a hardware-backed security key.")
	fmt.Println("  Run `xkey device attest-device` to attempt attestation again.")
	fmt.Println()
}

// hostname returns the local hostname, or "unknown" if it cannot be determined.
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
