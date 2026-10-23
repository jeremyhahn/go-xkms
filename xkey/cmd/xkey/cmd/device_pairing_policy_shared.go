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
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
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

// resolveEnterpriseApplicationPolicy resolves the enterprise plane of the
// attested-application allow-list (#1305) for loadPairingAttestationTrust,
// which is called both from a command's own RunE and from deep re-attestation
// call graphs that thread no *cobra.Command through (see
// resolveSOPINFromEnv). Only XKEY_SO_PIN can supply the SO PIN here, never
// --so-pin-stdin, since an unattended reconnect has no operator to answer a
// stdin prompt. unified is the CLI's own loaded config (GetConfig()) rather
// than read again here, so a test can supply a fixture the same way
// resolvePairingPolicy's own unified parameter does.
//
// Unlike resolvePairingPolicy's own resolution -- used for the
// unattestable-pairing WIDEN decision, whose safe fallback is simply the
// ordinary strict pairing path, still fully functional -- an unverified
// sealed section has NO safe fallback here: which allow-list a locked
// deployment intends is unknown until the section verifies, and there is no
// "ordinary strict path" to degrade to when the question is which
// application to trust at all. So a genuinely SEALED config directory that
// does not verify -- no XKEY_SO_PIN, or a PIN that does not match --
// REFUSES outright with attestation.ErrApplicationPolicyUnverifiable, never
// silently falling back to devices.yaml. A user (or attacker) able to write
// devices.yaml but not produce the SO PIN must never be able to bypass a
// deployment that locks the allow-list merely by leaving the PIN unsupplied.
//
// Only a genuinely UNSEALED (personal-mode) config directory falls through
// to the user's own devices.yaml -- there, the policy section IS the user's
// own file, so there is nothing to verify and nothing to bypass.
func resolveEnterpriseApplicationPolicy(unified *xkeyconfig.Config) (*xkeyconfig.PolicySection, error) {
	configDir := xkeyconfig.ConfigDir()
	sealed := xkeyconfig.IsEnterpriseMode(configDir)

	if !sealed {
		// Personal mode: no enterprise plane exists to verify in the first
		// place. unified may even be nil here -- loadPairingAttestationTrust
		// runs from contexts that never went through RootCmd's initConfig (a
		// direct unit test of the trust loader, chiefly) -- and an absent
		// config in an unsealed directory is still no plane to refuse
		// against; devices.yaml governs.
		return nil, nil
	}

	// Sealed from here on: every exit below either verifies or refuses, and
	// none of them falls back to devices.yaml.
	if unified == nil {
		return nil, &SentinelCauseError{
			Sentinel: attestation.ErrApplicationPolicyUnverifiable, Cause: xkeyconfig.ErrConfigInvalid}
	}

	soPIN, err := resolveSOPINFromEnv()
	if err != nil {
		return nil, err
	}

	policy, err := xkeyconfig.LoadVerifiedPolicy(unified, configDir, soPIN)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: attestation.ErrApplicationPolicyUnverifiable, Cause: err}
	}
	return &policy.Policy, nil
}

// loadPairingAttestationTrust builds this machine's Android hardware
// attestation trust material: the trust store's roots and the
// attested-application allow-list, resolved across the user's devices.yaml
// and, in a sealed (enterprise) deployment, the SO's allow-list instead once
// XKEY_SO_PIN verifies it (#1305). A sealed deployment whose section does NOT
// verify refuses outright -- see resolveEnterpriseApplicationPolicy -- so
// pairing and re-attestation never run on an application allow-list this
// machine could not confirm the SO's intent for.
//
// It is the CLI's half of a decision whose other half is shared: WHICH store
// and file to read is per-surface, what to do with them is not. A missing
// devices.yaml allow-lists nothing, so LoadTrust refuses with
// pairing.ErrApplicationPolicyUnconfigured; one that cannot be read refuses
// outright rather than being mistaken for an absent policy.
func loadPairingAttestationTrust() (_ *xkms.AndroidDeviceTrust, err error) {
	devices, err := loadDevicesConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	enterprise, err := resolveEnterpriseApplicationPolicy(GetConfig())
	if err != nil {
		return nil, err
	}
	apps := attestation.ResolveApplicationPolicy(devices.applicationPolicy(), enterprise)

	store, err := openTrustStore()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: attestation.ErrDeviceAttestVerifyFailed, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	return attestation.LoadTrust(store, apps)
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
