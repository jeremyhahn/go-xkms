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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// defaultAttestationGracePeriod is the default grace period for device attestation.
	defaultAttestationGracePeriod = 5 * time.Minute
)

// DeviceAttestationResult contains the result of device attestation verification.
type DeviceAttestationResult struct {
	AttestationTime   time.Time
	SecurityLevel     string
	BootStateVerified bool
	BootHashHex       string
	DeviceFingerprint string
}

// isDeviceAttestationRequired returns true if device attestation is needed
// based on the device's last attestation time and the configured grace period.
func isDeviceAttestationRequired(device *PairedDevice, policy *AttestationPolicy) bool {
	if device.LastDeviceAttestationTime.IsZero() {
		return true // Never attested
	}
	gracePeriod := time.Duration(device.AttestationGracePeriod)
	if gracePeriod == 0 && policy != nil {
		gracePeriod = time.Duration(policy.DefaultGracePeriod)
	}
	if gracePeriod == 0 {
		gracePeriod = defaultAttestationGracePeriod
	}
	return time.Since(device.LastDeviceAttestationTime) > gracePeriod
}

// recordDeviceAttestation updates device after successful attestation.
func recordDeviceAttestation(device *PairedDevice, result *DeviceAttestationResult) {
	device.LastDeviceAttestationTime = result.AttestationTime
	device.SecurityLevel = result.SecurityLevel
	device.BootStateVerified = result.BootStateVerified
	device.DeviceBootHashHex = result.BootHashHex
	device.DeviceFingerprint = result.DeviceFingerprint
}

// validateBootHashMatch checks if boot hash changed (detects tampering).
func validateBootHashMatch(device *PairedDevice, freshHash string) error {
	if device.DeviceBootHashHex == "" {
		return nil // First attestation
	}
	if device.DeviceBootHashHex != freshHash {
		return ErrBootHashMismatch
	}
	return nil
}

// validateSecurityLevel checks if the security level meets minimum requirements.
func validateSecurityLevel(level string, policy *AttestationPolicy) error {
	if policy == nil || policy.MinSecurityLevel == "" {
		return nil // No minimum requirement
	}
	levelOrder := map[string]int{
		"software":  0,
		"tee":       1,
		"strongbox": 2,
	}
	actualLevel, ok := levelOrder[level]
	if !ok {
		return fmt.Errorf("%w: unknown level %s", ErrSecurityLevelInsufficient, level)
	}
	minLevel, ok := levelOrder[policy.MinSecurityLevel]
	if !ok {
		return nil // Invalid policy, skip check
	}
	if actualLevel < minLevel {
		return fmt.Errorf("%w: got %s, require %s", ErrSecurityLevelInsufficient, level, policy.MinSecurityLevel)
	}
	return nil
}

// calculateDeviceFingerprint computes a fingerprint from the attestation root certificate.
func calculateDeviceFingerprint(rootCertDER []byte) string {
	hash := sha256.Sum256(rootCertDER)
	return hex.EncodeToString(hash[:])
}

// formatBootState returns a human-readable boot state description.
func formatBootState(bootState int) string {
	switch bootState {
	case 0:
		return "VERIFIED"
	case 1:
		return "SELF_SIGNED"
	case 2:
		return "UNVERIFIED"
	case 3:
		return "FAILED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", bootState)
	}
}

// formatAttestationDuration returns a human-readable duration string for attestation display.
func formatAttestationDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

// timeRemaining returns the time remaining before attestation is required.
// Returns 0 if attestation is already required.
func timeRemaining(device *PairedDevice, policy *AttestationPolicy) time.Duration {
	if device.LastDeviceAttestationTime.IsZero() {
		return 0
	}
	gracePeriod := time.Duration(device.AttestationGracePeriod)
	if gracePeriod == 0 && policy != nil {
		gracePeriod = time.Duration(policy.DefaultGracePeriod)
	}
	if gracePeriod == 0 {
		gracePeriod = defaultAttestationGracePeriod
	}
	elapsed := time.Since(device.LastDeviceAttestationTime)
	if elapsed >= gracePeriod {
		return 0
	}
	return gracePeriod - elapsed
}
