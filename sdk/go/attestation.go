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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// Hardware key-attestation surface re-exported so the xkey GUI/CLI verify
// Android Key Attestation chains through the canonical pkg/attestation packages
// via the SDK. Android identifiers carry an Android prefix where the bare name
// collides in the flat SDK namespace (VerifyOptions is already aliased to the
// CA package, and SecurityLevel to pkg/types).

// AndroidKeyDescription is the parsed Android key-attestation extension.
type AndroidKeyDescription = android.KeyDescription

// AndroidAuthorizationList is the parsed authorization list of an Android
// attestation.
type AndroidAuthorizationList = android.AuthorizationList

// AndroidVerifiedBootState reports the device's verified-boot state.
type AndroidVerifiedBootState = android.VerifiedBootState

// AndroidVerifyOptions configures Android key-attestation verification.
type AndroidVerifyOptions = android.VerifyOptions

// AndroidSecurityLevel indicates where an attested key is held (software,
// TEE, or StrongBox).
type AndroidSecurityLevel = android.SecurityLevel

// AndroidAttestationApplicationID identifies the application (package name
// and signing certificate digests) that requested an attested key.
type AndroidAttestationApplicationID = android.AttestationApplicationID

const (
	// AndroidSecurityLevelSoftware indicates a software-protected key.
	AndroidSecurityLevelSoftware = android.SecurityLevelSoftware
	// AndroidSecurityLevelTrustedEnvironment indicates TEE-protected keys.
	AndroidSecurityLevelTrustedEnvironment = android.SecurityLevelTrustedEnvironment
	// AndroidSecurityLevelStrongBox indicates a StrongBox-protected key.
	AndroidSecurityLevelStrongBox = android.SecurityLevelStrongBox
	// AndroidVerifiedBootVerified means the boot chain is fully verified.
	AndroidVerifiedBootVerified = android.VerifiedBootVerified
	// AndroidVerifiedBootSelfSigned means the boot image is self-signed.
	AndroidVerifiedBootSelfSigned = android.VerifiedBootSelfSigned
	// AndroidVerifiedBootUnverified means the bootloader is unlocked.
	AndroidVerifiedBootUnverified = android.VerifiedBootUnverified
	// AndroidVerifiedBootFailed means boot verification failed.
	AndroidVerifiedBootFailed = android.VerifiedBootFailed
)

// VerifyAndroidKeyAttestation verifies an Android key-attestation certificate
// chain against the given options.
var VerifyAndroidKeyAttestation = android.VerifyKeyAttestation

// ParseAndroidKeyAttestation parses the Android key-attestation extension
// out of a leaf certificate without verifying the certificate chain.
var ParseAndroidKeyAttestation = android.ParseKeyAttestation

// GoogleHardwareAttestationRoots returns the Google hardware-attestation root
// certificates.
var GoogleHardwareAttestationRoots = truststore.GoogleHardwareAttestationRoots
