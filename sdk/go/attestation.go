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
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
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

// AndroidRootOfTrust is the Android Verified Boot claim carried inside an
// attestation extension: the boot key, whether the bootloader is locked, the
// verified-boot state and the boot hash.
//
// It is exported because a caller cannot enforce a boot-state POLICY without
// it. AndroidVerifyOptions.VerifyBootState is "if a RootOfTrust is present, it
// must say verified", so an extension carrying none passes verification while
// claiming nothing -- and deciding whether that is acceptable is the
// consumer's call, made against this type. xkey's pairing path is the first
// such consumer (go-xkms#95).
type AndroidRootOfTrust = android.RootOfTrust

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

// AndroidAttestationPackageInfo is one package entry (name and version code)
// inside an AndroidAttestationApplicationID.
type AndroidAttestationPackageInfo = android.AttestationPackageInfo

// AndroidAttestationExtensionOptions carries the AuthorizationList claims a
// fixture can assert beyond RootOfTrust: the teeEnforced Origin and Purpose
// (go-xkms#132) and the softwareEnforced attestationApplicationId
// (go-xkms#1305). It exists on the SDK surface for the same
// reason BuildAndroidAttestationExtension does: a consumer that cannot build
// a synthetic attestation extension can only test its verifier against
// fixtures borrowed from elsewhere, or reach past sdk/go into
// pkg/attestation/android, which the architecture gate rightly refuses.
type AndroidAttestationExtensionOptions = android.AttestationExtensionOptions

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

	// AndroidOriginGenerated means the attested key was generated inside the
	// enforcement domain that authorized it and never existed elsewhere.
	AndroidOriginGenerated = android.OriginGenerated
	// AndroidOriginDerived means the key was derived inside the enforcement
	// domain from other key material.
	AndroidOriginDerived = android.OriginDerived
	// AndroidOriginImported means the key material entered the enforcement
	// domain from outside it, and may exist elsewhere too.
	AndroidOriginImported = android.OriginImported
	// AndroidOriginUnknown is reported for keys that predate the origin tag,
	// and is what a parsed AuthorizationList reports when it carries no
	// origin claim at all -- never AndroidOriginGenerated by coincidence of
	// the zero value.
	AndroidOriginUnknown = android.OriginUnknown

	// AndroidPurposeEncrypt authorizes the key for encryption.
	AndroidPurposeEncrypt = android.PurposeEncrypt
	// AndroidPurposeDecrypt authorizes the key for decryption.
	AndroidPurposeDecrypt = android.PurposeDecrypt
	// AndroidPurposeSign authorizes the key to produce signatures.
	AndroidPurposeSign = android.PurposeSign
	// AndroidPurposeVerify authorizes the key to verify signatures.
	AndroidPurposeVerify = android.PurposeVerify
	// AndroidPurposeDeriveKey authorizes the key for key derivation.
	AndroidPurposeDeriveKey = android.PurposeDeriveKey
	// AndroidPurposeWrapKey authorizes the key to wrap other keys.
	AndroidPurposeWrapKey = android.PurposeWrapKey
	// AndroidPurposeAgreeKey authorizes the key for key agreement.
	AndroidPurposeAgreeKey = android.PurposeAgreeKey
	// AndroidPurposeAttestKey authorizes the key to attest other keys.
	AndroidPurposeAttestKey = android.PurposeAttestKey
)

// VerifyAndroidKeyAttestation verifies an Android key-attestation certificate
// chain against the given options.
var VerifyAndroidKeyAttestation = android.VerifyKeyAttestation

// ParseAndroidKeyAttestation parses the Android key-attestation extension
// out of a leaf certificate without verifying the certificate chain.
var ParseAndroidKeyAttestation = android.ParseKeyAttestation

// AndroidKeyAttestationOID is the object identifier of the Android
// key-attestation certificate extension.
var AndroidKeyAttestationOID = android.AndroidKeyAttestationOID

// BuildAndroidAttestationExtension builds a KeyDescription extension whose
// teeEnforced AuthorizationList carries a RootOfTrust.
//
// It exists to let consumers construct SYNTHETIC attestation certificates for
// testing. That is why it is on the SDK surface at all: xkey re-implements the
// attestation decision against this extension, and a consumer that cannot
// build one can only test its verifier against fixtures it borrowed from
// somewhere — or reach past sdk/go into pkg/attestation/android, which the
// architecture gate rightly refuses.
//
// A nil rot reproduces the minimal builder's shape: a chain that verifies and
// carries a challenge while claiming nothing about boot state. That case
// exists to be REFUSED by a caller that requires the claim, so it has to be
// constructible on purpose.
var BuildAndroidAttestationExtension = android.BuildAttestationExtension

// BuildAndroidAttestationExtensionWithOptions builds a KeyDescription
// extension whose teeEnforced AuthorizationList carries RootOfTrust, Origin,
// and Purpose (go-xkms#132). It is BuildAndroidAttestationExtension's
// sibling for a fixture that also needs to assert an Origin or Purpose
// claim; that function's signature is additive-only, so this is how a
// consumer reaches the wider fixture without reaching past sdk/go.
var BuildAndroidAttestationExtensionWithOptions = android.BuildAttestationExtensionWithOptions

// GoogleHardwareAttestationRoots returns the Google hardware-attestation root
// certificates.
var GoogleHardwareAttestationRoots = truststore.GoogleHardwareAttestationRoots

// PIV slot-attestation surface. A PIV attestation certificate carries vendor
// extensions describing the device a key lives on and the policy governing its
// use; xkms produced that material (AttestPIV) without being able to read it
// back, so a consumer could establish only that a chain anchored — never that
// touch was required, or which device it came from.
//
// PIV identifiers carry a PIV prefix where the bare name would collide in the
// flat SDK namespace.

// PIVAttestation is what a PIV slot-attestation certificate says about the
// device and the key's policy.
//
// Every field is a pointer and nil means NOT USABLE, which is two situations a
// policy has to tell apart: the extension was absent, or it was present and
// did not decode. PIVAttestation.Unparseable lists the second group.
type PIVAttestation = pivcert.Attestation

// PIVFirmwareVersion is a device firmware version, with AtLeast for a caller
// enforcing a firmware floor.
type PIVFirmwareVersion = pivcert.FirmwareVersion

// PIVPINPolicy is how often the PIN must be presented to use a slot key.
type PIVPINPolicy = pivcert.PINPolicy

// PIVTouchPolicy is whether the device requires a physical touch to use a
// slot key — the claim a "touch must be required" policy is written against.
type PIVTouchPolicy = pivcert.TouchPolicy

// PIVFormFactor is the device's physical shape, with FIPS reporting the
// FIPS-model flag.
type PIVFormFactor = pivcert.FormFactor

// PIVAttestationVerifyOptions configures VerifyPIVAttestation. TrustedRoots is
// supplied by the caller: which vendor root a deployment trusts is its
// decision, and this SDK ships none.
type PIVAttestationVerifyOptions = pivcert.AttestationVerifyOptions

// PIV PIN policy values.
const (
	PIVPINPolicyNever  = pivcert.PINPolicyNever
	PIVPINPolicyOnce   = pivcert.PINPolicyOnce
	PIVPINPolicyAlways = pivcert.PINPolicyAlways
)

// PIV touch policy values.
const (
	PIVTouchPolicyNever  = pivcert.TouchPolicyNever
	PIVTouchPolicyAlways = pivcert.TouchPolicyAlways
	PIVTouchPolicyCached = pivcert.TouchPolicyCached
)

// PIV form factor values, without the FIPS bit. Compare against
// PIVFormFactor.Base and read PIVFormFactor.FIPS for the flag.
const (
	PIVFormFactorUSBAKeychain = pivcert.FormFactorUSBAKeychain
	PIVFormFactorUSBANano     = pivcert.FormFactorUSBANano
	PIVFormFactorUSBCKeychain = pivcert.FormFactorUSBCKeychain
	PIVFormFactorUSBCNano     = pivcert.FormFactorUSBCNano
	PIVFormFactorLightning    = pivcert.FormFactorLightning
)

// ParsePIVAttestation reads the attestation extensions from a PIV slot
// attestation certificate WITHOUT verifying its chain.
//
// Parsing and trusting are separate so a caller can inspect evidence it has
// not decided to trust. A deployment with no vendor root configured can use
// this — and PIVAttestation.HasAttestationExtensions — as the presence check
// it already performs, rather than being forced to choose between a full
// verdict and none.
var ParsePIVAttestation = pivcert.ParseAttestation

// VerifyPIVAttestation checks that a PIV slot attestation chains to a root the
// caller trusts, and returns what the leaf says about the device.
//
// The chain is leaf-first: the slot attestation certificate, then the device
// attestation certificate (slot f9). A nil error means the CHAIN verified, not
// that any policy is satisfied — a trusted chain may carry no readable claim
// at all, and the returned PIVAttestation is what says so.
var VerifyPIVAttestation = pivcert.VerifyAttestation

// BuildPIVAttestationExtensions builds the extensions ParsePIVAttestation
// reads, so a consumer can construct SYNTHETIC attestation certificates for
// testing without reaching past sdk/go into pkg/pivcert.
//
// It is an encoder for the same documented layout the parser implements, so
// the two agreeing proves they are consistent — never that either matches a
// physical device. See the scope note on pkg/pivcert's attestation parsing.
var BuildPIVAttestationExtensions = pivcert.BuildAttestationExtensions

// PIV attestation extension object identifiers, under Yubico's
// 1.3.6.1.4.1.41482.3 arc.
var (
	// OIDPIVFirmwareVersion carries the device firmware version.
	OIDPIVFirmwareVersion = pivcert.OIDFirmwareVersion

	// OIDPIVSerialNumber carries the device serial number.
	OIDPIVSerialNumber = pivcert.OIDSerialNumber

	// OIDPIVPINTouchPolicy carries the PIN policy and the touch policy.
	OIDPIVPINTouchPolicy = pivcert.OIDPINTouchPolicy

	// OIDPIVFormFactor carries the device form factor.
	OIDPIVFormFactor = pivcert.OIDFormFactor
)
