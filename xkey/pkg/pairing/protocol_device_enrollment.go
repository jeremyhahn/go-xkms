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

package pairing

// Android-native device enrollment: this host is the CA, the phone is the
// enrollee. These are local.* methods, so the laptop sends them to the phone.
//
// # Why this exists alongside the TCG family
//
// The TCG-CSR-IDEVID methods in protocol_attestation.go are specified in TPM2
// primitives -- an endorsement key, TPMT_PUBLIC attestation keys, a credential
// activation that only a TPM can complete. An Android phone has none of them
// and never will, so it answers that family with ErrorCodeNotApplicable.
//
// The security property the TCG ceremony buys is "the private key is in
// hardware on the machine that is asking, and it can prove that right now".
// Android proves the same thing by different means, and in one artifact:
// key attestation. A TPM needs credential activation because an EK certificate
// alone does not show the attestation key shares its TPM; Android's attestation
// extension covers the whole chain of custody at once, and adds something a TPM
// quote cannot express -- which application is asking.
//
// # What the CA must verify
//
// Receiving LocalGetDeviceEnrollmentRequestResult, a CA must:
//
//  1. Build a path from the attestation chain to a Google hardware root. This
//     is what makes the key hardware-backed rather than merely claimed.
//  2. Check the challenge in the leaf's attestation extension equals the nonce
//     it sent. This is what makes the evidence fresh rather than a replay.
//  3. Check RootOfTrust: verified boot state and bootloader lock.
//  4. Check attestationApplicationId against its allow-list of package names
//     and signing certificate digests. The TEE writes this field, not the app,
//     so it is the only part of the evidence the application cannot influence.
//  5. Confirm the CSR's public key is the key the leaf attests. Without this a
//     caller could pair someone else's attestation with its own CSR.
//
// Step 5 is the one that is easy to leave out and fatal to omit.
const (
	// MethodLocalGetDeviceEnrollmentRequest asks the phone for a CSR plus the
	// key attestation evidence backing it. Parameters carry the CA's nonce.
	MethodLocalGetDeviceEnrollmentRequest = "local.getDeviceEnrollmentRequest"

	// MethodLocalStoreDeviceCredential hands the phone the certificate the CA
	// issued for that request.
	MethodLocalStoreDeviceCredential = "local.storeDeviceCredential"
)

// AttestationFormatAndroidKey tags evidence as an Android key attestation
// chain. It is on the wire so a verifier rejects what it does not understand
// rather than guessing at the bytes.
const AttestationFormatAndroidKey = "android-key-attestation"

// Attestation security levels reported by the phone. Advisory: the
// authoritative value is in the attestation extension the CA parses itself.
const (
	SecurityLevelSoftware  = "software"
	SecurityLevelTEE       = "trusted_environment"
	SecurityLevelStrongBox = "strongbox"
)

// LocalGetDeviceEnrollmentRequestParams contains parameters for
// local.getDeviceEnrollmentRequest.
type LocalGetDeviceEnrollmentRequestParams struct {
	// Nonce is the CA's challenge, base64. The TEE embeds it in the
	// attestation extension at key generation, which is what binds the
	// evidence to this exchange.
	//
	// It must be freshly random per enrollment. Reusing one lets a phone
	// replay an attestation it produced while in a state the CA would now
	// reject.
	Nonce string `json:"nonce"`

	// Subject is the distinguished name the CA suggests for the certificate.
	// Optional, and advisory: the CA names the subject on what it issues.
	Subject string `json:"subject,omitempty"`
}

// LocalGetDeviceEnrollmentRequestResult contains the result of
// local.getDeviceEnrollmentRequest.
type LocalGetDeviceEnrollmentRequestResult struct {
	// Format is always AttestationFormatAndroidKey.
	Format string `json:"format"`

	// CSR is a PKCS#10 certification request, DER-encoded.
	CSR []byte `json:"csr"`

	// AttestationChain is the key attestation chain, leaf first, each
	// certificate DER-encoded and base64'd. The leaf certifies the CSR's key.
	AttestationChain []string `json:"attestationChain"`

	// SecurityLevel is where the phone believes the key lives. Advisory only;
	// verify the chain rather than trusting this.
	SecurityLevel string `json:"securityLevel"`

	// PlatformModel identifies the device model, for operators.
	PlatformModel string `json:"platformModel,omitempty"`

	// PlatformSerial is the device serial, when it discloses one.
	PlatformSerial string `json:"platformSerial,omitempty"`
}

// LocalStoreDeviceCredentialParams contains parameters for
// local.storeDeviceCredential.
type LocalStoreDeviceCredentialParams struct {
	// Certificate is the issued certificate, DER-encoded and base64'd.
	Certificate string `json:"certificate"`

	// Chain holds the issuer certificates, base64 DER, ordered issuer-first up
	// to the root, so the phone can present a complete path later.
	Chain []string `json:"chain,omitempty"`
}

// LocalStoreDeviceCredentialResult contains the result of
// local.storeDeviceCredential.
type LocalStoreDeviceCredentialResult struct {
	// Stored reports whether the phone accepted and persisted the credential.
	Stored bool `json:"stored"`

	// Fingerprint is the SHA-256 of the stored certificate, hex.
	Fingerprint string `json:"fingerprint"`

	// NotAfter is the expiry in epoch milliseconds. This is the
	// re-attestation deadline: when the credential lapses the device must
	// present fresh evidence to obtain another, which is how the issuing
	// authority states how often it wants proof.
	NotAfter int64 `json:"notAfter"`
}
