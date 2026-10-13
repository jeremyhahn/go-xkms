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

package entities

// DeviceAttestation is what a validated device-attest-01 or enroll-01
// challenge established about the device that answered it: the attested key and the
// device identity the evidence carried, kept so finalization -- one request,
// and one storage round trip, later -- can bind the certificate request to
// them (go-xkms#789, go-xkms#828).
//
// It is stored on the ACMEChallenge that produced it (see
// ACMEChallenge.DeviceAttestation), not in a side store: the challenge is
// already the record of how the authorization was validated, and this is
// what device-attest-01 validation specifically established. Nil until a
// device-attest-01 challenge has validated successfully.
type DeviceAttestation struct {
	// Format is the attestation format the evidence was verified under:
	// "tpm" or "dice" for device-attest-01, or "enroll-01" for the credential
	// activation record of an enroll-01 challenge (go-xkms#1391), in which
	// DeviceIdentityValue is the TCG permanent identifier of the activated
	// endorsement key certificate, LeafDER that certificate, and PubArea the
	// activation key (the IAK) the credential was bound to.
	Format string `yaml:"format" json:"format"`

	// DeviceIdentityType is the ACME identifier type the DeviceIdentityValue
	// was checked against (always "permanent-identifier" today -- see
	// pkg/acme/challenges/device-attest-01/identity.go).
	DeviceIdentityType string `yaml:"device-identity-type" json:"device_identity_type"`

	// DeviceIdentityValue is the device identity read from the attestation
	// evidence: the RFC 4043 permanentIdentifier otherName in the AIK
	// certificate for "tpm", or the hex-encoded TCG DICE Ueid for "dice".
	// It equals the order's authorized permanent-identifier -- that equality
	// is what let the authorization become valid.
	DeviceIdentityValue string `yaml:"device-identity-value" json:"device_identity_value"`

	// KeyAuthorization is the ACME key authorization the evidence answered.
	KeyAuthorization string `yaml:"key-authorization" json:"key_authorization"`

	// LeafDER is the certificate whose evidence was verified, DER-encoded:
	// the AIK certificate (x5c[0]) for "tpm", the alias certificate for
	// "dice". Carried as bytes because this record has to outlive the
	// request that produced it.
	LeafDER []byte `yaml:"leaf-der" json:"leaf_der"`

	// Algorithm, CertInfo, Signature and PubArea are the "tpm" format's
	// TPM2_Certify statement -- the COSE signature algorithm, the
	// TPMS_ATTEST, the AIK's signature over it, and the TPMT_PUBLIC of the
	// attested key -- carried as the device sent them so finalization can
	// re-verify the certification against the certificate request's key.
	// Zero/nil for "dice", which has no certification structure.
	Algorithm int64  `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
	CertInfo  []byte `yaml:"cert-info,omitempty" json:"cert_info,omitempty"`
	Signature []byte `yaml:"signature,omitempty" json:"signature,omitempty"`
	PubArea   []byte `yaml:"pub-area,omitempty" json:"pub_area,omitempty"`

	// AttestedSPKI is, for "dice", the DER SubjectPublicKeyInfo of the key
	// the device's provisioning record vouched for when the challenge was
	// validated (go-xkms#1441). Only the registry-anchored verifier sets it,
	// never the payload; finalization requires the certificate request's key
	// to equal it and refuses a "dice" record without one. Nil for "tpm".
	AttestedSPKI []byte `yaml:"attested-spki,omitempty" json:"attested_spki,omitempty"`
}
