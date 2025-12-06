// Package tpm2 provides TPM 2.0 functionality through go-keychain.
// This file re-exports commonly needed types from google/go-tpm/tpm2
// to allow consumers to use go-keychain without directly importing google's library.
package tpm2

import (
	"github.com/google/go-tpm/tpm2"
)

// Type re-exports from google/go-tpm/tpm2
// These allow consumers to use go-keychain without importing google's library directly

// TPMHandle represents a TPM handle
type TPMHandle = tpm2.TPMHandle

// TPMTPublic is the TPM public area structure
type TPMTPublic = tpm2.TPMTPublic

// TPM2BPublic is a sized TPM public structure
type TPM2BPublic = tpm2.TPM2BPublic

// TPM2BPrivate is a sized TPM private structure
type TPM2BPrivate = tpm2.TPM2BPrivate

// TPM2BDigest is a sized digest structure
type TPM2BDigest = tpm2.TPM2BDigest

// TPM2BName is a sized name structure
type TPM2BName = tpm2.TPM2BName

// TPMAlgID is a TPM algorithm identifier
type TPMAlgID = tpm2.TPMAlgID

// TPMIAlgHash is a TPM hash algorithm
type TPMIAlgHash = tpm2.TPMIAlgHash

// TPMIRHHierarchy is a hierarchy identifier
type TPMIRHHierarchy = tpm2.TPMIRHHierarchy

// TPMRC is a TPM return code
type TPMRC = tpm2.TPMRC

// CreateResponse is the response from TPM2_Create
type CreateResponse = tpm2.CreateResponse

// Algorithm constants
const (
	TPMAlgKeyedHash = tpm2.TPMAlgKeyedHash
	TPMAlgRSA       = tpm2.TPMAlgRSA
	TPMAlgECC       = tpm2.TPMAlgECC
	TPMAlgSHA1      = tpm2.TPMAlgSHA1
	TPMAlgSHA256    = tpm2.TPMAlgSHA256
	TPMAlgSHA384    = tpm2.TPMAlgSHA384
	TPMAlgSHA512    = tpm2.TPMAlgSHA512
	TPMAlgNull      = tpm2.TPMAlgNull
)

// Handle type constants
const (
	TPMHTTransient  = tpm2.TPMHTTransient
	TPMHTPersistent = tpm2.TPMHTPersistent
)

// Hierarchy constants
const (
	TPMRHOwner       = tpm2.TPMRHOwner
	TPMRHEndorsement = tpm2.TPMRHEndorsement
	TPMRHPlatform    = tpm2.TPMRHPlatform
	TPMRHNull        = tpm2.TPMRHNull
)

// SRK/EK Templates
var (
	// RSASRKTemplate is the RSA Storage Root Key template
	RSASRKTemplate = tpm2.RSASRKTemplate

	// ECCSRKTemplate is the ECC Storage Root Key template
	ECCSRKTemplate = tpm2.ECCSRKTemplate

	// RSAEKTemplate is the RSA Endorsement Key template
	RSAEKTemplate = tpm2.RSAEKTemplate

	// ECCEKTemplate is the ECC Endorsement Key template
	ECCEKTemplate = tpm2.ECCEKTemplate
)

// PolicyGetDigest is the TPM2_PolicyGetDigest command
type PolicyGetDigest = tpm2.PolicyGetDigest

// PolicyGetDigestResponse is the response from TPM2_PolicyGetDigest
type PolicyGetDigestResponse = tpm2.PolicyGetDigestResponse

// TPMAObject represents TPM object attributes
type TPMAObject = tpm2.TPMAObject

// UnmarshalPublic deserializes a TPMTPublic structure
func UnmarshalPublic(data []byte) (*tpm2.TPMTPublic, error) {
	return tpm2.Unmarshal[tpm2.TPMTPublic](data)
}

// MarshalPublic serializes a TPMTPublic structure
func MarshalPublic(pub *tpm2.TPMTPublic) []byte {
	return tpm2.Marshal(*pub)
}
