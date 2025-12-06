// Package store provides helper functions for key operations
package store

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"

	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Re-export config types
type (
	ECCConfig = store.ECCConfig
	RSAConfig = store.RSAConfig
)

// IsRSAPSS returns true if the signature algorithm is RSA-PSS
func IsRSAPSS(sigAlgo x509.SignatureAlgorithm) bool {
	return store.IsRSAPSS(sigAlgo)
}

// IsECDSA returns true if the signature algorithm is ECDSA
func IsECDSA(sigAlgo x509.SignatureAlgorithm) bool {
	return store.IsECDSA(sigAlgo)
}

// EncodePubKey encodes a public key to DER format
func EncodePubKey(pub crypto.PublicKey) ([]byte, error) {
	return store.EncodePubKey(pub)
}

// DecodePEM decodes a PEM block
func DecodePEM(data []byte) (*pem.Block, error) {
	return store.DecodePEM(data)
}

// DebugKeyAttributes logs key attributes for debugging
func DebugKeyAttributes(logger Logger, attrs *types.KeyAttributes) {
	store.DebugKeyAttributes(logger, attrs)
}

// ParseSignatureAlgorithm converts a string to x509.SignatureAlgorithm
func ParseSignatureAlgorithm(s string) (x509.SignatureAlgorithm, error) {
	return store.ParseSignatureAlgorithm(s)
}

// ParseKeyAlgorithm converts a string to x509.PublicKeyAlgorithm
func ParseKeyAlgorithm(s string) (x509.PublicKeyAlgorithm, error) {
	return store.ParseKeyAlgorithm(s)
}

// ParseCurve converts a string to an elliptic.Curve
func ParseCurve(s string) (elliptic.Curve, error) {
	return store.ParseCurve(s)
}

// AvailableHashes returns a map of available hash functions
func AvailableHashes() map[string]crypto.Hash {
	return store.AvailableHashes()
}
