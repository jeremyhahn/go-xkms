// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package store

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// IsRSAPSS returns true if the signature algorithm is RSA-PSS
func IsRSAPSS(sigAlgo x509.SignatureAlgorithm) bool {
	switch sigAlgo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

// IsECDSA returns true if the signature algorithm is ECDSA
func IsECDSA(sigAlgo x509.SignatureAlgorithm) bool {
	switch sigAlgo {
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return true
	default:
		return false
	}
}

// EncodePubKey encodes a public key to DER format
func EncodePubKey(pub crypto.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// DecodePEM decodes a PEM block
func DecodePEM(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return block, nil
}

// DebugKeyAttributes logs key attributes for debugging
func DebugKeyAttributes(logger Logger, attrs *types.KeyAttributes) {
	if !attrs.Debug {
		return
	}
	logger.Debugf("Key Attributes:")
	logger.Debugf("  CN: %s", attrs.CN)
	logger.Debugf("  KeyAlgorithm: %s", attrs.KeyAlgorithm)
	logger.Debugf("  KeyType: %s", attrs.KeyType)
	logger.Debugf("  StoreType: %s", attrs.StoreType)
	logger.Debugf("  Hash: %s", attrs.Hash)
	logger.Debugf("  SignatureAlgorithm: %s", attrs.SignatureAlgorithm)
	logger.Debugf("  PlatformPolicy: %t", attrs.PlatformPolicy)
}

// ParseSignatureAlgorithm converts a string to x509.SignatureAlgorithm
func ParseSignatureAlgorithm(s string) (x509.SignatureAlgorithm, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "SHA256-RSA", "SHA256WITHRSA":
		return x509.SHA256WithRSA, nil
	case "SHA384-RSA", "SHA384WITHRSA":
		return x509.SHA384WithRSA, nil
	case "SHA512-RSA", "SHA512WITHRSA":
		return x509.SHA512WithRSA, nil
	case "SHA256-RSA-PSS", "SHA256-RSAPSS", "SHA256WITHRSAPSS":
		return x509.SHA256WithRSAPSS, nil
	case "SHA384-RSA-PSS", "SHA384-RSAPSS", "SHA384WITHRSAPSS":
		return x509.SHA384WithRSAPSS, nil
	case "SHA512-RSA-PSS", "SHA512-RSAPSS", "SHA512WITHRSAPSS":
		return x509.SHA512WithRSAPSS, nil
	case "ECDSA-SHA256", "ECDSAWITHSHA256":
		return x509.ECDSAWithSHA256, nil
	case "ECDSA-SHA384", "ECDSAWITHSHA384":
		return x509.ECDSAWithSHA384, nil
	case "ECDSA-SHA512", "ECDSAWITHSHA512":
		return x509.ECDSAWithSHA512, nil
	case "ED25519":
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unknown signature algorithm: %s", s)
	}
}

// ParseKeyAlgorithm converts a string to x509.PublicKeyAlgorithm
func ParseKeyAlgorithm(s string) (x509.PublicKeyAlgorithm, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "RSA":
		return x509.RSA, nil
	case "ECDSA":
		return x509.ECDSA, nil
	case "ED25519":
		return x509.Ed25519, nil
	default:
		return x509.UnknownPublicKeyAlgorithm, fmt.Errorf("unknown key algorithm: %s", s)
	}
}

// ParseCurve converts a string to an elliptic.Curve
func ParseCurve(s string) (elliptic.Curve, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "P224", "P-224":
		return elliptic.P224(), nil
	case "P256", "P-256":
		return elliptic.P256(), nil
	case "P384", "P-384":
		return elliptic.P384(), nil
	case "P521", "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unknown curve: %s", s)
	}
}

// AvailableHashes returns a map of available hash functions
func AvailableHashes() map[string]crypto.Hash {
	return map[string]crypto.Hash{
		"SHA-1":   crypto.SHA1,
		"SHA-224": crypto.SHA224,
		"SHA-256": crypto.SHA256,
		"SHA-384": crypto.SHA384,
		"SHA-512": crypto.SHA512,
	}
}

// ECCConfig contains ECC configuration from config files
type ECCConfig struct {
	Curve string
}

// RSAConfig contains RSA configuration from config files
type RSAConfig struct {
	KeySize int
}
