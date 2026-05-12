// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import "crypto/x509"

// COSEAlgorithm represents a COSE algorithm identifier as defined in RFC 8152
type COSEAlgorithm int

// COSE Algorithm constants as defined in RFC 8152
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
const (
	COSEAlgorithmUnknown COSEAlgorithm = 0

	// ECDSA algorithms
	COSEAlgorithmES256 COSEAlgorithm = -7  // ECDSA w/ SHA-256
	COSEAlgorithmES384 COSEAlgorithm = -35 // ECDSA w/ SHA-384
	COSEAlgorithmES512 COSEAlgorithm = -36 // ECDSA w/ SHA-512

	// EdDSA algorithm
	COSEAlgorithmEdDSA COSEAlgorithm = -8 // EdDSA

	// RSA PKCS#1 v1.5 algorithms
	COSEAlgorithmRS256 COSEAlgorithm = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256
	COSEAlgorithmRS384 COSEAlgorithm = -258 // RSASSA-PKCS1-v1_5 w/ SHA-384
	COSEAlgorithmRS512 COSEAlgorithm = -259 // RSASSA-PKCS1-v1_5 w/ SHA-512

	// RSA PSS algorithms
	COSEAlgorithmPS256 COSEAlgorithm = -37 // RSASSA-PSS w/ SHA-256
	COSEAlgorithmPS384 COSEAlgorithm = -38 // RSASSA-PSS w/ SHA-384
	COSEAlgorithmPS512 COSEAlgorithm = -39 // RSASSA-PSS w/ SHA-512
)

// COSEAlgorithmFromSignatureAlgorithm converts an x509.SignatureAlgorithm to a COSEAlgorithm
func COSEAlgorithmFromSignatureAlgorithm(sigAlgo x509.SignatureAlgorithm) COSEAlgorithm {
	switch sigAlgo {
	case x509.ECDSAWithSHA256:
		return COSEAlgorithmES256
	case x509.ECDSAWithSHA384:
		return COSEAlgorithmES384
	case x509.ECDSAWithSHA512:
		return COSEAlgorithmES512
	case x509.SHA256WithRSA:
		return COSEAlgorithmRS256
	case x509.SHA384WithRSA:
		return COSEAlgorithmRS384
	case x509.SHA512WithRSA:
		return COSEAlgorithmRS512
	case x509.SHA256WithRSAPSS:
		return COSEAlgorithmPS256
	case x509.SHA384WithRSAPSS:
		return COSEAlgorithmPS384
	case x509.SHA512WithRSAPSS:
		return COSEAlgorithmPS512
	case x509.PureEd25519:
		return COSEAlgorithmEdDSA
	default:
		return COSEAlgorithmUnknown
	}
}
