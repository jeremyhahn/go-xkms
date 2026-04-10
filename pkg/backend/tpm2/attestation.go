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

package tpm2

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// AttestKey generates an attestation statement proving a key was created in
// the TPM and is resident within the hardware boundary. It uses the IAK
// (Initial Attestation Key) to sign a TPM2_Certify structure over the
// target key.
//
// Per TCG TPM 2.0 Part 3 - Commands, Section 18.2 (TPM2_Certify):
// The certification proves that the object with a specific Name is loaded
// in the TPM, signed by the IAK.
//
// The returned interface{} is an *attestation.AttestationStatement.
func (b *Backend) AttestKey(attrs *types.KeyAttributes, nonce []byte) (interface{}, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set parent to SRK if not specified
	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	// Set store type
	attrs.StoreType = types.StoreTPM2

	// Perform TPM2_Certify via the low-level TPM interface
	result, err := b.tpm.CertifyKey(attrs, nonce, b.keyBackend)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationFailed, err)
	}

	// Build certificate chain: [IAK cert, EK cert]
	var certChain []*x509.Certificate

	iakCert, err := b.tpm.IAKCertificate()
	if err != nil {
		b.logger.Debug("IAK certificate not available, attestation will lack certificate chain",
			"error", err.Error())
	} else {
		certChain = append(certChain, iakCert)
	}

	ekCert, err := b.tpm.EKCertificate()
	if err != nil {
		b.logger.Debug("EK certificate not available",
			"error", err.Error())
	} else {
		certChain = append(certChain, ekCert)
	}

	// Determine the attesting key algorithm from the IAK public key
	var attestingKeyAlgo x509.PublicKeyAlgorithm
	switch result.AttestingKeyPublic.(type) {
	case interface{ N() interface{} }:
		attestingKeyAlgo = x509.RSA
	default:
		// Determine from the signature algorithm
		attestingKeyAlgo = sigAlgoToKeyAlgo(result.SignatureAlgorithm)
	}

	return &attestation.AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: attestingKeyAlgo,
		AttestingKeyPublic:    result.AttestingKeyPublic,
		Signature:             result.Signature,
		SignatureAlgorithm:    result.SignatureAlgorithm,
		CertificateChain:      certChain,
		AttestedKeyPublic:     result.AttestedKeyPublic,
		AttestationData:       result.CertifyInfo,
		CreatedAt:             time.Now().UTC().Format(time.RFC3339),
		Backend:               "tpm2",
		Nonce:                 result.Nonce,
	}, nil
}

// sigAlgoToKeyAlgo maps an x509.SignatureAlgorithm to its corresponding
// x509.PublicKeyAlgorithm.
func sigAlgoToKeyAlgo(sigAlgo x509.SignatureAlgorithm) x509.PublicKeyAlgorithm {
	switch sigAlgo {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return x509.RSA
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return x509.ECDSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}
