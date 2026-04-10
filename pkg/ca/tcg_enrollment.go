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

package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// tpmHolder stores the TPM instance for enrollment operations using atomic
// pointer for lock-free thread safety.
var tpmInstance atomic.Pointer[tpm2.TrustedPlatformModule]

// SetTPM configures the TPM instance for enrollment operations requiring
// MakeCredentialWithExternalEK (server-side credential challenge).
//
// Thread-safe: Yes (atomic store)
func (ca *CA) SetTPM(tpm tpm2.TrustedPlatformModule) {
	tpmInstance.Store(&tpm)
}

// getTPM retrieves the configured TPM instance.
func (ca *CA) getTPM() tpm2.TrustedPlatformModule {
	ptr := tpmInstance.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// EnrollDevice performs complete TCG enrollment per TCG TPM 2.0 Keys for
// Device Identity and Attestation Section 6.2.2.
//
// The enrollment process:
//  1. Unmarshal the packed TCG-CSR-IDEVID
//  2. Parse the EK certificate from the CSR (PEM or DER)
//  3. Call MakeCredentialWithExternalEK to create the credential challenge
//  4. Sign the TCG-CSR-IDEVID to issue IAK and IDevID certificates
//  5. Return all components for the caller to complete the challenge/response
//
// The caller must:
//  1. Send CredentialBlob and EncryptedSecret to the device
//  2. Device calls TPM2_ActivateCredential and returns the decrypted secret
//  3. Caller compares returned secret with PlainSecret
//  4. If secrets match, deliver IAKCertDER and IDevIDCertDER to the device
func (ca *CA) EnrollDevice(packedCSR []byte, request *CertificateRequest) (*TCGEnrollmentResult, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	tpm := ca.getTPM()
	if tpm == nil {
		return nil, ErrTPMNotConfigured
	}

	// Unmarshal the CSR from packed bytes
	tcgCSR, err := tpm2.UnmarshalIDevIDCSR(packedCSR)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCGCSRUnmarshalFailed, err)
	}

	csrContent := &tcgCSR.CsrContents

	// Verify EK certificate exists in the CSR
	if len(csrContent.EkCert) == 0 {
		return nil, ErrTCGMissingEKCert
	}

	// Parse EK certificate - try PEM first, then DER
	var ekCert *x509.Certificate
	block, _ := pem.Decode(csrContent.EkCert)
	if block != nil {
		ekCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: pem: %v", ErrTCGInvalidEKCert, err)
		}
	} else {
		ekCert, err = x509.ParseCertificate(csrContent.EkCert)
		if err != nil {
			return nil, fmt.Errorf("%w: der: %v", ErrTCGInvalidEKCert, err)
		}
	}

	slog.Debug("EnrollDevice: generating MakeCredential challenge",
		slog.Int("ek_cert_size", len(csrContent.EkCert)),
		slog.Int("attest_pub_size", len(csrContent.AttestPub)))

	// Use MakeCredentialWithExternalEK to create the credential challenge.
	// This handles: loading IAK public key onto TPM, computing IAK Name,
	// loading external EK public key from certificate, calling TPM2_MakeCredential.
	credentialBlob, encryptedSecret, secret, err := tpm.MakeCredentialWithExternalEK(
		ekCert,
		csrContent.AttestPub,
		nil, // Let the TPM generate a random secret
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCGMakeCredentialFailed, err)
	}

	slog.Debug("EnrollDevice: MakeCredential succeeded, signing CSR",
		slog.Int("credential_blob_size", len(credentialBlob)),
		slog.Int("encrypted_secret_size", len(encryptedSecret)),
		slog.Int("secret_size", len(secret)))

	// Sign the TCG-CSR-IDEVID to issue IAK and IDevID certificates
	iakDER, idevidDER, err := ca.SignTCGCSRIDevID(tcgCSR, request)
	if err != nil {
		return nil, err
	}

	return &TCGEnrollmentResult{
		IAKCertDER:      iakDER,
		IDevIDCertDER:   idevidDER,
		CredentialBlob:  credentialBlob,
		EncryptedSecret: encryptedSecret,
		PlainSecret:     secret,
	}, nil
}
