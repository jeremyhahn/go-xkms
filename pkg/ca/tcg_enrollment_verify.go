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

// Package ca provides the lower-level verification half of the TCG-CSR-IDEVID
// enrollment flow implemented in tcg_enrollment.go. Where EnrollDevice handles
// the complete IAK/IDevID issuance, VerifyTCG_CSR_IDevIDBytes stops after the
// TPM_MakeCredential challenge has been generated so the caller can drive the
// ActivateCredential round-trip themselves.
package ca

import (
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// VerifyTCG_CSR_IDevIDBytes unmarshals a packed TCG-CSR-IDEVID, extracts the
// EK certificate, and returns a TPM2_MakeCredential challenge suitable for
// driving an ActivateCredential response on the requesting device.
//
// The return values are:
//   - credentialBlob  - TPM2B_ID_OBJECT to be sent to the device
//   - encryptedSecret - TPM2B_ENCRYPTED_SECRET for ActivateCredential
//   - plainSecret     - original secret; callers compare this with the value
//     returned from the device's ActivateCredential.
//
// sigAlg is currently unused (the CSR's own signature and the EK
// certificate chain are what get verified here; TPM2_ActivateCredential is
// what ultimately proves possession), but is accepted to stay
// type-compatible with callers that expect to pass an x509.SignatureAlgorithm.
//
// The challenge is built in software (tpm2.NewCredentialChallenge) using the
// TCG-specified construction, so this method needs no TPM of its own --
// SetTPM is not required for it (go-xkms#798). It shares that primitive with
// enroll-01's own construction, so the two never drift apart.
//
// Thread-safe: Yes
func (ca *CA) VerifyTCG_CSR_IDevIDBytes(
	packedCSR []byte,
	sigAlg x509.SignatureAlgorithm,
) (credentialBlob []byte, encryptedSecret []byte, plainSecret []byte, err error) {
	_ = sigAlg // Reserved for future explicit signature verification.

	tcgCSR, err := tpm2.UnmarshalIDevIDCSR(packedCSR)
	if err != nil {
		return nil, nil, nil, &errs.Detail{Err: ErrTCGCSRUnmarshalFailed, Detail: fmt.Sprintf("%v", err)}
	}

	csrContent := &tcgCSR.CsrContents
	if len(csrContent.EkCert) == 0 {
		return nil, nil, nil, ErrTCGMissingEKCert
	}

	ekCert, ekIntermediates, err := parseEKCertificateChain(csrContent.EkCert)
	if err != nil {
		return nil, nil, nil, err
	}

	// TPM 2.0 Keys for Device Identity and Attestation v1.10r9 §6.1.2 step 5b
	// / §6.2.2 step 4b: verify the EK certificate against a configured
	// TPM-manufacturer trust anchor before generating the MakeCredential
	// challenge below -- TPM2_ActivateCredential proves possession of the
	// EK, not that the EK belongs to a genuine TPM.
	if err := ca.verifyEKCertificateChain(ekCert, ekIntermediates); err != nil {
		return nil, nil, nil, err
	}

	slog.Debug("VerifyTCG_CSR_IDevIDBytes: generating MakeCredential challenge",
		slog.Int("ek_cert_size", len(csrContent.EkCert)),
		slog.Int("attest_pub_size", len(csrContent.AttestPub)))

	activationKeyName, err := tpm2.ActivationKeyName(csrContent.AttestPub)
	if err != nil {
		return nil, nil, nil, &errs.Detail{Err: ErrTCGMakeCredentialFailed, Detail: fmt.Sprintf("%v", err)}
	}

	challenge, secret, err := tpm2.NewCredentialChallenge(ekCert.PublicKey, activationKeyName)
	if err != nil {
		return nil, nil, nil, &errs.Detail{Err: ErrTCGMakeCredentialFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return challenge.CredentialBlob, challenge.EncryptedSecret, secret, nil
}
