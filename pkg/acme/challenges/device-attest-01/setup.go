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

package deviceattest01

import (
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// The device side of the "tpm" format
//
// The evidence a server verifies (tpm.go) is a TPM2_Certify of the key the
// certificate will be issued for, made by the device's attestation key. So the
// device answers a challenge by certifying that key -- which must already be
// in its TPM -- over TPMExtraData(alg, key authorization), and later signs its
// CSR with the same key, which is what BindCSRKey compares pubArea against.
//
// The attestation key is the TPM's IAK, whose certificate the device holds
// from enrollment (enroll-01 issues it beside the IDevID). There is no second,
// ad hoc attestation key: a verifier trusts x5c[0] because a CA certified it
// as this TPM's restricted attestation key, and the IAK is the key that
// certificate names.

var (
	// ErrAttestationKeyUnavailable is returned when the device's attestation
	// key, or the certificate that vouches for it, cannot be read. Without
	// both there is nothing a verifier could anchor the certification to.
	ErrAttestationKeyUnavailable = errors.New("device-attest-01: the device attestation key or its certificate is unavailable")

	// ErrNoCertificateKey is returned when Setup is asked to attest without a
	// key: the certification is of the key the certificate is issued for, and
	// there is no statement to make without one.
	ErrNoCertificateKey = errors.New("device-attest-01: no certificate key to attest")

	// ErrCertifyFailed is returned when the TPM refuses to certify the
	// certificate key with the attestation key.
	ErrCertifyFailed = errors.New("device-attest-01: TPM2_Certify of the certificate key failed")
)

// TrustedPlatformModule is the TPM a device answers a "tpm" challenge with:
// the holder of the certificate key and of the IAK that certifies it.
//
// It is the subset of pkg/tpm2.TrustedPlatformModule this format uses, so any
// go-xkms TPM satisfies it as it stands.
type TrustedPlatformModule interface {
	// IAKAttributes returns the Initial Attestation Key, whose signature
	// algorithm is the statement's alg.
	IAKAttributes() (*types.KeyAttributes, error)

	// IAKCertificate returns the IAK certificate, x5c[0] of the statement.
	IAKCertificate() (*x509.Certificate, error)

	// CertifyKey performs TPM2_Certify of keyAttrs by the IAK over nonce,
	// loading keyAttrs from backend if it is not resident.
	CertifyKey(keyAttrs *types.KeyAttributes, nonce []byte, backend store.KeyBackend) (*tpm2.CertifyResult, error)
}

var _ TrustedPlatformModule = (tpm2.TrustedPlatformModule)(nil)

// coseAlgorithms maps the signature algorithms a go-xkms IAK signs with to
// the COSE identifiers a "tpm" statement's alg carries. An IAK is a
// restricted TPM signing key, so only ECDSA, RSASSA-PKCS1-v1_5 and RSASSA-PSS
// with SHA-2 appear.
var coseAlgorithms = map[x509.SignatureAlgorithm]webauthncose.COSEAlgorithmIdentifier{
	x509.ECDSAWithSHA256:  webauthncose.AlgES256,
	x509.ECDSAWithSHA384:  webauthncose.AlgES384,
	x509.ECDSAWithSHA512:  webauthncose.AlgES512,
	x509.SHA256WithRSA:    webauthncose.AlgRS256,
	x509.SHA384WithRSA:    webauthncose.AlgRS384,
	x509.SHA512WithRSA:    webauthncose.AlgRS512,
	x509.SHA256WithRSAPSS: webauthncose.AlgPS256,
	x509.SHA384WithRSAPSS: webauthncose.AlgPS384,
	x509.SHA512WithRSAPSS: webauthncose.AlgPS512,
}

// Setup answers a device-attest-01 challenge with a "tpm" attestation
// statement for key, the TPM-resident key the certificate is to be issued for.
//
// The IAK certifies key with TPM2_Certify over TPMExtraData(alg, keyAuth),
// where alg is the IAK's signature algorithm. The statement carries:
//
//   - ver "2.0" and that alg;
//   - x5c: the IAK certificate;
//   - sig: the IAK's signature over certInfo (ASN.1 DER for ECDSA, the raw
//     value for RSA, as WebAuthn Level 2 section 6.5.6 encodes each);
//   - certInfo: the TPMS_ATTEST the TPM produced;
//   - pubArea: key's TPMT_PUBLIC.
//
// backend holds key's blobs; CertifyKey loads key from it under key.Parent,
// which for a go-xkms key is the Platform SRK. The CSR at finalization must be
// signed by key, or BindCSRKey refuses it.
//
// The result is the JSON challenge response a server fetches: an
// AttestationRequest whose attStmt is the CBOR attestation object.
func Setup(keyAuth string, tpm TrustedPlatformModule, key *types.KeyAttributes, backend store.KeyBackend) ([]byte, error) {
	if tpm == nil {
		return nil, &errs.Detail{Err: ErrAttestationKeyUnavailable, Detail: "no TPM"}
	}
	if key == nil {
		return nil, ErrNoCertificateKey
	}

	iak, err := tpm.IAKAttributes()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestationKeyUnavailable, Cause: err}
	}
	alg, supported := coseAlgorithms[iak.SignatureAlgorithm]
	if !supported {
		return nil, &errs.Detail{
			Err:    ErrInvalidKeyAlgorithm,
			Detail: "the IAK signs with " + iak.SignatureAlgorithm.String() + ", which has no COSE identifier",
		}
	}
	aikCertificate, err := tpm.IAKCertificate()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestationKeyUnavailable, Cause: err}
	}

	extraData, err := TPMExtraData(int64(alg), keyAuth)
	if err != nil {
		return nil, err
	}
	certification, err := tpm.CertifyKey(key, extraData, backend)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrCertifyFailed, Cause: err}
	}

	object := &AttestationObject{
		Format: FormatTPM.String(),
		AttStatement: AttestationStatement{
			Ver:      tpmStatementVersion,
			Alg:      int64(alg),
			X5c:      []interface{}{aikCertificate.Raw},
			Sig:      certification.Signature,
			CertInfo: certification.CertifyInfo,
			PubArea:  certification.AttestedKeyPublicArea,
		},
	}
	encoded, err := cbor.Marshal(object)
	if err != nil {
		return nil, err
	}
	return json.Marshal(AttestationRequest{AttStmt: encoded})
}
