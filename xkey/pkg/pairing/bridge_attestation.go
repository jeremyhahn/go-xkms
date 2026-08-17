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

package pairing

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"strings"

	gotpm2 "github.com/google/go-tpm/tpm2"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// TCG/IDevID enrollment defaults and limits.
const (
	// BackendTPM2 is the backend name assumed when a remote.* attestation
	// request does not name one explicitly.
	BackendTPM2 = "tpm2"

	// DefaultPCRBank is the PCR hash bank assumed when a quote request does
	// not name one.
	DefaultPCRBank = "sha256"

	// maxPCRIndex is the highest PCR index addressable on a PC Client TPM.
	maxPCRIndex = 23
)

// TPMEnroller is the narrow slice of TPM 2.0 functionality the bridge needs to
// answer a phone that is acting as the Certificate Authority for TCG-CSR-IDEVID
// device enrollment. It covers CSR production, credential activation, quoting,
// the attestation key's public area, and provisioning of the CA-issued
// certificates.
//
// *github.com/jeremyhahn/go-xkms/sdk/go.TPM2 satisfies this interface; the
// interface exists so the bridge handlers stay testable without a TPM or a
// simulator. It is deliberately not the full TrustedPlatformModule surface.
type TPMEnroller interface {
	// EKCertificate returns the manufacturer Endorsement Key certificate.
	// The CA uses it to establish that the TPM is genuine.
	EKCertificate() (*x509.Certificate, error)

	// IAKAttributes returns the Initial Attestation Key attributes, including
	// its TPM2B_PUBLIC public area and PCR hash algorithm.
	IAKAttributes() (*xkms.KeyAttributes, error)

	// IDevIDAttributes returns the Initial Device Identity Key attributes.
	IDevIDAttributes() (*xkms.KeyAttributes, error)

	// CreateTCG_CSR_IDEVID builds a TCG-CSR-IDEVID enrollment package binding
	// the IDevID key to the IAK and the IAK to the EK.
	CreateTCG_CSR_IDEVID(
		ekCert *x509.Certificate,
		akAttrs *xkms.KeyAttributes,
		idevidAttrs *xkms.KeyAttributes) (xkms.TCG_CSR_IDEVID, error)

	// ActivateCredential runs TPM2_ActivateCredential over a challenge the CA
	// produced with TPM2_MakeCredential, returning the recovered secret.
	ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error)

	// Quote produces a TPM2 quote over the named PCRs, bound to nonce and
	// signed by the IAK.
	Quote(pcrs []uint, nonce []byte) (xkms.Quote, error)

	// FixedProperties returns the TPM's fixed capability properties, used here
	// for the manufacturer identifier reported to the CA.
	FixedProperties() (*xkms.PropertiesFixed, error)

	// ProvisionIAKCert stores the CA-issued IAK certificate.
	ProvisionIAKCert(cert *x509.Certificate) error

	// ProvisionIDevIDCert stores the CA-issued IDevID certificate.
	ProvisionIDevIDCert(cert *x509.Certificate) error
}

// Compile-time proof that the concrete TPM satisfies the narrow interface.
var _ TPMEnroller = (*xkms.TPM2)(nil)

// enroller returns the configured TPM, or ErrTPMNotConfigured when this host
// has no TPM wired into the bridge.
func (b *Bridge) enroller() (TPMEnroller, error) {
	if b.tpm == nil {
		// A host that HAS a TPM we could not open is a fault an operator can
		// fix — most often permissions on the device node. Reporting it as
		// "no TPM configured" sends the phone to the wrong conclusion, so the
		// open failure is carried here and reported distinctly.
		if b.tpmOpenErr != nil {
			return nil, &SentinelCauseError{Sentinel: ErrTPMUnavailable, Cause: b.tpmOpenErr}
		}
		return nil, ErrTPMNotConfigured
	}
	return b.tpm, nil
}

// tpmError wraps a TPM failure so that callers match both ErrTPMOperationFailed
// and the underlying cause, while the cause still reaches the phone in the
// JSON-RPC error message.
func tpmError(cause error) error {
	return &SentinelCauseError{Sentinel: ErrTPMOperationFailed, Cause: cause}
}

// logTPM records an enrollment operation to the audit log when one is configured.
func (b *Bridge) logTPM(op audit.OperationType, method string, success bool, err error) {
	if b.auditLogger == nil {
		return
	}
	b.auditLogger.LogTPMOperation(op, success, err, map[string]any{
		"method":     method,
		"deviceId":   b.config.DeviceID,
		"deviceName": b.config.DeviceName,
	})
}

// handleGetTCGCSRIDevID handles remote.getTCGCSRIDevID - the phone, acting as
// the CA, asks this host to produce its TCG-CSR-IDEVID enrollment package.
//
// The returned CSR is the packed TCG structure defined in TCG "TPM 2.0 Keys for
// Device Identity and Attestation" section 13.1. It carries the EK certificate,
// the IAK public area with its creation ticket and certification, and the IDevID
// public area certified by the IAK.
func (b *Bridge) handleGetTCGCSRIDevID(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteGetTCGCSRIDevIDParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	backend := p.Backend
	if backend == "" {
		backend = BackendTPM2
	}
	if err := b.checkBackendAccess(backend); err != nil {
		return nil, err
	}

	tpm, err := b.enroller()
	if err != nil {
		return nil, err
	}

	result, err := buildTCGCSRIDevID(tpm)
	if err != nil {
		b.logger.Error("TCG-CSR-IDEVID generation failed", "backend", backend, "error", err)
		b.logTPM(audit.OpDeviceAttested, MethodRemoteGetTCGCSRIDevID, false, err)
		return nil, err
	}

	b.logger.Info("TCG-CSR-IDEVID generated",
		"backend", backend,
		"csrLen", len(result.CSR),
		"platformModel", result.PlatformModel)
	b.logTPM(audit.OpDeviceAttested, MethodRemoteGetTCGCSRIDevID, true, nil)

	return result, nil
}

// buildTCGCSRIDevID assembles the enrollment package from the TPM.
func buildTCGCSRIDevID(tpm TPMEnroller) (*RemoteGetTCGCSRIDevIDResult, error) {
	ekCert, err := tpm.EKCertificate()
	if err != nil {
		return nil, tpmError(err)
	}
	if ekCert == nil {
		return nil, tpmError(ErrEKCertificateMissing)
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return nil, tpmError(err)
	}
	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return nil, tpmError(err)
	}

	iakPublic, err := publicArea(iakAttrs)
	if err != nil {
		return nil, err
	}
	idevidPublic, err := publicArea(idevidAttrs)
	if err != nil {
		return nil, err
	}

	csr, err := tpm.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, idevidAttrs)
	if err != nil {
		return nil, tpmError(err)
	}

	packed, err := xkms.PackIDevIDCSR(&csr)
	if err != nil {
		return nil, tpmError(err)
	}

	// The TPM's fixed properties supply the manufacturer identifier. Model and
	// serial come from the CSR itself, which already resolves them from the
	// platform configuration with SMBIOS fallback.
	props, err := tpm.FixedProperties()
	if err != nil {
		return nil, tpmError(err)
	}

	var manufacturer string
	if props != nil {
		manufacturer = props.Manufacturer
	}

	return &RemoteGetTCGCSRIDevIDResult{
		CSR:                  packed,
		EKCert:               ekCert.Raw,
		IAKPublicKey:         iakPublic,
		IDevIDPublicKey:      idevidPublic,
		PlatformManufacturer: manufacturer,
		PlatformModel:        string(csr.CsrContents.ProdModel),
		PlatformSerial:       string(csr.CsrContents.ProdSerial),
	}, nil
}

// publicArea returns the key's TPM2B_PUBLIC bytes, matching the encoding the
// TCG-CSR-IDEVID uses for AttestPub and SigningPub.
func publicArea(attrs *xkms.KeyAttributes) ([]byte, error) {
	if attrs == nil || attrs.TPMAttributes == nil {
		return nil, tpmError(ErrTPMKeyNotProvisioned)
	}
	pub := attrs.TPMAttributes.BPublic.Bytes()
	if len(pub) == 0 {
		return nil, tpmError(ErrTPMKeyNotProvisioned)
	}
	return pub, nil
}

// handleActivateCredential handles remote.activateCredential - the phone, as
// the CA, sends a TPM2_MakeCredential challenge and this host proves EK
// possession by decrypting it with TPM2_ActivateCredential.
func (b *Bridge) handleActivateCredential(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteActivateCredentialParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	backend := p.Backend
	if backend == "" {
		backend = BackendTPM2
	}
	if err := b.checkBackendAccess(backend); err != nil {
		return nil, err
	}

	tpm, err := b.enroller()
	if err != nil {
		return nil, err
	}

	if len(p.CredentialBlob) == 0 || len(p.EncryptedSecret) == 0 {
		return nil, ErrBridgeInvalidParams
	}

	secret, err := tpm.ActivateCredential(p.CredentialBlob, p.EncryptedSecret)
	if err != nil {
		b.logger.Error("credential activation failed", "backend", backend, "error", err)
		b.logTPM(audit.OpDeviceAttested, MethodRemoteActivateCredential, false, err)
		return nil, tpmError(err)
	}

	b.logger.Info("credential activated",
		"backend", backend,
		"secretLen", len(secret))
	b.logTPM(audit.OpDeviceAttested, MethodRemoteActivateCredential, true, nil)

	return &RemoteActivateCredentialResult{DecryptedSecret: secret}, nil
}

// handleGetAttestationQuote handles remote.getAttestationQuote - the phone, as
// the CA, requests a TPM2 quote over platform PCRs signed by the IAK.
//
// The quote is always taken in the IAK's own PCR bank; requesting a different
// bank would yield PCR values that do not hash to the digest inside the signed
// TPMS_ATTEST, so a mismatch is rejected rather than silently answered.
func (b *Bridge) handleGetAttestationQuote(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteGetAttestationQuoteParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	backend := p.Backend
	if backend == "" {
		backend = BackendTPM2
	}
	if err := b.checkBackendAccess(backend); err != nil {
		return nil, err
	}

	tpm, err := b.enroller()
	if err != nil {
		return nil, err
	}

	pcrs, err := pcrSelection(p.PCRIndices)
	if err != nil {
		return nil, err
	}
	if len(p.Nonce) == 0 {
		return nil, ErrBridgeInvalidParams
	}

	requested := strings.ToLower(p.PCRBank)
	if requested == "" {
		requested = DefaultPCRBank
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return nil, tpmError(err)
	}
	if iakAttrs == nil || iakAttrs.TPMAttributes == nil {
		return nil, tpmError(ErrTPMKeyNotProvisioned)
	}
	signingBank, err := pcrBankName(iakAttrs.TPMAttributes.HashAlg)
	if err != nil {
		return nil, err
	}
	if requested != signingBank {
		b.logger.Warn("attestation quote PCR bank mismatch",
			"requested", requested,
			"attestationKeyBank", signingBank)
		return nil, ErrUnsupportedAlgorithm
	}

	quote, err := tpm.Quote(pcrs, p.Nonce)
	if err != nil {
		b.logger.Error("attestation quote failed", "backend", backend, "error", err)
		b.logTPM(audit.OpDeviceAttested, MethodRemoteGetAttestationQuote, false, err)
		return nil, tpmError(err)
	}

	values, err := pcrValues(quote.PCRs, signingBank)
	if err != nil {
		b.logTPM(audit.OpDeviceAttested, MethodRemoteGetAttestationQuote, false, err)
		return nil, err
	}

	b.logger.Info("attestation quote generated",
		"backend", backend,
		"pcrBank", signingBank,
		"pcrCount", len(values))
	b.logTPM(audit.OpDeviceAttested, MethodRemoteGetAttestationQuote, true, nil)

	return &RemoteGetAttestationQuoteResult{
		Quoted:    quote.Quoted,
		Signature: quote.Signature,
		PCRValues: values,
		PCRBank:   signingBank,
		Nonce:     p.Nonce,
	}, nil
}

// handleStoreEnrollmentCerts handles remote.storeEnrollmentCerts - the phone,
// having signed the IDevID, hands the issued certificates back for storage.
//
// The IAK and IDevID certificates are provisioned into the TPM (NVRAM or the
// configured certificate store, per platform configuration). Any supplied
// intermediate chain is validated as parseable X.509 but is not persisted by
// the TPM, which stores only the two leaf certificates.
func (b *Bridge) handleStoreEnrollmentCerts(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteStoreEnrollmentCertsParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	backend := p.Backend
	if backend == "" {
		backend = BackendTPM2
	}
	if err := b.checkBackendAccess(backend); err != nil {
		return nil, err
	}

	tpm, err := b.enroller()
	if err != nil {
		return nil, err
	}

	if len(p.IAKCert) == 0 || len(p.IDevIDCert) == 0 {
		return nil, ErrBridgeInvalidParams
	}

	iakCert, err := x509.ParseCertificate(p.IAKCert)
	if err != nil {
		b.logger.Error("IAK certificate parse failed", "error", err)
		return nil, ErrInvalidCertificate
	}
	idevidCert, err := x509.ParseCertificate(p.IDevIDCert)
	if err != nil {
		b.logger.Error("IDevID certificate parse failed", "error", err)
		return nil, ErrInvalidCertificate
	}
	for _, der := range p.Chain {
		if _, err := x509.ParseCertificate(der); err != nil {
			b.logger.Error("enrollment chain certificate parse failed", "error", err)
			return nil, ErrInvalidCertificate
		}
	}

	if err := tpm.ProvisionIAKCert(iakCert); err != nil {
		b.logger.Error("IAK certificate provisioning failed", "error", err)
		b.logTPM(audit.OpTPMProvisioned, MethodRemoteStoreEnrollmentCerts, false, err)
		return nil, tpmError(err)
	}
	if err := tpm.ProvisionIDevIDCert(idevidCert); err != nil {
		b.logger.Error("IDevID certificate provisioning failed", "error", err)
		b.logTPM(audit.OpTPMProvisioned, MethodRemoteStoreEnrollmentCerts, false, err)
		return nil, tpmError(err)
	}

	b.logger.Info("enrollment certificates stored",
		"backend", backend,
		"chainLen", len(p.Chain))
	b.logTPM(audit.OpTPMProvisioned, MethodRemoteStoreEnrollmentCerts, true, nil)

	return &RemoteStoreEnrollmentCertsResult{
		Stored:                true,
		IAKCertFingerprint:    certFingerprint(iakCert),
		IDevIDCertFingerprint: certFingerprint(idevidCert),
	}, nil
}

// certFingerprint returns the hex-encoded SHA-256 digest of a certificate's DER
// encoding.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// pcrSelection validates the requested PCR indices and converts them for the
// TPM quote call.
func pcrSelection(indices []int) ([]uint, error) {
	if len(indices) == 0 {
		return nil, ErrBridgeInvalidParams
	}
	pcrs := make([]uint, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx > maxPCRIndex {
			return nil, ErrBridgeInvalidParams
		}
		pcrs = append(pcrs, uint(idx))
	}
	return pcrs, nil
}

// pcrBankName maps a TPM hash algorithm to the lowercase PCR bank name used on
// the wire.
func pcrBankName(alg gotpm2.TPMIAlgHash) (string, error) {
	switch alg {
	case gotpm2.TPMAlgSHA1:
		return "sha1", nil
	case gotpm2.TPMAlgSHA256:
		return "sha256", nil
	case gotpm2.TPMAlgSHA384:
		return "sha384", nil
	case gotpm2.TPMAlgSHA512:
		return "sha512", nil
	default:
		return "", ErrUnsupportedAlgorithm
	}
}

// pcrValues decodes the gob-encoded PCR banks carried on a Quote and returns the
// values of the named bank keyed by PCR index.
func pcrValues(encoded []byte, bank string) (map[int][]byte, error) {
	banks, err := xkms.DecodePCRs(encoded)
	if err != nil {
		return nil, tpmError(err)
	}
	for _, candidate := range banks {
		if !strings.EqualFold(candidate.Algorithm, bank) {
			continue
		}
		values := make(map[int][]byte, len(candidate.PCRs))
		for _, pcr := range candidate.PCRs {
			values[int(pcr.ID)] = pcr.Value
		}
		return values, nil
	}
	return nil, tpmError(ErrPCRBankUnavailable)
}
