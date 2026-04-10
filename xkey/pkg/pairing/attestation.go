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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// AttestationMode specifies the attestation method.
type AttestationMode string

const (
	// AttestationModeAuto automatically selects TPM2 if available, otherwise software.
	AttestationModeAuto AttestationMode = "auto"
	// AttestationModeTPM2 requires TPM2 attestation.
	AttestationModeTPM2 AttestationMode = "tpm2"
	// AttestationModeSoftware uses software-only attestation.
	AttestationModeSoftware AttestationMode = "software"
)

// Attestation nonce size constant.
const attestationNonceSize = 32

// Default PCRs to include in TPM2 quote.
var defaultAttestationPCRs = []uint{0, 1, 7}

// Attestation errors.
var (
	// ErrTPM2NotAvailable indicates TPM2 is not available on this system.
	ErrTPM2NotAvailable = errors.New("pairing: TPM2 not available")

	// ErrTPM2Required indicates TPM2 attestation was required but not available.
	ErrTPM2Required = errors.New("pairing: TPM2 attestation required but not available")

	// ErrInvalidAttestationNonce indicates the attestation nonce is invalid.
	ErrInvalidAttestationNonce = errors.New("pairing: invalid attestation nonce")

	// ErrAttestationGenerationFailed indicates attestation generation failed.
	ErrAttestationGenerationFailed = errors.New("pairing: attestation generation failed")
)

// LaptopAttestor generates attestation for the laptop/desktop.
type LaptopAttestor interface {
	// GenerateAttestation creates an attestation response with the given nonce.
	GenerateAttestation(nonce []byte) (*RemoteAttestDeviceResult, error)
	// Mode returns the current attestation mode.
	Mode() AttestationMode
	// IsTPM2Available returns true if TPM2 is available.
	IsTPM2Available() bool
}

// LaptopAttestorConfig configures the laptop attestor.
type LaptopAttestorConfig struct {
	Mode   AttestationMode
	TPM    tpm2.TrustedPlatformModule // nil if TPM2 not available
	Logger *slog.Logger
	// PCRs to include in TPM2 quote (default: 0, 1, 7)
	PCRs []uint
}

// laptopAttestor implements LaptopAttestor.
type laptopAttestor struct {
	cfg *LaptopAttestorConfig
	log *slog.Logger
}

// NewLaptopAttestor creates a new laptop attestor.
func NewLaptopAttestor(cfg *LaptopAttestorConfig) (LaptopAttestor, error) {
	if cfg == nil {
		cfg = &LaptopAttestorConfig{
			Mode: AttestationModeAuto,
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if len(cfg.PCRs) == 0 {
		cfg.PCRs = defaultAttestationPCRs
	}

	return &laptopAttestor{
		cfg: cfg,
		log: logger.With("component", "laptop_attestor"),
	}, nil
}

// Mode returns the configured attestation mode.
func (a *laptopAttestor) Mode() AttestationMode {
	return a.cfg.Mode
}

// IsTPM2Available returns true if TPM2 is available and configured.
func (a *laptopAttestor) IsTPM2Available() bool {
	return a.cfg.TPM != nil
}

// GenerateAttestation creates an attestation response with the given nonce.
func (a *laptopAttestor) GenerateAttestation(nonce []byte) (*RemoteAttestDeviceResult, error) {
	if len(nonce) != attestationNonceSize {
		return nil, ErrInvalidAttestationNonce
	}

	// Determine which attestation method to use
	useTPM2 := false
	switch a.cfg.Mode {
	case AttestationModeTPM2:
		if !a.IsTPM2Available() {
			return nil, ErrTPM2Required
		}
		useTPM2 = true
	case AttestationModeAuto:
		useTPM2 = a.IsTPM2Available()
	case AttestationModeSoftware:
		useTPM2 = false
	default:
		// Default to auto mode behavior
		useTPM2 = a.IsTPM2Available()
	}

	if useTPM2 {
		return a.generateTPM2Attestation(nonce)
	}
	return a.generateSoftwareAttestation(nonce)
}

// generateTPM2Attestation generates attestation using TPM2.
func (a *laptopAttestor) generateTPM2Attestation(nonce []byte) (*RemoteAttestDeviceResult, error) {
	a.log.Info("generating TPM2 attestation", slog.Int("nonce_len", len(nonce)))

	tpmDevice := a.cfg.TPM

	// Generate TPM2 Quote with the provided nonce
	quote, err := tpmDevice.Quote(a.cfg.PCRs, nonce)
	if err != nil {
		a.log.Error("TPM2 quote failed", slog.String("error", err.Error()))
		return nil, ErrAttestationGenerationFailed
	}

	// Get certificates
	var certChain [][]byte

	// Try to get IAK certificate
	iakCert, err := tpmDevice.IAKCertificate()
	if err == nil && iakCert != nil {
		certChain = append(certChain, iakCert.Raw)
	}

	// Try to get EK certificate
	ekCert, err := tpmDevice.EKCertificate()
	if err == nil && ekCert != nil {
		certChain = append(certChain, ekCert.Raw)
	}

	// Decode PCR values from the quote
	pcrBanks, err := tpm2.DecodePCRs(quote.PCRs)
	if err != nil {
		a.log.Warn("failed to decode PCRs from quote", slog.String("error", err.Error()))
		// Continue without PCR values - they're optional for the response
	}

	// Convert PCR values to map, preferring SHA256 bank
	pcrMap := make(map[int][]byte)
	for _, bank := range pcrBanks {
		if bank.Algorithm == "SHA256" {
			for _, pcr := range bank.PCRs {
				pcrMap[int(pcr.ID)] = pcr.Value
			}
			break
		}
	}

	// If no SHA256 bank found, use first available bank
	if len(pcrMap) == 0 && len(pcrBanks) > 0 {
		for _, pcr := range pcrBanks[0].PCRs {
			pcrMap[int(pcr.ID)] = pcr.Value
		}
	}

	// Compute boot hash from PCR values
	bootHash := computeBootHash(pcrMap)

	// Get firmware version from TPM fixed properties if available
	firmwareVersion := ""
	props, err := tpmDevice.FixedProperties()
	if err == nil && props != nil {
		// Construct firmware version from major.minor
		firmwareVersion = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
	}

	result := &RemoteAttestDeviceResult{
		Format:            "tpm2",
		SecurityLevel:     "hardware",
		Nonce:             nonce,
		CertificateChain:  certChain,
		PlatformPCRs:      pcrMap,
		QuoteData:         quote.Quoted,
		QuoteSignature:    quote.Signature,
		FirmwareVersion:   firmwareVersion,
		BootHashHex:       bootHash,
		BootStateVerified: true, // TPM2 quote implies verified boot chain
	}

	a.log.Info("TPM2 attestation generated",
		slog.Int("cert_count", len(certChain)),
		slog.Int("pcr_count", len(pcrMap)),
		slog.String("firmware_version", firmwareVersion),
	)

	return result, nil
}

// generateSoftwareAttestation generates software-only attestation.
func (a *laptopAttestor) generateSoftwareAttestation(nonce []byte) (*RemoteAttestDeviceResult, error) {
	a.log.Info("generating software attestation", slog.Int("nonce_len", len(nonce)))

	result := &RemoteAttestDeviceResult{
		Format:            "software",
		SecurityLevel:     "software",
		Nonce:             nonce,
		CertificateChain:  nil, // No certificates for software attestation
		PlatformPCRs:      nil,
		QuoteData:         nil,
		QuoteSignature:    nil,
		FirmwareVersion:   "",
		BootHashHex:       "",
		BootStateVerified: false,
	}

	return result, nil
}

// computeBootHash computes a combined hash of PCR values.
func computeBootHash(pcrs map[int][]byte) string {
	if len(pcrs) == 0 {
		return ""
	}

	h := sha256.New()
	// Hash PCRs in order (0-23)
	for i := 0; i <= 23; i++ {
		if val, ok := pcrs[i]; ok {
			h.Write(val)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ParseAttestationMode parses a string into an AttestationMode.
func ParseAttestationMode(s string) AttestationMode {
	switch s {
	case "tpm2":
		return AttestationModeTPM2
	case "software":
		return AttestationModeSoftware
	case "auto", "":
		return AttestationModeAuto
	default:
		return AttestationModeAuto
	}
}
