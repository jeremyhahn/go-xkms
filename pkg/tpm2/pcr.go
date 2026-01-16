package tpm2

import (
	"crypto/sha1" // #nosec G505 -- SHA-1 required for TPM 2.0 specification compatibility
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
)

// IsPlatformPCRExtended checks if the platform PCR (configured in tpm.config.PlatformPCR)
// has been extended from its initial zero state. This is useful for determining
// if platform measurements have already been recorded.
//
// Returns true if the PCR contains non-zero values (already extended),
// false if the PCR is all zeros (initial boot state).
func (tpm *TPM2) IsPlatformPCRExtended() (bool, error) {
	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return false, err
	}

	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      hashAlgID,
					PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
				},
			},
		},
	}
	response, err := pcrRead.Execute(tpm.transport)
	if err != nil {
		return false, err
	}

	// Check if any digests were returned
	if len(response.PCRValues.Digests) == 0 {
		return false, nil
	}

	// Check if the PCR value is all zeros (initial state)
	pcrValue := response.PCRValues.Digests[0].Buffer
	for _, b := range pcrValue {
		if b != 0 {
			return true, nil // PCR has been extended
		}
	}
	return false, nil // PCR is at initial state (all zeros)
}

// ExtendPCR extends a Platform Configuration Register (PCR) with the provided data.
// The data is first hashed using the specified hash algorithm, then the hash is
// extended into the PCR. This operation is irreversible until TPM reset.
//
// Parameters:
//   - pcrIndex: The PCR index to extend (0-23 typically)
//   - hashAlg: The hash algorithm to use ("sha1", "sha256", "sha384", "sha512")
//   - data: The data to hash and extend into the PCR
//
// Returns an error if the PCR extension fails.
func (tpm *TPM2) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("tpm: ExtendPCR: data cannot be nil or empty")
	}

	hashAlgID, err := ParsePCRBankAlgID(hashAlg)
	if err != nil {
		return err
	}

	// Hash the data using the specified algorithm
	var digest []byte
	switch hashAlg {
	case "sha1":
		h := sha1.Sum(data) // #nosec G401 -- SHA-1 required for TPM 2.0 specification compatibility
		digest = h[:]
	case "sha256":
		h := sha256.Sum256(data)
		digest = h[:]
	case "sha384":
		h := sha512.Sum384(data)
		digest = h[:]
	case "sha512":
		h := sha512.Sum512(data)
		digest = h[:]
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", hashAlg)
	}

	tpm.logger.Debug("tpm: ExtendPCR - extending PCR",
		slog.Int("pcrIndex", pcrIndex),
		slog.String("hashAlg", hashAlg),
		slog.Int("dataSize", len(data)))

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcrIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: hashAlgID,
					Digest:  digest,
				},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("tpm: ExtendPCR failed", slog.String("error", err.Error()))
		return err
	}

	return nil
}
