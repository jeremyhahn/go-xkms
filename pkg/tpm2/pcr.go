package tpm2

import (
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
)

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
		return &errs.Message{Msg: "tpm: ExtendPCR: data cannot be nil or empty"}
	}

	hashAlgID, err := ParsePCRBankAlgID(hashAlg)
	if err != nil {
		return err
	}

	// Hash the data using the specified algorithm
	hasher, err := GetHashFunction(hashAlg)
	if err != nil {
		return err
	}
	hasher.Write(data)
	digest := hasher.Sum(nil)

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
