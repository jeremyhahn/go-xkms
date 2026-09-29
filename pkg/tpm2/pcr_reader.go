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
	"errors"
	"strconv"

	"github.com/google/go-tpm/tpm2"
)

// ErrPCRBankUnavailable is returned when the TPM answers a PCR read with no
// digest, which it does for a bank it has not allocated.
var ErrPCRBankUnavailable = errors.New("tpm: PCR bank not allocated on this TPM")

// PCRReadError reports a PCR a BankPCRReader could not read.
type PCRReadError struct {
	// Bank is the PCR bank the read named.
	Bank string

	// Index is the PCR that could not be read.
	Index int

	// Err is the failure.
	Err error
}

// Error implements the error interface.
func (e *PCRReadError) Error() string {
	return "tpm: reading PCR " + strconv.Itoa(e.Index) + " in bank " + e.Bank + ": " + e.Err.Error()
}

// Unwrap exposes the failure for errors.Is/errors.As.
func (e *PCRReadError) Unwrap() error { return e.Err }

// BankPCRReader reads the current values of PCRs in one bank of a TPM. Its
// ReadPCRs has the shape PCR policies take (pkg/seal/policy.PCRReader), so a
// host with a TPM serves /api/v1/policies/* from it.
type BankPCRReader struct {
	tpm TrustedPlatformModule
}

// NewBankPCRReader returns a BankPCRReader over tpm. It returns
// ErrNotInitialized when tpm is nil.
func NewBankPCRReader(tpm TrustedPlatformModule) (*BankPCRReader, error) {
	if tpm == nil {
		return nil, ErrNotInitialized
	}
	return &BankPCRReader{tpm: tpm}, nil
}

// ReadPCRs returns the current value of each PCR in indices from bank
// ("sha1", "sha256", "sha384" or "sha512", case-insensitive). It reads only
// the named bank. It returns ErrInvalidPCRBankType for an unknown bank,
// ErrInvalidPCRIndex for an index outside 0..23, and a *PCRReadError for a
// PCR the TPM could not read, including one in a bank it has not allocated
// (ErrPCRBankUnavailable).
func (r *BankPCRReader) ReadPCRs(bank string, indices []int) (map[int][]byte, error) {
	algID, err := ParsePCRBankAlgID(bank)
	if err != nil {
		return nil, err
	}
	for _, index := range indices {
		if index < 0 || index > maxPCRIndex {
			return nil, ErrInvalidPCRIndex
		}
	}

	values := make(map[int][]byte, len(indices))
	for _, index := range indices {
		response, err := tpm2.PCRRead{
			PCRSelectionIn: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{{
					Hash:      algID,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(index)),
				}},
			},
		}.Execute(r.tpm.Transport())
		if err != nil {
			return nil, &PCRReadError{Bank: bank, Index: index, Err: err}
		}
		if len(response.PCRValues.Digests) == 0 {
			return nil, &PCRReadError{Bank: bank, Index: index, Err: ErrPCRBankUnavailable}
		}
		values[index] = response.PCRValues.Digests[0].Buffer
	}
	return values, nil
}
