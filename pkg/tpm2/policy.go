package tpm2

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Policy digest computation errors.
var (
	ErrPolicyInvalidDigest = errors.New("tpm: invalid PCR digest hex value")
	ErrPolicyEmptyPCRs     = errors.New("tpm: no PCR indices provided")
)

// PCRDigestSize returns the hash digest size in bytes for the given PCR bank.
func PCRDigestSize(bank string) int {
	switch bank {
	case PCRBankSHA1:
		return sha1.Size
	case PCRBankSHA256:
		return sha256.Size
	case PCRBankSHA384:
		return sha512.Size384
	case PCRBankSHA512:
		return sha512.Size
	default:
		return sha256.Size
	}
}

// pcrBankTPMAlgID maps a PCR bank name to the TPM2 algorithm ID used in
// TPML_PCR_SELECTION wire encoding.
var pcrBankTPMAlgID = map[string]uint16{
	PCRBankSHA1:   0x0004, // TPM_ALG_SHA1
	PCRBankSHA256: 0x000B, // TPM_ALG_SHA256
	PCRBankSHA384: 0x000C, // TPM_ALG_SHA384
	PCRBankSHA512: 0x000D, // TPM_ALG_SHA512
}

// EncodePCRSelection encodes a TPML_PCR_SELECTION structure for the given
// bank and PCR indices, matching the TPM 2.0 wire format used by tpm2-tools.
//
// Wire format (big-endian):
//
//	TPML_PCR_SELECTION {
//	  count      uint32  = 1
//	  TPMS_PCR_SELECTION {
//	    hash          uint16  = algorithm ID
//	    sizeofSelect  uint8   = 3
//	    pcrSelect     [3]byte = bitmap of PCR 0-23
//	  }
//	}
func EncodePCRSelection(bank string, indices []int) []byte {
	algID, ok := pcrBankTPMAlgID[bank]
	if !ok {
		algID = pcrBankTPMAlgID[PCRBankSHA256]
	}

	// Build bitmap: 3 bytes covers PCR 0-23.
	var bitmap [3]byte
	for _, idx := range indices {
		if idx >= 0 && idx < 24 {
			bitmap[idx/8] |= 1 << (idx % 8)
		}
	}

	return []byte{
		// count = 1 (uint32 big-endian)
		0, 0, 0, 1,
		// algorithm ID (uint16 big-endian)
		byte(algID >> 8), byte(algID),
		// sizeofSelect, always three octets for the 24 PCRs
		3,
		// PCR bitmap
		bitmap[0], bitmap[1], bitmap[2],
	}
}

// ComputePolicyPCRDigest computes a TPM2 PolicyPCR digest from the given
// bank, PCR indices, and PCR digest values. The result is the same binary
// format produced by tpm2_createpolicy / tpm2_policypcr -L policy.bin.
//
// Algorithm:
//  1. Concatenate PCR digests in ascending index order (zero-fill missing)
//  2. Hash the concatenation to form pcrDigestHash
//  3. policyDigest = H(zeros || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || pcrDigestHash)
//
// The returned slice length matches the hash size of the given bank.
func ComputePolicyPCRDigest(bank string, pcrIndices []int, pcrDigests map[string]string) ([]byte, error) {
	pcrDigestHash, err := PCRCompositeDigest(bank, pcrIndices, pcrDigests)
	if err != nil {
		return nil, err
	}

	policyHash, err := pcrBankHash(bank)
	if err != nil {
		return nil, err
	}

	// Step 3: Compute the policy digest.
	pcrSelect := EncodePCRSelection(bank, sortedPCRIndices(pcrIndices))
	oldDigest := make([]byte, len(pcrDigestHash)) // Initial empty policy digest (zeros).

	policyHash.Write(oldDigest)
	// TPM_CC_PolicyPCR = 0x0000017F (big-endian).
	policyHash.Write([]byte{0x00, 0x00, 0x01, 0x7F})
	policyHash.Write(pcrSelect)
	policyHash.Write(pcrDigestHash)

	return policyHash.Sum(nil), nil
}

// PCRCompositeDigest computes the pcrDigest operand of TPM2_PolicyPCR (TCG
// TPM 2.0 Part 3, section 23.7): the bank's hash over the selected PCR values
// concatenated in ascending index order. pcrDigests maps "<bank>:<index>" to
// the hex PCR value; a missing value is zero-filled, as tpm2-tools does, which
// can only make a later TPM2_PolicyPCR fail, never pass.
//
// Steps 1 and 2 of ComputePolicyPCRDigest are this function; it exists on its
// own for callers that hand the operand to a live TPM2_PolicyPCR or to an
// approved-policy trial digest rather than wanting the finished policy digest.
func PCRCompositeDigest(bank string, pcrIndices []int, pcrDigests map[string]string) ([]byte, error) {
	if len(pcrIndices) == 0 {
		return nil, ErrPolicyEmptyPCRs
	}

	sorted := sortedPCRIndices(pcrIndices)
	hashSize := PCRDigestSize(bank)

	// Step 1: Concatenate PCR digests in sorted order.
	var pcrComposite []byte
	for _, idx := range sorted {
		key := fmt.Sprintf("%s:%d", bank, idx)
		if d, ok := pcrDigests[key]; ok {
			b, err := hex.DecodeString(d)
			if err != nil {
				return nil, &errs.Detail{Err: ErrPolicyInvalidDigest, Detail: key}
			}
			pcrComposite = append(pcrComposite, b...)
		} else {
			// Zero-fill for missing digests.
			pcrComposite = append(pcrComposite, make([]byte, hashSize)...)
		}
	}

	// Step 2: Hash the composite to form pcrDigestHash.
	compositeHash, err := pcrBankHash(bank)
	if err != nil {
		return nil, err
	}
	compositeHash.Write(pcrComposite)
	return compositeHash.Sum(nil), nil
}

// sortedPCRIndices returns a sorted copy of indices.
func sortedPCRIndices(indices []int) []int {
	sorted := make([]int, len(indices))
	copy(sorted, indices)
	sort.Ints(sorted)
	return sorted
}

// pcrBankHash returns a new hasher for the given PCR bank name; an unknown
// bank uses SHA-256. Under FIPS 140-only mode a bank whose hash the Go
// Cryptographic Module refuses (SHA-1) returns a *HashRefusedError.
func pcrBankHash(bank string) (hash.Hash, error) {
	if _, ok := pcrBankTPMAlgID[bank]; !ok {
		return sha256.New(), nil
	}
	return GetHashFunction(bank)
}
