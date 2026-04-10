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
		// sizeofSelect = 3
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
	if len(pcrIndices) == 0 {
		return nil, ErrPolicyEmptyPCRs
	}

	sorted := make([]int, len(pcrIndices))
	copy(sorted, pcrIndices)
	sort.Ints(sorted)

	hashSize := PCRDigestSize(bank)
	newHash := pcrBankHashFunc(bank)

	// Step 1: Concatenate PCR digests in sorted order.
	var pcrComposite []byte
	for _, idx := range sorted {
		key := fmt.Sprintf("%s:%d", bank, idx)
		if d, ok := pcrDigests[key]; ok {
			b, err := hex.DecodeString(d)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrPolicyInvalidDigest, key)
			}
			pcrComposite = append(pcrComposite, b...)
		} else {
			// Zero-fill for missing digests.
			pcrComposite = append(pcrComposite, make([]byte, hashSize)...)
		}
	}

	// Step 2: Hash the composite to form pcrDigestHash.
	compositeHash := newHash()
	compositeHash.Write(pcrComposite)
	pcrDigestHash := compositeHash.Sum(nil)

	// Step 3: Compute the policy digest.
	pcrSelect := EncodePCRSelection(bank, sorted)
	oldDigest := make([]byte, compositeHash.Size()) // Initial empty policy digest (zeros).

	policyHash := newHash()
	policyHash.Write(oldDigest)
	// TPM_CC_PolicyPCR = 0x0000017F (big-endian).
	policyHash.Write([]byte{0x00, 0x00, 0x01, 0x7F})
	policyHash.Write(pcrSelect)
	policyHash.Write(pcrDigestHash)

	return policyHash.Sum(nil), nil
}

// pcrBankHashFunc returns a constructor for the hash function associated
// with the given PCR bank name.
func pcrBankHashFunc(bank string) func() hash.Hash {
	switch bank {
	case PCRBankSHA1:
		return sha1.New
	case PCRBankSHA384:
		return sha512.New384
	case PCRBankSHA512:
		return sha512.New
	default:
		return sha256.New
	}
}
