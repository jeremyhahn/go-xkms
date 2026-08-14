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

package store

import (
	"encoding/binary"
	"strconv"
)

// Platform policy pin record encoding.
//
// The record is stored next to the object's public and private areas under
// FSEXT_PLATFORM_POLICY. It is a fixed header followed by the PCR digest:
//
//	offset  size  field
//	     0     4  magic ("XPPP")
//	     4     1  version (currently 1)
//	     5     2  PCR bank TPM_ALG_ID, big endian
//	     7     4  PCR index, big endian
//	    11     2  PCR digest length, big endian
//	    13     n  PCR digest
//
// The record contains no secret and is not integrity protected: it only
// supplies an operand of TPM2_PolicyOR. A forged or corrupted record cannot
// grant access, because the resulting session policy digest still has to equal
// the AuthPolicy sealed into the object's TPM-protected public area, and the
// password branch still has to satisfy the object's UserAuth. A wrong record
// can only make an authorization attempt fail.
const (
	// PlatformPolicyPinVersion is the version written into new pin records.
	PlatformPolicyPinVersion uint8 = 1

	platformPolicyPinMagic     = "XPPP"
	platformPolicyPinHeaderLen = 13

	// platformPolicyPinMaxDigest bounds the accepted PCR digest length. The
	// largest TPM 2.0 PCR bank digest is SHA-512 (64 bytes); the bound is
	// generous enough for future banks while still rejecting garbage.
	platformPolicyPinMaxDigest = 128
)

// PlatformPolicyPin records the TPM2_PolicyPCR branch inputs that were in
// force when a platform-policy object's AuthPolicy was computed.
//
// The platform policy is a TPM2_PolicyOR over two branches: TPM2_PolicyPCR
// (automatic unlock while the platform measurements are unchanged) and
// TPM2_PolicyAuthValue (recovery with a PIN). The OR digest is computed over
// BOTH branch digests, so a session that recomputes the PolicyPCR branch from
// live PCRs produces a different OR digest once the PCRs move -- which locks
// out the PIN branch as well, exactly when recovery is needed.
//
// Persisting the PCR selection and the PCR digest that were current at
// creation time lets the PIN branch rebuild the original PolicyPCR branch
// digest without consulting live PCRs, so the OR digest stays reproducible
// across a platform change. The PolicyPCR branch itself is unaffected: a
// session that takes it still has to demonstrate the live PCR state to the
// TPM.
type PlatformPolicyPin struct {
	// PCRBank is the TPM_ALG_ID of the PCR bank the policy was computed
	// over (TCG TPM 2.0 Part 2, Section 6.3).
	PCRBank uint16

	// PCRIndex is the platform PCR the policy was computed over.
	PCRIndex uint32

	// PCRDigest is the digest of the platform PCR value that was current
	// when the policy was computed. This is the pcrDigest parameter of
	// TPM2_PolicyPCR (TCG TPM 2.0 Part 3, Section 23.7).
	PCRDigest []byte
}

// MarshalBinary encodes the pin into its on-disk representation.
func (p *PlatformPolicyPin) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, &PlatformPolicyPinFormatError{Reason: "nil pin"}
	}
	if len(p.PCRDigest) == 0 {
		return nil, &PlatformPolicyPinFormatError{Reason: "empty PCR digest"}
	}
	if len(p.PCRDigest) > platformPolicyPinMaxDigest {
		return nil, &PlatformPolicyPinFormatError{
			Reason: "PCR digest too long: " + strconv.Itoa(len(p.PCRDigest)),
		}
	}

	out := make([]byte, platformPolicyPinHeaderLen+len(p.PCRDigest))
	copy(out[0:4], platformPolicyPinMagic)
	out[4] = PlatformPolicyPinVersion
	binary.BigEndian.PutUint16(out[5:7], p.PCRBank)
	binary.BigEndian.PutUint32(out[7:11], p.PCRIndex)
	binary.BigEndian.PutUint16(out[11:13], uint16(len(p.PCRDigest)))
	copy(out[platformPolicyPinHeaderLen:], p.PCRDigest)

	return out, nil
}

// UnmarshalPlatformPolicyPin decodes a pin record written by MarshalBinary.
// Records that do not carry the magic marker, or that carry an unsupported
// version, are rejected rather than guessed at: an object whose pin cannot be
// read must fail loudly instead of silently falling back to a policy the
// object was not created with.
func UnmarshalPlatformPolicyPin(data []byte) (*PlatformPolicyPin, error) {
	if len(data) < platformPolicyPinHeaderLen {
		return nil, &PlatformPolicyPinFormatError{
			Reason: "record too short: " + strconv.Itoa(len(data)) + " bytes",
		}
	}
	if string(data[0:4]) != platformPolicyPinMagic {
		return nil, &PlatformPolicyPinFormatError{Reason: "bad magic"}
	}
	if data[4] != PlatformPolicyPinVersion {
		return nil, &PlatformPolicyPinVersionError{Version: data[4]}
	}

	digestLen := int(binary.BigEndian.Uint16(data[11:13]))
	if digestLen == 0 {
		return nil, &PlatformPolicyPinFormatError{Reason: "empty PCR digest"}
	}
	if digestLen > platformPolicyPinMaxDigest {
		return nil, &PlatformPolicyPinFormatError{
			Reason: "PCR digest too long: " + strconv.Itoa(digestLen),
		}
	}
	if len(data) != platformPolicyPinHeaderLen+digestLen {
		return nil, &PlatformPolicyPinFormatError{
			Reason: "record length " + strconv.Itoa(len(data)) +
				" does not match digest length " + strconv.Itoa(digestLen),
		}
	}

	digest := make([]byte, digestLen)
	copy(digest, data[platformPolicyPinHeaderLen:])

	return &PlatformPolicyPin{
		PCRBank:   binary.BigEndian.Uint16(data[5:7]),
		PCRIndex:  binary.BigEndian.Uint32(data[7:11]),
		PCRDigest: digest,
	}, nil
}

// PlatformPolicyPinFormatError indicates a platform policy pin record could
// not be decoded.
type PlatformPolicyPinFormatError struct {
	Reason string
}

// Error returns a human-readable description of the decoding failure.
func (e *PlatformPolicyPinFormatError) Error() string {
	return "tpm2 store: invalid platform policy pin record: " + e.Reason
}

// PlatformPolicyPinVersionError indicates a platform policy pin record was
// written by a newer implementation than the one reading it.
type PlatformPolicyPinVersionError struct {
	Version uint8
}

// Error returns a human-readable description of the version mismatch.
func (e *PlatformPolicyPinVersionError) Error() string {
	return "tpm2 store: unsupported platform policy pin record version: " +
		strconv.Itoa(int(e.Version))
}
