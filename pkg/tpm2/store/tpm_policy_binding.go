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

package store

import (
	"encoding/binary"
	"strconv"
)

// TPM policy binding record encoding.
//
// The record is stored next to the object's public and private areas under
// FSEXT_TPM_POLICY:
//
//	offset  size  field
//	     0     4  magic ("XTPB")
//	     4     1  version (currently 1)
//	     5     4  policy NV index handle, big endian
//	     9     2  policy hash TPM_ALG_ID, big endian
//	    11     1  flags (bit 0: the authPolicy has a PolicyAuthValue branch)
//	    12     2  scope length, big endian
//	    14     n  scope (UTF-8)
//	  14+n     2  policy name length, big endian
//	  16+n     m  policy name (UTF-8)
//
// The record carries no secret and is not integrity protected. It only tells
// the session code which authorization path to build. A forged record cannot
// grant access: the session it produces still has to reach the authPolicy
// sealed into the object's TPM-protected public area.
const (
	// TPMPolicyBindingVersion is the version written into new binding records.
	TPMPolicyBindingVersion uint8 = 1

	tpmPolicyBindingMagic     = "XTPB"
	tpmPolicyBindingHeaderLen = 14

	// tpmPolicyBindingMaxName bounds the scope and policy name lengths so a
	// corrupt length field is refused instead of trusted.
	tpmPolicyBindingMaxName = 1024

	// tpmPolicyBindingFlagAuthValue marks a binding whose authPolicy is
	// PolicyOR(PolicyAuthorizeNV, PolicyAuthValue).
	tpmPolicyBindingFlagAuthValue uint8 = 0x01
)

// TPMPolicyBinding records that an object was created under a named,
// authorized TPM policy: which policy, in which scope, through which NV
// index, and whether its authPolicy also carries a PolicyAuthValue branch.
type TPMPolicyBinding struct {
	// Scope is the tenant the policy belongs to ("system" for the platform).
	Scope string

	// Policy is the policy's name within Scope.
	Policy string

	// Index is the NV index the object's PolicyAuthorizeNV branch names.
	Index uint32

	// HashAlg is the TPM_ALG_ID of the policy digests (the session hash).
	HashAlg uint16

	// AuthValueBranch reports whether the object's authPolicy is
	// PolicyOR(PolicyAuthorizeNV, PolicyAuthValue) rather than
	// PolicyAuthorizeNV alone.
	AuthValueBranch bool
}

// validate reports the first reason b cannot be encoded.
func (b *TPMPolicyBinding) validate() error {
	switch {
	case b == nil:
		return &TPMPolicyBindingFormatError{Reason: "nil binding"}
	case b.Scope == "":
		return &TPMPolicyBindingFormatError{Reason: "empty scope"}
	case b.Policy == "":
		return &TPMPolicyBindingFormatError{Reason: "empty policy name"}
	case len(b.Scope) > tpmPolicyBindingMaxName:
		return &TPMPolicyBindingFormatError{Reason: "scope too long: " + strconv.Itoa(len(b.Scope))}
	case len(b.Policy) > tpmPolicyBindingMaxName:
		return &TPMPolicyBindingFormatError{Reason: "policy name too long: " + strconv.Itoa(len(b.Policy))}
	case b.Index == 0:
		return &TPMPolicyBindingFormatError{Reason: "zero NV index"}
	case b.HashAlg == 0:
		return &TPMPolicyBindingFormatError{Reason: "zero hash algorithm"}
	}
	return nil
}

// MarshalBinary encodes the binding into its on-disk representation.
func (b *TPMPolicyBinding) MarshalBinary() ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}

	out := make([]byte, 0, tpmPolicyBindingHeaderLen+len(b.Scope)+2+len(b.Policy))
	out = append(out, tpmPolicyBindingMagic...)
	out = append(out, TPMPolicyBindingVersion)
	out = binary.BigEndian.AppendUint32(out, b.Index)
	out = binary.BigEndian.AppendUint16(out, b.HashAlg)
	var flags uint8
	if b.AuthValueBranch {
		flags |= tpmPolicyBindingFlagAuthValue
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.Scope))) // #nosec G115 -- bounded by validate
	out = append(out, b.Scope...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.Policy))) // #nosec G115 -- bounded by validate
	out = append(out, b.Policy...)
	return out, nil
}

// UnmarshalTPMPolicyBinding decodes a binding record written by MarshalBinary.
// A record that is truncated, carries unknown flags or trailing bytes, or was
// written by an unknown version is refused: an object whose binding cannot be
// read must fail loudly rather than be authorized along a guessed path.
func UnmarshalTPMPolicyBinding(data []byte) (*TPMPolicyBinding, error) {
	if len(data) < tpmPolicyBindingHeaderLen {
		return nil, &TPMPolicyBindingFormatError{
			Reason: "record too short: " + strconv.Itoa(len(data)) + " bytes",
		}
	}
	if string(data[0:4]) != tpmPolicyBindingMagic {
		return nil, &TPMPolicyBindingFormatError{Reason: "bad magic"}
	}
	if data[4] != TPMPolicyBindingVersion {
		return nil, &TPMPolicyBindingVersionError{Version: data[4]}
	}
	flags := data[11]
	if flags&^tpmPolicyBindingFlagAuthValue != 0 {
		return nil, &TPMPolicyBindingFormatError{Reason: "unknown flags: " + strconv.Itoa(int(flags))}
	}

	scope, rest, err := readBindingString(data[12:], "scope")
	if err != nil {
		return nil, err
	}
	policy, rest, err := readBindingString(rest, "policy name")
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, &TPMPolicyBindingFormatError{Reason: strconv.Itoa(len(rest)) + " trailing bytes"}
	}

	binding := &TPMPolicyBinding{
		Scope:           scope,
		Policy:          policy,
		Index:           binary.BigEndian.Uint32(data[5:9]),
		HashAlg:         binary.BigEndian.Uint16(data[9:11]),
		AuthValueBranch: flags&tpmPolicyBindingFlagAuthValue != 0,
	}
	if err := binding.validate(); err != nil {
		return nil, err
	}
	return binding, nil
}

// readBindingString reads one length-prefixed string field and returns it
// with the bytes that follow it.
func readBindingString(data []byte, field string) (string, []byte, error) {
	if len(data) < 2 {
		return "", nil, &TPMPolicyBindingFormatError{Reason: field + " length truncated"}
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	if n == 0 || n > tpmPolicyBindingMaxName {
		return "", nil, &TPMPolicyBindingFormatError{Reason: "invalid " + field + " length: " + strconv.Itoa(n)}
	}
	if len(data) < 2+n {
		return "", nil, &TPMPolicyBindingFormatError{Reason: field + " truncated"}
	}
	return string(data[2 : 2+n]), data[2+n:], nil
}

// TPMPolicyBindingFormatError indicates a TPM policy binding record could not
// be encoded or decoded.
type TPMPolicyBindingFormatError struct {
	Reason string
}

// Error returns a human-readable description of the failure.
func (e *TPMPolicyBindingFormatError) Error() string {
	return "tpm2 store: invalid TPM policy binding record: " + e.Reason
}

// TPMPolicyBindingVersionError indicates a TPM policy binding record was
// written by a version this implementation does not read.
type TPMPolicyBindingVersionError struct {
	Version uint8
}

// Error returns a human-readable description of the version mismatch.
func (e *TPMPolicyBindingVersionError) Error() string {
	return "tpm2 store: unsupported TPM policy binding record version: " +
		strconv.Itoa(int(e.Version))
}
