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
//	     4     1  version (3)
//	     5     4  policy NV index handle, big endian
//	     9     2  policy hash TPM_ALG_ID, big endian
//	    11     1  flags
//	                bit 0: the authPolicy has an outer PolicyAuthValue branch
//	                bit 1: the policy has an auth_value condition
//	    12     2  scope length, big endian
//	    14     n  scope (UTF-8)
//	  14+n     2  policy name length, big endian
//	  16+n     m  policy name (UTF-8)
//	16+n+m     2  authority length, big endian (0: none)
//	           a  scope authority public area (TPM2B_PUBLIC)
//	           1  approval count
//	              per approval: 2-byte big-endian length, then the approval
//	              as pkg/tpm2 encodes it
//
// The authority and approvals let a node authorize the policy offline,
// without the policy registry. A record written while the policy is revoked
// carries none.
//
// The record carries no secret and is not integrity protected. It only tells
// the session code which authorization path to build and which approvals to
// present. A forged record cannot grant access: the TPM verifies every
// approval's signature against the authority the policy's NV index names, and
// the session still has to reach the authPolicy sealed into the object's
// TPM-protected public area.
const (
	// TPMPolicyBindingVersion is the version of the binding record format.
	TPMPolicyBindingVersion uint8 = 3

	tpmPolicyBindingMagic     = "XTPB"
	tpmPolicyBindingHeaderLen = 14

	// tpmPolicyBindingMaxName bounds the scope and policy name lengths so a
	// corrupt length field is refused instead of trusted.
	tpmPolicyBindingMaxName = 1024

	// tpmPolicyBindingMaxBlob bounds the authority and each approval, the
	// largest value their 2-byte length fields hold.
	tpmPolicyBindingMaxBlob = 0xFFFF

	// tpmPolicyBindingMaxApprovals bounds the approvals, the largest value
	// their 1-byte count holds.
	tpmPolicyBindingMaxApprovals = 0xFF

	// tpmPolicyBindingFlagAuthValue marks a binding whose authPolicy is
	// PolicyOR(PolicyAuthorizeNV, PolicyAuthValue).
	tpmPolicyBindingFlagAuthValue uint8 = 0x01

	// tpmPolicyBindingFlagAuthValueCondition marks a binding to a policy with
	// an auth_value condition.
	tpmPolicyBindingFlagAuthValueCondition uint8 = 0x02

	// tpmPolicyBindingFlags are the flags the format defines.
	tpmPolicyBindingFlags = tpmPolicyBindingFlagAuthValue | tpmPolicyBindingFlagAuthValueCondition
)

// TPMPolicyBinding is the decoded binding record: the named policy an object
// was created under and how its authPolicy is shaped, plus the scope
// authority and the policy's approvals current when the record was written.
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

	// AuthValueCondition reports whether the policy has an auth_value
	// condition, so the object's password counts only inside the policy's
	// branches. It excludes AuthValueBranch.
	AuthValueCondition bool

	// Authority is the scope authority's public area (a marshalled
	// TPM2B_PUBLIC), the key every approval is signed with. Empty when the
	// record carries no approvals.
	Authority []byte

	// Approvals are the policy's approvals, one per branch, each encoded by
	// pkg/tpm2. Empty when the policy was revoked as the record was written.
	Approvals [][]byte
}

// validate reports whether b can be encoded.
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
	case b.AuthValueBranch && b.AuthValueCondition:
		return &TPMPolicyBindingFormatError{Reason: "an outer auth value branch on a policy with an auth_value condition"}
	case len(b.Authority) > tpmPolicyBindingMaxBlob:
		return &TPMPolicyBindingFormatError{Reason: "authority too long: " + strconv.Itoa(len(b.Authority))}
	case len(b.Approvals) > tpmPolicyBindingMaxApprovals:
		return &TPMPolicyBindingFormatError{Reason: "too many approvals: " + strconv.Itoa(len(b.Approvals))}
	case len(b.Approvals) > 0 && len(b.Authority) == 0:
		return &TPMPolicyBindingFormatError{Reason: "approvals without an authority"}
	}
	for i, approval := range b.Approvals {
		if len(approval) == 0 || len(approval) > tpmPolicyBindingMaxBlob {
			return &TPMPolicyBindingFormatError{
				Reason: "invalid approval " + strconv.Itoa(i) + " length: " + strconv.Itoa(len(approval)),
			}
		}
	}
	return nil
}

// MarshalBinary encodes the binding record.
func (b *TPMPolicyBinding) MarshalBinary() ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}

	size := tpmPolicyBindingHeaderLen + len(b.Scope) + 2 + len(b.Policy) + 2 + len(b.Authority) + 1
	for _, approval := range b.Approvals {
		size += 2 + len(approval)
	}
	out := make([]byte, 0, size)
	out = append(out, tpmPolicyBindingMagic...)
	out = append(out, TPMPolicyBindingVersion)
	out = binary.BigEndian.AppendUint32(out, b.Index)
	out = binary.BigEndian.AppendUint16(out, b.HashAlg)
	var flags uint8
	if b.AuthValueBranch {
		flags |= tpmPolicyBindingFlagAuthValue
	}
	if b.AuthValueCondition {
		flags |= tpmPolicyBindingFlagAuthValueCondition
	}
	out = append(out, flags)
	out = appendBindingBytes(out, []byte(b.Scope))
	out = appendBindingBytes(out, []byte(b.Policy))
	out = appendBindingBytes(out, b.Authority)
	out = append(out, uint8(len(b.Approvals))) // #nosec G115 -- bounded by validate
	for _, approval := range b.Approvals {
		out = appendBindingBytes(out, approval)
	}
	return out, nil
}

// appendBindingBytes appends v with its 2-byte big-endian length; validate
// bounds every value it is given.
func appendBindingBytes(out, v []byte) []byte {
	out = binary.BigEndian.AppendUint16(out, uint16(len(v))) // #nosec G115 -- bounded by validate
	return append(out, v...)
}

// UnmarshalTPMPolicyBinding decodes a binding record. It returns a
// *TPMPolicyBindingVersionError for a version other than
// TPMPolicyBindingVersion and a *TPMPolicyBindingFormatError for any other
// malformed record.
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
	if flags&^tpmPolicyBindingFlags != 0 {
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
	authority, rest, err := readBindingBytes(rest, "authority")
	if err != nil {
		return nil, err
	}
	if len(rest) < 1 {
		return nil, &TPMPolicyBindingFormatError{Reason: "approval count truncated"}
	}
	count := int(rest[0])
	rest = rest[1:]
	var approvals [][]byte
	for i := range count {
		var approval []byte
		approval, rest, err = readBindingBytes(rest, "approval "+strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, approval)
	}
	if len(rest) != 0 {
		return nil, &TPMPolicyBindingFormatError{Reason: strconv.Itoa(len(rest)) + " trailing bytes"}
	}

	binding := &TPMPolicyBinding{
		Scope:              scope,
		Policy:             policy,
		Index:              binary.BigEndian.Uint32(data[5:9]),
		HashAlg:            binary.BigEndian.Uint16(data[9:11]),
		AuthValueBranch:    flags&tpmPolicyBindingFlagAuthValue != 0,
		AuthValueCondition: flags&tpmPolicyBindingFlagAuthValueCondition != 0,
		Authority:          authority,
		Approvals:          approvals,
	}
	if err := binding.validate(); err != nil {
		return nil, err
	}
	return binding, nil
}

// readBindingString reads a 2-byte big-endian length followed by a non-empty
// string of at most tpmPolicyBindingMaxName bytes, returning the remainder.
func readBindingString(data []byte, field string) (string, []byte, error) {
	v, rest, err := readBindingBytes(data, field)
	if err != nil {
		return "", nil, err
	}
	if len(v) == 0 || len(v) > tpmPolicyBindingMaxName {
		return "", nil, &TPMPolicyBindingFormatError{Reason: "invalid " + field + " length: " + strconv.Itoa(len(v))}
	}
	return string(v), rest, nil
}

// readBindingBytes reads a 2-byte big-endian length followed by that many
// bytes, returning a copy of them (nil when empty) and the remainder.
func readBindingBytes(data []byte, field string) ([]byte, []byte, error) {
	if len(data) < 2 {
		return nil, nil, &TPMPolicyBindingFormatError{Reason: field + " length truncated"}
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+n {
		return nil, nil, &TPMPolicyBindingFormatError{Reason: field + " truncated"}
	}
	if n == 0 {
		return nil, data[2:], nil
	}
	return append([]byte(nil), data[2:2+n]...), data[2+n:], nil
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
