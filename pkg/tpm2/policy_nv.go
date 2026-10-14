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

package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// NV indices of named, authorized policies.
//
// Two kinds of index serve the authorized policies: a policy index per named
// policy (an ordinary index holding the TPMT_HA that TPM2_PolicyAuthorizeNV
// compares against) and a revocation counter per scope (a counter index that
// TPM2_PolicyNV compares an approval's epoch with).
//
// Both are defined with
//
//	TPMA_NV_AUTHWRITE   writes (NV_Write, NV_Increment) prove the index's
//	                    authValue -- the scope's write secret -- through a
//	                    salted HMAC session;
//	TPMA_NV_POLICYREAD  reads need no secret: the index's authPolicy is
//	                    PolicyOR(PolicyCommandCode(TPM_CC_NV_Read),
//	                             PolicyCommandCode(<the policy command>))
//	                    so anybody may read it, but only with TPM2_NV_Read or
//	                    the one policy command that consumes it;
//	TPMA_NV_NO_DA       the write secret is a random value, so dictionary
//	                    attack protection would only let a caller lock the
//	                    TPM out for every tenant.
//
// TPMA_NV_AUTHREAD is deliberately not set. It would authorize reads with the
// same authValue as writes, so every object use -- PolicyAuthorizeNV and
// PolicyNV authorize their read of the index through it -- would have to hold
// the write secret. An empty authValue with AUTHREAD would instead leave the
// index writable by anyone. POLICYREAD separates the two: reading needs a
// policy session that states the command, and writing needs the secret.

// nvHandlePageSize is how many NV handles FindFreeNVIndex asks the TPM for
// per TPM2_GetCapability.
const nvHandlePageSize = 256

// nvReadCommands lists, per NV index type, the commands the index's
// POLICYREAD authPolicy lets a secret-less policy session read it with.
var nvReadCommands = map[tpm2.TPMNT][]tpm2.TPMCC{
	tpm2.TPMNTOrdinary: {tpm2.TPMCCNVRead, tpm2.TPMCCPolicyAuthorizeNV},
	tpm2.TPMNTCounter:  {tpm2.TPMCCNVRead, tpm2.TPMCCPolicyNV},
}

// nvReadPolicy returns the POLICYREAD authPolicy of an index of type nt, and
// the branch digests a read session names in TPM2_PolicyOR.
func nvReadPolicy(hashAlg tpm2.TPMAlgID, nt tpm2.TPMNT) ([]byte, [][]byte, error) {
	commands, ok := nvReadCommands[nt]
	if !ok {
		return nil, nil, &errs.Detail{Err: ErrPolicyDigestCompute, Detail: fmt.Sprintf("no read policy for NV type %d", nt)}
	}
	branches := make([][]byte, len(commands))
	for i, cc := range commands {
		branch, err := trialDigest(hashAlg, tpm2.PolicyCommandCode{Code: cc})
		if err != nil {
			return nil, nil, err
		}
		branches[i] = branch
	}
	digest, err := trialDigest(hashAlg, policyOR(branches))
	if err != nil {
		return nil, nil, err
	}
	return digest, branches, nil
}

// NVIndexName returns the current Name of the NV index at index.
func (tpm *TPM2) NVIndexName(index tpm2.TPMHandle) (tpm2.TPM2BName, error) {
	_, name, err := tpm.nvPublic(index)
	return name, err
}

// nvPublic reads the public area and Name of the NV index at index.
func (tpm *TPM2) nvPublic(index tpm2.TPMHandle) (*tpm2.TPMSNVPublic, tpm2.TPM2BName, error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: index}.Execute(tpm.transport)
	if err != nil {
		return nil, tpm2.TPM2BName{}, err
	}
	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return nil, tpm2.TPM2BName{}, err
	}
	return pub, rsp.NVName, nil
}

// FindFreeNVIndex returns the lowest NV index in [first, last] that is not
// defined, or ErrTPMNVExhausted when every index in the range is in use.
// NVOwnerIndexFirst and NVOwnerIndexLast bound the owner range.
func (tpm *TPM2) FindFreeNVIndex(first, last tpm2.TPMHandle) (tpm2.TPMHandle, error) {
	if first > last || first>>24 != tpm2.TPMHandle(tpm2.TPMHTNVIndex) || last>>24 != tpm2.TPMHandle(tpm2.TPMHTNVIndex) {
		return 0, &errs.Detail{Err: ErrInvalidNVIndexRange, Detail: fmt.Sprintf("0x%08x-0x%08x", first, last)}
	}

	// TPM_CAP_HANDLES reports the defined NV indices at or above property in
	// ascending order, so the first gap at or above first is the answer.
	candidate := first
	property := uint32(first)
	for {
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      property,
			PropertyCount: nvHandlePageSize,
		}.Execute(tpm.transport)
		if err != nil {
			return 0, err
		}
		handles, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			return 0, err
		}
		for _, h := range handles.Handle {
			if h > candidate || h > last {
				return candidate, nil
			}
			if h < candidate {
				continue
			}
			if candidate == last {
				return 0, &errs.Detail{Err: ErrTPMNVExhausted, Detail: fmt.Sprintf("0x%08x-0x%08x", first, last)}
			}
			candidate++
		}
		if !rsp.MoreData || len(handles.Handle) == 0 {
			return candidate, nil
		}
		property = uint32(handles.Handle[len(handles.Handle)-1]) + 1
	}
}

// defineAuthorizedIndex defines an NV index of type nt and dataSize at index
// under the owner hierarchy, with the attributes documented at the top of this
// file and writeAuth as its authValue. ownerAuth authorizes TPM2_NV_DefineSpace;
// both cross the bus inside one salted session that encrypts the new index's
// authValue.
func (tpm *TPM2) defineAuthorizedIndex(
	index tpm2.TPMHandle,
	nameAlg tpm2.TPMAlgID,
	nt tpm2.TPMNT,
	dataSize uint16,
	writeAuth, ownerAuth []byte) (tpm2.TPM2BName, error) {

	readPolicy, _, err := nvReadPolicy(nameAlg, nt)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	defs := tpm2.NVDefineSpace{
		Auth: tpm2.TPM2BAuth{Buffer: writeAuth},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    index,
			NameAlg:    nameAlg,
			AuthPolicy: tpm2.TPM2BDigest{Buffer: readPolicy},
			Attributes: tpm2.TPMANV{
				AuthWrite:  true,
				PolicyRead: true,
				NoDA:       true,
				NT:         nt,
			},
			DataSize: dataSize,
		}),
	}
	if err := tpm.nvDefineSpace(tpm2.TPMRHOwner, ownerAuth, &defs); err != nil {
		if errors.Is(err, tpm2.TPMRCNVSpace) {
			return tpm2.TPM2BName{}, &errs.Joined{Lead: ErrTPMNVExhausted, Cause: err}
		}
		return tpm2.TPM2BName{}, err
	}
	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	name, err := tpm2.NVName(pub)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	tpm.logger.Debug("tpm: defined authorized-policy NV index",
		slog.String("index", fmt.Sprintf("0x%08x", index)),
		slog.Int("type", int(nt)))
	return *name, nil
}

// DefinePolicyIndex defines the policy NV index of a named policy at index:
// an ordinary index sized for one TPMT_HA of hashAlg, written with writeAuth
// and read without a secret, only by TPM2_NV_Read and TPM2_PolicyAuthorizeNV.
// ownerAuth authorizes the definition. The returned Name is the index's Name
// before its first write; WritePolicyIndex returns the Name objects bind to.
func (tpm *TPM2) DefinePolicyIndex(
	index tpm2.TPMHandle,
	hashAlg tpm2.TPMAlgID,
	writeAuth, ownerAuth []byte) (tpm2.TPM2BName, error) {

	digestSize, err := hashAlgDigestSize(hashAlg)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	return tpm.defineAuthorizedIndex(index, hashAlg, tpm2.TPMNTOrdinary, 2+digestSize, writeAuth, ownerAuth)
}

// WritePolicyIndex writes digest, a policy digest of hashAlg, into the policy
// NV index at index as a TPMT_HA, proving writeAuth through a salted session,
// and returns the index's Name once written.
func (tpm *TPM2) WritePolicyIndex(
	index tpm2.TPMHandle,
	writeAuth, digest []byte,
	hashAlg tpm2.TPMAlgID) (tpm2.TPM2BName, error) {

	digestSize, err := hashAlgDigestSize(hashAlg)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	if len(digest) != int(digestSize) {
		return tpm2.TPM2BName{}, &errs.Detail{
			Err:    ErrInvalidPolicyIndexContent,
			Detail: fmt.Sprintf("digest is %d bytes, want %d", len(digest), digestSize),
		}
	}
	_, name, err := tpm.nvPublic(index)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}

	session, closer, err := tpm.objectAuthSession(writeAuth, encryptNone)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	defer tpm.closeSession(closer, "policy index write")

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: index, Name: name, Auth: session},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: name},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: tpm2.Marshal(tpm2.TPMTHA{HashAlg: hashAlg, Digest: digest}),
		},
	}.Execute(tpm.transport)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	return tpm.NVIndexName(index)
}

// ReadPolicyIndex returns the hash algorithm and digest held by the policy NV
// index at index. The read needs no secret.
func (tpm *TPM2) ReadPolicyIndex(index tpm2.TPMHandle) (tpm2.TPMAlgID, []byte, error) {
	pub, _, err := tpm.nvPublic(index)
	if err != nil {
		return 0, nil, err
	}
	data, err := tpm.nvPolicyRead(index, pub.DataSize)
	if err != nil {
		return 0, nil, err
	}
	ha, err := tpm2.Unmarshal[tpm2.TPMTHA](data)
	if err != nil {
		return 0, nil, &errs.Joined{Lead: ErrInvalidPolicyIndexContent, Cause: err}
	}
	digestSize, err := hashAlgDigestSize(ha.HashAlg)
	if err != nil || len(ha.Digest) != int(digestSize) {
		return 0, nil, &errs.Detail{Err: ErrInvalidPolicyIndexContent, Detail: fmt.Sprintf("hash 0x%x, %d bytes", ha.HashAlg, len(ha.Digest))}
	}
	return ha.HashAlg, ha.Digest, nil
}

// DefineCounterIndex defines a scope's revocation counter at index and
// increments it once, so it is written (and its Name final) before any
// approval names it. The counter's nameAlg is the TPM's configured algorithm.
// It is incremented with writeAuth and read without a secret, only by
// TPM2_NV_Read and TPM2_PolicyNV. ownerAuth authorizes the definition. The
// returned Name is the written counter's, the one approvals name.
func (tpm *TPM2) DefineCounterIndex(
	index tpm2.TPMHandle,
	writeAuth, ownerAuth []byte) (tpm2.TPM2BName, error) {

	if _, err := tpm.defineAuthorizedIndex(index, tpm.algID, tpm2.TPMNTCounter, 8, writeAuth, ownerAuth); err != nil {
		return tpm2.TPM2BName{}, err
	}
	if _, err := tpm.IncrementCounter(index, writeAuth); err != nil {
		return tpm2.TPM2BName{}, err
	}
	return tpm.NVIndexName(index)
}

// IncrementCounter increments the counter index at index, proving writeAuth
// through a salted session, and returns its new value.
func (tpm *TPM2) IncrementCounter(index tpm2.TPMHandle, writeAuth []byte) (uint64, error) {
	_, name, err := tpm.nvPublic(index)
	if err != nil {
		return 0, err
	}
	session, closer, err := tpm.objectAuthSession(writeAuth, encryptNone)
	if err != nil {
		return 0, err
	}
	defer tpm.closeSession(closer, "counter increment")

	_, err = tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: index, Name: name, Auth: session},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: name},
	}.Execute(tpm.transport)
	if err != nil {
		return 0, err
	}
	return tpm.ReadCounter(index)
}

// ReadCounter returns the value of the counter index at index. The read needs
// no secret.
func (tpm *TPM2) ReadCounter(index tpm2.TPMHandle) (uint64, error) {
	data, err := tpm.nvPolicyRead(index, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(data), nil
}

// UndefineNVIndex deletes the NV index at index under the owner hierarchy,
// proving ownerAuth through a salted session.
func (tpm *TPM2) UndefineNVIndex(index tpm2.TPMHandle, ownerAuth []byte) error {
	_, name, err := tpm.nvPublic(index)
	if err != nil {
		return err
	}
	return tpm.withHierarchyAuth(tpm2.TPMRHOwner, ownerAuth, encryptNone, func(authHandle tpm2.AuthHandle) error {
		_, err := tpm2.NVUndefineSpace{
			AuthHandle: authHandle,
			NVIndex:    tpm2.NamedHandle{Handle: index, Name: name},
		}.Execute(tpm.transport)
		return err
	})
}

// nvPolicyRead reads size bytes from offset 0 of an authorized-policy NV
// index through its POLICYREAD authorization.
func (tpm *TPM2) nvPolicyRead(index tpm2.TPMHandle, size uint16) ([]byte, error) {
	auth, closer, err := tpm.nvPolicyReadAuth(index, tpm2.TPMCCNVRead)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closer, "NV policy read")

	rsp, err := tpm2.NVRead{
		AuthHandle: auth,
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: auth.Name},
		Size:       size,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}
	return rsp.Data.Buffer, nil
}

// nvPolicyReadAuth returns the authorization that reads the NV index at index
// for the command cc: a policy session that has run PolicyCommandCode(cc) and
// the PolicyOR of the index's read policy. The session carries no secret. The
// returned closer flushes it.
func (tpm *TPM2) nvPolicyReadAuth(index tpm2.TPMHandle, cc tpm2.TPMCC) (tpm2.AuthHandle, func() error, error) {
	pub, name, err := tpm.nvPublic(index)
	if err != nil {
		return tpm2.AuthHandle{}, noopCloser, err
	}
	_, branches, err := nvReadPolicy(pub.NameAlg, pub.Attributes.NT)
	if err != nil {
		return tpm2.AuthHandle{}, noopCloser, err
	}

	session, closer, err := tpm.startPolicySession(pub.NameAlg, nil)
	if err != nil {
		return tpm2.AuthHandle{}, noopCloser, err
	}
	if _, err := (tpm2.PolicyCommandCode{PolicySession: session.Handle(), Code: cc}).Execute(tpm.transport); err != nil {
		tpm.closeSession(closer, "NV policy read")
		return tpm2.AuthHandle{}, noopCloser, err
	}
	or := policyOR(branches)
	or.PolicySession = session.Handle()
	if _, err := or.Execute(tpm.transport); err != nil {
		tpm.closeSession(closer, "NV policy read")
		return tpm2.AuthHandle{}, noopCloser, err
	}
	return tpm2.AuthHandle{Handle: index, Name: name, Auth: session}, closer, nil
}
