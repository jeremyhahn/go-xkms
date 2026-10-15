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
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ErrPolicyBindingUnknown is returned by a StaticPolicyResolver for a policy
// none of its binding records names.
var ErrPolicyBindingUnknown = errors.New("tpm2: no binding record names the policy")

// maxApprovalField bounds every length-prefixed field of an encoded approval
// and the number of its conditions, the largest values their length fields
// hold.
const (
	maxApprovalField      = 0xFFFF
	maxApprovalConditions = 0xFF
)

// An approval, as a binding record carries it, is encoded as:
//
//	size  field
//	   2  session hash TPM_ALG_ID, big endian
//	   4  revocation counter NV index handle, big endian
//	   8  epoch, big endian
//	   4  policy NV index handle, big endian
//	      policy reference      (2-byte length, bytes)
//	      authority public area (2-byte length, TPM2B_PUBLIC)
//	      signature             (2-byte length, TPMT_SIGNATURE)
//	   1  condition count
//	      per condition: type (1), TPMA_LOCALITY (1),
//	      PCR selection (2-byte length, TPML_PCR_SELECTION),
//	      PCR digest (2-byte length, bytes)

// marshalPolicyApproval encodes approval for a binding record.
func marshalPolicyApproval(approval *PolicyApproval) ([]byte, error) {
	if approval == nil {
		return nil, &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: "nil approval"}
	}
	conditions := approval.Branch.Conditions
	if len(conditions) > maxApprovalConditions {
		return nil, &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: "too many conditions: " + strconv.Itoa(len(conditions))}
	}
	w := &approvalWriter{}
	w.out = binary.BigEndian.AppendUint16(w.out, uint16(approval.HashAlg))
	w.out = binary.BigEndian.AppendUint32(w.out, uint32(approval.Counter))
	w.out = binary.BigEndian.AppendUint64(w.out, approval.Epoch)
	w.out = binary.BigEndian.AppendUint32(w.out, uint32(approval.Index))
	w.field("policy reference", approval.PolicyRef)
	w.field("authority public area", tpm2.Marshal(approval.AuthorityPublic))
	w.field("signature", tpm2.Marshal(approval.Signature))
	w.out = append(w.out, uint8(len(conditions))) // #nosec G115 -- bounded above
	for _, c := range conditions {
		w.out = append(w.out, uint8(c.Type))
		w.out = append(w.out, tpm2.Marshal(c.Locality)...)
		w.field("PCR selection", tpm2.Marshal(c.PCRSelection))
		w.field("PCR digest", c.PCRDigest)
	}
	if w.err != nil {
		return nil, w.err
	}
	return w.out, nil
}

// approvalWriter appends length-prefixed fields, keeping the first error.
type approvalWriter struct {
	out []byte
	err error
}

// field appends v with its 2-byte big-endian length.
func (w *approvalWriter) field(name string, v []byte) {
	if len(v) > maxApprovalField {
		w.err = &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: name + " too long: " + strconv.Itoa(len(v))}
		return
	}
	w.out = binary.BigEndian.AppendUint16(w.out, uint16(len(v))) // #nosec G115 -- bounded above
	w.out = append(w.out, v...)
}

// unmarshalPolicyApproval decodes an approval marshalPolicyApproval encoded.
func unmarshalPolicyApproval(data []byte) (*PolicyApproval, error) {
	r := &approvalReader{data: data}
	approval := &PolicyApproval{
		HashAlg: tpm2.TPMAlgID(binary.BigEndian.Uint16(r.take(2, "hash algorithm"))),
		Counter: tpm2.TPMHandle(binary.BigEndian.Uint32(r.take(4, "counter index"))),
		Epoch:   binary.BigEndian.Uint64(r.take(8, "epoch")),
		Index:   tpm2.TPMHandle(binary.BigEndian.Uint32(r.take(4, "policy index"))),
	}
	approval.PolicyRef = r.field("policy reference")
	authority := r.field("authority public area")
	signature := r.field("signature")
	count := int(r.take(1, "condition count")[0])
	if r.err != nil {
		return nil, r.err
	}

	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](authority)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidPolicyApproval, Detail: "authority public area", Cause: err}
	}
	approval.AuthorityPublic = *public
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](signature)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidPolicyApproval, Detail: "signature", Cause: err}
	}
	approval.Signature = *sig

	for range count {
		condition, err := r.condition()
		if err != nil {
			return nil, err
		}
		approval.Branch.Conditions = append(approval.Branch.Conditions, condition)
	}
	if len(r.data) != 0 {
		return nil, &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: strconv.Itoa(len(r.data)) + " trailing bytes"}
	}
	return approval, nil
}

// approvalReader consumes an encoded approval, keeping the first error. Once
// it has failed, every read returns zeroed bytes of the requested size, so
// callers check err once after a run of reads.
type approvalReader struct {
	data []byte
	err  error
}

// take returns the next n bytes.
func (r *approvalReader) take(n int, name string) []byte {
	if r.err == nil && len(r.data) < n {
		r.err = &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: name + " truncated"}
	}
	if r.err != nil {
		return make([]byte, n)
	}
	v := r.data[:n]
	r.data = r.data[n:]
	return v
}

// field returns a copy of the next 2-byte-length-prefixed field, nil when
// it is empty.
func (r *approvalReader) field(name string) []byte {
	n := int(binary.BigEndian.Uint16(r.take(2, name+" length")))
	v := r.take(n, name)
	if r.err != nil || n == 0 {
		return nil
	}
	return append([]byte(nil), v...)
}

// condition decodes the next condition.
func (r *approvalReader) condition() (PolicyCondition, error) {
	c := PolicyCondition{Type: PolicyConditionType(r.take(1, "condition type")[0])}
	locality := r.take(1, "locality")
	selection := r.field("PCR selection")
	c.PCRDigest = r.field("PCR digest")
	if r.err != nil {
		return PolicyCondition{}, r.err
	}
	l, err := tpm2.Unmarshal[tpm2.TPMALocality](locality)
	if err != nil {
		return PolicyCondition{}, &errs.Joined{Lead: ErrInvalidPolicyApproval, Detail: "locality", Cause: err}
	}
	c.Locality = *l
	pcrs, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](selection)
	if err != nil {
		return PolicyCondition{}, &errs.Joined{Lead: ErrInvalidPolicyApproval, Detail: "PCR selection", Cause: err}
	}
	c.PCRSelection = *pcrs
	return c, nil
}

// bindingApprovals returns the scope authority and the encoded approvals a
// binding record for scope's policy name carries: none for a revoked policy.
// Approvals signed by different authorities (a key created while the
// scope's authority rotates) are also left out; finishing the rotation
// refreshes every record of the scope.
func bindingApprovals(r PolicyBindingResolver, scope, name string) ([]byte, [][]byte, error) {
	approvals, err := r.Approvals(scope, name)
	if errors.Is(err, ErrPolicyRevoked) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var authority []byte
	encoded := make([][]byte, 0, len(approvals))
	for _, approval := range approvals {
		if approval == nil {
			return nil, nil, &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: "nil approval"}
		}
		public := tpm2.Marshal(approval.AuthorityPublic)
		if authority == nil {
			authority = public
		} else if !bytes.Equal(authority, public) {
			return nil, nil, nil
		}
		approval, err := marshalPolicyApproval(approval)
		if err != nil {
			return nil, nil, err
		}
		encoded = append(encoded, approval)
	}
	if len(encoded) == 0 {
		return nil, nil, nil
	}
	return authority, encoded, nil
}

// RefreshPolicyBinding rewrites the authority and approvals of the binding
// record backend holds for keyAttrs from r, so the record authorizes the
// policy's current approvals offline. An object with no binding record is
// left alone. The policy service calls it for every object bound to a named
// policy after the scope's approvals change.
func RefreshPolicyBinding(r PolicyBindingResolver, keyAttrs *types.KeyAttributes, backend store.KeyBackend) error {
	if r == nil {
		return ErrPolicyResolverUnset
	}
	if backend == nil {
		return ErrNoStorageBackend
	}
	record, err := backend.Get(keyAttrs, store.FSEXT_TPM_POLICY)
	if errors.Is(err, store.ErrBlobNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	binding, err := store.UnmarshalTPMPolicyBinding(record)
	if err != nil {
		return err
	}
	if binding.Authority, binding.Approvals, err = bindingApprovals(r, binding.Scope, binding.Policy); err != nil {
		return err
	}
	refreshed, err := binding.MarshalBinary()
	if err != nil {
		return err
	}
	return backend.Save(keyAttrs, refreshed, store.FSEXT_TPM_POLICY, true)
}

// StaticPolicyResolver is a PolicyBindingResolver that answers from binding
// records alone, with no policy registry or database, so a node can
// authorize its named policies offline (for example to unseal at boot).
// The TPM still verifies each approval's signature against the authority
// the policy's NV index names, and the epoch against the scope's revocation
// counter, so a record cannot resurrect a revoked or superseded approval.
type StaticPolicyResolver struct {
	bindings map[staticPolicyKey]*staticPolicyBinding
}

// staticPolicyKey names a policy within its scope.
type staticPolicyKey struct {
	scope, policy string
}

// staticPolicyBinding is one policy's decoded record.
type staticPolicyBinding struct {
	record    []byte
	info      PolicyIndexInfo
	approvals []*PolicyApproval
}

// NewStaticPolicyResolver returns a resolver for the named policies the
// binding records (.tpmpolicy blobs) name. It refuses a malformed record,
// an approval signed by any key other than the record's authority, an
// approval that does not describe the record's policy, and two different
// records for one policy.
func NewStaticPolicyResolver(records ...[]byte) (*StaticPolicyResolver, error) {
	r := &StaticPolicyResolver{bindings: make(map[staticPolicyKey]*staticPolicyBinding, len(records))}
	for _, record := range records {
		binding, err := store.UnmarshalTPMPolicyBinding(record)
		if err != nil {
			return nil, err
		}
		key := staticPolicyKey{scope: binding.Scope, policy: binding.Policy}
		if existing, ok := r.bindings[key]; ok {
			if !bytes.Equal(existing.record, record) {
				return nil, &errs.Detail{Err: ErrPolicyApprovalMismatch, Detail: "conflicting binding records for " + binding.Scope + "/" + binding.Policy}
			}
			continue
		}
		approvals, err := staticApprovals(binding)
		if err != nil {
			return nil, err
		}
		r.bindings[key] = &staticPolicyBinding{
			record: record,
			info: PolicyIndexInfo{
				Index:              tpm2.TPMHandle(binding.Index),
				HashAlg:            tpm2.TPMAlgID(binding.HashAlg),
				AuthValueCondition: binding.AuthValueCondition,
			},
			approvals: approvals,
		}
	}
	return r, nil
}

// staticApprovals decodes and checks binding's approvals.
func staticApprovals(binding *store.TPMPolicyBinding) ([]*PolicyApproval, error) {
	approvals := make([]*PolicyApproval, 0, len(binding.Approvals))
	for _, encoded := range binding.Approvals {
		approval, err := unmarshalPolicyApproval(encoded)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(tpm2.Marshal(approval.AuthorityPublic), binding.Authority) {
			return nil, &errs.Detail{Err: ErrPolicyApprovalMismatch, Detail: "approval signed by a key other than the record's authority"}
		}
		if err := validateApproval(approval, binding, tpm2.TPMAlgID(binding.HashAlg)); err != nil {
			return nil, err
		}
		approvals = append(approvals, approval)
	}
	return approvals, nil
}

// binding returns scope's policy name, or ErrPolicyBindingUnknown.
func (r *StaticPolicyResolver) binding(scope, name string) (*staticPolicyBinding, error) {
	b, ok := r.bindings[staticPolicyKey{scope: scope, policy: name}]
	if !ok {
		return nil, &errs.Detail{Err: ErrPolicyBindingUnknown, Detail: scope + "/" + name}
	}
	return b, nil
}

// PolicyIndex returns what an object bound to scope's policy name commits
// to, as its binding record states it.
func (r *StaticPolicyResolver) PolicyIndex(scope, name string) (PolicyIndexInfo, error) {
	b, err := r.binding(scope, name)
	if err != nil {
		return PolicyIndexInfo{}, err
	}
	return b.info, nil
}

// Approvals returns the approvals the binding record of scope's policy name
// carries, or ErrPolicyRevoked when it carries none.
func (r *StaticPolicyResolver) Approvals(scope, name string) ([]*PolicyApproval, error) {
	b, err := r.binding(scope, name)
	if err != nil {
		return nil, err
	}
	if len(b.approvals) == 0 {
		return nil, ErrPolicyRevoked
	}
	return b.approvals, nil
}
