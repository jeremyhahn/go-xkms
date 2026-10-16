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

package apierrors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestTPMPolicyClassOf classifies the TPM policy API's typed and sentinel
// errors, bare and wrapped: a policy or scope still in use is a
// precondition refusal, a malformed name or mode an invalid argument, an
// unknown policy not found, and a tenant in mode none a precondition.
func TestTPMPolicyClassOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Class
	}{
		{"policy in use", &tpmpolicy.PolicyInUseError{Policy: "boot", Objects: []string{"key/a"}}, ClassFailedPrecondition},
		{"scope in use", &tpmpolicy.ScopeInUseError{Tenant: "acme"}, ClassFailedPrecondition},
		{"bank unavailable", &tpmpolicy.PCRBankUnavailableError{Bank: "sha384"}, ClassFailedPrecondition},
		{"invalid name", &tpmpolicy.InvalidNameError{Name: "a/b"}, ClassInvalidArgument},
		{"invalid mode", &tpmpolicy.InvalidModeError{Mode: "cloud"}, ClassInvalidArgument},
		{"invalid tenant", &tpmpolicy.InvalidTenantError{Tenant: ".."}, ClassInvalidArgument},
		{"invalid bank", &tpmpolicy.InvalidPCRBankError{Bank: "md5"}, ClassInvalidArgument},
		{"invalid pcr", &tpmpolicy.InvalidPCRError{PCR: 24}, ClassInvalidArgument},
		{"invalid locality in a branch", &tpmpolicy.InvalidBranchError{Branch: 1, Err: &tpmpolicy.InvalidLocalityError{Locality: 5}}, ClassInvalidArgument},
		{"unknown condition", &tpmpolicy.UnknownConditionTypeError{Type: "time"}, ClassInvalidArgument},
		{"duplicate condition", &tpmpolicy.DuplicateConditionError{Type: tpmpolicy.ConditionPCR}, ClassInvalidArgument},
		{"condition operand", &tpmpolicy.ConditionOperandError{Type: tpmpolicy.ConditionAuthValue, Operand: "bank"}, ClassInvalidArgument},
		{"description too long", &tpmpolicy.DescriptionTooLongError{Length: 5000, Max: 4096}, ClassInvalidArgument},
		{"no branches", tpmpolicy.ErrNoBranches, ClassInvalidArgument},
		{"empty branch", &tpmpolicy.InvalidBranchError{Err: tpmpolicy.ErrEmptyBranch}, ClassInvalidArgument},
		{"empty localities", tpmpolicy.ErrEmptyLocalitySelection, ClassInvalidArgument},
		{"supplied PCR values", tpmpolicy.ErrPCRValuesSupplied, ClassInvalidArgument},
		{"auth value required", fmt.Errorf("create key: %w", pkgtpm2.ErrPolicyAuthValueRequired), ClassInvalidArgument},
		{"invalid kind", &xkms.InvalidTPMObjectKindError{Kind: "blob"}, ClassInvalidArgument},
		{"policy not found", tpmpolicy.ErrPolicyNotFound, ClassNotFound},
		{"not assigned", fmt.Errorf("lookup: %w", tpmpolicy.ErrNotAssigned), ClassNotFound},
		{"exists", tpmpolicy.ErrPolicyExists, ClassAlreadyExists},
		{"mode none through a scope", &tpm2backend.ScopeError{Tenant: "acme", Err: tpmpolicy.ErrTPMModeNone}, ClassFailedPrecondition},
		{"vtpm unavailable", tpmpolicy.ErrVTPMUnavailable, ClassFailedPrecondition},
		{"reserved object", &tpm2backend.ReservedObjectError{CN: "tpm-storage-key"}, ClassInvalidArgument},
		{"symmetric keys unsupported by the TPM", tpm2backend.ErrSymmetricKeysUnsupported, ClassUnimplemented},
		{"not configured", xkms.ErrNotConfigured, ClassUnavailable},
		{"policy off TPM", xkms.ErrTPMPolicyNotSupported, ClassInvalidArgument},
		{"branch without reference values", xkms.ErrTPMPolicyBranchUpdate, ClassInvalidArgument},
		{"no such branch", &tpmpolicy.InvalidBranchError{Branch: 3, Err: tpmpolicy.ErrNoSuchBranch}, ClassInvalidArgument},
		{"branch without a pcr condition", &tpmpolicy.InvalidBranchError{Err: tpmpolicy.ErrNoPCRCondition}, ClassInvalidArgument},
		{"refused reference values", &tpmpolicy.ReferenceValuesError{Op: "verify the signed CoRIM", Err: refvalue.ErrSignature}, ClassInvalidArgument},
		{"no reference signer", tpmpolicy.ErrNoReferenceSigner, ClassFailedPrecondition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := TPMPolicyClassOf(tt.err)
			assert.True(t, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestTPMPolicyClassOf_Unclassified proves nil and an unrelated error are
// not classified.
func TestTPMPolicyClassOf_Unclassified(t *testing.T) {
	_, ok := TPMPolicyClassOf(nil)
	assert.False(t, ok)
	_, ok = TPMPolicyClassOf(errors.New("unrelated"))
	assert.False(t, ok)
}

// TestAs reports whether an error chain holds a type.
func TestAs(t *testing.T) {
	wrapped := fmt.Errorf("delete: %w", &tpmpolicy.PolicyInUseError{Policy: "boot"})
	assert.True(t, As[*tpmpolicy.PolicyInUseError](wrapped))
	assert.False(t, As[*tpmpolicy.ScopeInUseError](wrapped))
}
