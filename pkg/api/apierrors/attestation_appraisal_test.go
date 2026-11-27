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

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestAttestationAppraisalClassOf proves the Verifier's errors, typed and
// sentinel, classify the way every transport reports them.
func TestAttestationAppraisalClassOf(t *testing.T) {
	tests := []struct {
		err  error
		want Class
	}{
		{xkms.ErrNotConfigured, ClassUnavailable},
		{appraisal.ErrNilRequest, ClassInvalidArgument},
		{&appraisal.NameError{Name: "a/b"}, ClassInvalidArgument},
		{&appraisal.EndorsementInvalidError{Reason: "no key"}, ClassInvalidArgument},
		{&appraisal.ReferenceValuesRejectedError{Reason: "bad signature"}, ClassInvalidArgument},
		{&appraisal.AKIntermediateError{Index: 1}, ClassInvalidArgument},
		{fmt.Errorf("get: %w", appraisal.ErrRecordNotFound), ClassNotFound},
		{&appraisal.StoreError{Op: "put", Err: errors.New("down")}, ClassUnavailable},
		// A rejection caused by a store outage is the outage.
		{&appraisal.ReferenceValuesRejectedError{Reason: "key source", Cause: appraisal.ErrStoreUnavailable}, ClassUnavailable},
	}
	for _, tt := range tests {
		got, ok := AttestationAppraisalClassOf(tt.err)
		if !ok || got != tt.want {
			t.Errorf("AttestationAppraisalClassOf(%v) = %v, %v; want %v, true", tt.err, got, ok, tt.want)
		}
	}
}

// TestAttestationAppraisalClassOf_Unclassified proves nil and an error
// outside the model are not classified.
func TestAttestationAppraisalClassOf_Unclassified(t *testing.T) {
	for _, err := range []error{nil, errors.New("unrelated")} {
		if _, ok := AttestationAppraisalClassOf(err); ok {
			t.Errorf("AttestationAppraisalClassOf(%v) classified an unclassified error", err)
		}
	}
}
