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

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestAttestationAppraisalClassOf proves each appraisal sentinel, bare or
// wrapped, maps to its class (go-xkms#1660).
func TestAttestationAppraisalClassOf(t *testing.T) {
	tests := []struct {
		err  error
		want Class
	}{
		{xkms.ErrNotConfigured, ClassUnavailable},
		{appraisal.ErrNilRequest, ClassInvalidArgument},
		{appraisal.ErrInvalidName, ClassInvalidArgument},
		{appraisal.ErrInvalidTenant, ClassInvalidArgument},
		{appraisal.ErrInvalidRepository, ClassInvalidArgument},
		{appraisal.ErrEndorsementInvalid, ClassInvalidArgument},
		{appraisal.ErrReferenceValuesRejected, ClassInvalidArgument},
		{appraisal.ErrInvalidAKIntermediate, ClassInvalidArgument},
		{&appraisal.EvidenceRefusedError{Check: appraisal.AppraisalCheckEKCertificate, Cause: errors.New("no anchor")}, ClassInvalidArgument},
		{fmt.Errorf("get: %w", appraisal.ErrRecordNotFound), ClassNotFound},
		{appraisal.ErrStoreUnavailable, ClassUnavailable},
	}
	for _, tt := range tests {
		got, ok := AttestationAppraisalClassOf(tt.err)
		assert.True(t, ok, "%v must classify", tt.err)
		assert.Equal(t, tt.want, got, "%v", tt.err)
	}
}

// TestAttestationAppraisalClassOf_Unclassified proves an error outside the
// table is left for the caller's Internal fallback.
func TestAttestationAppraisalClassOf_Unclassified(t *testing.T) {
	for _, err := range []error{nil, errors.New("disk full"), xkms.ErrKeyNotFound} {
		_, ok := AttestationAppraisalClassOf(err)
		assert.False(t, ok, "%v", err)
	}
}
