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
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// AttestationAppraisalSentinelClasses classifies the errors of the
// attestation Verifier verbs (pkg/xkms's servicer_attestation.go over
// pkg/attestation/appraisal, go-xkms#1608). A server without an Appraiser
// has nothing to answer with. The appraisal's typed errors wrap these
// sentinels, so this one table classifies them. A store outage is checked
// before the request faults, because a rejection can wrap the outage that
// caused it.
var AttestationAppraisalSentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{appraisal.ErrStoreUnavailable, ClassUnavailable},
	{appraisal.ErrRecordNotFound, ClassNotFound},
	{appraisal.ErrNilRequest, ClassInvalidArgument},
	{appraisal.ErrInvalidName, ClassInvalidArgument},
	{appraisal.ErrInvalidTenant, ClassInvalidArgument},
	{appraisal.ErrEndorsementInvalid, ClassInvalidArgument},
	{appraisal.ErrReferenceValuesRejected, ClassInvalidArgument},
	{appraisal.ErrInvalidRepository, ClassInvalidArgument},
	{appraisal.ErrInvalidSigningKey, ClassInvalidArgument},
	{appraisal.ErrSigningKeyRefused, ClassInvalidArgument},
	{appraisal.ErrInvalidAKIntermediate, ClassInvalidArgument},
}

// AttestationAppraisalClassOf classifies an error of the attestation
// Verifier verbs.
func AttestationAppraisalClassOf(err error) (Class, bool) {
	return ClassOf(AttestationAppraisalSentinelClasses, err)
}
