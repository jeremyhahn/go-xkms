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

package types

import "github.com/jeremyhahn/go-xkms/pkg/errs"

// SealedDataAuthenticationError reports SealedData that failed
// authentication (see ErrSealedDataAuthentication). detail says what was
// wrong with it; cause, when non-nil, is the backend's own error -- an AEAD
// open failure, a KMS InvalidCiphertextException, a TPM_RC_INTEGRITY -- and
// stays reachable with errors.Is and errors.As next to the sentinel.
//
// Every Sealer builds its authentication failures with this one function so
// the error has the same shape whichever backend produced it.
func SealedDataAuthenticationError(detail string, cause error) error {
	if cause == nil {
		return &errs.Detail{Err: ErrSealedDataAuthentication, Detail: detail}
	}
	return &errs.Joined{Lead: ErrSealedDataAuthentication, Detail: detail, Cause: cause}
}
