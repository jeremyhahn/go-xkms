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

package peer

import (
	"errors"

	evid "github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
)

// The quote checks themselves -- parsing the TPMS_ATTEST, the signature, the
// PCR digest and the baseline comparison -- are the evidence primitives in
// pkg/attestation/evidence. This file maps their outcome onto this
// verifier's failure classes.

// fromEvidence converts an evidence-primitive error into a failure. A
// ClassAbsent error is an absence; everything else, including an error that
// is not an *evid.Error, is cryptographic, so an unexpected error never
// softens a verdict.
func fromEvidence(err error) *failure {
	var e *evid.Error
	if errors.As(err, &e) {
		if e.Class == evid.ClassAbsent {
			return absent(e.Reason)
		}
		return wrong(e.Reason)
	}
	return wrong(err.Error())
}

// copyPCRs deep-copies a PCR map so a verdict never aliases the evidence's
// buffers.
func copyPCRs(in map[int][]byte) map[int][]byte {
	out := make(map[int][]byte, len(in))
	for idx, value := range in {
		cp := make([]byte, len(value))
		copy(cp, value)
		out[idx] = cp
	}
	return out
}
