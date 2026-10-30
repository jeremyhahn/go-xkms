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

//go:build pkcs11

package hardware

import (
	"errors"

	"github.com/miekg/pkcs11"
)

// PKCS11SearchFinalizer ends an object search on a session. *pkcs11.Ctx
// satisfies it.
type PKCS11SearchFinalizer interface {
	FindObjectsFinal(session pkcs11.SessionHandle) error
}

// ClearFailedPKCS11Search finalizes whatever search a failed
// C_FindObjectsInit left open on session and returns initErr, joined with the
// Final's own failure. Every caller of C_FindObjectsInit calls it when Init
// fails.
//
// A token may mark the session as searching before the rest of
// C_FindObjectsInit fails: SoftHSM2 does when it cannot read an object's
// attributes while another session is writing one (CKR_GENERAL_ERROR). Nothing
// would ever finalize that search, so every later C_FindObjectsInit on the
// session fails CKR_OPERATION_ACTIVE -- one failed search under write
// contention poisons the session for every later user. C_FindObjectsFinal
// clears it; CKR_OPERATION_NOT_INITIALIZED means there was nothing to clear.
func ClearFailedPKCS11Search(ctx PKCS11SearchFinalizer, session pkcs11.SessionHandle, initErr error) error {
	finalErr := ctx.FindObjectsFinal(session)
	if finalErr == nil || isCKR(finalErr, pkcs11.CKR_OPERATION_NOT_INITIALIZED) {
		return initErr
	}
	return errors.Join(initErr, finalErr)
}
