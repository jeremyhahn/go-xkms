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

package module

import (
	"bytes"
	"testing"
)

// gcmInitIV is the IV a CK_GCM_PARAMS on C_MessageEncryptInit chose, which
// applyGCMMessageIV either keeps, replaces or clears.
var gcmInitIV = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

func newGCMMessageOperation() *EncryptOperation {
	op := newEncryptOperation(&Mechanism{Type: CKM_AES_GCM}, 1, "key", "backend")
	op.SetIV(gcmInitIV)
	return op
}

func TestApplyGCMMessageIV_CallerIV(t *testing.T) {
	callerIV := []byte{11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	op := newGCMMessageOperation()

	applyGCMMessageIV(op, &AESGCMMessageParams{IV: callerIV, IVGenerator: CKG_NO_GENERATE})

	if !bytes.Equal(op.IV(), callerIV) {
		t.Fatalf("CKG_NO_GENERATE must seal under the caller's pIv: got %x, want %x", op.IV(), callerIV)
	}
}

func TestApplyGCMMessageIV_GeneratorClearsIV(t *testing.T) {
	// The generator replaces whatever IV the operation was initialised with,
	// even when the caller also left an IV in pIv: the token's IV is the one
	// handed back (v3.2 §6.13.7). The counter generators never get here:
	// validateGCMMessageIVGeneration refuses them first.
	for _, generator := range []IVGenerator{CKG_GENERATE, CKG_GENERATE_RANDOM} {
		op := newGCMMessageOperation()

		applyGCMMessageIV(op, &AESGCMMessageParams{IV: gcmInitIV, IVGenerator: generator})

		if len(op.IV()) != 0 {
			t.Errorf("generator %#x left IV %x on the operation; it must be empty so the backend generates one",
				generator, op.IV())
		}
	}
}

func TestApplyGCMMessageIV_NilParamsKeepsIV(t *testing.T) {
	op := newGCMMessageOperation()

	applyGCMMessageIV(op, nil)

	if !bytes.Equal(op.IV(), gcmInitIV) {
		t.Fatalf("nil params must leave the operation's IV unchanged: got %x, want %x", op.IV(), gcmInitIV)
	}
}
