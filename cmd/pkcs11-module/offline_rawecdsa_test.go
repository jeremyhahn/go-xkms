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

package main

import (
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// p384OID is the DER-encoded OID of NIST P-384 (secp384r1), CKA_EC_PARAMS.
var p384OID = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}

// TestOffline_RawCKMECDSA signs caller-built digests with raw CKM_ECDSA on the
// offline module's software keystore, the mechanism strongSwan's pkcs11 plugin
// uses: it hashes locally and hands the token only the digest. PKCS#11 v3.2
// §6.3.4 gives CKM_ECDSA no fixed input length -- a digest longer than the
// curve order is truncated -- so every curve must accept 32-, 48- and 64-byte
// digests. Each signature must verify through the module, and the same
// signature must not verify over a changed digest.
func TestOffline_RawCKMECDSA(t *testing.T) {
	offlineEnv(t, sealStrategyNone)

	if rv, _ := callC(t, C_Initialize, cNull()); rv != module.CKR_OK {
		t.Fatalf("C_Initialize = %s, want CKR_OK", rv)
	}
	m := module.GetGlobalModule()
	session := provisionOfflineToken(t, m)

	curves := []struct {
		name   string
		params []byte
	}{
		{"P-256", p256OID},
		{"P-384", p384OID},
	}
	for _, curve := range curves {
		label := "raw-" + curve.name
		pub, priv, rv := m.GenerateKeyPair(session, &module.Mechanism{Type: module.CKM_EC_KEY_PAIR_GEN},
			[]module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
				module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
				module.NewStringAttribute(module.CKA_LABEL, label),
				module.NewAttribute(module.CKA_EC_PARAMS, curve.params),
				module.NewBoolAttribute(module.CKA_VERIFY, true),
				module.NewBoolAttribute(module.CKA_TOKEN, false),
			},
			[]module.Attribute{
				module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
				module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_EC)),
				module.NewStringAttribute(module.CKA_LABEL, label),
				module.NewBoolAttribute(module.CKA_SIGN, true),
				module.NewBoolAttribute(module.CKA_TOKEN, false),
			})
		if rv != module.CKR_OK {
			t.Fatalf("%s: GenerateKeyPair: %s", curve.name, rv)
		}

		for _, size := range []int{32, 48, 64} {
			digest := make([]byte, size)
			if _, err := rand.Read(digest); err != nil {
				t.Fatalf("rand: %v", err)
			}

			if rv := m.SignInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, priv); rv != module.CKR_OK {
				t.Fatalf("%s/%d: SignInit: %s", curve.name, size, rv)
			}
			signature, rv := m.Sign(session, digest)
			if rv != module.CKR_OK {
				t.Fatalf("%s/%d: raw CKM_ECDSA Sign = %s, want CKR_OK", curve.name, size, rv)
			}
			// C_Sign ends the operation once the signature is delivered.
			if rv := m.FinishOperation(session, module.OperationSign); rv != module.CKR_OK {
				t.Fatalf("%s/%d: FinishOperation(sign): %s", curve.name, size, rv)
			}

			if rv := m.VerifyInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, pub); rv != module.CKR_OK {
				t.Fatalf("%s/%d: VerifyInit: %s", curve.name, size, rv)
			}
			if rv := m.Verify(session, digest, signature); rv != module.CKR_OK {
				t.Fatalf("%s/%d: Verify of the module's own signature = %s, want CKR_OK", curve.name, size, rv)
			}

			digest[0] ^= 0xff
			if rv := m.VerifyInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, pub); rv != module.CKR_OK {
				t.Fatalf("%s/%d: VerifyInit: %s", curve.name, size, rv)
			}
			if rv := m.Verify(session, digest, signature); rv != module.CKR_SIGNATURE_INVALID {
				t.Fatalf("%s/%d: Verify over a changed digest = %s, want CKR_SIGNATURE_INVALID", curve.name, size, rv)
			}
		}
	}
}
