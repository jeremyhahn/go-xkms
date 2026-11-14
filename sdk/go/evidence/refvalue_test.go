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

package evidence

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
)

// TestVerifySignedCoRIM_ReExport proves the SDK name is wired to the
// primitive: trust-source validation and malformed input surface the
// package's errors through the SDK aliases.
func TestVerifySignedCoRIM_ReExport(t *testing.T) {
	if _, err := VerifySignedCoRIM([]byte{0x01}, CoRIMVerifyOptions{}); !errors.Is(err, ErrCoRIMTrustSource) {
		t.Fatalf("no trust source: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if _, err := VerifySignedCoRIM([]byte{0x01}, CoRIMVerifyOptions{PublicKey: key.Public()}); !errors.Is(err, ErrCoRIMMalformed) {
		t.Fatalf("malformed: %v", err)
	}
}

// TestSignCoRIM_ReExport proves the SDK's SignCoRIM signs a CoRIM that
// VerifySignedCoRIM accepts under the signer's public key, and refuses a
// missing signer and a malformed CoRIM with the re-exported errors.
func TestSignCoRIM_ReExport(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	unsigned, err := appraisaltest.UnsignedCoRIM(map[uint32][]byte{0: make([]byte, 32)})
	if err != nil {
		t.Fatalf("unsigned corim: %v", err)
	}
	signed, err := SignCoRIM(unsigned, CoRIMMeta{SignerName: "Acme"}, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	manifest, err := VerifySignedCoRIM(signed, CoRIMVerifyOptions{PublicKey: key.Public()})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if manifest.Signer != "Acme" {
		t.Fatalf("signer = %q, want Acme", manifest.Signer)
	}

	if _, err := SignCoRIM(unsigned, CoRIMMeta{SignerName: "Acme"}, nil); !errors.Is(err, ErrCoRIMSignerKey) {
		t.Fatalf("no signer: %v", err)
	}
	if _, err := SignCoRIM([]byte{0xff}, CoRIMMeta{SignerName: "Acme"}, key); !errors.Is(err, ErrCoRIMMalformed) {
		t.Fatalf("malformed: %v", err)
	}
}

func TestReferenceManifestPCRDigests_ReExport(t *testing.T) {
	m := &ReferenceManifest{ReferenceValues: []ReferenceValue{{Measurements: []ReferenceMeasurement{{
		Key: MeasurementKey{Kind: MeasurementKeyUint, Uint: 30},
	}}}}}
	if _, err := m.PCRDigests(crypto.SHA256); !errors.Is(err, ErrCoRIMPCRIndex) {
		t.Fatalf("out-of-range index: %v", err)
	}
}
