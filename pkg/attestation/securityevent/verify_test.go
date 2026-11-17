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

package securityevent_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/securityevent"
)

// testDevice stands in for a device that signs evidence carrying the
// Verifier's eat_nonce and the record's Detached Submodule Digest. Its
// evidence is sig(64) || len(nonce) || nonce || dsd, signed with ed25519.
type testDevice struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newTestDevice(t *testing.T) testDevice {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{priv: priv, pub: pub}
}

func (d testDevice) sign(nonce, dsd []byte) []byte {
	payload := append([]byte{byte(len(nonce))}, nonce...)
	payload = append(payload, dsd...)
	return append(ed25519.Sign(d.priv, payload), payload...)
}

var errBadSignature = errors.New("test: bad signature")

// verifier authenticates the device's evidence and returns its claims.
func (d testDevice) verifier() securityevent.EvidenceVerifier {
	return func(evidence []byte) ([]byte, []byte, error) {
		if len(evidence) < ed25519.SignatureSize+1 {
			return nil, nil, errBadSignature
		}
		sig, payload := evidence[:ed25519.SignatureSize], evidence[ed25519.SignatureSize:]
		if !ed25519.Verify(d.pub, payload, sig) {
			return nil, nil, errBadSignature
		}
		n := int(payload[0])
		if len(payload) < 1+n {
			return nil, nil, errBadSignature
		}
		return payload[1 : 1+n], payload[1+n:], nil
	}
}

func TestVerify_SignatureNonceAndBinding(t *testing.T) {
	dev := newTestDevice(t)
	cs := encodedRecord(t)
	nonce := []byte("verifier-challenge-0001")
	dsd, err := securityevent.DetachedDigest(cs, securityevent.AlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	evidence := dev.sign(nonce, dsd)

	rec, err := securityevent.Verify(cs, evidence, nonce, dev.verifier())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want, err := securityevent.Decode(cs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := securityevent.Encode(rec)
	if err != nil {
		t.Fatal(err)
	}
	wantEnc, err := securityevent.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantEnc) {
		t.Fatalf("Verify returned a different record")
	}
}

func TestVerify_Refusals(t *testing.T) {
	dev := newTestDevice(t)
	other := newTestDevice(t)
	cs := encodedRecord(t)
	nonce := []byte("verifier-challenge-0001")
	dsd, err := securityevent.DetachedDigest(cs, securityevent.AlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	good := dev.sign(nonce, dsd)
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0x01

	cases := []struct {
		name     string
		cs       []byte
		evidence []byte
		nonce    []byte
		verify   securityevent.EvidenceVerifier
		want     error
	}{
		{"signature by another device", cs, other.sign(nonce, dsd), nonce, dev.verifier(), securityevent.ErrEvidence},
		{"evidence tampered", cs, tampered, nonce, dev.verifier(), securityevent.ErrEvidence},
		{"stale nonce", cs, dev.sign([]byte("an-earlier-challenge"), dsd), nonce, dev.verifier(), securityevent.ErrNonceMismatch},
		{"nonce prefix", cs, dev.sign(nonce[:4], dsd), nonce, dev.verifier(), securityevent.ErrNonceMismatch},
		{"evidence over another record", cs, dev.sign(nonce, mustDigest(t, []byte{0xa0})), nonce, dev.verifier(), securityevent.ErrDigestMismatch},
		{"no nonce", cs, good, nil, dev.verifier(), securityevent.ErrNonceMismatch},
		{"no verifier", cs, good, nonce, nil, securityevent.ErrEvidence},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := securityevent.Verify(tc.cs, tc.evidence, tc.nonce, tc.verify); !errors.Is(err, tc.want) {
				t.Fatalf("Verify err = %v, want %v", err, tc.want)
			}
		})
	}
}

func mustDigest(t *testing.T, cs []byte) []byte {
	t.Helper()
	dsd, err := securityevent.DetachedDigest(cs, securityevent.AlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return dsd
}
