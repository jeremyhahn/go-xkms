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

package checkpoint

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"sync"
	"testing"
)

// rsaTestKey is generated once: RSA key generation dominates test time.
var rsaTestKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// builtinCase is a key for one built-in algorithm and the options NewSigner
// needs to select it.
type builtinCase struct {
	id   string
	key  crypto.Signer
	opts []SignerOption
}

// builtinCases returns one signing key per built-in algorithm.
func builtinCases(t *testing.T) []builtinCase {
	t.Helper()
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	ec := func(curve elliptic.Curve) *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa: %v", err)
		}
		return key
	}
	ml := func(params mldsa.Parameters) *mldsa.PrivateKey {
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatalf("mldsa: %v", err)
		}
		return key
	}
	named := func(id string) []SignerOption {
		return []SignerOption{WithAlgorithm(id)}
	}
	return []builtinCase{
		{id: AlgorithmEd25519, key: edKey},
		{id: AlgorithmECDSA, key: ec(elliptic.P256())},
		{id: AlgorithmECDSA, key: ec(elliptic.P384())},
		{id: AlgorithmECDSA, key: ec(elliptic.P521())},
		{id: AlgorithmECDSAP224SHA256, key: ec(elliptic.P224())},
		{id: AlgorithmECDSAP384SHA384, key: ec(elliptic.P384()), opts: named(AlgorithmECDSAP384SHA384)},
		{id: AlgorithmECDSAP521SHA512, key: ec(elliptic.P521()), opts: named(AlgorithmECDSAP521SHA512)},
		{id: AlgorithmRSAPKCS1SHA256, key: rsaTestKey(), opts: named(AlgorithmRSAPKCS1SHA256)},
		{id: AlgorithmRSAPKCS1SHA384, key: rsaTestKey(), opts: named(AlgorithmRSAPKCS1SHA384)},
		{id: AlgorithmRSAPKCS1SHA512, key: rsaTestKey(), opts: named(AlgorithmRSAPKCS1SHA512)},
		{id: AlgorithmRSAPSSSHA256, key: rsaTestKey(), opts: named(AlgorithmRSAPSSSHA256)},
		{id: AlgorithmRSAPSSSHA384, key: rsaTestKey(), opts: named(AlgorithmRSAPSSSHA384)},
		{id: AlgorithmRSAPSSSHA512, key: rsaTestKey(), opts: named(AlgorithmRSAPSSSHA512)},
		{id: AlgorithmMLDSA44, key: ml(mldsa.MLDSA44())},
		{id: AlgorithmMLDSA65, key: ml(mldsa.MLDSA65())},
		{id: AlgorithmMLDSA87, key: ml(mldsa.MLDSA87())},
	}
}

// newEd25519Signer returns a Signer for a fresh Ed25519 key.
func newEd25519Signer(t *testing.T, name string) *Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	s, err := NewSigner(name, key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

// isolateRegistry restores the algorithm registry when the test ends, so a
// test that registers algorithms leaves no trace.
func isolateRegistry(t *testing.T) {
	t.Helper()
	saved := algorithms.Load()
	t.Cleanup(func() { algorithms.Store(saved) })
}

// fakeSigner is a crypto.Signer with a fixed public key that returns a fixed
// signature or error.
type fakeSigner struct {
	pub crypto.PublicKey
	sig []byte
	err error
}

func (f *fakeSigner) Public() crypto.PublicKey { return f.pub }

func (f *fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return f.sig, f.err
}
