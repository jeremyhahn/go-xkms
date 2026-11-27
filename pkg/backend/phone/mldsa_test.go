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

package phone

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mldsaTestKey generates an ML-DSA key with the standard library and returns
// it with its SubjectPublicKeyInfo DER, as the phone sends it (#2405).
func mldsaTestKey(t *testing.T, params mldsa.Parameters) (*mldsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return priv, der
}

func mldsaAttrs(cn string, algo types.QuantumAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                cn,
		KeyAlgorithm:      x509.MLDSA,
		QuantumAttributes: &types.QuantumAttributes{Algorithm: algo},
	}
}

// decodeParams re-encodes a request's params into out, whatever Go type the
// backend used for them.
func decodeParams(t *testing.T, req *pairingproto.Request, out any) {
	t.Helper()
	data, err := json.Marshal(req.Params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
}

func TestAlgorithmMapping_MLDSA(t *testing.T) {
	sets, ok := algorithmMapping[x509.MLDSA]
	if !ok {
		t.Fatal("algorithmMapping has no x509.MLDSA entry")
	}
	for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		if sets[name] != name {
			t.Errorf("algorithmMapping[MLDSA][%q] = %q, want %q", name, sets[name], name)
		}
	}
}

func TestMapAlgorithm_MLDSA(t *testing.T) {
	cases := map[types.QuantumAlgorithm]string{
		types.QuantumAlgorithmMLDSA44: "ML-DSA-44",
		types.QuantumAlgorithmMLDSA65: "ML-DSA-65",
		types.QuantumAlgorithmMLDSA87: "ML-DSA-87",
	}
	for algo, want := range cases {
		got, err := mapAlgorithm(mldsaAttrs("k", algo))
		if err != nil {
			t.Fatalf("mapAlgorithm(%s): %v", algo, err)
		}
		if got != want {
			t.Errorf("mapAlgorithm(%s) = %q, want %q", algo, got, want)
		}
	}

	// QuantumAttributes alone (KeyAlgorithm unset) names the key too.
	attrs := &types.KeyAttributes{QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA44}}
	if got, err := mapAlgorithm(attrs); err != nil || got != "ML-DSA-44" {
		t.Errorf("mapAlgorithm(quantum only) = %q, %v; want ML-DSA-44", got, err)
	}

	for _, bad := range []*types.KeyAttributes{
		{KeyAlgorithm: x509.MLDSA},
		mldsaAttrs("k", types.QuantumAlgorithmMLKEM768),
	} {
		if _, err := mapAlgorithm(bad); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("mapAlgorithm(%+v) err = %v, want ErrUnsupportedAlgorithm", bad, err)
		}
	}
}

func TestMapAlgorithmToAttributes_MLDSA(t *testing.T) {
	for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		_, keyAlgo, ecc, rsaAttrs := mapAlgorithmToAttributes(name, 0)
		if keyAlgo != x509.MLDSA || ecc != nil || rsaAttrs != nil {
			t.Errorf("mapAlgorithmToAttributes(%q) = %v, %v, %v; want MLDSA, nil, nil", name, keyAlgo, ecc, rsaAttrs)
		}
	}
	attrs := mapKeyInfoToAttributes(&pairingproto.KeyInfo{KeyID: "pq", Algorithm: "ML-DSA-65"})
	if attrs.QuantumAttributes == nil || attrs.QuantumAttributes.Algorithm != types.QuantumAlgorithmMLDSA65 {
		t.Errorf("mapKeyInfoToAttributes(ML-DSA-65).QuantumAttributes = %+v", attrs.QuantumAttributes)
	}
}

func TestParsePublicKey_MLDSA(t *testing.T) {
	priv, der := mldsaTestKey(t, mldsa.MLDSA87())
	pub, err := parsePublicKey(der, "ML-DSA-87")
	if err != nil {
		t.Fatalf("parsePublicKey: %v", err)
	}
	mpub, ok := pub.(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("parsePublicKey returned %T, want *mldsa.PublicKey", pub)
	}
	if !mpub.Equal(priv.PublicKey()) {
		t.Error("parsed ML-DSA public key differs from the generated one")
	}

	// An SPKI whose parameter set differs from the named algorithm is refused.
	if _, err := parsePublicKey(der, "ML-DSA-44"); !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("parsePublicKey(87 key, ML-DSA-44) err = %v, want ErrInvalidPublicKey", err)
	}
}

// TestBackend_GenerateKey_MLDSA_SignVerify drives generateKey and a pure
// ML-DSA sign through the phone protocol and verifies the signature with
// crypto/mldsa (#2405).
func TestBackend_GenerateKey_MLDSA_SignVerify(t *testing.T) {
	priv, der := mldsaTestKey(t, mldsa.MLDSA65())
	msg := []byte("phone ML-DSA message")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
			switch req.Method {
			case pairingproto.MethodLocalGenerateKey:
				var p pairingproto.LocalGenerateKeyParams
				decodeParams(t, req, &p)
				if p.Algorithm != "ML-DSA-65" {
					t.Errorf("generateKey algorithm = %q, want ML-DSA-65", p.Algorithm)
				}
				return mockSuccessResponse(pairingproto.LocalGenerateKeyResult{
					KeyID: p.KeyID, PublicKeyDER: der, Algorithm: "ML-DSA-65",
				}), nil
			case pairingproto.MethodLocalSign:
				var p pairingproto.LocalSignParams
				decodeParams(t, req, &p)
				if p.Algorithm != "ML-DSA-65" {
					t.Errorf("sign algorithm = %q, want ML-DSA-65", p.Algorithm)
				}
				sig, err := priv.Sign(nil, p.Data, crypto.Hash(0))
				if err != nil {
					return nil, err
				}
				return mockSuccessResponse(pairingproto.LocalSignResult{Signature: sig, Algorithm: "ML-DSA-65"}), nil
			default:
				return nil, errors.New("unexpected method " + req.Method)
			}
		},
	}

	b := newTestBackend(t, sender)
	key, err := b.GenerateKey(context.Background(), mldsaAttrs("pq-key", types.QuantumAlgorithmMLDSA65))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("GenerateKey returned %T, want crypto.Signer", key)
	}
	pub, ok := signer.Public().(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *mldsa.PublicKey", signer.Public())
	}

	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := mldsa.Verify(pub, msg, sig, nil); err != nil {
		t.Fatalf("mldsa.Verify: %v", err)
	}

	// Pure ML-DSA signs the message: a pre-hash option is refused.
	if _, err := signer.Sign(nil, msg, crypto.SHA256); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("Sign with SHA256 opts err = %v, want ErrUnsupportedAlgorithm", err)
	}
}
