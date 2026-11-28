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

package trustedca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
)

// The possession-request signing vector, copied as test data from
// pkg/acme/challenges/device-attest-01/possession_test.go.
const (
	possessionVectorNonce               = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	possessionVectorClaims              = "a30a5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1901005101a1b2c3d4e5f60718293a4b5c6d7e8f9019011181821901025854a50050bcc710071a6653c1967ef0d3d5ede421016374667702a2181f6374667718210103a111a20782015820ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad1818636170700c00"
	possessionVectorApplicationEvidence = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	possessionSigningPrivateKey         = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
	possessionSigningSignature          = "3045022100988e2c169e224acc501b7d6726feab417d9a122279f0cc5af3e90469a3bf77fb02202804c18ee8905d81103b627d87606da1d074b1a01faaa05044fa99b0725f0956"
	possessionSigningCSRSHA256          = "4dfccbaa3825ba37a3378621efff198ddc58b00a0bb52111cde87519f4dab6d2"
)

// The SDK names are the deviceattest01 values themselves.
var (
	_ func([]byte, []byte) ([]byte, error)                            = AssemblePossessionCSR
	_ func(*ecdsa.PublicKey, *dice.ClaimsSet, []byte) ([]byte, error) = BuildPossessionCRI
	_ func(crypto.Signer, *dice.ClaimsSet, []byte) ([]byte, error)    = SignPossessionCSR
	_ func(string) []byte                                             = DICENonce
	_ func(*x509.CertificateRequest) (*PossessionRequest, error)      = ParsePossessionCSR
	_ *deviceattest01.PossessionRequest                               = (*PossessionRequest)(nil)
)

func possessionHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func possessionVector(t *testing.T) (*ecdsa.PrivateKey, *dice.ClaimsSet, []byte) {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), possessionHex(t, possessionSigningPrivateKey))
	if err != nil {
		t.Fatalf("ParseRawPrivateKey: %v", err)
	}
	claims, err := dice.ParseClaimsSet(possessionHex(t, possessionVectorClaims))
	if err != nil {
		t.Fatalf("ParseClaimsSet: %v", err)
	}
	return key, claims, possessionHex(t, possessionVectorNonce)
}

func TestAssemblePossessionCSR_SigningVector(t *testing.T) {
	key, claims, nonce := possessionVector(t)

	cri, err := BuildPossessionCRI(&key.PublicKey, claims, nonce)
	if err != nil {
		t.Fatalf("BuildPossessionCRI: %v", err)
	}
	// A nil random source makes crypto/ecdsa sign deterministically, per RFC 6979.
	digest := sha256.Sum256(cri)
	signature, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := hex.EncodeToString(signature); got != possessionSigningSignature {
		t.Fatalf("signature = %s, want %s", got, possessionSigningSignature)
	}

	csrDER, err := AssemblePossessionCSR(cri, signature)
	if err != nil {
		t.Fatalf("AssemblePossessionCSR: %v", err)
	}
	csrDigest := sha256.Sum256(csrDER)
	if got := hex.EncodeToString(csrDigest[:]); got != possessionSigningCSRSHA256 {
		t.Fatalf("CSR SHA-256 = %s, want %s", got, possessionSigningCSRSHA256)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	request, err := ParsePossessionCSR(csr)
	if err != nil {
		t.Fatalf("ParsePossessionCSR: %v", err)
	}
	if want := possessionHex(t, possessionVectorApplicationEvidence); !bytes.Equal(request.ApplicationEvidence, want) {
		t.Fatalf("ApplicationEvidence = %x, want %x", request.ApplicationEvidence, want)
	}

	// SignPossessionCSR signs with crypto/rand, so only its parse is checked.
	signedDER, err := SignPossessionCSR(key, claims, nonce)
	if err != nil {
		t.Fatalf("SignPossessionCSR: %v", err)
	}
	signedCSR, err := x509.ParseCertificateRequest(signedDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest(signed): %v", err)
	}
	signed, err := ParsePossessionCSR(signedCSR)
	if err != nil {
		t.Fatalf("ParsePossessionCSR(signed): %v", err)
	}
	if !key.PublicKey.Equal(signed.PublicKey) {
		t.Fatal("SignPossessionCSR request public key is not the signer's")
	}
}

func TestAssemblePossessionCSR_Refusals(t *testing.T) {
	key, claims, nonce := possessionVector(t)
	cri, err := BuildPossessionCRI(&key.PublicKey, claims, nonce)
	if err != nil {
		t.Fatalf("BuildPossessionCRI: %v", err)
	}
	digest := sha256.Sum256(cri)
	signature, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cases := []struct {
		name     string
		call     func() error
		sdk, pkg error
	}{
		{
			name: "cri with a trailing byte",
			call: func() error {
				_, err := AssemblePossessionCSR(append(append([]byte{}, cri...), 0x00), signature)
				return err
			},
			sdk: ErrPossessionCSRMalformed,
			pkg: deviceattest01.ErrPossessionCSRMalformed,
		},
		{
			name: "signature not an ECDSA-Sig-Value",
			call: func() error {
				_, err := AssemblePossessionCSR(cri, []byte{0x01})
				return err
			},
			sdk: ErrPossessionSignatureInvalid,
			pkg: deviceattest01.ErrPossessionSignatureInvalid,
		},
		{
			name: "nil signer",
			call: func() error {
				_, err := SignPossessionCSR(nil, claims, nonce)
				return err
			},
			sdk: ErrPossessionSigningFailed,
			pkg: deviceattest01.ErrPossessionSigningFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if !errors.Is(err, tc.sdk) {
				t.Fatalf("err = %v, want the SDK sentinel %v", err, tc.sdk)
			}
			if !errors.Is(err, tc.pkg) {
				t.Fatalf("err = %v, want the deviceattest01 sentinel %v", err, tc.pkg)
			}
		})
	}
	if !errors.Is(ErrPossessionMeasurementsShape, deviceattest01.ErrPossessionMeasurementsShape) {
		t.Fatal("ErrPossessionMeasurementsShape is not the deviceattest01 sentinel")
	}
}

func TestDICENonce(t *testing.T) {
	const keyAuth = "token.thumbprint"
	want := sha256.Sum256([]byte(keyAuth))
	got := DICENonce(keyAuth)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("DICENonce = %x, want %x", got, want)
	}
	if !bytes.Equal(got, deviceattest01.DICENonce(keyAuth)) {
		t.Fatal("DICENonce differs from deviceattest01.DICENonce")
	}
}
