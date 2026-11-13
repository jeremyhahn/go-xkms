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

package attestation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

// BenchmarkVerifySignature benchmarks signature verification
func BenchmarkVerifySignature(b *testing.B) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	data := []byte("test attestation data")
	h := sha256.Sum256(data)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       data,
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.VerifySignature(stmt, opts)
	}
}
