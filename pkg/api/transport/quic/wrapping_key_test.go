// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package quic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"sync"
)

var (
	testWrappingKeyOnce sync.Once
	testWrappingKeyPEM  string
)

// testWrappingPublicKeyPEM returns a real PKIX public key in PEM, the shape
// the REST import-parameters response carries, so a mock server answers with
// what the transport has to decode.
func testWrappingPublicKeyPEM() string {
	testWrappingKeyOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			panic(err)
		}
		testWrappingKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	})
	return testWrappingKeyPEM
}
