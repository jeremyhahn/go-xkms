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

package avr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	aggeneric "github.com/jeremyhahn/trusted-firmware/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These measure the host side only. Nothing here is a measurement of a device:
// a 16 MHz part answering over a serial line dominates any round trip by
// orders of magnitude, and a benchmark that included one would be measuring
// the link. What is worth watching is that the answers this backend gives
// WITHOUT a round trip stay free -- a capability report that allocated per
// call would be paid on every request a service serves.

func BenchmarkCapabilities(b *testing.B) {
	backend := benchBackend(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = backend.Capabilities()
	}
}

func BenchmarkAttestLevel(b *testing.B) {
	backend := benchBackend(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := backend.AttestLevel(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAlgorithmsNamed(b *testing.B) {
	backend := benchBackend(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = backend.Algorithms().Named()
	}
}

func BenchmarkListKeys(b *testing.B) {
	backend := benchBackend(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := backend.ListKeys(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewDeviceKey(b *testing.B) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	point := make([]byte, devicePointLen)
	key.X.FillBytes(point[:32])
	key.Y.FillBytes(point[32:])

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := newDeviceKey(point, aggeneric.SlotDeviceID, DefaultKeyCN); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeviceError(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := deviceError(aggeneric.StatusErrNotProvisioned); err == nil {
			b.Fatal("expected an error")
		}
	}
}

func benchBackend(b *testing.B) *Backend {
	b.Helper()
	link := newFakeLink().answer(aggeneric.CmdCaps, capsPayload(
		aggeneric.CryptoSecureElement,
		aggeneric.FeatureAttest,
		aggeneric.AlgECDSAP256SHA256|aggeneric.AlgHMACSHA256,
	))
	backend, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = backend.Close() })
	var _ types.KeyProvider = backend
	return backend
}

// The attestation path against a device that answers instantly. The link is
// not the measurement -- a real part spends milliseconds per page -- so what
// this watches is the cost of the checks: parsing 471 bytes of DER, walking
// the extension, decoding the claims set and comparing the nonce.
func BenchmarkCheckAliasCertificate(b *testing.B) {
	der, err := hex.DecodeString(vecAliasCertHex)
	if err != nil {
		b.Fatal(err)
	}
	nonce, err := hex.DecodeString(vecAliasCertNonceHex)
	if err != nil {
		b.Fatal(err)
	}
	backend := benchBackend(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := backend.checkAliasCertificate(der, nonce); err != nil {
			b.Fatal(err)
		}
	}
}
