// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration && gcpkms

package sshbackend

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestSSHBackend_GCPKMS proves SSH key generation + signing on the GCP Cloud KMS
// backend. GCP has no emulator, so the test uses the real backend code over a
// self-consistent mock client backed by one in-memory ECDSA-P256 key: GetPublicKey
// returns that key's PKIX PEM and AsymmetricSign signs with it (GCP returns ASN.1
// DER for ECDSA), so the SSH signature genuinely verifies. ECDSA-P256 is the only
// SSH-valid algorithm on GCP (RSA is PKCS1v15 too, but ECDSA is the cross-cloud
// default); ed25519 is unsupported and must be rejected.
func TestSSHBackend_GCPKMS(t *testing.T) {
	ec, pubPEM := newECDSAKeyPEM(t)

	mock := &gcpkms.MockKMSClient{
		GetPublicKeyFunc: func(context.Context, *kmspb.GetPublicKeyRequest, ...interface{}) (*kmspb.PublicKey, error) {
			return &kmspb.PublicKey{Pem: pubPEM, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}, nil
		},
		AsymmetricSignFunc: func(_ context.Context, req *kmspb.AsymmetricSignRequest, _ ...interface{}) (*kmspb.AsymmetricSignResponse, error) {
			sig, err := ecdsa.SignASN1(rand.Reader, ec, req.GetDigest().GetSha256())
			if err != nil {
				return nil, err
			}
			return &kmspb.AsymmetricSignResponse{Signature: sig}, nil
		},
	}

	keyStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend (keys): %v", err)
	}
	certStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend (certs): %v", err)
	}

	be, err := gcpkms.NewBackendWithClient(&gcpkms.Config{
		ProjectID:   "test-project",
		LocationID:  "us-east1",
		KeyRingID:   "ssh-backend-test",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, mock)
	if err != nil {
		t.Fatalf("gcpkms.NewBackendWithClient: %v", err)
	}

	runMatrix(t, resolverFor("gcpkms", be), "gcpkms", cloudAlgos, true)
	assertRejects(t, resolverFor("gcpkms", be), "gcpkms", keys.AlgorithmEd25519)
}
