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

//go:build integration && gcpkms

package integration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// emulatorEndpoint returns the floci-gcp Cloud KMS emulator endpoint.
// Defaults to localhost:4588; the docker-compose lane overrides it via
// GCPKMS_EMULATOR_ENDPOINT to reach the floci-gcp service container.
func emulatorEndpoint() string {
	if ep := os.Getenv("GCPKMS_EMULATOR_ENDPOINT"); ep != "" {
		return ep
	}
	return "localhost:4588"
}

// ensureEmulatorKeyRing creates the key ring on the emulator if it does not
// already exist. The gcpkms backend requires the key ring to be provisioned
// out of band, matching real GCP KMS behavior.
func ensureEmulatorKeyRing(ctx context.Context, endpoint, projectID, location, keyRing string) error {
	client, err := kms.NewKeyManagementClient(ctx,
		option.WithEndpoint(endpoint),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
	if err != nil {
		return err
	}
	defer client.Close()

	parent := "projects/" + projectID + "/locations/" + location
	_, err = client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    parent,
		KeyRingId: keyRing,
	})
	if status.Code(err) == codes.AlreadyExists {
		return nil
	}
	return err
}

// TestGCPKMSEmulator tests the GCP KMS backend against the floci-gcp Cloud
// KMS emulator over real gRPC. Unlike TestGCPKMSMock, signatures produced
// here are real and are cryptographically verified against the public key.
//
// Emulator algorithm coverage (floci-gcp): GOOGLE_SYMMETRIC_ENCRYPTION,
// EC_SIGN_P256_SHA256, RSA_SIGN_PKCS1_{2048,3072,4096}_SHA256 and
// RSA_DECRYPT_OAEP. EC P-384 and RSA-PSS remain covered by TestGCPKMSMock
// and the opt-in real-cloud suite.
func TestGCPKMSEmulator(t *testing.T) {
	ctx := context.Background()
	endpoint := emulatorEndpoint()

	const (
		projectID = "test-project"
		location  = "global"
		keyRing   = "xkms-integration"
	)

	require.NoError(t, ensureEmulatorKeyRing(ctx, endpoint, projectID, location, keyRing),
		"failed to provision key ring on emulator at %s", endpoint)

	cfg := &gcpkms.Config{
		ProjectID:   projectID,
		LocationID:  location,
		KeyRingID:   keyRing,
		Endpoint:    endpoint,
		Insecure:    true,
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := gcpkms.NewBackend(ctx, cfg)
	require.NoError(t, err, "failed to create GCP KMS backend against emulator")
	defer b.Close()

	t.Run("RSASignAndVerify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "emulator-rsa-pkcs1",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		signer, err := b.GenerateRSA(ctx, attrs)
		require.NoError(t, err, "failed to generate RSA key on emulator")
		require.NotNil(t, signer)

		digest := sha256.Sum256([]byte("gcpkms emulator rsa pkcs1 signing"))
		signature, err := b.Sign(attrs, digest[:], crypto.SHA256)
		require.NoError(t, err, "failed to sign with RSA key")
		require.NotEmpty(t, signature)

		// Backend-side verification
		require.NoError(t, b.Verify(attrs, digest[:], signature))

		// Independent local verification against the public key proves the
		// emulator produced a real RSASSA-PKCS1-v1_5 signature.
		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "expected *rsa.PublicKey, got %T", signer.Public())
		require.NoError(t, rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature))

		// Corrupted signature must fail verification
		bad := append([]byte(nil), signature...)
		bad[0] ^= 0xFF
		assert.Error(t, rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], bad))
	})

	t.Run("ECDSASignAndVerify", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "emulator-ecdsa-p256",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		signer, err := b.GenerateECDSA(ctx, attrs)
		require.NoError(t, err, "failed to generate ECDSA P-256 key on emulator")
		require.NotNil(t, signer)

		digest := sha256.Sum256([]byte("gcpkms emulator ecdsa p256 signing"))
		signature, err := b.Sign(attrs, digest[:], crypto.SHA256)
		require.NoError(t, err, "failed to sign with ECDSA key")
		require.NotEmpty(t, signature)

		require.NoError(t, b.Verify(attrs, digest[:], signature))

		ecPub, ok := signer.Public().(*ecdsa.PublicKey)
		require.True(t, ok, "expected *ecdsa.PublicKey, got %T", signer.Public())
		require.True(t, ecdsa.VerifyASN1(ecPub, digest[:], signature),
			"emulator ECDSA signature failed local verification")

		otherDigest := sha256.Sum256([]byte("a different message"))
		assert.False(t, ecdsa.VerifyASN1(ecPub, otherDigest[:], signature))
	})

	t.Run("SignerRetrieval", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "emulator-signer-lookup",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		_, err := b.GenerateECDSA(ctx, attrs)
		require.NoError(t, err)

		signer, err := b.Signer(ctx, attrs)
		require.NoError(t, err, "failed to retrieve signer for existing key")
		require.NotNil(t, signer.Public(), "public key should be retrievable from emulator")
	})

	t.Run("SymmetricEncryptDecrypt", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:                 "emulator-aes256",
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_GCPKMS,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}

		key, err := b.GenerateSymmetricKey(ctx, attrs)
		require.NoError(t, err, "failed to generate symmetric key on emulator")
		require.NotNil(t, key)

		encrypter, err := b.SymmetricEncrypter(ctx, attrs)
		require.NoError(t, err)

		plaintext := []byte("gcpkms emulator symmetric round-trip")
		encrypted, err := encrypter.Encrypt(plaintext, nil)
		require.NoError(t, err, "failed to encrypt via emulator")
		require.NotEmpty(t, encrypted.Ciphertext)

		decrypted, err := encrypter.Decrypt(encrypted, nil)
		require.NoError(t, err, "failed to decrypt via emulator")
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("ListAndDeleteKey", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "emulator-lifecycle",
			KeyAlgorithm: x509.RSA,
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_GCPKMS,
			Hash:         crypto.SHA256,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		_, err := b.GenerateRSA(ctx, attrs)
		require.NoError(t, err)

		keys, err := b.ListKeys(ctx)
		require.NoError(t, err, "failed to list keys from emulator")
		found := false
		for _, k := range keys {
			if k.CN == attrs.CN {
				found = true
				break
			}
		}
		assert.True(t, found, "generated key should appear in ListKeys")

		require.NoError(t, b.DeleteKey(ctx, attrs), "failed to delete key on emulator")
	})
}
