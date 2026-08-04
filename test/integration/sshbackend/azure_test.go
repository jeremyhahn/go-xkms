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

//go:build integration && azurekv

package sshbackend

import (
	"context"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// azureRealisticClient wraps the in-memory Azure mock to emit ECDSA signatures
// in the IEEE-P1363 r‖s form that REAL Azure Key Vault returns for ES256 (the
// mock returns ASN.1 DER). This makes the test faithful to production so it
// exercises the backend's P1363→DER conversion — without it, an Azure ECDSA key
// cannot serve as a crypto.Signer / SSH key.
type azureRealisticClient struct {
	*azurekv.MockKeyVaultClient
}

func (c *azureRealisticClient) Sign(ctx context.Context, keyName, keyVersion string, params azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	resp, err := c.MockKeyVaultClient.Sign(ctx, keyName, keyVersion, params, options)
	if err != nil {
		return resp, err
	}
	if params.Algorithm != nil {
		switch *params.Algorithm {
		case azkeys.SignatureAlgorithmES256, azkeys.SignatureAlgorithmES384, azkeys.SignatureAlgorithmES512:
			p1363, cerr := derToP1363(resp.Result, 32) // P-256 ⇒ 32-byte coordinates
			if cerr != nil {
				return azkeys.SignResponse{}, cerr
			}
			resp.Result = p1363
		}
	}
	return resp, nil
}

// derToP1363 converts an ASN.1 DER ECDSA signature to fixed-width r‖s.
func derToP1363(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// TestSSHBackend_AzureKV proves SSH key generation + signing on the Azure Key
// Vault backend. Azure has no emulator, so the test drives the real backend code
// over the in-memory mock — wrapped to return the P1363 r‖s signatures real Azure
// produces — so the backend's ECDSA conversion is genuinely exercised and the SSH
// signature verifies. ECDSA-P256 is the cross-cloud default; ed25519 is rejected.
func TestSSHBackend_AzureKV(t *testing.T) {
	client := &azureRealisticClient{MockKeyVaultClient: azurekv.NewMockKeyVaultClient()}

	keyStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend (keys): %v", err)
	}
	certStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend (certs): %v", err)
	}

	be, err := azurekv.NewBackendWithClient(&azurekv.Config{
		VaultURL:    "https://ssh-backend-test.vault.azure.net/",
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}, client)
	if err != nil {
		t.Fatalf("azurekv.NewBackendWithClient: %v", err)
	}

	runMatrix(t, resolverFor("azurekv", be), "azurekv", cloudAlgos, true)
	assertRejects(t, resolverFor("azurekv", be), "azurekv", keys.AlgorithmEd25519)
}
