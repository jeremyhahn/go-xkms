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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestAzureKVDecrypter_RPCError proves azurekvDecrypter.Decrypt surfaces a
// Key Vault Decrypt RPC failure wrapped rather than returning a
// zero-length plaintext. Every other branch of Decrypt (padding selection,
// nil opts, unsupported OAEP hash) is already covered by
// TestSignerAndDecrypter_RSAOAEPBranches; this is the one remaining gap,
// the RPC failure itself, which MockKeyVaultClient.SetDecryptError exists
// specifically to inject.
func TestAzureKVDecrypter_RPCError(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "decrypter-rpc-error",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	decrypter, err := b.Decrypter(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Decrypter() error = %v", err)
	}

	mockClient.SetDecryptError(errors.New("azure: decrypt denied"))

	if _, err := decrypter.Decrypt(nil, []byte("ciphertext"), nil); err == nil {
		t.Error("Decrypt() expected error when the Decrypt RPC fails, got nil")
	}
}
