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

package xkms

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTenantAccess(t *testing.T) {
	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wantErr bool
		errType error
	}{
		{
			name:    "nil attrs returns nil",
			attrs:   nil,
			wantErr: false,
		},
		{
			name:    "empty TenantID returns nil",
			attrs:   &types.KeyAttributes{CN: "test-key"},
			wantErr: false,
		},
		{
			name: "valid TenantID returns nil",
			attrs: &types.KeyAttributes{
				CN:       "test-key",
				TenantID: "acme-corp",
			},
			wantErr: false,
		},
		{
			name: "valid TenantID with dashes returns nil",
			attrs: &types.KeyAttributes{
				CN:       "test-key",
				TenantID: "tenant-123-abc",
			},
			wantErr: false,
		},
		{
			name: "path traversal with double dots returns error",
			attrs: &types.KeyAttributes{
				CN:       "test-key",
				TenantID: "../evil",
			},
			wantErr: true,
		},
		{
			name: "forward slash in TenantID returns error",
			attrs: &types.KeyAttributes{
				CN:       "test-key",
				TenantID: "tenant/escape",
			},
			wantErr: true,
		},
		{
			name: "backslash in TenantID returns error",
			attrs: &types.KeyAttributes{
				CN:       "test-key",
				TenantID: "tenant\\escape",
			},
			wantErr: true,
		},
		{
			name: "embedded double dots returns error",
			attrs: &types.KeyAttributes{
				CN:       "test-key",
				TenantID: "safe..notreally",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTenantAccess(tt.attrs)
			if tt.wantErr {
				require.Error(t, err)
				var invalidTenantErr *storage.ErrInvalidTenantID
				assert.True(t, errors.As(err, &invalidTenantErr),
					"expected *storage.ErrInvalidTenantID, got %T", err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateKey_TenantValidation(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	t.Run("single-tenant mode works unchanged", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-key",
			KeyAlgorithm: x509.ECDSA,
		}
		key, err := GenerateKey(attrs)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("valid tenant passes validation", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "tenant-key",
			TenantID:     "acme-corp",
			KeyAlgorithm: x509.ECDSA,
		}
		key, err := GenerateKey(attrs)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("invalid tenant rejected", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "evil-key",
			TenantID:     "../escape",
			KeyAlgorithm: x509.ECDSA,
		}
		key, err := GenerateKey(attrs)
		assert.Error(t, err)
		assert.Nil(t, key)
		var invalidTenantErr *storage.ErrInvalidTenantID
		assert.True(t, errors.As(err, &invalidTenantErr))
	})
}

func TestKey_TenantValidation(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	// Pre-generate a key so we can retrieve it
	attrs := &types.KeyAttributes{
		CN:           "retrieve-key",
		KeyAlgorithm: x509.ECDSA,
	}
	_, genErr := GenerateKey(attrs)
	require.NoError(t, genErr)

	t.Run("single-tenant retrieval works", func(t *testing.T) {
		key, err := Key(attrs)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("invalid tenant rejected on retrieval", func(t *testing.T) {
		badAttrs := &types.KeyAttributes{
			CN:       "retrieve-key",
			TenantID: "bad/tenant",
		}
		key, err := Key(badAttrs)
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestDeleteKey_TenantValidation(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	t.Run("invalid tenant rejected on delete", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:       "some-key",
			TenantID: "..\\escape",
		}
		err := DeleteKey(attrs)
		assert.Error(t, err)
		var invalidTenantErr *storage.ErrInvalidTenantID
		assert.True(t, errors.As(err, &invalidTenantErr))
	})

	t.Run("empty tenant allows delete", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "del-key",
			KeyAlgorithm: x509.ECDSA,
		}
		// Generate so the key exists
		_, genErr := GenerateKey(attrs)
		require.NoError(t, genErr)

		err := DeleteKey(attrs)
		assert.NoError(t, err)
	})
}

func TestBackendFor_TenantValidation(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	t.Run("nil attrs returns default backend", func(t *testing.T) {
		b, err := BackendFor(nil)
		require.NoError(t, err)
		assert.NotNil(t, b)
	})

	t.Run("empty TenantID returns default backend", func(t *testing.T) {
		b, err := BackendFor(&types.KeyAttributes{CN: "test"})
		require.NoError(t, err)
		assert.NotNil(t, b)
	})

	t.Run("valid TenantID passes through", func(t *testing.T) {
		b, err := BackendFor(&types.KeyAttributes{
			CN:       "test",
			TenantID: "valid-tenant",
		})
		require.NoError(t, err)
		assert.NotNil(t, b)
	})

	t.Run("invalid TenantID rejected in BackendFor", func(t *testing.T) {
		b, err := BackendFor(&types.KeyAttributes{
			CN:       "test",
			TenantID: "../traversal",
		})
		assert.Error(t, err)
		assert.Nil(t, b)
	})
}

func TestTenantID_PropagatesThroughAttrs(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	// Generate a key with a tenant ID and verify it propagates
	attrs := &types.KeyAttributes{
		CN:           "tenant-scoped-key",
		TenantID:     "acme-corp",
		KeyAlgorithm: x509.ECDSA,
	}
	key, err := GenerateKey(attrs)
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Verify TenantID is preserved on the attrs
	assert.Equal(t, "acme-corp", attrs.TenantID)
}

func TestSigner_TenantValidation(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	t.Run("invalid tenant rejected", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:       "signer-key",
			TenantID: "evil/../path",
		}
		signer, err := Signer(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
	})
}

func TestDecrypter_TenantValidation(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	t.Run("invalid tenant rejected", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:       "decrypter-key",
			TenantID: "/absolute/path",
		}
		decrypter, err := Decrypter(attrs)
		assert.Error(t, err)
		assert.Nil(t, decrypter)
	})
}

func TestCertificateOps_TenantValidation(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	badAttrs := &types.KeyAttributes{
		CN:       "cert-key",
		TenantID: "bad..tenant",
	}

	t.Run("Certificate rejects invalid tenant", func(t *testing.T) {
		cert, err := Certificate(badAttrs)
		assert.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("SaveCertificate rejects invalid tenant", func(t *testing.T) {
		err := SaveCertificate(badAttrs, nil)
		assert.Error(t, err)
	})

	t.Run("DeleteCertificate rejects invalid tenant", func(t *testing.T) {
		err := DeleteCertificate(badAttrs)
		assert.Error(t, err)
	})

	t.Run("CertificateChain rejects invalid tenant", func(t *testing.T) {
		chain, err := CertificateChain(badAttrs)
		assert.Error(t, err)
		assert.Nil(t, chain)
	})

	t.Run("SaveCertificateChain rejects invalid tenant", func(t *testing.T) {
		err := SaveCertificateChain(badAttrs, nil)
		assert.Error(t, err)
	})

	t.Run("CertificateExists rejects invalid tenant", func(t *testing.T) {
		exists, err := CertificateExists(badAttrs)
		assert.Error(t, err)
		assert.False(t, exists)
	})

	t.Run("TLSCertificate rejects invalid tenant", func(t *testing.T) {
		_, err := TLSCertificate(badAttrs)
		assert.Error(t, err)
	})
}

func TestGenerateKeyWithBackend_TenantValidation(t *testing.T) {
	t.Cleanup(func() { Reset() })

	mock := newMockKeyStore("test")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"test": mock},
		DefaultBackend: "test",
	})
	require.NoError(t, err)

	t.Run("invalid tenant rejected", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "gen-key",
			TenantID:     "../../escape",
			KeyAlgorithm: x509.ECDSA,
		}
		key, err := GenerateKeyWithBackend("test", attrs)
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("valid tenant accepted", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "gen-key-valid",
			TenantID:     "valid-tenant",
			KeyAlgorithm: x509.ECDSA,
		}
		key, err := GenerateKeyWithBackend("test", attrs)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})
}
