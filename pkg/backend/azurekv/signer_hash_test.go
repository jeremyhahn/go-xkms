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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// algorithmRecorder records the algorithm of every Key Vault sign request.
type algorithmRecorder struct {
	KeyVaultClient
	mu   sync.Mutex
	algs []azkeys.SignatureAlgorithm
}

func (r *algorithmRecorder) Sign(ctx context.Context, name, version string, params azkeys.SignParameters, opts *azkeys.SignOptions) (azkeys.SignResponse, error) {
	r.mu.Lock()
	if params.Algorithm != nil {
		r.algs = append(r.algs, *params.Algorithm)
	}
	r.mu.Unlock()
	return r.KeyVaultClient.Sign(ctx, name, version, params, opts)
}

func (r *algorithmRecorder) last() azkeys.SignatureAlgorithm {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.algs) == 0 {
		return ""
	}
	return r.algs[len(r.algs)-1]
}

// TestSigner_HonorsSuppliedHash checks that the signer sends Key Vault the
// algorithm of the hash named in SignerOpts when the key's attributes carry
// no Hash (as Azure ListKeys returns them): a SHA-384 digest is ES384 or
// RS384, a SHA-512 digest is ES512 or RS512, never the ES256/RS256 default.
func TestSigner_HonorsSuppliedHash(t *testing.T) {
	cases := []struct {
		name  string
		attrs *types.KeyAttributes
		opts  crypto.SignerOpts
		want  azkeys.SignatureAlgorithm
	}{
		{
			name:  "P-384 SHA-384",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()}},
			opts:  crypto.SHA384,
			want:  azkeys.SignatureAlgorithmES384,
		},
		{
			name:  "P-521 SHA-512",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P521()}},
			opts:  crypto.SHA512,
			want:  azkeys.SignatureAlgorithmES512,
		},
		{
			name:  "RSA PKCS#1 v1.5 SHA-384",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 2048}},
			opts:  crypto.SHA384,
			want:  azkeys.SignatureAlgorithmRS384,
		},
		{
			name:  "RSA PSS SHA-512",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 2048}},
			opts:  &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash},
			want:  azkeys.SignatureAlgorithmPS512,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &algorithmRecorder{KeyVaultClient: NewMockKeyVaultClient()}
			b, err := NewBackendWithClient(&Config{
				VaultURL:    "https://test-vault.vault.azure.net/",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}, rec)
			require.NoError(t, err)

			tc.attrs.CN = "hash-" + string(tc.want)
			tc.attrs.KeyType = backend.KEY_TYPE_SIGNING
			tc.attrs.StoreType = backend.STORE_AZUREKV
			_, err = b.CreateKey(tc.attrs)
			require.NoError(t, err)

			// The signer is built from attributes without Hash, as a
			// listing returns them.
			listed := *tc.attrs
			listed.Hash = 0
			signer, err := b.Signer(context.Background(), &listed)
			require.NoError(t, err)

			h := tc.opts.HashFunc().New()
			h.Write([]byte("release CoRIM"))
			digest := h.Sum(nil)
			sig, err := signer.Sign(rand.Reader, digest, tc.opts)
			require.NoError(t, err)
			require.Equal(t, tc.want, rec.last())

			switch pub := signer.Public().(type) {
			case *ecdsa.PublicKey:
				require.True(t, ecdsa.VerifyASN1(pub, digest, sig))
			case *rsa.PublicKey:
				if pss, ok := tc.opts.(*rsa.PSSOptions); ok {
					require.NoError(t, rsa.VerifyPSS(pub, pss.Hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}))
				} else {
					require.NoError(t, rsa.VerifyPKCS1v15(pub, tc.opts.HashFunc(), digest, sig))
				}
			}
		})
	}
}
