//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestSign_IAK_EveryCommandFailurePropagates sweeps the restricted signing
// path (TPM2_Hash for the ticket, then TPM2_Sign) proving no TPM failure
// yields a signature.
func TestSign_IAK_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSignHarness(t)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.Sign(rand.Reader, []byte("attested payload"), &store.SignerOpts{
				KeyAttributes: h.IAK,
				Backend:       h.Backend,
			})
			return err
		}
	})
}

// TestSign_IDevID_EveryCommandFailurePropagates sweeps the persistent
// IDevID signing path proving no TPM failure yields a signature.
func TestSign_IDevID_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSignHarness(t)
		digest := sha256.Sum256([]byte("payload"))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
				KeyAttributes: h.IDevID,
				Backend:       h.Backend,
			})
			return err
		}
	})
}

// TestSign_ChildKey_EveryCommandFailurePropagates sweeps the child key
// signing path (load under the SRK, TPM2_Sign, flushes) for RSA and ECDSA
// keys proving no TPM failure yields a signature.
func TestSign_ChildKey_EveryCommandFailurePropagates(t *testing.T) {
	tests := []struct {
		name  string
		attrs func(srk *types.KeyAttributes) *types.KeyAttributes
	}{
		{"RSA", func(srk *types.KeyAttributes) *types.KeyAttributes {
			return &types.KeyAttributes{
				CN:            "sign-sweep-rsa",
				KeyAlgorithm:  x509.RSA,
				Hash:          crypto.SHA256,
				KeyType:       types.KeyTypeSigning,
				StoreType:     types.StoreTPM2,
				Parent:        srk,
				RSAAttributes: &types.RSAAttributes{KeySize: 2048},
			}
		}},
		{"ECDSA", func(srk *types.KeyAttributes) *types.KeyAttributes {
			return &types.KeyAttributes{
				CN:            "sign-sweep-ecdsa",
				KeyAlgorithm:  x509.ECDSA,
				Hash:          crypto.SHA256,
				KeyType:       types.KeyTypeSigning,
				StoreType:     types.StoreTPM2,
				Parent:        srk,
				ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
				tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)
				tpmImpl := tpm.(*TPM2)
				attrs := tt.attrs(srkAttrs)
				var err error
				if attrs.KeyAlgorithm == x509.RSA {
					_, err = tpmImpl.CreateRSA(attrs, backend, true)
				} else {
					_, err = tpmImpl.CreateECDSA(attrs, backend, true)
				}
				require.NoError(t, err)
				digest := sha256.Sum256([]byte("payload"))

				return tpmImpl.transport, func(tr transport.TPM) error {
					tpmImpl.transport = tr
					_, err := tpmImpl.Sign(rand.Reader, digest[:], &store.SignerOpts{
						KeyAttributes: tt.attrs(srkAttrs),
						Backend:       backend,
					})
					return err
				}
			},
				// The last two commands are Sign's deferred cleanups of the
				// key's session and its loaded handle; they are logged, not
				// returned.
				7, 8)
		})
	}
}
