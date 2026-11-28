package xkms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestReleaseAlgorithm_UnrecordedRSAOnPSSBackendSignsPS256: an RSA key whose
// listing records no signature algorithm signs PS256 when its backend honours
// the PSS options it is given (software, PKCS#11, AWS KMS, Azure Key Vault),
// and the signature verifies as PS256. A backend whose padding is fixed by
// the key (GCP KMS), or one that is not known, is still refused.
func TestReleaseAlgorithm_UnrecordedRSAOnPSSBackendSignsPS256(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, store := range []types.StoreType{
		types.StoreSoftware, types.StorePKCS11, types.StoreAWSKMS, types.StoreAzureKV,
	} {
		s := opaqueSigner{signer: k, sigAlg: x509.UnknownSignatureAlgorithm, store: store, sign: k.Sign}
		got, err := releaseAlgorithm(s)
		require.NoError(t, err, store)
		assert.Equal(t, cose.AlgorithmPS256, got, store)

		signer, err := cose.NewSigner(got, s)
		require.NoError(t, err, store)
		msg := cose.NewSign1Message()
		msg.Payload = []byte("corim")
		require.NoError(t, msg.Sign(rand.Reader, nil, signer), store)
		verifier, err := cose.NewVerifier(cose.AlgorithmPS256, k.Public())
		require.NoError(t, err)
		require.NoError(t, msg.Verify(nil, verifier), store)
	}
	for _, store := range []types.StoreType{types.StoreGCPKMS, types.StoreUnknown, ""} {
		_, err := releaseAlgorithm(opaqueSigner{signer: k, sigAlg: x509.UnknownSignatureAlgorithm, store: store, sign: k.Sign})
		require.ErrorIs(t, err, refvalue.ErrUnsupportedKey, store)
	}
	// A recorded PKCS#1 v1.5 algorithm is refused on every backend.
	_, err = releaseAlgorithm(opaqueSigner{signer: k, sigAlg: x509.SHA256WithRSA, store: types.StoreSoftware, sign: k.Sign})
	require.ErrorIs(t, err, refvalue.ErrUnsupportedKey)
}
