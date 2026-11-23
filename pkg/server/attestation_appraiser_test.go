package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// serviceSigner signs with a key the XKMSService holds, so a CoRIM is signed
// by the tenant's repository signing key without its private half leaving
// the backend.
type serviceSigner struct {
	ctx    context.Context
	svc    *xkms.XKMSService
	keyID  string
	public crypto.PublicKey
}

func (s *serviceSigner) Public() crypto.PublicKey { return s.public }

func (s *serviceSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	resp, err := s.svc.Sign(s.ctx, &transport.SignRequest{
		Backend: "software", KeyID: s.keyID, Data: digest, DataIsDigest: true,
	})
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

// TestServer_StoresARepositorySignedCoRIM proves the Appraiser server.New
// composes resolves a repository's signing key through the XKMSService: a
// CoRIM signed by the tenant's release key is stored, and one signed by any
// other key is refused rather than failing as a missing configuration.
func TestServer_StoresARepositorySignedCoRIM(t *testing.T) {
	cfg := createMinimalConfig(t)
	cfg.CA = testFirstBootCAConfig()
	srv, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, srv.Shutdown()) })
	svc := srv.XKMSService()
	require.NotNil(t, svc)
	ctx := context.Background()

	resp, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: appraisal.ReleaseSigningKeyID, Backend: "software", KeyType: "signing", Algorithm: "ecdsa", Curve: "P-256",
	})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	release := &serviceSigner{ctx: ctx, svc: svc, keyID: appraisal.ReleaseSigningKeyID, public: pub}

	pcrs := appraisaltest.PCRValues(0, 7)
	signed, err := appraisaltest.SignCoRIM(pcrs, release, nil)
	require.NoError(t, err)
	_, err = svc.PutAttestationReferenceValues(ctx, &appraisal.PutReferenceValuesRequest{
		Name: "baseline", Repository: "acme/app", SignedCoRIM: signed,
	})
	require.NoError(t, err)
	record, err := svc.GetAttestationReferenceValues(ctx, &appraisal.GetReferenceValuesRequest{Name: "baseline"})
	require.NoError(t, err)
	assert.Equal(t, "acme/app", record.Repository)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	forged, err := appraisaltest.SignCoRIM(pcrs, other, nil)
	require.NoError(t, err)
	_, err = svc.PutAttestationReferenceValues(ctx, &appraisal.PutReferenceValuesRequest{
		Name: "forged", Repository: "acme/app", SignedCoRIM: forged,
	})
	require.ErrorIs(t, err, appraisal.ErrSigningKeyRefused)
	var cfgErr *appraisal.ConfigError
	assert.NotErrorAs(t, err, &cfgErr)
}
