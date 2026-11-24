package image

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/stretchr/testify/require"
)

// tlogRecorder is a tlog.Appender recording every (log, entry) pair.
type tlogRecorder struct {
	logs    []string
	entries []map[string]any
}

func (r *tlogRecorder) Append(_ context.Context, log string, entry []byte) error {
	var m map[string]any
	if err := json.Unmarshal(entry, &m); err != nil {
		return err
	}
	r.logs = append(r.logs, log)
	r.entries = append(r.entries, m)
	return nil
}

func tlogSigner(t *testing.T, f *signerFixture, rec tlog.Appender) (*Signer, *x509.Certificate) {
	t.Helper()
	key := newECDSAKey(t)
	cert := f.pki.codeSigning(t, key.Public())
	signer, err := NewSigner(&SignerConfig{
		Signer:      key,
		Certificate: cert,
		Chain:       []*x509.Certificate{f.pki.certificate},
		Registry:    f.client,
		Log:         rec,
	})
	require.NoError(t, err)
	return signer, cert
}

func TestSignImage_AppendsImageSigned(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	rec := &tlogRecorder{}
	signer, cert := tlogSigner(t, f, rec)

	result, err := signer.SignImage(t.Context(), f.ref, nil)
	require.NoError(t, err)

	require.Equal(t, []string{tlog.LogImageSigning}, rec.logs)
	env := sha256.Sum256(result.Envelope)
	der := sha256.Sum256(cert.Raw)
	require.Equal(t, map[string]any{
		"kind":            tlog.KindImageSigned,
		"image_digest":    result.Digest,
		"envelope_sha256": hex.EncodeToString(env[:]),
		"signer":          hex.EncodeToString(der[:]),
	}, rec.entries[0])
}

func TestSignImage_FailedSignatureAppendsNothing(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	rec := &tlogRecorder{}
	signer, _ := tlogSigner(t, f, rec)
	f.registry.unavailable.Store(100)

	_, err := signer.SignImage(t.Context(), f.ref, nil)
	require.ErrorIs(t, err, ErrRegistryUnavailable)
	require.Empty(t, rec.logs)
}

type failingTlog struct{}

func (failingTlog) Append(context.Context, string, []byte) error { return context.DeadlineExceeded }

func TestSignImage_AppendFailureIsAppendError(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	signer, _ := tlogSigner(t, f, failingTlog{})

	result, err := signer.SignImage(t.Context(), f.ref, nil)
	var ae *tlog.AppendError
	require.ErrorAs(t, err, &ae)
	require.Equal(t, tlog.LogImageSigning, ae.Log)
	require.Nil(t, result)
}
