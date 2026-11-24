package tlog

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func TestEntry_CertIssuedEncodesKindAndFields(t *testing.T) {
	e := CertIssued{SHA256: "ab01", Serial: "1f", Profile: "server", Tenant: "t1"}
	require.Equal(t, KindCertIssued, e.Kind())
	require.Equal(t, LogIssuance, e.Log())
	b, err := Encode(e)
	require.NoError(t, err)
	require.Equal(t, map[string]any{
		"kind": "cert-issued", "sha256": "ab01", "serial": "1f", "profile": "server", "tenant": "t1",
	}, decode(t, b))
}

func TestEntry_ImageSignedEncodesKindAndFields(t *testing.T) {
	e := ImageSigned{ImageDigest: "sha256:aa", EnvelopeSHA256: "bb", Signer: "cc"}
	require.Equal(t, KindImageSigned, e.Kind())
	require.Equal(t, LogImageSigning, e.Log())
	b, err := json.Marshal(e)
	require.NoError(t, err)
	require.Equal(t, map[string]any{
		"kind": "image-signed", "image_digest": "sha256:aa", "envelope_sha256": "bb", "signer": "cc",
	}, decode(t, b))
}

func TestEntry_RevokedEncodesKindAndFields(t *testing.T) {
	e := Revoked{Serial: "2a", Reason: "keyCompromise"}
	require.Equal(t, KindRevoked, e.Kind())
	require.Equal(t, LogRevocation, e.Log())
	b, err := Encode(e)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"kind": "revoked", "serial": "2a", "reason": "keyCompromise"}, decode(t, b))
}

type recordingAppender struct {
	logs    []string
	entries [][]byte
}

func (r *recordingAppender) Append(_ context.Context, log string, entry []byte) error {
	r.logs = append(r.logs, log)
	r.entries = append(r.entries, entry)
	return nil
}

func TestAppender_FakeRecordsLogAndEntry(t *testing.T) {
	rec := &recordingAppender{}
	var a Appender = rec
	require.NoError(t, AppendEntry(context.Background(), a, Revoked{Serial: "01", Reason: "superseded"}))
	require.Equal(t, []string{LogRevocation}, rec.logs)
	require.Len(t, rec.entries, 1)
	require.Equal(t, "revoked", decode(t, rec.entries[0])["kind"])
}

func TestAppender_NilIsNoOp(t *testing.T) {
	require.NoError(t, AppendEntry(context.Background(), nil, Revoked{Serial: "01"}))
}

type failingAppender struct{ err error }

func (f failingAppender) Append(context.Context, string, []byte) error { return f.err }

func TestAppender_FailureIsAppendError(t *testing.T) {
	cause := errors.New("node down")
	err := AppendEntry(context.Background(), failingAppender{err: cause}, CertIssued{Serial: "01"})
	var ae *AppendError
	require.ErrorAs(t, err, &ae)
	require.Equal(t, LogIssuance, ae.Log)
	require.ErrorIs(t, err, cause)
}
