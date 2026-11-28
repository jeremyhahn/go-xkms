package tlog

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/vlog"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/vlogwire"
	"github.com/stretchr/testify/require"
)

type ctxKey struct{}

// fakeVlog records VlogCreate and VlogAppend calls; a log exists once it
// is created.
type fakeVlog struct {
	transport.VlogClient
	created  []*vlogwire.CreateRequest
	appended []*vlogwire.AppendRequest
	exists   map[string]bool
	ctxVals  []any
}

func (f *fakeVlog) VlogCreate(ctx context.Context, req *vlogwire.CreateRequest) (*vlogwire.CreateResult, error) {
	f.created = append(f.created, req)
	if f.exists[req.Log] {
		return nil, &vlog.LogExistsError{}
	}
	f.exists[req.Log] = true
	return &vlogwire.CreateResult{}, nil
}

func (f *fakeVlog) VlogAppend(ctx context.Context, req *vlogwire.AppendRequest) (*vlogwire.AppendResult, error) {
	f.ctxVals = append(f.ctxVals, ctx.Value(ctxKey{}))
	if !f.exists[req.Log] {
		return nil, &vlog.LogNotFoundError{}
	}
	f.appended = append(f.appended, req)
	return &vlogwire.AppendResult{}, nil
}

type fakeClient struct{ v *fakeVlog }

func (c fakeClient) Vlog() transport.VlogClient { return c.v }

type appenderCA struct{ s *ecdsa.PrivateKey }

func (c appenderCA) Signer(context.Context) (crypto.Signer, error) { return c.s, nil }

func newBoundProvider(t *testing.T) *HeadSignerProvider {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p := NewHeadSignerProvider()
	require.NoError(t, p.Bind(appenderCA{s: k}))
	return p
}

func TestNodeAppender_CreatesMissingLogThenAppendsOneEntry(t *testing.T) {
	fv := &fakeVlog{exists: map[string]bool{}}
	a := NewNodeAppender(fakeClient{v: fv}, NodeAppenderConfig{
		Tenant: "system",
		Keys:   newBoundProvider(t),
		Context: func(ctx context.Context) (context.Context, error) {
			return context.WithValue(ctx, ctxKey{}, "caller"), nil
		},
	})
	require.NoError(t, a.Append(context.Background(), LogIssuance, []byte("e1")))
	require.NoError(t, a.Append(context.Background(), LogIssuance, []byte("e2")))

	require.Len(t, fv.created, 1)
	require.Equal(t, LogIssuance, fv.created[0].Log)
	require.Equal(t, "system/issuance", fv.created[0].Origin)
	require.Equal(t, qrdbsdk.HeadSignatureECDSAP256SHA256, fv.created[0].SigningKeyType)
	require.Len(t, fv.appended, 2)
	require.Equal(t, [][]byte{[]byte("e1")}, fv.appended[0].Entries)
	require.Equal(t, [][]byte{[]byte("e2")}, fv.appended[1].Entries)
	for _, v := range fv.ctxVals {
		require.Equal(t, "caller", v, "every call runs in the configured caller context")
	}
}

func TestNodeAppender_ExistingLogSkipsCreate(t *testing.T) {
	// The log exists, but this appender has not seen it yet: the append
	// succeeds without a create.
	fv := &fakeVlog{exists: map[string]bool{LogRevocation: true}}
	a := NewNodeAppender(fakeClient{v: fv}, NodeAppenderConfig{Tenant: "system", Keys: newBoundProvider(t)})
	require.NoError(t, a.Append(context.Background(), LogRevocation, []byte("e")))
	require.Empty(t, fv.created)
	require.Len(t, fv.appended, 1)
}

func TestNodeAppender_UnboundCAFails(t *testing.T) {
	fv := &fakeVlog{exists: map[string]bool{}}
	a := NewNodeAppender(fakeClient{v: fv}, NodeAppenderConfig{Tenant: "system", Keys: NewHeadSignerProvider()})
	err := a.Append(context.Background(), LogIssuance, []byte("e"))
	require.ErrorIs(t, err, ErrCANotBound)
	require.Empty(t, fv.appended)
}

func TestNodeAppender_ContextErrorFails(t *testing.T) {
	fv := &fakeVlog{exists: map[string]bool{LogIssuance: true}}
	cause := errors.New("no identity")
	a := NewNodeAppender(fakeClient{v: fv}, NodeAppenderConfig{
		Tenant: "system", Keys: newBoundProvider(t),
		Context: func(context.Context) (context.Context, error) { return nil, cause },
	})
	require.ErrorIs(t, a.Append(context.Background(), LogIssuance, []byte("e")), cause)
	require.Empty(t, fv.appended)
}
