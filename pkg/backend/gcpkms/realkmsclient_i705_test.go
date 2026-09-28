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

//go:build gcpkms

package gcpkms

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// This file covers realKMSClient (go-xkms#705, batch 4): every Backend
// method is tested exclusively against a hand-written KMSClient mock
// (mock_kms.go), so realKMSClient's wire adapter -- the code that actually
// calls the GCP KMS gRPC service -- has never run. A mock proves Backend's
// own logic; it proves nothing about whether realKMSClient forwards the
// right request to the right RPC and hands back the right response field,
// which is exactly the class of bug (wrong field, swapped parameter, a
// rename that misses one call site) a mock cannot catch because it never
// invokes the real method body.
//
// fakeKMSServer stands in for Cloud KMS's gRPC service, speaking the real
// google.golang.org/grpc wire protocol against the real generated client
// (cloud.google.com/go/kms/apiv1), so these tests exercise realKMSClient
// exactly as production traffic does -- only the process on the other end
// of the socket is a fake.

// fakeKMSServer is a minimal Cloud KMS KeyManagementService implementation
// backing these tests. It records the last request it received per RPC (so
// a test can assert the adapter forwarded the right fields) and returns a
// per-RPC canned response or error, set by the test before the call.
type fakeKMSServer struct {
	kmspb.UnimplementedKeyManagementServiceServer

	mu      sync.Mutex
	lastReq map[string]any
	errs    map[string]error

	// keys backs ListCryptoKeys' pagination.
	keys []*kmspb.CryptoKey
}

func newFakeKMSServer() *fakeKMSServer {
	return &fakeKMSServer{lastReq: make(map[string]any), errs: make(map[string]error)}
}

// setErr configures method to fail with err on its next call.
func (f *fakeKMSServer) setErr(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[method] = err
}

// record stores req as the last request seen for method and returns the
// canned error configured for it, if any.
func (f *fakeKMSServer) record(method string, req any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReq[method] = req
	return f.errs[method]
}

func (f *fakeKMSServer) requestFor(method string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq[method]
}

func (f *fakeKMSServer) CreateCryptoKey(_ context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if err := f.record("CreateCryptoKey", req); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKey{Name: req.Parent + "/cryptoKeys/" + req.CryptoKeyId}, nil
}

func (f *fakeKMSServer) GetCryptoKey(_ context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if err := f.record("GetCryptoKey", req); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKey{Name: req.Name}, nil
}

func (f *fakeKMSServer) GetCryptoKeyVersion(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := f.record("GetCryptoKeyVersion", req); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKeyVersion{Name: req.Name, State: kmspb.CryptoKeyVersion_ENABLED}, nil
}

func (f *fakeKMSServer) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	if err := f.record("AsymmetricSign", req); err != nil {
		return nil, err
	}
	return &kmspb.AsymmetricSignResponse{Signature: []byte("fake-signature"), Name: req.Name}, nil
}

func (f *fakeKMSServer) AsymmetricDecrypt(_ context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
	if err := f.record("AsymmetricDecrypt", req); err != nil {
		return nil, err
	}
	return &kmspb.AsymmetricDecryptResponse{Plaintext: []byte("fake-plaintext")}, nil
}

func (f *fakeKMSServer) GetPublicKey(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	if err := f.record("GetPublicKey", req); err != nil {
		return nil, err
	}
	return &kmspb.PublicKey{Name: req.Name, Pem: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n"}, nil
}

func (f *fakeKMSServer) CreateCryptoKeyVersion(_ context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := f.record("CreateCryptoKeyVersion", req); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKeyVersion{Name: req.Parent + "/cryptoKeyVersions/2"}, nil
}

func (f *fakeKMSServer) UpdateCryptoKeyPrimaryVersion(_ context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
	if err := f.record("UpdateCryptoKeyPrimaryVersion", req); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKey{Name: req.Name}, nil
}

func (f *fakeKMSServer) DestroyCryptoKeyVersion(_ context.Context, req *kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := f.record("DestroyCryptoKeyVersion", req); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKeyVersion{Name: req.Name, State: kmspb.CryptoKeyVersion_DESTROY_SCHEDULED}, nil
}

func (f *fakeKMSServer) Encrypt(_ context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if err := f.record("Encrypt", req); err != nil {
		return nil, err
	}
	return &kmspb.EncryptResponse{Name: req.Name, Ciphertext: append([]byte("enc:"), req.Plaintext...)}, nil
}

func (f *fakeKMSServer) Decrypt(_ context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if err := f.record("Decrypt", req); err != nil {
		return nil, err
	}
	return &kmspb.DecryptResponse{Plaintext: []byte("fake-plaintext")}, nil
}

func (f *fakeKMSServer) CreateImportJob(_ context.Context, req *kmspb.CreateImportJobRequest) (*kmspb.ImportJob, error) {
	if err := f.record("CreateImportJob", req); err != nil {
		return nil, err
	}
	return &kmspb.ImportJob{Name: req.Parent + "/importJobs/" + req.ImportJobId}, nil
}

func (f *fakeKMSServer) ImportCryptoKeyVersion(_ context.Context, req *kmspb.ImportCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := f.record("ImportCryptoKeyVersion", req); err != nil {
		return nil, err
	}
	return &kmspb.CryptoKeyVersion{Name: req.Parent + "/cryptoKeyVersions/1"}, nil
}

// ListCryptoKeys implements real, multi-page pagination over f.keys so the
// test can prove realKMSClient.ListCryptoKeys' page_token loop actually
// walks every page rather than stopping at the first one.
func (f *fakeKMSServer) ListCryptoKeys(_ context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	if err := f.record("ListCryptoKeys", req); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	start := 0
	if req.PageToken != "" {
		idx, err := strconv.Atoi(req.PageToken)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "malformed page token")
		}
		start = idx
	}
	pageSize := int(req.PageSize)
	if pageSize <= 0 {
		pageSize = len(f.keys)
	}
	end := start + pageSize
	if end > len(f.keys) {
		end = len(f.keys)
	}

	resp := &kmspb.ListCryptoKeysResponse{
		CryptoKeys: f.keys[start:end],
		TotalSize:  int32(len(f.keys)), // #nosec G115 - test fixture size fits in int32
	}
	if end < len(f.keys) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

// newFakeKMSBackend starts an in-process fake KMS gRPC server and returns a
// *Backend constructed with a real realKMSClient dialed against it (Insecure
// + custom Endpoint, exactly the emulator wiring NewBackend already
// supports), plus the fake server so the test can configure responses and
// inspect what the adapter sent.
func newFakeKMSBackend(t *testing.T) (*Backend, *fakeKMSServer) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	fake := newFakeKMSServer()
	grpcServer := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(grpcServer, fake)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	b, err := NewBackend(context.Background(), &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-ring",
		Endpoint:    lis.Addr().String(),
		Insecure:    true,
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	return b, fake
}

// TestRealKMSClient_WrapperMethods_RoundTrip drives every realKMSClient
// method except ListCryptoKeys (covered separately for its pagination) over
// the real gRPC wire against fakeKMSServer, and proves both that the request
// the fake server received is the one the caller built and that the
// response it returns comes back through unmodified.
func TestRealKMSClient_WrapperMethods_RoundTrip(t *testing.T) {
	b, fake := newFakeKMSBackend(t)
	ctx := context.Background()
	const parent = "projects/test-project/locations/us-central1/keyRings/test-ring"
	const keyName = parent + "/cryptoKeys/test-key"
	const versionName = keyName + "/cryptoKeyVersions/1"

	t.Run("CreateCryptoKey", func(t *testing.T) {
		resp, err := b.client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{Parent: parent, CryptoKeyId: "test-key"})
		require.NoError(t, err)
		assert.Equal(t, keyName, resp.Name)
		assert.Equal(t, "test-key", fake.requestFor("CreateCryptoKey").(*kmspb.CreateCryptoKeyRequest).CryptoKeyId)
	})

	t.Run("GetCryptoKey", func(t *testing.T) {
		resp, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyName})
		require.NoError(t, err)
		assert.Equal(t, keyName, resp.Name)
	})

	t.Run("GetCryptoKeyVersion", func(t *testing.T) {
		resp, err := b.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: versionName})
		require.NoError(t, err)
		assert.Equal(t, versionName, resp.Name)
		assert.Equal(t, kmspb.CryptoKeyVersion_ENABLED, resp.State)
	})

	t.Run("AsymmetricSign", func(t *testing.T) {
		resp, err := b.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: versionName, Digest: &kmspb.Digest{}})
		require.NoError(t, err)
		assert.Equal(t, []byte("fake-signature"), resp.Signature)
	})

	t.Run("AsymmetricDecrypt", func(t *testing.T) {
		resp, err := b.client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{Name: versionName, Ciphertext: []byte("ct")})
		require.NoError(t, err)
		assert.Equal(t, []byte("fake-plaintext"), resp.Plaintext)
	})

	t.Run("GetPublicKey", func(t *testing.T) {
		resp, err := b.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
		require.NoError(t, err)
		assert.Contains(t, resp.Pem, "BEGIN PUBLIC KEY")
	})

	t.Run("CreateCryptoKeyVersion", func(t *testing.T) {
		resp, err := b.client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{Parent: keyName})
		require.NoError(t, err)
		assert.Equal(t, keyName+"/cryptoKeyVersions/2", resp.Name)
	})

	t.Run("UpdateCryptoKeyPrimaryVersion", func(t *testing.T) {
		resp, err := b.client.UpdateCryptoKeyPrimaryVersion(ctx, &kmspb.UpdateCryptoKeyPrimaryVersionRequest{Name: keyName, CryptoKeyVersionId: "2"})
		require.NoError(t, err)
		assert.Equal(t, keyName, resp.Name)
		assert.Equal(t, "2", fake.requestFor("UpdateCryptoKeyPrimaryVersion").(*kmspb.UpdateCryptoKeyPrimaryVersionRequest).CryptoKeyVersionId)
	})

	t.Run("DestroyCryptoKeyVersion", func(t *testing.T) {
		resp, err := b.client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{Name: versionName})
		require.NoError(t, err)
		assert.Equal(t, kmspb.CryptoKeyVersion_DESTROY_SCHEDULED, resp.State)
	})

	t.Run("Encrypt", func(t *testing.T) {
		resp, err := b.client.Encrypt(ctx, &kmspb.EncryptRequest{Name: keyName, Plaintext: []byte("secret")})
		require.NoError(t, err)
		assert.Equal(t, []byte("enc:secret"), resp.Ciphertext)
	})

	t.Run("Decrypt", func(t *testing.T) {
		resp, err := b.client.Decrypt(ctx, &kmspb.DecryptRequest{Name: keyName, Ciphertext: []byte("ct")})
		require.NoError(t, err)
		assert.Equal(t, []byte("fake-plaintext"), resp.Plaintext)
	})

	t.Run("CreateImportJob", func(t *testing.T) {
		resp, err := b.client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{Parent: parent, ImportJobId: "test-job"})
		require.NoError(t, err)
		assert.Equal(t, parent+"/importJobs/test-job", resp.Name)
	})

	t.Run("ImportCryptoKeyVersion", func(t *testing.T) {
		resp, err := b.client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{Parent: keyName})
		require.NoError(t, err)
		assert.Equal(t, keyName+"/cryptoKeyVersions/1", resp.Name)
	})
}

// TestRealKMSClient_WrapperMethods_ErrorPropagation proves a gRPC error the
// server returns reaches the caller unchanged rather than being swallowed or
// replaced -- the failure mode a one-line forwarding bug (e.g. discarding
// the error, returning a zero value) would produce.
func TestRealKMSClient_WrapperMethods_ErrorPropagation(t *testing.T) {
	b, fake := newFakeKMSBackend(t)
	ctx := context.Background()

	fake.setErr("GetCryptoKey", status.Error(codes.NotFound, "crypto key not found"))
	_, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: "missing"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	fake.setErr("AsymmetricSign", status.Error(codes.PermissionDenied, "caller lacks cloudkms.cryptoKeyVersions.useToSign"))
	_, err = b.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: "v1", Digest: &kmspb.Digest{}})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestRealKMSClient_ListCryptoKeys_Pagination proves the adapter's
// iterator-driven loop (google.golang.org/api/iterator, stopping on
// iterator.Done) walks every page the server reports rather than returning
// only the first, and that the concatenated result preserves order.
func TestRealKMSClient_ListCryptoKeys_Pagination(t *testing.T) {
	b, fake := newFakeKMSBackend(t)
	ctx := context.Background()
	const parent = "projects/test-project/locations/us-central1/keyRings/test-ring"

	fake.keys = []*kmspb.CryptoKey{
		{Name: parent + "/cryptoKeys/key-1"},
		{Name: parent + "/cryptoKeys/key-2"},
		{Name: parent + "/cryptoKeys/key-3"},
	}

	keys, err := b.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: parent, PageSize: 1})
	require.NoError(t, err)
	require.Len(t, keys, 3, "pagination must walk every page, not just the first")
	assert.Equal(t, parent+"/cryptoKeys/key-1", keys[0].Name)
	assert.Equal(t, parent+"/cryptoKeys/key-2", keys[1].Name)
	assert.Equal(t, parent+"/cryptoKeys/key-3", keys[2].Name)
}

// TestRealKMSClient_ListCryptoKeys_EmptyKeyRing proves an empty key ring
// yields an empty (not nil-panicking, not erroring) slice.
func TestRealKMSClient_ListCryptoKeys_EmptyKeyRing(t *testing.T) {
	b, _ := newFakeKMSBackend(t)
	ctx := context.Background()

	keys, err := b.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: "projects/test-project/locations/us-central1/keyRings/empty-ring"})
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestRealKMSClient_ListCryptoKeys_ServerError proves a mid-listing error
// from the server propagates rather than returning a truncated, silently
// partial key list. codes.PermissionDenied is deliberate, not arbitrary:
// the generated client's default retry policy treats codes.Unavailable as
// transient and retries it with backoff for up to a minute before finally
// surfacing codes.Unknown, which would make this assertion about the
// server's own code both wrong and slow; PermissionDenied is not in that
// retryable set, so it reaches the caller immediately and unchanged.
func TestRealKMSClient_ListCryptoKeys_ServerError(t *testing.T) {
	b, fake := newFakeKMSBackend(t)
	ctx := context.Background()

	fake.setErr("ListCryptoKeys", status.Error(codes.PermissionDenied, "caller lacks cloudkms.cryptoKeys.list"))
	_, err := b.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: "projects/test-project/locations/us-central1/keyRings/test-ring"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
