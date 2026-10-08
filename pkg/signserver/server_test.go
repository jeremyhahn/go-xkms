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

package signserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const (
	testToken   = "ike"
	testLabel   = "vtep-ike"
	testLabel2  = "vtep-ike-384"
	testUserPIN = "user-pin-1234"
	testSOPIN   = "so-pin-5678"
)

// newSoftwareBackend returns an in-memory software key backend.
func newSoftwareBackend(t *testing.T) xkms.Backend {
	t.Helper()
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

// socketPath returns a socket path in a fresh private directory short enough
// for sun_path.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ss")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "sign.sock")
}

// newTestServer builds a server admitting uids, with one slot naming two keys.
func newTestServer(t *testing.T, uids []uint32) *Server {
	t.Helper()
	srv, err := New(context.Background(), Config{
		SocketPath:     socketPath(t),
		AllowedUIDs:    uids,
		Backends:       map[string]xkms.Backend{"software": newSoftwareBackend(t)},
		DefaultBackend: "software",
		StateDAOs:      testutil.NewMemoryDAOFactory(),
		Slots:          []Slot{{Token: testToken, Keys: []string{testLabel, testLabel2}}},
	})
	require.NoError(t, err)
	return srv
}

// serve starts srv and waits until its socket accepts connections.
func serve(t *testing.T, srv *Server) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		require.NoError(t, srv.Stop(context.Background()))
		require.NoError(t, <-done)
	})

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(srv.SocketPath()); err == nil {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("server exited before binding: %v", err)
		case <-deadline:
			t.Fatal("server did not bind its socket")
		case <-ticker.C:
		}
	}
}

// remoteModule initializes a remote-mode module against srv, configured the
// way an IKE daemon's environment configures libxkms_pkcs11.so.
func remoteModule(t *testing.T, srv *Server) *module.Module {
	t.Helper()
	cfg := module.DefaultConfig()
	cfg.Target = "unix://" + srv.SocketPath()
	cfg.StorageType = module.StorageTypeRemote
	cfg.TokenLabel = testToken
	cfg.DefaultBackend = "software"
	cfg.Timeout = 10 * time.Second
	m, err := module.New(module.WithConfig(cfg))
	require.NoError(t, err)
	require.Equal(t, module.CKR_OK, m.Initialize(nil))
	t.Cleanup(func() { m.Finalize() })
	return m
}

// findOne returns the single object matching template.
func findOne(t *testing.T, m *module.Module, session module.SessionHandle, template []module.Attribute) module.ObjectHandle {
	t.Helper()
	require.Equal(t, module.CKR_OK, m.FindObjectsInit(session, template))
	handles, rv := m.FindObjects(session, 4)
	require.Equal(t, module.CKR_OK, rv)
	require.Equal(t, module.CKR_OK, m.FindObjectsFinal(session))
	require.Len(t, handles, 1)
	return handles[0]
}

// verifyRawECDSA checks a CKM_ECDSA signature (r || s) over digest.
func verifyRawECDSA(t *testing.T, pub *ecdsa.PublicKey, digest, sig []byte) {
	t.Helper()
	half := len(sig) / 2
	require.Equal(t, (pub.Curve.Params().BitSize+7)/8, half, "CKM_ECDSA signature width")
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	require.True(t, ecdsa.Verify(pub, digest, r, s), "signature must verify under the provisioned public key")
}

// TestRemoteModuleSignsThroughSignServer is the charon-shaped flow: the
// embedder creates the IKE keys in process, then a remote-mode module on the
// allowlisted uid logs in, finds each key by CKA_LABEL and by CKA_ID, and
// signs a pre-hashed digest with CKM_ECDSA on P-256 and P-384.
func TestRemoteModuleSignsThroughSignServer(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, []uint32{uint32(os.Geteuid())})

	p256, err := srv.CreateKey(ctx, KeyRequest{
		Token: testToken, Label: testLabel, ID: []byte{0xa1, 0x01}, Curve: "P-256",
		UserPIN: testUserPIN, SOPIN: testSOPIN,
	})
	require.NoError(t, err)
	require.True(t, p256.Created)
	require.Equal(t, "software", p256.Backend)

	p384, err := srv.CreateKey(ctx, KeyRequest{
		Token: testToken, Label: testLabel2, ID: []byte{0xa1, 0x02}, Curve: "P-384", UserPIN: testUserPIN,
	})
	require.NoError(t, err)

	serve(t, srv)
	m := remoteModule(t, srv)

	session, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION)
	require.Equal(t, module.CKR_OK, rv)
	require.Equal(t, module.CKR_OK, m.Login(session, module.CKU_USER, []byte(testUserPIN)))

	cases := []struct {
		key    *Key
		digest []byte
	}{
		{key: p256, digest: sha256Sum("ike auth payload")},
		{key: p384, digest: sha384Sum("ike auth payload")},
	}
	for _, tc := range cases {
		byLabel := findOne(t, m, session, []module.Attribute{
			module.NewULongAttribute(module.CKA_CLASS, uint64(module.CKO_PRIVATE_KEY)),
			module.NewStringAttribute(module.CKA_LABEL, tc.key.Label),
		})
		byID := findOne(t, m, session, []module.Attribute{
			module.NewULongAttribute(module.CKA_CLASS, uint64(module.CKO_PRIVATE_KEY)),
			module.NewAttribute(module.CKA_ID, tc.key.ID),
		})
		require.Equal(t, byLabel, byID, "label and id must name the same key")

		require.Equal(t, module.CKR_OK, m.SignInit(session, &module.Mechanism{Type: module.CKM_ECDSA}, byID))
		sig, rv := m.Sign(session, tc.digest)
		require.Equal(t, module.CKR_OK, rv)
		// The C boundary terminates the operation once it has copied the
		// signature out (PKCS#11 v3.2 §5.2 length-query contract).
		require.Equal(t, module.CKR_OK, m.FinishOperation(session, module.OperationSign))
		verifyRawECDSA(t, tc.key.PublicKey, tc.digest, sig)
	}
}

// TestSignServerRefusesUnlistedUID proves the peer gate: the same module, on
// a uid the server does not list, cannot reach the key at all.
func TestSignServerRefusesUnlistedUID(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, []uint32{uint32(os.Geteuid()) + 1})
	key, err := srv.CreateKey(ctx, KeyRequest{
		Token: testToken, Label: testLabel, ID: []byte{1}, Curve: "P-256", UserPIN: testUserPIN, SOPIN: testSOPIN,
	})
	require.NoError(t, err)
	serve(t, srv)

	client := keystoreClient(t, srv)
	_, err = client.Sign(ctx, &pb.SignRequest{KeyId: key.KeyID, Backend: key.Backend, Data: sha256Sum("x"), Hash: "NONE"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err), "the connection must be refused at accept time")

	cfg := module.DefaultConfig()
	cfg.Target = "unix://" + srv.SocketPath()
	cfg.StorageType = module.StorageTypeRemote
	cfg.TokenLabel = testToken
	cfg.Timeout = 2 * time.Second
	m, err := module.New(module.WithConfig(cfg))
	require.NoError(t, err)
	assert.Equal(t, module.CKR_DEVICE_ERROR, m.Initialize(nil),
		"a refused peer's module cannot even reach the token: C_Initialize fails")
}

// TestSignServerPolicyDeniesEverythingButSigning drives the keystore service
// directly, as a process on the allowlisted uid that bypassed the module
// would: only the sign-only slot's RPCs, keys and counter records are served.
func TestSignServerPolicyDeniesEverythingButSigning(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, []uint32{uint32(os.Geteuid())})
	key, err := srv.CreateKey(ctx, KeyRequest{
		Token: testToken, Label: testLabel, ID: []byte{1}, Curve: "P-256", UserPIN: testUserPIN, SOPIN: testSOPIN,
	})
	require.NoError(t, err)

	// A key in the same backend that no slot names.
	_, err = srv.service.GenerateKey(ctx, &transport.GenerateKeyRequest{KeyID: "unnamed", Backend: "software", Algorithm: "ECDSA", KeyType: "signing", Curve: "P-256"})
	require.NoError(t, err)

	serve(t, srv)
	client := keystoreClient(t, srv)

	_, err = client.Sign(ctx, &pb.SignRequest{KeyId: key.KeyID, Backend: key.Backend, Data: sha256Sum("ok"), Hash: "NONE"})
	require.NoError(t, err, "a named key signs")

	denied := map[string]func() error{
		"sign with an unnamed key": func() error {
			_, err := client.Sign(ctx, &pb.SignRequest{KeyId: "unnamed", Backend: "software", Data: sha256Sum("x"), Hash: "NONE"})
			return err
		},
		"generate a key": func() error {
			_, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "evil", Backend: "software", Algorithm: "ECDSA"})
			return err
		},
		"list keys": func() error {
			_, err := client.ListKeys(ctx, &pb.ListKeysRequest{})
			return err
		},
		"overwrite a key object": func() error {
			_, err := client.PKCS11StatePut(ctx, &pb.PKCS11StatePutRequest{Token: testToken, Key: "pkcs11/objects/1", Value: []byte("{}")})
			return err
		},
		"overwrite the token state": func() error {
			_, err := client.PKCS11StateDelete(ctx, &pb.PKCS11StateDeleteRequest{Token: testToken, Key: "pkcs11/tokens/0"})
			return err
		},
		"read another token": func() error {
			_, err := client.PKCS11StateList(ctx, &pb.PKCS11StateListRequest{Token: "other"})
			return err
		},
	}
	for name, call := range denied {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}

	_, err = client.PKCS11StateList(ctx, &pb.PKCS11StateListRequest{Token: testToken, Prefix: "pkcs11/"})
	require.NoError(t, err, "the slot's own records are readable")
	_, err = client.PKCS11StatePut(ctx, &pb.PKCS11StatePutRequest{
		Token: testToken, Key: counterPrefix + "0/failed_user", Value: []byte("0"),
	})
	require.NoError(t, err, "the lockout counters are writable")
}

func TestCreateKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t, []uint32{uint32(os.Geteuid())})
	req := KeyRequest{Token: testToken, Label: testLabel, ID: []byte{7}, Curve: "P-256", UserPIN: testUserPIN, SOPIN: testSOPIN}

	first, err := srv.CreateKey(ctx, req)
	require.NoError(t, err)
	again, err := srv.CreateKey(ctx, req)
	require.NoError(t, err)
	assert.False(t, again.Created, "an identical key is returned, not recreated")
	assert.Equal(t, first.KeyID, again.KeyID)
	assert.True(t, first.PublicKey.Equal(again.PublicKey))

	conflict := req
	conflict.ID = []byte{8}
	_, err = srv.CreateKey(ctx, conflict)
	assert.ErrorIs(t, err, module.ErrProvisionKeyConflict)

	otherCurve := req
	otherCurve.Curve = "P-384"
	_, err = srv.CreateKey(ctx, otherCurve)
	assert.ErrorIs(t, err, module.ErrProvisionKeyConflict)

	_, err = srv.CreateKey(ctx, KeyRequest{Token: "nope", Label: testLabel})
	assert.ErrorIs(t, err, ErrUnknownSlot)

	_, err = srv.CreateKey(ctx, KeyRequest{Token: testToken, Label: "not-named"})
	assert.ErrorIs(t, err, ErrKeyNotNamed)

	_, err = srv.CreateKey(ctx, KeyRequest{Token: testToken, Label: testLabel2, ID: []byte{9}, Curve: "P-521", UserPIN: testUserPIN})
	assert.ErrorIs(t, err, module.ErrProvisionCurveUnsupported)

	_, err = srv.CreateKey(ctx, KeyRequest{Token: testToken, Label: testLabel2, ID: []byte{9}, Curve: "P-256", UserPIN: "wrong-pin-0000"})
	var perr *module.ProvisionError
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, "C_Login(CKU_USER)", perr.Step)
}

func TestCreateKeyOnUninitializedTokenNeedsSOPIN(t *testing.T) {
	srv := newTestServer(t, []uint32{uint32(os.Geteuid())})
	_, err := srv.CreateKey(context.Background(), KeyRequest{
		Token: testToken, Label: testLabel, ID: []byte{1}, Curve: "P-256", UserPIN: testUserPIN,
	})
	assert.ErrorIs(t, err, module.ErrProvisionSOPINRequired)
}

func TestNewValidatesConfig(t *testing.T) {
	backends := map[string]xkms.Backend{"software": newSoftwareBackend(t)}
	valid := func() Config {
		return Config{
			SocketPath:  socketPath(t),
			AllowedUIDs: []uint32{1000},
			Backends:    backends,
			StateDAOs:   testutil.NewMemoryDAOFactory(),
			Slots:       []Slot{{Token: testToken, Keys: []string{testLabel}}},
		}
	}
	tests := map[string]struct {
		mutate func(*Config)
		want   error
	}{
		"socket path":   {func(c *Config) { c.SocketPath = "" }, ErrSocketPathRequired},
		"peers":         {func(c *Config) { c.AllowedUIDs = nil }, ErrNoAllowedPeers},
		"backends":      {func(c *Config) { c.Backends = nil }, ErrBackendsRequired},
		"state":         {func(c *Config) { c.StateDAOs = nil }, ErrStateStorageRequired},
		"slots":         {func(c *Config) { c.Slots = nil }, ErrSlotsRequired},
		"slot token":    {func(c *Config) { c.Slots = []Slot{{Keys: []string{"k"}}} }, ErrSlotTokenRequired},
		"slot keys":     {func(c *Config) { c.Slots = []Slot{{Token: "t"}} }, ErrSlotKeysRequired},
		"empty label":   {func(c *Config) { c.Slots = []Slot{{Token: "t", Keys: []string{""}}} }, ErrSlotKeysRequired},
		"duplicate":     {func(c *Config) { c.Slots = append(c.Slots, c.Slots[0]) }, ErrSlotDuplicate},
		"default unset": {func(c *Config) { c.DefaultBackend = "tpm2" }, xkms.ErrDefaultBackendNotFound},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(&cfg)
			_, err := New(context.Background(), cfg)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.want), "error %v is not %v", err, tt.want)
		})
	}

	srv, err := New(context.Background(), valid())
	require.NoError(t, err)
	assert.Equal(t, DefaultSocketMode, srv.config.SocketMode)
}

// TestNewRefusesAStateFactoryWithoutTheDatabase proves a DAO factory that does
// not serve StateDatabase fails New as "open token store", not at first use.
func TestNewRefusesAStateFactoryWithoutTheDatabase(t *testing.T) {
	_, err := New(context.Background(), Config{
		SocketPath:  socketPath(t),
		AllowedUIDs: []uint32{1000},
		Backends:    map[string]xkms.Backend{"software": newSoftwareBackend(t)},
		StateDAOs:   dao.NewStoreFactory(nil),
		Slots:       []Slot{{Token: testToken, Keys: []string{testLabel}}},
	})
	var serr *Error
	require.ErrorAs(t, err, &serr)
	assert.Equal(t, "open token store", serr.Op)
}

func TestRefreshHonoursCancellation(t *testing.T) {
	srv := newTestServer(t, []uint32{uint32(os.Geteuid())})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, srv.Refresh(ctx), context.Canceled)
}

func TestPolicyRejectsMismatchedRequestShapes(t *testing.T) {
	p := &policy{slots: map[string]map[string]struct{}{testToken: {}}, keys: newKeys()}
	for method, decide := range rules {
		if method == pb.KeystoreService_Health_FullMethodName {
			assert.NoError(t, decide(p, struct{}{}))
			continue
		}
		assert.ErrorIs(t, decide(p, struct{}{}), ErrRequestShape, method)
	}
	err := p.stream(nil, nil, &grpc.StreamServerInfo{FullMethod: "/x/Stream"}, nil)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func newKeys() *atomic.Pointer[keySet] {
	k := &atomic.Pointer[keySet]{}
	k.Store(&keySet{})
	return k
}

func keystoreClient(t *testing.T, srv *Server) pb.KeystoreServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+srv.SocketPath(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewKeystoreServiceClient(conn)
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func sha384Sum(s string) []byte {
	sum := sha512.Sum384([]byte(s))
	return sum[:]
}

func TestServeReportsBindFailure(t *testing.T) {
	dir, err := os.MkdirTemp("", "ss")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// A socket directory other users can write to is refused before bind.
	require.NoError(t, os.Chmod(dir, 0o777))

	srv, err := New(context.Background(), Config{
		SocketPath:  filepath.Join(dir, "sign.sock"),
		AllowedUIDs: []uint32{uint32(os.Geteuid())},
		Backends:    map[string]xkms.Backend{"software": newSoftwareBackend(t)},
		StateDAOs:   testutil.NewMemoryDAOFactory(),
		Slots:       []Slot{{Token: testToken, Keys: []string{testLabel}}},
	})
	require.NoError(t, err)

	err = srv.Serve()
	var serr *Error
	require.ErrorAs(t, err, &serr)
	assert.Equal(t, "serve", serr.Op)
	assert.Contains(t, err.Error(), "signserver: serve: ")
}

func TestPolicyCounterWriteNeedsAKnownSlot(t *testing.T) {
	p := &policy{slots: map[string]map[string]struct{}{testToken: {}}, keys: newKeys()}
	err := p.admitCounterWrite(&pb.PKCS11StatePutRequest{Token: "other", Key: counterPrefix + "0/failed_user"})
	assert.ErrorIs(t, err, ErrUnknownSlot)
	assert.NoError(t, p.admitCounterWrite(&pb.PKCS11StatePutRequest{Token: testToken, Key: counterPrefix + "0/failed_so"}))
}

func TestErrorMessagesNameTheOperationAndSlot(t *testing.T) {
	err := &Error{Op: "create key", Err: &SlotError{Token: "ike", Err: ErrKeyNotNamed}}
	assert.Equal(t, "signserver: create key: slot ike: "+ErrKeyNotNamed.Error(), err.Error())
	assert.ErrorIs(t, err, ErrKeyNotNamed)
}
