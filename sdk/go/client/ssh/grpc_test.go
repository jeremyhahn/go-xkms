// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ----------------------------------------------------------------------------
// Fake KeystoreService server.
//
// The fake records the last request it saw for each RPC so tests can assert
// that the SDK marshalled the caller's DTO onto the wire correctly, and lets
// each test program the response (or a gRPC status error) that comes back.
// ----------------------------------------------------------------------------

type fakeKeystore struct {
	pb.UnimplementedKeystoreServiceServer

	// Programmable responses.
	keyResp     *pb.SSHKeyResponse
	listResp    *pb.SSHListKeysResponse
	pubResp     *pb.SSHPublicKeyResponse
	signResp    *pb.SSHSignResponse
	pinsResp    *pb.SSHListKnownHostsResponse
	entriesResp *pb.SSHListAuthorizedKeysResponse
	err         error

	// Recorded requests.
	genReq    *pb.SSHGenerateKeyRequest
	importReq *pb.SSHImportKeyRequest
	getRef    *pb.SSHKeyRef
	listReq   *pb.SSHListKeysRequest
	deleteRef *pb.SSHKeyRef
	exportRef *pb.SSHKeyRef
	signReq   *pb.SSHSignRequest
	addPinReq *pb.SSHAddKnownHostRequest
	rmPinReq  *pb.SSHRemoveKnownHostRequest
	addAKReq  *pb.SSHAddAuthorizedKeyRequest
	rmAKRef   *pb.SSHAuthorizedKeyRef
}

func (f *fakeKeystore) SSHGenerateKey(_ context.Context, req *pb.SSHGenerateKeyRequest) (*pb.SSHKeyResponse, error) {
	f.genReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.keyResp, nil
}

func (f *fakeKeystore) SSHImportKey(_ context.Context, req *pb.SSHImportKeyRequest) (*pb.SSHKeyResponse, error) {
	f.importReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.keyResp, nil
}

func (f *fakeKeystore) SSHGetKey(_ context.Context, ref *pb.SSHKeyRef) (*pb.SSHKeyResponse, error) {
	f.getRef = ref
	if f.err != nil {
		return nil, f.err
	}
	return f.keyResp, nil
}

func (f *fakeKeystore) SSHListKeys(_ context.Context, req *pb.SSHListKeysRequest) (*pb.SSHListKeysResponse, error) {
	f.listReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.listResp, nil
}

func (f *fakeKeystore) SSHDeleteKey(_ context.Context, ref *pb.SSHKeyRef) (*emptypb.Empty, error) {
	f.deleteRef = ref
	if f.err != nil {
		return nil, f.err
	}
	return &emptypb.Empty{}, nil
}

func (f *fakeKeystore) SSHExportPublic(_ context.Context, ref *pb.SSHKeyRef) (*pb.SSHPublicKeyResponse, error) {
	f.exportRef = ref
	if f.err != nil {
		return nil, f.err
	}
	return f.pubResp, nil
}

func (f *fakeKeystore) SSHSign(_ context.Context, req *pb.SSHSignRequest) (*pb.SSHSignResponse, error) {
	f.signReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.signResp, nil
}

func (f *fakeKeystore) SSHAddKnownHost(_ context.Context, req *pb.SSHAddKnownHostRequest) (*emptypb.Empty, error) {
	f.addPinReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &emptypb.Empty{}, nil
}

func (f *fakeKeystore) SSHListKnownHosts(_ context.Context, _ *pb.SSHListKnownHostsRequest) (*pb.SSHListKnownHostsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.pinsResp, nil
}

func (f *fakeKeystore) SSHRemoveKnownHost(_ context.Context, req *pb.SSHRemoveKnownHostRequest) (*emptypb.Empty, error) {
	f.rmPinReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &emptypb.Empty{}, nil
}

func (f *fakeKeystore) SSHAddAuthorizedKey(_ context.Context, req *pb.SSHAddAuthorizedKeyRequest) (*emptypb.Empty, error) {
	f.addAKReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &emptypb.Empty{}, nil
}

func (f *fakeKeystore) SSHListAuthorizedKeys(_ context.Context, _ *pb.SSHListAuthorizedKeysRequest) (*pb.SSHListAuthorizedKeysResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.entriesResp, nil
}

func (f *fakeKeystore) SSHRemoveAuthorizedKey(_ context.Context, ref *pb.SSHAuthorizedKeyRef) (*emptypb.Empty, error) {
	f.rmAKRef = ref
	if f.err != nil {
		return nil, f.err
	}
	return &emptypb.Empty{}, nil
}

// newGRPCFixture starts the fake KeystoreService on an ephemeral loopback
// port and returns it alongside a real SDK gRPC client bound to it.
func newGRPCFixture(t *testing.T, fake *fakeKeystore) sdkssh.Client {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, fake)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(lis)
	}()

	client, err := sdkssh.NewGRPC(sdkssh.GRPCOptions{Endpoint: lis.Addr().String()})
	if err != nil {
		srv.Stop()
		<-done
		t.Fatalf("NewGRPC: %v", err)
	}

	t.Cleanup(func() {
		_ = client.Close()
		srv.Stop()
		<-done
	})
	return client
}

// testPublicKeyLine returns a real ed25519 authorized_keys line plus its
// parsed form, so signer/verify tests exercise genuine key material.
func testPublicKeyLine(t *testing.T) (string, gossh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return string(gossh.MarshalAuthorizedKey(sshPub)), sshPub
}

// ----------------------------------------------------------------------------
// Constructor.
// ----------------------------------------------------------------------------

func TestNewGRPC_MissingEndpoint(t *testing.T) {
	_, err := sdkssh.NewGRPC(sdkssh.GRPCOptions{})
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %v", err)
	}
	if nilErr.Field != "Endpoint" {
		t.Errorf("Field = %q, want %q", nilErr.Field, "Endpoint")
	}
}

func TestNewGRPC_TLSCAUnreadable(t *testing.T) {
	// TLSEnabled with an unreadable CA must fail loudly rather than
	// silently falling back to an insecure connection.
	_, err := sdkssh.NewGRPC(sdkssh.GRPCOptions{
		Endpoint:   "127.0.0.1:1",
		TLSEnabled: true,
		TLSCAFile:  filepath.Join(t.TempDir(), "missing-ca.pem"),
	})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %v", err)
	}
	if protoErr.Message != "read tls ca" {
		t.Errorf("Message = %q, want %q", protoErr.Message, "read tls ca")
	}
}

func TestNewGRPC_TLSCAMalformed(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a pem certificate"), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	_, err := sdkssh.NewGRPC(sdkssh.GRPCOptions{
		Endpoint:   "127.0.0.1:1",
		TLSEnabled: true,
		TLSCAFile:  caPath,
	})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %v", err)
	}
	if protoErr.Message != "parse tls ca: no certificates found" {
		t.Errorf("Message = %q", protoErr.Message)
	}
}

func TestGRPCClose_Idempotent(t *testing.T) {
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)
	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close must not panic on the nil'd conn nor report an error.
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Keys.
// ----------------------------------------------------------------------------

func TestGRPCKeys_GenerateMarshalsRequestAndMapsResponse(t *testing.T) {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	fake := &fakeKeystore{
		keyResp: &pb.SSHKeyResponse{Key: &pb.SSHKeyInfo{
			Scope:        "user",
			Owner:        "alice",
			Name:         "laptop",
			Algorithm:    "ed25519",
			PublicKey:    "ssh-ed25519 AAAA",
			Fingerprint:  "SHA256:abc",
			CreatedAt:    timestamppb.New(created),
			Comment:      "alice@laptop",
			Backend:      "tpm2",
			BackendKeyId: "ssh-user-alice-laptop",
		}},
	}
	client := newGRPCFixture(t, fake)

	key, err := client.Keys().Generate(context.Background(), sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "laptop",
		Algorithm: "rsa",
		RSABits:   4096,
		Comment:   "alice@laptop",
		Backend:   "tpm2",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Every DTO field must reach the wire — a dropped field here is exactly
	// the regression class that silently downgrades key strength/placement.
	if fake.genReq.GetAlgorithm() != "rsa" {
		t.Errorf("wire Algorithm = %q, want rsa", fake.genReq.GetAlgorithm())
	}
	if fake.genReq.GetRsaBits() != 4096 {
		t.Errorf("wire RsaBits = %d, want 4096", fake.genReq.GetRsaBits())
	}
	if fake.genReq.GetBackend() != "tpm2" {
		t.Errorf("wire Backend = %q, want tpm2", fake.genReq.GetBackend())
	}
	if fake.genReq.GetScope() != "user" || fake.genReq.GetOwner() != "alice" || fake.genReq.GetName() != "laptop" {
		t.Errorf("wire identity = %q/%q/%q", fake.genReq.GetScope(), fake.genReq.GetOwner(), fake.genReq.GetName())
	}
	if fake.genReq.GetComment() != "alice@laptop" {
		t.Errorf("wire Comment = %q", fake.genReq.GetComment())
	}

	// And the response must map back completely, including the backend
	// correlation fields the unified key view depends on.
	if key.Backend != "tpm2" || key.BackendKeyID != "ssh-user-alice-laptop" {
		t.Errorf("backend correlation lost: %q / %q", key.Backend, key.BackendKeyID)
	}
	if key.Fingerprint != "SHA256:abc" || key.Algorithm != "ed25519" {
		t.Errorf("key = %+v", key)
	}
	if !key.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", key.CreatedAt, created)
	}
}

func TestGRPCKeys_GenerateErrorMapping(t *testing.T) {
	// Each gRPC status code must surface as the corresponding typed SDK
	// error so callers can branch on it across transports.
	tests := []struct {
		name  string
		code  codes.Code
		check func(error) bool
	}{
		{"not_found", codes.NotFound, func(e error) bool {
			var t *sdkssh.NotFoundError
			return errors.As(e, &t)
		}},
		{"invalid_argument", codes.InvalidArgument, func(e error) bool {
			var t *sdkssh.InvalidRequestError
			return errors.As(e, &t)
		}},
		{"failed_precondition", codes.FailedPrecondition, func(e error) bool {
			var t *sdkssh.ServerError
			return errors.As(e, &t)
		}},
		{"unavailable", codes.Unavailable, func(e error) bool {
			var t *sdkssh.ServerError
			return errors.As(e, &t)
		}},
		{"internal_falls_through", codes.Internal, func(e error) bool {
			var t *sdkssh.ProtocolError
			return errors.As(e, &t)
		}},
		{"permission_denied_falls_through", codes.PermissionDenied, func(e error) bool {
			var t *sdkssh.ProtocolError
			return errors.As(e, &t)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeKeystore{err: status.Error(tc.code, "boom-"+tc.name)}
			client := newGRPCFixture(t, fake)

			_, err := client.Keys().Generate(context.Background(), sdkssh.GenerateRequest{Name: "k"})
			if err == nil {
				t.Fatal("expected error")
			}
			if !tc.check(err) {
				t.Fatalf("code %v mapped to wrong type: %T (%v)", tc.code, err, err)
			}
			// The server's message must be preserved for operators.
			if got := err.Error(); !strings.Contains(got, "boom-"+tc.name) {
				t.Errorf("server message lost: %q", got)
			}
		})
	}
}

func TestGRPCKeys_NilKeyInResponse(t *testing.T) {
	// A server that answers OK but omits the key must not panic the client.
	fake := &fakeKeystore{keyResp: &pb.SSHKeyResponse{}}
	client := newGRPCFixture(t, fake)

	key, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{Scope: "user", Owner: "a", Name: "k"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if key != nil {
		t.Fatalf("expected nil key for empty response, got %+v", key)
	}
}

func TestGRPCKeys_GetSendsKeyRef(t *testing.T) {
	fake := &fakeKeystore{keyResp: &pb.SSHKeyResponse{Key: &pb.SSHKeyInfo{Name: "laptop"}}}
	client := newGRPCFixture(t, fake)

	if _, err := client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
	}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fake.getRef.GetScope() != "user" || fake.getRef.GetOwner() != "alice" || fake.getRef.GetName() != "laptop" {
		t.Errorf("key ref = %+v", fake.getRef)
	}
}

func TestGRPCKeys_ImportForwardsPEM(t *testing.T) {
	pemBytes := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
	fake := &fakeKeystore{keyResp: &pb.SSHKeyResponse{Key: &pb.SSHKeyInfo{Name: "imported"}}}
	client := newGRPCFixture(t, fake)

	key, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{
		Scope: "user", Owner: "alice", Name: "imported", PEM: pemBytes, Comment: "from-file",
	}, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if key.Name != "imported" {
		t.Errorf("Name = %q", key.Name)
	}
	if string(fake.importReq.GetPem()) != string(pemBytes) {
		t.Errorf("PEM not forwarded verbatim")
	}
	if fake.importReq.GetComment() != "from-file" {
		t.Errorf("Comment = %q", fake.importReq.GetComment())
	}
}

func TestGRPCKeys_ImportError(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.InvalidArgument, "encrypted pem unsupported")}
	client := newGRPCFixture(t, fake)

	_, err := client.Keys().Import(context.Background(), sdkssh.ImportRequest{Name: "k", PEM: []byte("x")}, nil)
	var invalid *sdkssh.InvalidRequestError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidRequestError, got %T %v", err, err)
	}
}

func TestGRPCKeys_ListMapsAllEntries(t *testing.T) {
	fake := &fakeKeystore{listResp: &pb.SSHListKeysResponse{Keys: []*pb.SSHKeyInfo{
		{Name: "one", Algorithm: "ed25519", Backend: "software"},
		{Name: "two", Algorithm: "rsa", Backend: "pkcs11", BackendKeyId: "cn-two"},
	}}}
	client := newGRPCFixture(t, fake)

	keys, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("len = %d, want 2", len(keys))
	}
	if keys[0].Name != "one" || keys[1].Name != "two" {
		t.Errorf("order/mapping wrong: %q %q", keys[0].Name, keys[1].Name)
	}
	if keys[1].BackendKeyID != "cn-two" {
		t.Errorf("BackendKeyID = %q", keys[1].BackendKeyID)
	}
	if fake.listReq.GetScope() != "user" || fake.listReq.GetOwner() != "alice" {
		t.Errorf("list filter not forwarded: %+v", fake.listReq)
	}
}

func TestGRPCKeys_ListEmptyIsNotError(t *testing.T) {
	fake := &fakeKeystore{listResp: &pb.SSHListKeysResponse{}}
	client := newGRPCFixture(t, fake)

	keys, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("len = %d, want 0", len(keys))
	}
}

func TestGRPCKeys_ListError(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.Unavailable, "down")}
	client := newGRPCFixture(t, fake)

	if _, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestGRPCKeys_DeleteSendsRefAndReportsSuccess(t *testing.T) {
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)

	if err := client.Keys().Delete(context.Background(), sdkssh.DeleteKeyRequest{
		Scope: "service", Owner: "svc", Name: "deploy",
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if fake.deleteRef.GetScope() != "service" || fake.deleteRef.GetName() != "deploy" {
		t.Errorf("delete ref = %+v", fake.deleteRef)
	}
}

func TestGRPCKeys_DeleteNotFound(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.NotFound, "no such key")}
	client := newGRPCFixture(t, fake)

	err := client.Keys().Delete(context.Background(), sdkssh.DeleteKeyRequest{Name: "ghost"})
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T %v", err, err)
	}
}

func TestGRPCKeys_ExportPublic(t *testing.T) {
	fake := &fakeKeystore{pubResp: &pb.SSHPublicKeyResponse{
		Algorithm: "ed25519", Line: "ssh-ed25519 AAAA host", Fingerprint: "SHA256:zzz",
	}}
	client := newGRPCFixture(t, fake)

	pub, err := client.Keys().ExportPublic(context.Background(), sdkssh.ExportRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
	})
	if err != nil {
		t.Fatalf("ExportPublic: %v", err)
	}
	if pub.Algorithm != "ed25519" || pub.Line != "ssh-ed25519 AAAA host" || pub.Fingerprint != "SHA256:zzz" {
		t.Errorf("pub = %+v", pub)
	}
	if fake.exportRef.GetName() != "laptop" {
		t.Errorf("export ref = %+v", fake.exportRef)
	}
}

func TestGRPCKeys_ExportPublicError(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.NotFound, "gone")}
	client := newGRPCFixture(t, fake)

	_, err := client.Keys().ExportPublic(context.Background(), sdkssh.ExportRequest{Name: "gone"})
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T %v", err, err)
	}
}

// ----------------------------------------------------------------------------
// Remote signer proxy.
// ----------------------------------------------------------------------------

func TestGRPCKeys_SignerForwardsDigestAndReturnsSignature(t *testing.T) {
	line, sshPub := testPublicKeyLine(t)
	fake := &fakeKeystore{
		pubResp:  &pb.SSHPublicKeyResponse{Algorithm: "ed25519", Line: line},
		signResp: &pb.SSHSignResponse{Format: "ssh-ed25519", Blob: []byte("sig-blob")},
	}
	client := newGRPCFixture(t, fake)

	signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
	})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	// The proxy's public key must be the exported one — a mismatch here means
	// the server would reject every auth attempt.
	if string(signer.PublicKey().Marshal()) != string(sshPub.Marshal()) {
		t.Error("signer public key does not match exported key")
	}

	digest := []byte("data-to-sign")
	sig, err := signer.Sign(rand.Reader, digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Format != "ssh-ed25519" || string(sig.Blob) != "sig-blob" {
		t.Errorf("signature = %+v", sig)
	}
	// The digest must reach the server unmodified, addressed to the right key.
	if string(fake.signReq.GetDigest()) != string(digest) {
		t.Errorf("digest = %q, want %q", fake.signReq.GetDigest(), digest)
	}
	if fake.signReq.GetKey().GetName() != "laptop" || fake.signReq.GetKey().GetOwner() != "alice" {
		t.Errorf("sign key ref = %+v", fake.signReq.GetKey())
	}
}

func TestGRPCKeys_SignerExportFails(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.NotFound, "no key")}
	client := newGRPCFixture(t, fake)

	if _, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "ghost"}); err == nil {
		t.Fatal("expected error when the key cannot be exported")
	}
}

func TestGRPCKeys_SignerUnparsablePublicKey(t *testing.T) {
	// A hostile/broken server returning garbage in Line must produce a typed
	// protocol error, not a panic or a signer with a nil public key.
	fake := &fakeKeystore{pubResp: &pb.SSHPublicKeyResponse{Line: "this-is-not-an-ssh-key"}}
	client := newGRPCFixture(t, fake)

	_, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "laptop"})
	var protoErr *sdkssh.ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *ProtocolError, got %T %v", err, err)
	}
	if protoErr.Message != "parse exported public key" {
		t.Errorf("Message = %q", protoErr.Message)
	}
}

func TestGRPCSigner_SignServerError(t *testing.T) {
	line, _ := testPublicKeyLine(t)
	fake := &fakeKeystore{pubResp: &pb.SSHPublicKeyResponse{Line: line}}
	client := newGRPCFixture(t, fake)

	signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	// Flip the server to failing now that the signer exists.
	fake.err = status.Error(codes.FailedPrecondition, "hardware locked")

	_, err = signer.Sign(rand.Reader, []byte("x"))
	var srvErr *sdkssh.ServerError
	if !errors.As(err, &srvErr) {
		t.Fatalf("expected *ServerError, got %T %v", err, err)
	}
}

// ----------------------------------------------------------------------------
// KnownHosts.
// ----------------------------------------------------------------------------

func TestGRPCKnownHosts_AddForwardsAllFields(t *testing.T) {
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)

	if err := client.KnownHosts().Add(context.Background(), sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com",
		Fingerprint: "SHA256:pin", Algorithm: "ssh-ed25519", Source: "tofu",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got := fake.addPinReq
	if got.GetHost() != "git.example.com" || got.GetFingerprint() != "SHA256:pin" ||
		got.GetAlgorithm() != "ssh-ed25519" || got.GetSource() != "tofu" {
		t.Errorf("pin request = %+v", got)
	}
}

func TestGRPCKnownHosts_AddError(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.InvalidArgument, "bad fingerprint")}
	client := newGRPCFixture(t, fake)

	err := client.KnownHosts().Add(context.Background(), sdkssh.AddKnownHostRequest{Host: "h"})
	var invalid *sdkssh.InvalidRequestError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidRequestError, got %T %v", err, err)
	}
}

func TestGRPCKnownHosts_ListMapsTimestampAndSource(t *testing.T) {
	added := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fake := &fakeKeystore{pinsResp: &pb.SSHListKnownHostsResponse{Pins: []*pb.SSHPin{{
		Scope: "user", Owner: "alice", Host: "git.example.com",
		Fingerprint: "SHA256:pin", Algorithm: "ssh-ed25519",
		AddedAt: timestamppb.New(added), Source: "tofu",
	}}}}
	client := newGRPCFixture(t, fake)

	pins, err := client.KnownHosts().List(context.Background(), sdkssh.ListKnownHostsRequest{Scope: "user"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("len = %d", len(pins))
	}
	if !pins[0].AddedAt.Equal(added) {
		t.Errorf("AddedAt = %v, want %v", pins[0].AddedAt, added)
	}
	if pins[0].Source != "tofu" || pins[0].Algorithm != "ssh-ed25519" {
		t.Errorf("pin = %+v", pins[0])
	}
}

func TestGRPCKnownHosts_ListError(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.Unavailable, "down")}
	client := newGRPCFixture(t, fake)

	if _, err := client.KnownHosts().List(context.Background(), sdkssh.ListKnownHostsRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestGRPCKnownHosts_Remove(t *testing.T) {
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)

	if err := client.KnownHosts().Remove(context.Background(), sdkssh.RemoveKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com",
	}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if fake.rmPinReq.GetHost() != "git.example.com" {
		t.Errorf("remove request = %+v", fake.rmPinReq)
	}
}

func TestGRPCKnownHosts_RemoveNotFound(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.NotFound, "no pin")}
	client := newGRPCFixture(t, fake)

	err := client.KnownHosts().Remove(context.Background(), sdkssh.RemoveKnownHostRequest{Host: "h"})
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T %v", err, err)
	}
}

// TestGRPCKnownHosts_VerifyTrustDecisions covers the client-side host-key
// trust comparison. Getting any branch of this wrong is a MITM exposure.
func TestGRPCKnownHosts_VerifyTrustDecisions(t *testing.T) {
	line, sshPub := testPublicKeyLine(t)
	_ = line
	goodFP := gossh.FingerprintSHA256(sshPub)

	t.Run("matching_pin_accepted", func(t *testing.T) {
		fake := &fakeKeystore{pinsResp: &pb.SSHListKnownHostsResponse{Pins: []*pb.SSHPin{
			{Host: "git.example.com", Fingerprint: goodFP},
		}}}
		client := newGRPCFixture(t, fake)

		if err := client.KnownHosts().Verify(context.Background(), "user", "alice", "git.example.com", sshPub); err != nil {
			t.Fatalf("expected trust, got %v", err)
		}
	})

	t.Run("mismatched_pin_rejected", func(t *testing.T) {
		fake := &fakeKeystore{pinsResp: &pb.SSHListKnownHostsResponse{Pins: []*pb.SSHPin{
			{Host: "git.example.com", Fingerprint: "SHA256:someone-elses-key"},
		}}}
		client := newGRPCFixture(t, fake)

		err := client.KnownHosts().Verify(context.Background(), "user", "alice", "git.example.com", sshPub)
		var mm *sdkssh.MismatchError
		if !errors.As(err, &mm) {
			t.Fatalf("expected *MismatchError (MITM signal), got %T %v", err, err)
		}
		if mm.Expected != "SHA256:someone-elses-key" || mm.Received != goodFP {
			t.Errorf("mismatch detail = %+v", mm)
		}
	})

	t.Run("unpinned_host_rejected", func(t *testing.T) {
		fake := &fakeKeystore{pinsResp: &pb.SSHListKnownHostsResponse{Pins: []*pb.SSHPin{
			{Host: "other.example.com", Fingerprint: goodFP},
		}}}
		client := newGRPCFixture(t, fake)

		err := client.KnownHosts().Verify(context.Background(), "user", "alice", "git.example.com", sshPub)
		var nf *sdkssh.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("expected *NotFoundError for unpinned host, got %T %v", err, err)
		}
	})

	t.Run("nil_key_rejected", func(t *testing.T) {
		fake := &fakeKeystore{pinsResp: &pb.SSHListKnownHostsResponse{}}
		client := newGRPCFixture(t, fake)

		err := client.KnownHosts().Verify(context.Background(), "user", "alice", "h", nil)
		var nilErr *sdkssh.NilInputError
		if !errors.As(err, &nilErr) {
			t.Fatalf("expected *NilInputError, got %T %v", err, err)
		}
	})

	t.Run("list_failure_propagates", func(t *testing.T) {
		fake := &fakeKeystore{err: status.Error(codes.Unavailable, "down")}
		client := newGRPCFixture(t, fake)

		// A store outage must NOT be treated as "host is trusted".
		if err := client.KnownHosts().Verify(context.Background(), "user", "alice", "h", sshPub); err == nil {
			t.Fatal("store outage must not yield trust")
		}
	})
}

func TestGRPCKnownHosts_CallbackStripsPort(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	goodFP := gossh.FingerprintSHA256(sshPub)
	fake := &fakeKeystore{pinsResp: &pb.SSHListKnownHostsResponse{Pins: []*pb.SSHPin{
		{Host: "git.example.com", Fingerprint: goodFP},
	}}}
	client := newGRPCFixture(t, fake)

	cb := client.KnownHosts().Callback(context.Background(), "user", "alice")

	// x/crypto/ssh hands the callback "host:port"; pins are stored per-host,
	// so the port must be stripped or every pinned host fails to verify.
	if err := cb("git.example.com:22", &net.TCPAddr{}, sshPub); err != nil {
		t.Fatalf("callback with port must match host pin: %v", err)
	}
	if err := cb("git.example.com", &net.TCPAddr{}, sshPub); err != nil {
		t.Fatalf("callback without port: %v", err)
	}
	if err := cb("evil.example.com:22", &net.TCPAddr{}, sshPub); err == nil {
		t.Fatal("callback must reject an unpinned host")
	}
}

// ----------------------------------------------------------------------------
// AuthorizedKeys.
// ----------------------------------------------------------------------------

func TestGRPCAuthorizedKeys_AddForwardsOptions(t *testing.T) {
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)

	if err := client.AuthorizedKeys().Add(context.Background(), sdkssh.AddAuthorizedKeyRequest{
		Scope: "service", Owner: "svc", Name: "deploy",
		Line:    "ssh-ed25519 AAAA deploy@ci",
		Options: []string{"no-pty", "command=\"/usr/bin/deploy\""},
		Comment: "ci",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got := fake.addAKReq
	// Options are a security control (forced command / no-pty). Dropping them
	// on the wire silently widens access.
	if len(got.GetOptions()) != 2 || got.GetOptions()[0] != "no-pty" {
		t.Errorf("options not forwarded: %v", got.GetOptions())
	}
	if got.GetLine() != "ssh-ed25519 AAAA deploy@ci" {
		t.Errorf("line = %q", got.GetLine())
	}
}

func TestGRPCAuthorizedKeys_AddError(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.InvalidArgument, "bad line")}
	client := newGRPCFixture(t, fake)

	err := client.AuthorizedKeys().Add(context.Background(), sdkssh.AddAuthorizedKeyRequest{Name: "x"})
	var invalid *sdkssh.InvalidRequestError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidRequestError, got %T %v", err, err)
	}
}

func TestGRPCAuthorizedKeys_List(t *testing.T) {
	fake := &fakeKeystore{entriesResp: &pb.SSHListAuthorizedKeysResponse{Entries: []*pb.SSHAuthorizedEntry{
		{Scope: "service", Owner: "svc", Name: "deploy", Line: "ssh-ed25519 AAAA", Options: []string{"no-pty"}, Comment: "ci"},
	}}}
	client := newGRPCFixture(t, fake)

	entries, err := client.AuthorizedKeys().List(context.Background(), sdkssh.ListAuthorizedKeysRequest{Scope: "service"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len = %d", len(entries))
	}
	if entries[0].Name != "deploy" || entries[0].Comment != "ci" || len(entries[0].Options) != 1 {
		t.Errorf("entry = %+v", entries[0])
	}
}

func TestGRPCAuthorizedKeys_ListError(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.Unavailable, "down")}
	client := newGRPCFixture(t, fake)

	if _, err := client.AuthorizedKeys().List(context.Background(), sdkssh.ListAuthorizedKeysRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

// TestGRPCAuthorizedKeys_GetResolvesByName pins the list-then-match behaviour
// of Get, which has no dedicated RPC. A regression here returns the wrong
// entry (or none) for a name that exists.
func TestGRPCAuthorizedKeys_GetResolvesByName(t *testing.T) {
	fake := &fakeKeystore{entriesResp: &pb.SSHListAuthorizedKeysResponse{Entries: []*pb.SSHAuthorizedEntry{
		{Name: "alpha", Line: "ssh-ed25519 AAAA alpha"},
		{Name: "beta", Line: "ssh-ed25519 BBBB beta", Comment: "the-one"},
		{Name: "gamma", Line: "ssh-ed25519 CCCC gamma"},
	}}}
	client := newGRPCFixture(t, fake)

	entry, err := client.AuthorizedKeys().Get(context.Background(), "service", "svc", "beta")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Name != "beta" || entry.Comment != "the-one" {
		t.Fatalf("resolved the wrong entry: %+v", entry)
	}
}

func TestGRPCAuthorizedKeys_GetMissingName(t *testing.T) {
	fake := &fakeKeystore{entriesResp: &pb.SSHListAuthorizedKeysResponse{Entries: []*pb.SSHAuthorizedEntry{
		{Name: "alpha"},
	}}}
	client := newGRPCFixture(t, fake)

	_, err := client.AuthorizedKeys().Get(context.Background(), "service", "svc", "nope")
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T %v", err, err)
	}
	if nf.Resource != "authorized_key" {
		t.Errorf("Resource = %q", nf.Resource)
	}
}

func TestGRPCAuthorizedKeys_GetListFailurePropagates(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.Unavailable, "down")}
	client := newGRPCFixture(t, fake)

	_, err := client.AuthorizedKeys().Get(context.Background(), "service", "svc", "beta")
	var nf *sdkssh.NotFoundError
	if errors.As(err, &nf) {
		t.Fatal("a transport outage must not be reported as not-found")
	}
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGRPCAuthorizedKeys_Remove(t *testing.T) {
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)

	if err := client.AuthorizedKeys().Remove(context.Background(), "service", "svc", "deploy"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if fake.rmAKRef.GetName() != "deploy" || fake.rmAKRef.GetScope() != "service" {
		t.Errorf("remove ref = %+v", fake.rmAKRef)
	}
}

func TestGRPCAuthorizedKeys_RemoveNotFound(t *testing.T) {
	fake := &fakeKeystore{err: status.Error(codes.NotFound, "no entry")}
	client := newGRPCFixture(t, fake)

	err := client.AuthorizedKeys().Remove(context.Background(), "service", "svc", "ghost")
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T %v", err, err)
	}
}

func TestGRPCAuthorizedKeys_EmitIsLocalAndAppliesOptions(t *testing.T) {
	line, _ := testPublicKeyLine(t)
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)

	out, err := client.AuthorizedKeys().Emit(context.Background(), sdkssh.EmitRequest{
		PublicKey: line,
		Options:   []string{"no-pty", "no-agent-forwarding"},
		Comment:   "restricted",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !strings.Contains(out, "no-pty") || !strings.Contains(out, "no-agent-forwarding") {
		t.Errorf("options missing from emitted line: %q", out)
	}
	if !strings.Contains(out, "restricted") {
		t.Errorf("comment missing from emitted line: %q", out)
	}
	if !strings.Contains(out, "ssh-ed25519") {
		t.Errorf("key type missing from emitted line: %q", out)
	}
}

func TestGRPCAuthorizedKeys_EmitRejectsGarbage(t *testing.T) {
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)

	if _, err := client.AuthorizedKeys().Emit(context.Background(), sdkssh.EmitRequest{
		PublicKey: "definitely not a public key",
	}); err == nil {
		t.Fatal("expected a parse error for a malformed public key")
	}
}

func TestGRPCAuthorizedKeys_VerifyMatchesByFingerprint(t *testing.T) {
	line, sshPub := testPublicKeyLine(t)
	otherLine, _ := testPublicKeyLine(t)

	fake := &fakeKeystore{entriesResp: &pb.SSHListAuthorizedKeysResponse{Entries: []*pb.SSHAuthorizedEntry{
		{Name: "other", Line: otherLine},
		{Name: "mine", Line: line},
	}}}
	client := newGRPCFixture(t, fake)

	entry, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", sshPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if entry.Name != "mine" {
		t.Fatalf("matched the wrong entry: %q", entry.Name)
	}
}

func TestGRPCAuthorizedKeys_VerifySkipsUnparsableEntriesButStillMatches(t *testing.T) {
	line, sshPub := testPublicKeyLine(t)
	fake := &fakeKeystore{entriesResp: &pb.SSHListAuthorizedKeysResponse{Entries: []*pb.SSHAuthorizedEntry{
		{Name: "corrupt", Line: "###not-a-key###"},
		{Name: "mine", Line: line},
	}}}
	client := newGRPCFixture(t, fake)

	// One corrupt row in the store must not shadow a legitimate match.
	entry, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", sshPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if entry.Name != "mine" {
		t.Fatalf("matched %q", entry.Name)
	}
}

func TestGRPCAuthorizedKeys_VerifyRejectsUnknownKey(t *testing.T) {
	knownLine, _ := testPublicKeyLine(t)
	_, strangerPub := testPublicKeyLine(t)

	fake := &fakeKeystore{entriesResp: &pb.SSHListAuthorizedKeysResponse{Entries: []*pb.SSHAuthorizedEntry{
		{Name: "known", Line: knownLine},
	}}}
	client := newGRPCFixture(t, fake)

	_, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", strangerPub)
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("an unauthorized key must be rejected, got %T %v", err, err)
	}
}

func TestGRPCAuthorizedKeys_VerifyNilKey(t *testing.T) {
	fake := &fakeKeystore{entriesResp: &pb.SSHListAuthorizedKeysResponse{}}
	client := newGRPCFixture(t, fake)

	_, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", nil)
	var nilErr *sdkssh.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilInputError, got %T %v", err, err)
	}
}

func TestGRPCAuthorizedKeys_VerifyListFailurePropagates(t *testing.T) {
	_, sshPub := testPublicKeyLine(t)
	fake := &fakeKeystore{err: status.Error(codes.Unavailable, "down")}
	client := newGRPCFixture(t, fake)

	// A store outage must never be reported as "authorized".
	if _, err := client.AuthorizedKeys().Verify(context.Background(), "service", "svc", sshPub); err == nil {
		t.Fatal("store outage must not yield authorization")
	}
}

// ----------------------------------------------------------------------------
// Session (unsupported over gRPC).
// ----------------------------------------------------------------------------

func TestGRPCSession_DialUnsupported(t *testing.T) {
	fake := &fakeKeystore{}
	client := newGRPCFixture(t, fake)

	_, err := client.Session().Dial(context.Background(), sdkssh.SessionDialRequest{Host: "h", User: "u"})
	var ni *sdkssh.NotImplementedError
	if !errors.As(err, &ni) {
		t.Fatalf("expected *NotImplementedError, got %T %v", err, err)
	}
	if ni.Transport != "grpc" || ni.Op != "Session.Dial" {
		t.Errorf("error detail = %+v", ni)
	}
}

// ----------------------------------------------------------------------------
// Console (unsupported).
// ----------------------------------------------------------------------------

// TestGRPCConsole_Unsupported pins the decision that the xkms server never
// terminates an SSH session. The gRPC transport once carried an SSHConsole
// bidi stream that dialed the target host from the server; it was removed
// because it turned the vault into an SSH proxy — server-side request forgery
// and remote code execution against the target, initiated by whoever held a
// key-use grant. The client (xkey) runs the SSH protocol itself and asks the
// server only to sign the authentication challenge (SSHSign).
func TestGRPCConsole_Unsupported(t *testing.T) {
	client := newGRPCFixture(t, &fakeKeystore{})

	session, err := client.Console(context.Background(),
		sdkssh.ConsoleConnectRequest{Host: "h", User: "u"}, sdkssh.ConsoleConfig{})
	if session != nil {
		t.Fatal("Console must not return a session over gRPC")
	}

	var unsupported *sdkssh.ConsoleUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("Console error = %T (%v), want *ConsoleUnsupportedError", err, err)
	}
	if unsupported.Transport != "grpc" {
		t.Errorf("Transport = %q, want %q", unsupported.Transport, "grpc")
	}
}
