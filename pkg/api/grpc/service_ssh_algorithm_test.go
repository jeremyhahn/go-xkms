package grpc

import (
	"context"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// generateBackendSSHKey creates a software-backend key named name and
// returns its parsed public key.
func generateBackendSSHKey(t *testing.T, svc *Service, name, algorithm string) gossh.PublicKey {
	t.Helper()
	ctx := context.Background()
	if _, err := svc.SSHGenerateKey(ctx, &pb.SSHGenerateKeyRequest{
		Scope: "user", Owner: "alice", Name: name,
		Algorithm: algorithm, RsaBits: 2048, Backend: "software",
	}); err != nil {
		t.Fatalf("SSHGenerateKey: %v", err)
	}
	line, err := svc.SSHExportPublic(ctx, &pb.SSHKeyRef{Scope: "user", Owner: "alice", Name: name})
	if err != nil {
		t.Fatalf("SSHExportPublic: %v", err)
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line.GetLine()))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	return pub
}

// TestService_SSHSignWithAlgorithm covers RFC 8332 §3 on the gRPC sign
// path, through the embedded backend signer: a named algorithm produces a
// signature of that format, and an algorithm the key type does not allow
// is InvalidArgument.
func TestService_SSHSignWithAlgorithm(t *testing.T) {
	ctx := context.Background()
	svc := newSSHService(t)
	rsaPub := generateBackendSSHKey(t, svc, "rsa-key", "rsa")
	generateBackendSSHKey(t, svc, "ecdsa-key", "ecdsa-p256")

	t.Run("rsa-sha2-512", func(t *testing.T) {
		data := []byte("session data")
		resp, err := svc.SSHSign(ctx, &pb.SSHSignRequest{
			Key:       &pb.SSHKeyRef{Scope: "user", Owner: "alice", Name: "rsa-key"},
			Digest:    data,
			Algorithm: gossh.KeyAlgoRSASHA512,
		})
		if err != nil {
			t.Fatalf("SSHSign: %v", err)
		}
		sig := &gossh.Signature{Format: resp.GetFormat(), Blob: resp.GetBlob()}
		if sig.Format != gossh.KeyAlgoRSASHA512 {
			t.Fatalf("Format = %q, want %q", sig.Format, gossh.KeyAlgoRSASHA512)
		}
		if err := rsaPub.Verify(data, sig); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	refusals := []struct {
		name, key, algorithm string
	}{
		{"unknown algorithm", "rsa-key", "rsa-sha2-1024"},
		{"rsa algorithm for ecdsa key", "ecdsa-key", gossh.KeyAlgoRSASHA256},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.SSHSign(ctx, &pb.SSHSignRequest{
				Key:       &pb.SSHKeyRef{Scope: "user", Owner: "alice", Name: tt.key},
				Digest:    []byte("d"),
				Algorithm: tt.algorithm,
			})
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Fatalf("code = %v (%v), want InvalidArgument", got, err)
			}
		})
	}
}
