package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	pkgsshkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// generateSSHKeyWith creates a user/alice key of the given algorithm and
// returns its parsed public key.
func generateSSHKeyWith(t *testing.T, s *Server, name, algorithm string) gossh.PublicKey {
	t.Helper()
	result, err := s.handleSSHKeysGenerate(context.Background(), sshRequest(t, "ssh.keys.generate",
		sdkssh.GenerateRequest{Scope: "user", Owner: "alice", Name: name, Algorithm: algorithm, RSABits: 2048}))
	require.NoError(t, err)
	key, ok := result.(*sdkssh.Key)
	require.True(t, ok, "generate must return *sdkssh.Key, got %T", result)
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key.PublicKey))
	require.NoError(t, err)
	return pub
}

// TestSSHKeys_SignWithAlgorithm covers RFC 8332 §3 on the MCP sign path:
// a named algorithm produces a signature of that format, and an algorithm
// the key type does not allow is invalid params.
func TestSSHKeys_SignWithAlgorithm(t *testing.T) {
	server := newSSHServer(t)
	ctx := context.Background()
	rsaPub := generateSSHKeyWith(t, server, "rsa-key", "rsa")
	generateSSHKeyWith(t, server, "ecdsa-key", "ecdsa-p256")

	t.Run("rsa-sha2-512", func(t *testing.T) {
		data := []byte("session data")
		result, err := server.handleSSHKeysSign(ctx, sshRequest(t, "ssh.keys.sign", SSHSignParams{
			Scope: "user", Owner: "alice", Name: "rsa-key", Digest: data, Algorithm: gossh.KeyAlgoRSASHA512,
		}))
		require.NoError(t, err)
		res := result.(SSHSignResult)
		sig := &gossh.Signature{Format: res.Format, Blob: res.Blob, Rest: res.Rest}
		require.Equal(t, gossh.KeyAlgoRSASHA512, sig.Format)
		require.NoError(t, rsaPub.Verify(data, sig))
	})

	refusals := []struct {
		name, key, algorithm string
	}{
		{"unknown algorithm", "rsa-key", "rsa-sha2-1024"},
		{"rsa algorithm for ecdsa key", "ecdsa-key", gossh.KeyAlgoRSASHA256},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			_, err := server.handleSSHKeysSign(ctx, sshRequest(t, "ssh.keys.sign", SSHSignParams{
				Scope: "user", Owner: "alice", Name: tt.key, Digest: []byte("d"), Algorithm: tt.algorithm,
			}))
			var opErr *KeyOpError
			require.True(t, errors.As(err, &opErr), "err = %v", err)
			require.Equal(t, ErrCodeInvalidParams, opErr.Code)
			var algErr *pkgsshkeys.SignatureAlgorithmError
			require.True(t, errors.As(err, &algErr), "err = %v", err)
		})
	}
}
