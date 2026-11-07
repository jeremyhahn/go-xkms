package rest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

// postSSHSign posts a sign request carrying algorithm to a server whose key
// signs with signer.
func postSSHSign(t *testing.T, signer gossh.Signer, data []byte, algorithm string) *http.Response {
	t.Helper()
	mc := newMockSSHClient()
	mc.keys.signer = signer
	srv := newSSHTestServer(t, mc)
	body, err := json.Marshal(restSignRequestDTO{Digest: data, Algorithm: algorithm})
	require.NoError(t, err)
	resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/user/alice/k/sign", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestSSHHandleSign_Algorithm covers RFC 8332 §3 on the REST sign path: a
// named algorithm produces a signature of that format, and an algorithm the
// key type does not allow is 400.
func TestSSHHandleSign_Algorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaSigner, err := gossh.NewSignerFromKey(rsaKey)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecSigner, err := gossh.NewSignerFromKey(ecKey)
	require.NoError(t, err)

	t.Run("rsa-sha2-512", func(t *testing.T) {
		data := []byte("session data")
		resp := postSSHSign(t, rsaSigner, data, gossh.KeyAlgoRSASHA512)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var out restSignResponseDTO
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		sig := &gossh.Signature{Format: out.Format, Blob: out.Blob, Rest: out.Rest}
		require.Equal(t, gossh.KeyAlgoRSASHA512, sig.Format)
		require.NoError(t, rsaSigner.PublicKey().Verify(data, sig))
	})

	refusals := []struct {
		name      string
		signer    gossh.Signer
		algorithm string
	}{
		{"unknown algorithm", rsaSigner, "rsa-sha2-1024"},
		{"rsa algorithm for ecdsa key", ecSigner, gossh.KeyAlgoRSASHA256},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			resp := postSSHSign(t, tt.signer, []byte("d"), tt.algorithm)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var env sshErrorEnvelope
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
			require.Contains(t, env.Error, "not allowed for key type")
		})
	}
}
