package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// statusDaemonHandler answers the IPC status request with a fixed response.
type statusDaemonHandler struct {
	resp *ipc.Response
}

func (h *statusDaemonHandler) HandleTouch() (*ipc.Response, error) {
	return nil, ipc.ErrHandlerFailed
}

func (h *statusDaemonHandler) HandleTypePassword(string) (*ipc.Response, error) {
	return nil, ipc.ErrHandlerFailed
}

func (h *statusDaemonHandler) HandleStatus() (*ipc.Response, error) {
	return h.resp, nil
}

// runFIDO2StatusAgainstDaemon serves resp on a private socket and runs
// `xkey fido2 status` against it.
func runFIDO2StatusAgainstDaemon(t *testing.T, resp *ipc.Response) (string, string, error) {
	t.Helper()

	sockPath := filepath.Join(privateTempDir(t), "xkey-ipc.sock")
	srv, err := ipc.NewServer(sockPath, &statusDaemonHandler{resp: resp}, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = srv.Close() })

	cmd := fido2StatusTestCmd()
	require.NoError(t, cmd.Flags().Set("socket", sockPath))
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = runFIDO2Status(cmd, nil)
	return out.String(), sockPath, err
}

func TestRunFIDO2Status_ReportsRunningDaemonAndStore(t *testing.T) {
	resp := ipc.OKResponse(ipc.ActionDaemonReady)
	resp.Storage = &ipc.StorageResult{Type: "file", Path: "/var/lib/xkey/fido2", EncryptedAtRest: true}

	out, sockPath, err := runFIDO2StatusAgainstDaemon(t, resp)
	require.NoError(t, err)
	assert.Contains(t, out, "FIDO2 daemon: running ("+ipc.ActionDaemonReady+")")
	assert.Contains(t, out, "Socket:       "+sockPath)
	assert.Contains(t, out, "Store path:   /var/lib/xkey/fido2")
	assert.Contains(t, out, "At rest:      encrypted by the barrier")
}

func TestRunFIDO2Status_DaemonReportsError(t *testing.T) {
	resp := &ipc.Response{Status: ipc.StatusError, Error: "authenticator not initialized"}

	out, _, err := runFIDO2StatusAgainstDaemon(t, resp)
	require.ErrorIs(t, err, ErrFIDO2StatusFailed)
	assert.Contains(t, err.Error(), "authenticator not initialized")
	assert.NotContains(t, out, "running")
}

func TestPrintFIDO2Storage_AtRestStates(t *testing.T) {
	tests := []struct {
		name    string
		storage *ipc.StorageResult
		want    []string
	}{
		{
			name:    "not reported",
			storage: nil,
			want:    []string{"Store:        unknown (daemon did not report it)"},
		},
		{
			name:    "memory",
			storage: &ipc.StorageResult{Type: string(FIDO2StorageTypeMemory)},
			want:    []string{"nothing stored"},
		},
		{
			name:    "plaintext with prefix",
			storage: &ipc.StorageResult{Type: "pebble", Prefix: "fido2/"},
			want:    []string{"Store prefix: fido2/", "At rest:      NOT encrypted"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			printFIDO2Storage(&out, tt.storage)
			for _, want := range tt.want {
				assert.Contains(t, out.String(), want)
			}
		})
	}
}

func TestDeriveCOSEFromPKCS8_AlgorithmPerKeyType(t *testing.T) {
	marshal := func(t *testing.T, key any) []byte {
		t.Helper()
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		return der
	}
	ecKey := func(t *testing.T, curve elliptic.Curve) []byte {
		t.Helper()
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		return marshal(t, priv)
	}

	t.Run("P-384", func(t *testing.T) {
		alg, cose, err := deriveCOSEFromPKCS8(ecKey(t, elliptic.P384()))
		require.NoError(t, err)
		assert.Equal(t, keybackend.COSEAlgES384, alg)
		assert.NotEmpty(t, cose)
	})

	t.Run("P-521", func(t *testing.T) {
		alg, _, err := deriveCOSEFromPKCS8(ecKey(t, elliptic.P521()))
		require.NoError(t, err)
		assert.Equal(t, keybackend.COSEAlgES512, alg)
	})

	t.Run("Ed25519", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		alg, cose, err := deriveCOSEFromPKCS8(marshal(t, priv))
		require.NoError(t, err)
		assert.Equal(t, keybackend.COSEAlgEdDSA, alg)
		assert.NotEmpty(t, cose)
	})

	t.Run("RSA is refused", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		_, _, err = deriveCOSEFromPKCS8(marshal(t, priv))
		assert.ErrorIs(t, err, ErrFIDO2CDPCaptureUnsupportedKey)
	})
}

func TestDecodeCDPSecret_AcceptsPaddedAndRaw(t *testing.T) {
	secret := []byte("cdp-shared-secret!")

	padded, err := decodeCDPSecret([]byte(base64.StdEncoding.EncodeToString(secret)))
	require.NoError(t, err)
	assert.Equal(t, secret, padded)

	raw, err := decodeCDPSecret([]byte(base64.RawStdEncoding.EncodeToString(secret)))
	require.NoError(t, err)
	assert.Equal(t, secret, raw)

	_, err = decodeCDPSecret([]byte("not base64 at all!"))
	var corrupt base64.CorruptInputError
	assert.True(t, errors.As(err, &corrupt), "want a base64.CorruptInputError, got %v", err)
}
