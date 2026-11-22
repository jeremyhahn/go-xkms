// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFederationAgent_NilConfig(t *testing.T) {
	_, err := NewFederationAgent(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentNotConfigured))
}

func TestNewFederationAgent_EmptyEndpoint(t *testing.T) {
	_, err := NewFederationAgent(&FederationConfig{
		Endpoint: "",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyEndpoint))
}

func TestNewFederationAgent_InvalidClientCert(t *testing.T) {
	_, err := NewFederationAgent(&FederationConfig{
		Endpoint:   "https://dr-xkms.company.com:8443",
		ClientCert: "/nonexistent/cert.pem",
		ClientKey:  "/nonexistent/key.pem",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestNewFederationAgent_InvalidCACert_MissingFile(t *testing.T) {
	_, err := NewFederationAgent(&FederationConfig{
		Endpoint: "https://dr-xkms.company.com:8443",
		CACert:   "/nonexistent/ca.pem",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestNewFederationAgent_InvalidCACert_BadPEM(t *testing.T) {
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not-a-pem-certificate"), 0600))

	_, err := NewFederationAgent(&FederationConfig{
		Endpoint: "https://dr-xkms.company.com:8443",
		CACert:   caPath,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestNewFederationAgent_CustomTimeout(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint: "https://localhost:8443",
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, agent.client.Timeout)
}

func TestFederationAgent_Type(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint: "https://localhost:8443",
	})
	require.NoError(t, err)
	assert.Equal(t, escrow.AgentTypeXKMS, agent.Type())
}

func TestFederationAgent_Available_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthPath && r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	assert.True(t, agent.Available(context.Background()))
}

func TestFederationAgent_Available_ServerReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	assert.False(t, agent.Available(context.Background()))
}

func TestFederationAgent_Available_ServerDown(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint: "http://127.0.0.1:19999",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	assert.False(t, agent.Available(context.Background()))
}

func TestFederationAgent_Available_AfterClose(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)

	require.NoError(t, agent.Close())
	assert.False(t, agent.Available(context.Background()))
}

func TestFederationAgent_EscrowKey_Success(t *testing.T) {
	expectedReceipt := escrow.EscrowReceipt{
		EscrowID:   "escrow-001",
		KeyID:      "key-001",
		Agent:      "xkms",
		EscrowedAt: time.Now().UTC().Truncate(time.Second),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == apiPrefix && r.Method == http.MethodPost {
			var req escrow.EscrowRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			assert.Equal(t, "key-001", req.KeyID)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(expectedReceipt)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	receipt, err := agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:             "key-001",
		WrappedKey:        []byte("wrapped-key-material"),
		WrappingAlgorithm: "AES-KW",
	})
	require.NoError(t, err)
	require.NotNil(t, receipt)
	assert.Equal(t, "escrow-001", receipt.EscrowID)
	assert.Equal(t, "key-001", receipt.KeyID)
	assert.Equal(t, "xkms", receipt.Agent)
}

func TestFederationAgent_EscrowKey_NilRequest(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNilRequest))
}

func TestFederationAgent_EscrowKey_InvalidRequest(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestFederationAgent_EscrowKey_ServerRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEscrowFailed))
}

func TestFederationAgent_EscrowKey_Conflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAlreadyEscrowed))
}

func TestFederationAgent_EscrowKey_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestFederationAgent_EscrowKey_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestFederationAgent_EscrowKey_AfterClose(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)
	require.NoError(t, agent.Close())

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentClosed))
}

func TestFederationAgent_EscrowKey_InvalidJSON_Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid json"))
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEscrowFailed))
}

func TestFederationAgent_RecoverKey_Success(t *testing.T) {
	expectedResp := escrow.RecoverResponse{
		KeyID:             "key-001",
		WrappedKey:        []byte("recovered-wrapped-key"),
		WrappingAlgorithm: "AES-KW",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == apiPrefix+"/recover" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(expectedResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	resp, err := agent.RecoverKey(context.Background(), &escrow.RecoverRequest{
		KeyID: "key-001",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "key-001", resp.KeyID)
	assert.Equal(t, []byte("recovered-wrapped-key"), resp.WrappedKey)
	assert.Equal(t, "AES-KW", resp.WrappingAlgorithm)
}

func TestFederationAgent_RecoverKey_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{
		KeyID: "nonexistent-key",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrKeyNotFound))
}

func TestFederationAgent_RecoverKey_NilRequest(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrNilRequest))
}

func TestFederationAgent_RecoverKey_InvalidRequest(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestFederationAgent_RecoverKey_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "key-001"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestFederationAgent_RecoverKey_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "key-001"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestFederationAgent_RecoverKey_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "key-001"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrRecoverFailed))
}

func TestFederationAgent_RecoverKey_InvalidJSON_Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid json"))
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "key-001"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrRecoverFailed))
}

func TestFederationAgent_RecoverKey_AfterClose(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)
	require.NoError(t, agent.Close())

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{KeyID: "key-001"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentClosed))
}

func TestFederationAgent_ListEscrowed_Success(t *testing.T) {
	records := []escrow.EscrowRecord{
		{EscrowID: "e1", KeyID: "k1", Agent: "xkms"},
		{EscrowID: "e2", KeyID: "k2", Agent: "xkms"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == apiPrefix && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(records)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	result, err := agent.ListEscrowed(context.Background())
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "e1", result[0].EscrowID)
	assert.Equal(t, "e2", result[1].EscrowID)
}

func TestFederationAgent_ListEscrowed_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.ListEscrowed(context.Background())
	require.Error(t, err)
}

func TestFederationAgent_ListEscrowed_AfterClose(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)
	require.NoError(t, agent.Close())

	_, err = agent.ListEscrowed(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentClosed))
}

func TestFederationAgent_ListEscrowed_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.ListEscrowed(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestFederationAgent_ListEscrowed_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid"))
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	_, err = agent.ListEscrowed(context.Background())
	require.Error(t, err)
}

func TestFederationAgent_ListEscrowed_ServerUnavailable(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint: "http://127.0.0.1:19999",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	_, err = agent.ListEscrowed(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentUnavailable))
}

func TestFederationAgent_RevokeEscrow_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == apiPrefix+"/escrow-001" && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "escrow-001")
	require.NoError(t, err)
}

func TestFederationAgent_RevokeEscrow_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrKeyNotFound))
}

func TestFederationAgent_RevokeEscrow_EmptyID(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyKeyID))
}

func TestFederationAgent_RevokeEscrow_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "escrow-001")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAuthenticationFailed))
}

func TestFederationAgent_RevokeEscrow_AfterClose(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)
	require.NoError(t, agent.Close())

	err = agent.RevokeEscrow(context.Background(), "escrow-001")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentClosed))
}

func TestFederationAgent_RevokeEscrow_ServerUnavailable(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint: "http://127.0.0.1:19999",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "escrow-001")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentUnavailable))
}

func TestFederationAgent_EscrowKey_ServerUnavailable(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint: "http://127.0.0.1:19999",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	_, err = agent.EscrowKey(context.Background(), &escrow.EscrowRequest{
		KeyID:      "key-001",
		WrappedKey: []byte("wrapped-key-material"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentUnavailable))
}

func TestFederationAgent_RecoverKey_ServerUnavailable(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint: "http://127.0.0.1:19999",
		Timeout:  500 * time.Millisecond,
	})
	require.NoError(t, err)

	_, err = agent.RecoverKey(context.Background(), &escrow.RecoverRequest{
		KeyID: "key-001",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrAgentUnavailable))
}

func TestFederationAgent_RevokeEscrow_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	agent, err := NewFederationAgent(&FederationConfig{Endpoint: srv.URL})
	require.NoError(t, err)

	err = agent.RevokeEscrow(context.Background(), "escrow-001")
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrRevokeFailed))
}

// writeSelfSignedPair writes a self-signed ECDSA P-256 certificate and its
// PKCS#8 key as PEM files and returns their paths.
func writeSelfSignedPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "escrow-client"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

// A valid client pair and CA file configure mutual TLS 1.3: the client
// presents the certificate and verifies the server against the CA pool.
func TestNewFederationAgent_MutualTLSConfigured(t *testing.T) {
	certPath, keyPath := writeSelfSignedPair(t)
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint:   "https://dr-xkms.company.com:8443",
		ClientCert: certPath,
		ClientKey:  keyPath,
		CACert:     certPath,
	})
	require.NoError(t, err)

	transport, ok := agent.client.Transport.(*http.Transport)
	require.True(t, ok)
	tlsConfig := transport.TLSClientConfig
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	require.Len(t, tlsConfig.Certificates, 1)
	assert.NotNil(t, tlsConfig.RootCAs)
}

// An endpoint that does not parse as a URL fails every operation before any
// request is sent, each with its operation's sentinel and no partial result.
func TestFederationAgent_MalformedEndpointRefused(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://%zz"})
	require.NoError(t, err)
	ctx := context.Background()

	assert.False(t, agent.Available(ctx))

	tests := []struct {
		name    string
		call    func() (any, error)
		wantErr error
	}{
		{
			name: "escrow",
			call: func() (any, error) {
				return agent.EscrowKey(ctx, &escrow.EscrowRequest{KeyID: "key-001", WrappedKey: []byte("wrapped")})
			},
			wantErr: escrow.ErrEscrowFailed,
		},
		{
			name:    "recover",
			call:    func() (any, error) { return agent.RecoverKey(ctx, &escrow.RecoverRequest{KeyID: "key-001"}) },
			wantErr: escrow.ErrRecoverFailed,
		},
		{
			name:    "list",
			call:    func() (any, error) { return agent.ListEscrowed(ctx) },
			wantErr: escrow.ErrRecoverFailed,
		},
		{
			name:    "revoke",
			call:    func() (any, error) { return nil, agent.RevokeEscrow(ctx, "escrow-001") },
			wantErr: escrow.ErrRevokeFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.call()
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, got)
		})
	}
}
