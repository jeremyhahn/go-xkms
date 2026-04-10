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
	"encoding/json"
	"errors"
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

func TestNewFederationAgent_Success(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{
		Endpoint: "https://dr-xkms.company.com:8443",
	})
	require.NoError(t, err)
	require.NotNil(t, agent)
	assert.Equal(t, "https://dr-xkms.company.com:8443", agent.endpoint)
}

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

func TestFederationAgent_Close(t *testing.T) {
	agent, err := NewFederationAgent(&FederationConfig{Endpoint: "https://localhost:8443"})
	require.NoError(t, err)

	err = agent.Close()
	require.NoError(t, err)
	assert.True(t, agent.closed.Load())
}

func TestFederationConfig_Validate_Success(t *testing.T) {
	cfg := &FederationConfig{
		Endpoint: "https://dr-xkms.company.com:8443",
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestFederationConfig_Validate_EmptyEndpoint(t *testing.T) {
	cfg := &FederationConfig{}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, escrow.ErrEmptyEndpoint))
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
