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

package ct

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPLogSubmitter(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		submitter := NewHTTPLogSubmitter(nil)
		require.NotNil(t, submitter)
		require.NotNil(t, submitter.client)
	})

	t.Run("custom client", func(t *testing.T) {
		customClient := &http.Client{Timeout: 60 * time.Second}
		submitter := NewHTTPLogSubmitter(customClient)
		require.NotNil(t, submitter)
		assert.Equal(t, customClient, submitter.client)
	})
}

func TestHTTPLogSubmitter_SubmitPrecert(t *testing.T) {
	t.Run("invalid context type", func(t *testing.T) {
		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: "https://test.example.com"}

		_, err := submitter.SubmitPrecert("not a context", []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.Malformed, caErr.Type)
	})

	t.Run("successful submission", func(t *testing.T) {
		// Create mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			assert.Equal(t, "/ct/v1/add-pre-chain", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, http.MethodPost, r.Method)

			// Parse request body
			var req addPrecertChainRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.NotEmpty(t, req.Chain)

			// Return mock SCT response
			logID := make([]byte, 32)
			for i := range logID {
				logID[i] = byte(i)
			}

			// Build signature: hashAlg(1) + sigAlg(1) + sigLen(2) + sig(N)
			sig := []byte{0x04, 0x03, 0x00, 0x08} // SHA256 + ECDSA + 8-byte signature
			sig = append(sig, []byte("mocksig!")...)

			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         base64.StdEncoding.EncodeToString(logID),
				Timestamp:  uint64(time.Now().UnixMilli()),
				Extensions: "",
				Signature:  base64.StdEncoding.EncodeToString(sig),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("precert-der"), [][]byte{[]byte("issuer")}, log)
		require.NoError(t, err)
		require.NotNil(t, sct)
		assert.Equal(t, V1, sct.Version)
		assert.NotZero(t, sct.Timestamp)
	})

	t.Run("submission with trailing slash URL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/ct/v1/add-pre-chain", r.URL.Path)

			logID := make([]byte, 32)
			sig := []byte{0x04, 0x03, 0x00, 0x04, 'm', 'o', 'c', 'k'}

			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         base64.StdEncoding.EncodeToString(logID),
				Timestamp:  uint64(time.Now().UnixMilli()),
				Signature:  base64.StdEncoding.EncodeToString(sig),
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL + "/"} // Trailing slash

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("precert-der"), nil, log)
		require.NoError(t, err)
		require.NotNil(t, sct)
	})

	t.Run("HTTP error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid request"))
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.SerializationFailure, caErr.Type)
	})

	t.Run("invalid log ID in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         "not-valid-base64!!!",
				Timestamp:  uint64(time.Now().UnixMilli()),
				Signature:  base64.StdEncoding.EncodeToString([]byte{0x04, 0x03, 0x00, 0x01, 0x00}),
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.SerializationFailure, caErr.Type)
	})

	t.Run("wrong log ID length", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         base64.StdEncoding.EncodeToString([]byte("too-short")),
				Timestamp:  uint64(time.Now().UnixMilli()),
				Signature:  base64.StdEncoding.EncodeToString([]byte{0x04, 0x03, 0x00, 0x01, 0x00}),
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.Malformed, caErr.Type)
	})

	t.Run("invalid extensions in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logID := make([]byte, 32)
			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         base64.StdEncoding.EncodeToString(logID),
				Timestamp:  uint64(time.Now().UnixMilli()),
				Extensions: "not-valid-base64!!!",
				Signature:  base64.StdEncoding.EncodeToString([]byte{0x04, 0x03, 0x00, 0x01, 0x00}),
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.SerializationFailure, caErr.Type)
	})

	t.Run("invalid signature in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logID := make([]byte, 32)
			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         base64.StdEncoding.EncodeToString(logID),
				Timestamp:  uint64(time.Now().UnixMilli()),
				Signature:  "not-valid-base64!!!",
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.SerializationFailure, caErr.Type)
	})

	t.Run("signature too short", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logID := make([]byte, 32)
			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         base64.StdEncoding.EncodeToString(logID),
				Timestamp:  uint64(time.Now().UnixMilli()),
				Signature:  base64.StdEncoding.EncodeToString([]byte{0x04, 0x03}), // Only 2 bytes
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.Malformed, caErr.Type)
	})

	t.Run("signature data incomplete", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logID := make([]byte, 32)
			// sigLen claims 100 bytes but only 1 is provided
			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         base64.StdEncoding.EncodeToString(logID),
				Timestamp:  uint64(time.Now().UnixMilli()),
				Signature:  base64.StdEncoding.EncodeToString([]byte{0x04, 0x03, 0x00, 0x64, 0x00}), // Claims 100 bytes
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.Malformed, caErr.Type)
	})

	t.Run("with extensions in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logID := make([]byte, 32)
			sig := []byte{0x04, 0x03, 0x00, 0x04, 'm', 'o', 'c', 'k'}
			ext := []byte{0x01, 0x02, 0x03}

			resp := addPrecertChainResponse{
				SCTVersion: V1,
				ID:         base64.StdEncoding.EncodeToString(logID),
				Timestamp:  uint64(time.Now().UnixMilli()),
				Extensions: base64.StdEncoding.EncodeToString(ext),
				Signature:  base64.StdEncoding.EncodeToString(sig),
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, sct.Extensions)
	})

	t.Run("context cancelled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(1 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: server.URL}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := submitter.SubmitPrecert(ctx, []byte("test"), nil, log)
		assert.Error(t, err)
	})

	t.Run("network error", func(t *testing.T) {
		submitter := NewHTTPLogSubmitter(nil)
		log := LogGroup{URL: "http://localhost:1"} // Port 1 should not be open

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.Error(t, err)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
	})
}

func TestMockLogSubmitter(t *testing.T) {
	t.Run("basic submission", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{
			Name:     "Test Log",
			Operator: "Test Op",
			URL:      "https://test.example.com",
		}

		precertDER := []byte("test-precert-data")
		chain := [][]byte{[]byte("issuer-cert")}

		sct, err := submitter.SubmitPrecert(context.Background(), precertDER, chain, log)
		require.NoError(t, err)
		require.NotNil(t, sct)

		assert.Equal(t, V1, sct.Version)
		assert.NotZero(t, sct.Timestamp)
	})

	t.Run("configured SCT", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{URL: "https://test.example.com"}
		expectedSCT := &SignedCertificateTimestamp{
			Version:   V1,
			Timestamp: 12345678,
		}

		submitter.SetSCT(log.URL, expectedSCT)

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)

		assert.Equal(t, expectedSCT.Timestamp, sct.Timestamp)
	})

	t.Run("configured error", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{URL: "https://test.example.com"}
		expectedErr := errors.New("submission failed")

		submitter.SetError(log.URL, expectedErr)

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("delay simulation", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		submitter.Delay = 100 * time.Millisecond

		log := LogGroup{URL: "https://test.example.com"}

		start := time.Now()
		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
	})

	t.Run("context cancellation during delay", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		submitter.Delay = 1 * time.Second

		log := LogGroup{URL: "https://test.example.com"}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := submitter.SubmitPrecert(ctx, []byte("test"), nil, log)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("invalid context type", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		log := LogGroup{URL: "https://test.example.com"}

		// Pass invalid context type
		_, err := submitter.SubmitPrecert("not a context", []byte("test"), nil, log)
		assert.Error(t, err)
	})

	t.Run("submission tracking", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log1 := LogGroup{URL: "https://log1.example.com", Name: "Log1"}
		log2 := LogGroup{URL: "https://log2.example.com", Name: "Log2"}

		_, _ = submitter.SubmitPrecert(context.Background(), []byte("cert1"), nil, log1)
		_, _ = submitter.SubmitPrecert(context.Background(), []byte("cert2"), [][]byte{[]byte("chain")}, log2)

		submissions := submitter.GetSubmissions()
		require.Len(t, submissions, 2)

		assert.Equal(t, []byte("cert1"), submissions[0].PrecertDER)
		assert.Equal(t, "Log1", submissions[0].Log.Name)

		assert.Equal(t, []byte("cert2"), submissions[1].PrecertDER)
		assert.Equal(t, "Log2", submissions[1].Log.Name)
		assert.Len(t, submissions[1].Chain, 1)
	})

	t.Run("reset", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{URL: "https://test.example.com"}

		submitter.SetSCT(log.URL, &SignedCertificateTimestamp{})
		submitter.SetError(log.URL, errors.New("error"))
		_, _ = submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)

		// Reset clears everything
		submitter.Reset()

		assert.Empty(t, submitter.SCTs)
		assert.Empty(t, submitter.Errors)
		assert.Empty(t, submitter.Submissions)
	})

	t.Run("log ID from LogGroup", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		var customLogID [32]byte
		for i := range customLogID {
			customLogID[i] = byte(i)
		}

		log := LogGroup{
			URL:   "https://test.example.com",
			LogID: customLogID,
		}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)

		assert.Equal(t, customLogID, sct.LogID)
	})

	t.Run("log ID generated from URL when not set", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{
			URL: "https://test.example.com",
			// LogID is zero value
		}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)

		// Log ID should be SHA-256 of URL
		assert.NotEqual(t, [32]byte{}, sct.LogID)
	})

	t.Run("submission with nil chain", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		log := LogGroup{URL: "https://test.example.com"}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)
		require.NotNil(t, sct)

		submissions := submitter.GetSubmissions()
		require.Len(t, submissions, 1)
		assert.Nil(t, submissions[0].Chain)
	})

	t.Run("submission with empty chain", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		log := LogGroup{URL: "https://test.example.com"}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), [][]byte{}, log)
		require.NoError(t, err)
		require.NotNil(t, sct)

		submissions := submitter.GetSubmissions()
		require.Len(t, submissions, 1)
		assert.Empty(t, submissions[0].Chain)
	})

	t.Run("multiple submissions to same log", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		log := LogGroup{URL: "https://test.example.com"}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("cert1"), nil, log)
		require.NoError(t, err)

		_, err = submitter.SubmitPrecert(context.Background(), []byte("cert2"), nil, log)
		require.NoError(t, err)

		submissions := submitter.GetSubmissions()
		require.Len(t, submissions, 2)
	})

	t.Run("concurrent submissions thread-safe", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				log := LogGroup{URL: "https://test.example.com"}
				_, _ = submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		submissions := submitter.GetSubmissions()
		assert.Len(t, submissions, 10)
	})
}
