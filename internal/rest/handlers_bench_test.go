// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// createBenchmarkHandler creates a handler context for benchmarking
func createBenchmarkHandler(b *testing.B) *HandlerContext {
	b.Helper()

	keyStorage := storage.New()
	config := &software.Config{
		KeyStorage: keyStorage,
	}

	backend, err := software.NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}

	ks, err := keychain.New(&keychain.Config{
		Backend: backend,
	})
	if err != nil {
		b.Fatalf("Failed to create keystore: %v", err)
	}

	// Initialize the global keychain facade
	err = keychain.Initialize(&keychain.FacadeConfig{
		Backends: map[string]keychain.KeyStore{
			"software": ks,
		},
		DefaultBackend: "software",
	})
	if err != nil {
		b.Fatalf("Failed to initialize keychain: %v", err)
	}

	return NewHandlerContext("v1.0.0")
}

// BenchmarkREST_HealthHandler benchmarks health check endpoint
func BenchmarkREST_HealthHandler(b *testing.B) {
	handler := createBenchmarkHandler(b)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.HealthHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	}
}

// BenchmarkREST_ListBackendsHandler benchmarks listing backends
func BenchmarkREST_ListBackendsHandler(b *testing.B) {
	handler := createBenchmarkHandler(b)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ListBackendsHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	}
}

// BenchmarkREST_GetBackendHandler benchmarks getting a backend
func BenchmarkREST_GetBackendHandler(b *testing.B) {
	handler := createBenchmarkHandler(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()

		// Create fresh request with route context
		r := httptest.NewRequest(http.MethodGet, "/api/v1/backends/software", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "software")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

		handler.GetBackendHandler(w, r)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	}
}

// BenchmarkREST_GenerateKeyRSA benchmarks RSA key generation via REST
func BenchmarkREST_GenerateKeyRSA(b *testing.B) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		b.Run(fmt.Sprintf("RSA-%d", keySize), func(b *testing.B) {
			handler := createBenchmarkHandler(b)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				reqBody := GenerateKeyRequest{
					KeyID:   fmt.Sprintf("bench-rsa-%d", i),
					Backend: "software",
					KeyType: "rsa",
					KeySize: keySize,
				}

				body, err := json.Marshal(reqBody)
				if err != nil {
					b.Fatalf("Failed to marshal request: %v", err)
				}

				req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				w := httptest.NewRecorder()
				handler.GenerateKeyHandler(w, req)

				if w.Code != http.StatusCreated {
					b.Fatalf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
				}
			}
		})
	}
}

// BenchmarkREST_GenerateKeyECDSA benchmarks ECDSA key generation via REST
func BenchmarkREST_GenerateKeyECDSA(b *testing.B) {
	curves := []string{"P256", "P384", "P521"}

	for _, curve := range curves {
		b.Run(fmt.Sprintf("ECDSA-%s", curve), func(b *testing.B) {
			handler := createBenchmarkHandler(b)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				reqBody := GenerateKeyRequest{
					KeyID:   fmt.Sprintf("bench-ecdsa-%d", i),
					Backend: "software",
					KeyType: "ecdsa",
					Curve:   curve,
				}

				body, err := json.Marshal(reqBody)
				if err != nil {
					b.Fatalf("Failed to marshal request: %v", err)
				}

				req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				w := httptest.NewRecorder()
				handler.GenerateKeyHandler(w, req)

				if w.Code != http.StatusCreated {
					b.Fatalf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
				}
			}
		})
	}
}

// BenchmarkREST_SignData benchmarks data signing via REST
func BenchmarkREST_SignData(b *testing.B) {
	handler := createBenchmarkHandler(b)

	// Pre-generate a key
	genReq := GenerateKeyRequest{
		KeyID:   "bench-sign-key",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	}

	body, _ := json.Marshal(genReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.GenerateKeyHandler(w, req)

	if w.Code != http.StatusCreated {
		b.Fatalf("Failed to generate key: %d", w.Code)
	}

	data := []byte("benchmark data to sign")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		signReq := SignRequest{
			Data: data,
		}

		body, err := json.Marshal(signReq)
		if err != nil {
			b.Fatalf("Failed to marshal request: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/bench-sign-key/sign?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "bench-sign-key")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.SignHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	}
}

// BenchmarkREST_GetPublicKey benchmarks public key retrieval via REST
func BenchmarkREST_GetPublicKey(b *testing.B) {
	handler := createBenchmarkHandler(b)

	// Pre-generate a key
	genReq := GenerateKeyRequest{
		KeyID:   "bench-pubkey",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	}

	body, _ := json.Marshal(genReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.GenerateKeyHandler(w, req)

	if w.Code != http.StatusCreated {
		b.Fatalf("Failed to generate key: %d", w.Code)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/bench-pubkey?backend=software", nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "bench-pubkey")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetKeyHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	}
}

// BenchmarkREST_ListKeys benchmarks key listing via REST
func BenchmarkREST_ListKeys(b *testing.B) {
	counts := []int{10, 100}

	for _, count := range counts {
		b.Run(fmt.Sprintf("%dKeys", count), func(b *testing.B) {
			handler := createBenchmarkHandler(b)

			// Pre-generate keys
			for i := 0; i < count; i++ {
				reqBody := GenerateKeyRequest{
					KeyID:   fmt.Sprintf("bench-list-%d", i),
					Backend: "software",
					KeyType: "ecdsa",
					Curve:   "P256",
				}

				body, _ := json.Marshal(reqBody)
				req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				handler.GenerateKeyHandler(w, req)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=software", nil)
				w := httptest.NewRecorder()
				handler.ListKeysHandler(w, req)

				if w.Code != http.StatusOK {
					b.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
				}
			}
		})
	}
}

// BenchmarkREST_ConcurrentRequests benchmarks concurrent REST requests
func BenchmarkREST_ConcurrentRequests(b *testing.B) {
	handler := createBenchmarkHandler(b)

	// Pre-generate a key
	genReq := GenerateKeyRequest{
		KeyID:   "bench-concurrent",
		Backend: "software",
		KeyType: "ecdsa",
		Curve:   "P256",
	}

	body, _ := json.Marshal(genReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.GenerateKeyHandler(w, req)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(testPB *testing.PB) {
		for testPB.Next() {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/bench-concurrent?backend=software", nil)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", "bench-concurrent")
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			w := httptest.NewRecorder()
			handler.GetKeyHandler(w, req)

			if w.Code != http.StatusOK {
				b.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
			}
		}
	})
}

// BenchmarkREST_EncryptDecryptRoundtrip benchmarks symmetric encryption round-trip
func BenchmarkREST_EncryptDecryptRoundtrip(b *testing.B) {
	sizes := []int{1024, 10 * 1024}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dKB", size/1024), func(b *testing.B) {
			handler := createBenchmarkHandler(b)

			// Pre-generate AES key
			genReq := GenerateKeyRequest{
				KeyID:     "bench-encrypt",
				Backend:   "software",
				KeyType:   "aes",
				Algorithm: "aes-256-gcm",
				KeySize:   256,
			}

			body, _ := json.Marshal(genReq)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.GenerateKeyHandler(w, req)

			plaintext := make([]byte, size)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Encrypt
				encReq := EncryptRequest{
					Plaintext: plaintext,
				}

				body, _ := json.Marshal(encReq)
				req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/bench-encrypt/encrypt?backend=software", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("id", "bench-encrypt")
				req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

				w := httptest.NewRecorder()
				handler.EncryptHandler(w, req)

				if w.Code != http.StatusOK {
					b.Fatalf("Encrypt failed: %d", w.Code)
				}

				// Decrypt
				var encResp EncryptResponse
				_ = json.NewDecoder(w.Body).Decode(&encResp)

				decReq := DecryptRequest{
					Ciphertext: encResp.Ciphertext,
					Nonce:      encResp.Nonce,
					Tag:        encResp.Tag,
				}

				body, _ = json.Marshal(decReq)
				req = httptest.NewRequest(http.MethodPost, "/api/v1/keys/bench-encrypt/decrypt?backend=software", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				rctx = chi.NewRouteContext()
				rctx.URLParams.Add("id", "bench-encrypt")
				req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

				w = httptest.NewRecorder()
				handler.DecryptHandler(w, req)

				if w.Code != http.StatusOK {
					b.Fatalf("Decrypt failed: %d", w.Code)
				}
			}

			b.SetBytes(int64(size) * 2) // Count both encrypt and decrypt
		})
	}
}
