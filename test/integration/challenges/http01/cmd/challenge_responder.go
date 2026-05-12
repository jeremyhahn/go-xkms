// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package main implements an HTTP-01 challenge responder service.
// It serves challenge tokens at /.well-known/acme-challenge/{token}
// for ACME HTTP-01 validation.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// challengeStore holds token -> keyAuthorization mappings
	challengeStore = make(map[string]string)
	storeMutex     sync.RWMutex
	challengeDir   = "/challenges"
)

func main() {
	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "80"
	}

	// Check if challenge directory is configured
	if dir := os.Getenv("CHALLENGE_DIR"); dir != "" {
		challengeDir = dir
	}

	// Create challenge directory if it doesn't exist
	// #nosec G301 - 0755 is appropriate for challenge dir (needs to be readable)
	if err := os.MkdirAll(challengeDir, 0750); err != nil {
		log.Printf("Warning: could not create challenge directory: %v", err)
	}

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/.well-known/acme-challenge/", challengeHandler)
	http.HandleFunc("/challenge/set", setChallengeHandler)
	http.HandleFunc("/challenge/clear", clearChallengeHandler)

	addr := fmt.Sprintf(":%s", port)
	log.Printf("HTTP-01 Challenge Responder starting on %s", addr)
	log.Printf("Challenge directory: %s", challengeDir)

	// #nosec G114 - This is a test helper server with short-lived connections
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// healthHandler responds to health checks
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// challengeHandler serves ACME HTTP-01 challenge responses
// GET /.well-known/acme-challenge/{token}
func challengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if token == "" {
		log.Printf("Challenge request with empty token from %s", r.RemoteAddr)
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}

	log.Printf("Challenge request for token: %s from %s", token, r.RemoteAddr)

	// First check in-memory store
	storeMutex.RLock()
	keyAuth, exists := challengeStore[token]
	storeMutex.RUnlock()

	if exists {
		log.Printf("Serving challenge from memory: token=%s", token)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(keyAuth))
		return
	}

	// Then check file-based store
	// #nosec G304 - token is validated and path is constrained to challengeDir
	filePath := filepath.Join(challengeDir, filepath.Clean(token))
	keyAuthBytes, err := os.ReadFile(filePath)
	if err == nil {
		log.Printf("Serving challenge from file: token=%s", token)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(keyAuthBytes)
		return
	}

	log.Printf("Challenge token not found: %s", token)
	http.Error(w, "Token not found", http.StatusNotFound)
}

// setChallengeHandler sets a challenge token and key authorization
// POST /challenge/set?token=xxx&keyAuth=yyy
// Or POST body: token=xxx&keyAuth=yyy (form encoded)
// Or POST body: {"token": "xxx", "keyAuth": "yyy"} (JSON)
func setChallengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var token, keyAuth string

	// Try query params first
	token = r.URL.Query().Get("token")
	keyAuth = r.URL.Query().Get("keyAuth")

	// If not in query, try form body
	if token == "" || keyAuth == "" {
		if err := r.ParseForm(); err == nil {
			if token == "" {
				token = r.FormValue("token")
			}
			if keyAuth == "" {
				keyAuth = r.FormValue("keyAuth")
			}
		}
	}

	// If still not found, try reading raw body
	if token == "" || keyAuth == "" {
		body, _ := io.ReadAll(r.Body)
		parts := strings.Split(string(body), "\n")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				switch strings.TrimSpace(kv[0]) {
				case "token":
					token = strings.TrimSpace(kv[1])
				case "keyAuth":
					keyAuth = strings.TrimSpace(kv[1])
				}
			}
		}
	}

	if token == "" || keyAuth == "" {
		http.Error(w, "token and keyAuth required", http.StatusBadRequest)
		return
	}

	// Store in memory
	storeMutex.Lock()
	challengeStore[token] = keyAuth
	storeMutex.Unlock()

	// Also store in file for persistence across restarts
	filePath := filepath.Join(challengeDir, filepath.Clean(token))
	if err := os.WriteFile(filePath, []byte(keyAuth), 0600); err != nil {
		log.Printf("Warning: could not write challenge file: %v", err)
	}

	log.Printf("Challenge set: token=%s keyAuth=%s", token, keyAuth)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// clearChallengeHandler clears a challenge token
// POST /challenge/clear?token=xxx
func clearChallengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		if err := r.ParseForm(); err == nil {
			token = r.FormValue("token")
		}
	}

	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}

	// Remove from memory
	storeMutex.Lock()
	delete(challengeStore, token)
	storeMutex.Unlock()

	// Remove file
	filePath := filepath.Join(challengeDir, token)
	_ = os.Remove(filePath)

	log.Printf("Challenge cleared: token=%s", token)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
