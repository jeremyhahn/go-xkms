// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build integration

package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Crypto REST DTOs (mirror pkg/api/rest/types.go; []byte marshals as base64).
// ──────────────────────────────────────────────────────────────────────────────

type signReqDTO struct {
	Backend string `json:"backend,omitempty"`
	Data    []byte `json:"data"`
	Hash    string `json:"hash,omitempty"`
}

type signRespDTO struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm,omitempty"`
}

type verifyReqDTO struct {
	Backend   string `json:"backend,omitempty"`
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	Hash      string `json:"hash,omitempty"`
}

type verifyRespDTO struct {
	Valid bool `json:"valid"`
}

type getKeyRespDTO struct {
	PublicKeyPEM string `json:"public_key_pem"`
}

type encryptAsymReqDTO struct {
	Backend   string `json:"backend,omitempty"`
	Plaintext []byte `json:"plaintext"`
}

type encryptAsymRespDTO struct {
	Ciphertext []byte `json:"ciphertext"`
}

type decryptReqDTO struct {
	Backend    string `json:"backend,omitempty"`
	Ciphertext []byte `json:"ciphertext"`
}

type decryptRespDTO struct {
	Plaintext []byte `json:"plaintext"`
}

type rotateRespDTO struct {
	Success      bool   `json:"success"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// encryptAsym encrypts plaintext to keyID's public key (RSA-OAEP) on baseURL.
func encryptAsym(ctx context.Context, baseURL, keyID string, plaintext []byte) ([]byte, int, error) {
	body, _ := json.Marshal(encryptAsymReqDTO{Backend: backendName, Plaintext: plaintext})
	code, raw, err := post(ctx, fmt.Sprintf("%s/api/v1/keys/%s/encrypt-asym?backend=%s", baseURL, keyID, backendName), string(body))
	if err != nil || code != http.StatusOK {
		return nil, code, err
	}
	var resp encryptAsymRespDTO
	if uerr := json.Unmarshal(raw, &resp); uerr != nil {
		return nil, code, uerr
	}
	return resp.Ciphertext, code, nil
}

// decryptData decrypts ciphertext with keyID's private key on baseURL.
func decryptData(ctx context.Context, baseURL, keyID string, ciphertext []byte) ([]byte, int, error) {
	body, _ := json.Marshal(decryptReqDTO{Backend: backendName, Ciphertext: ciphertext})
	code, raw, err := post(ctx, fmt.Sprintf("%s/api/v1/keys/%s/decrypt?backend=%s", baseURL, keyID, backendName), string(body))
	if err != nil || code != http.StatusOK {
		return nil, code, err
	}
	var resp decryptRespDTO
	if uerr := json.Unmarshal(raw, &resp); uerr != nil {
		return nil, code, uerr
	}
	return resp.Plaintext, code, nil
}

// rotateKey rotates keyID on baseURL and returns the new public key PEM.
func rotateKey(ctx context.Context, baseURL, keyID string) (string, int, error) {
	code, raw, err := post(ctx, fmt.Sprintf("%s/api/v1/keys/%s/rotate?backend=%s", baseURL, keyID, backendName), "{}")
	if err != nil || code != http.StatusOK {
		return "", code, err
	}
	var resp rotateRespDTO
	if uerr := json.Unmarshal(raw, &resp); uerr != nil {
		return "", code, uerr
	}
	return resp.PublicKeyPEM, code, nil
}

// keySpec describes a key to generate. Curve applies to ECDSA; Bits to RSA.
type keySpec struct {
	name    string
	keyType string
	curve   string
	bits    int
}

// cryptoKeySpecs is the matrix of key algorithms exercised end-to-end. All are
// supported by the pkcs8 backend the cluster/standalone nodes run.
var cryptoKeySpecs = []keySpec{
	{name: "ecdsa-p256", keyType: "ecdsa", curve: "P-256"},
	{name: "ecdsa-p384", keyType: "ecdsa", curve: "P-384"},
	{name: "ed25519", keyType: "ed25519"},
	{name: "rsa-2048", keyType: "rsa", bits: 2048},
}

// genKeyReq builds the POST /api/v1/keys body for a spec.
func (s keySpec) genKeyReq(keyID string) string {
	m := map[string]any{"key_id": keyID, "backend": backendName, "key_type": s.keyType}
	if s.curve != "" {
		m["curve"] = s.curve
	}
	if s.bits > 0 {
		m["bits"] = s.bits
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// genKey creates a key on baseURL and returns the HTTP status.
func genKey(ctx context.Context, baseURL string, spec keySpec, keyID string) (int, []byte, error) {
	return post(ctx, baseURL+"/api/v1/keys", spec.genKeyReq(keyID))
}

// signData signs data with keyID on baseURL and returns the signature bytes.
func signData(ctx context.Context, baseURL, keyID string, data []byte) ([]byte, int, error) {
	body, _ := json.Marshal(signReqDTO{Backend: backendName, Data: data})
	// The Sign handler reads the backend from the URL query, not the body.
	code, raw, err := post(ctx, fmt.Sprintf("%s/api/v1/keys/%s/sign?backend=%s", baseURL, keyID, backendName), string(body))
	if err != nil || code != http.StatusOK {
		return nil, code, err
	}
	var resp signRespDTO
	if uerr := json.Unmarshal(raw, &resp); uerr != nil {
		return nil, code, uerr
	}
	return resp.Signature, code, nil
}

// verifySig verifies a signature with keyID on baseURL.
func verifySig(ctx context.Context, baseURL, keyID string, data, sig []byte) (bool, int, error) {
	body, _ := json.Marshal(verifyReqDTO{Backend: backendName, Data: data, Signature: sig})
	code, raw, err := post(ctx, fmt.Sprintf("%s/api/v1/keys/%s/verify?backend=%s", baseURL, keyID, backendName), string(body))
	if err != nil || code != http.StatusOK {
		return false, code, err
	}
	var resp verifyRespDTO
	if uerr := json.Unmarshal(raw, &resp); uerr != nil {
		return false, code, uerr
	}
	return resp.Valid, code, nil
}

// publicKeyPEM fetches the PEM-encoded public key for keyID on baseURL.
func publicKeyPEM(ctx context.Context, baseURL, keyID string) (string, int, error) {
	code, raw, err := get(ctx, fmt.Sprintf("%s/api/v1/keys/%s?backend=%s", baseURL, keyID, backendName))
	if err != nil || code != http.StatusOK {
		return "", code, err
	}
	var resp getKeyRespDTO
	if uerr := json.Unmarshal(raw, &resp); uerr != nil {
		return "", code, uerr
	}
	return resp.PublicKeyPEM, code, nil
}

// deleteKey deletes keyID on baseURL and returns the HTTP status.
func deleteKey(ctx context.Context, baseURL, keyID string) (int, []byte, error) {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodDelete,
		fmt.Sprintf("%s/api/v1/keys/%s?backend=%s", baseURL, keyID, backendName), nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, body, nil
}

// waitKeyReplicated blocks until keyID is visible on every node, or fails.
func waitKeyReplicated(t *testing.T, ctx context.Context, nodes [3]string, keyID string) {
	t.Helper()
	for i, u := range nodes {
		nodeIdx := i + 1
		poll(t, 20*time.Second, 400*time.Millisecond, func() (bool, string) {
			return keyExists(ctx, u, keyID),
				fmt.Sprintf("key %q not yet replicated to node%d", keyID, nodeIdx)
		})
	}
}

// signAndVerifyRoundTrip signs data with keyID on signURL and verifies the
// resulting signature with the SAME key on verifyURL — proving the private key
// material is present and usable on signURL and the public half on verifyURL.
func signAndVerifyRoundTrip(t *testing.T, ctx context.Context, signURL, verifyURL, keyID string) {
	t.Helper()
	data := []byte(fmt.Sprintf("cluster-crypto-payload-%s-%d", keyID, time.Now().UnixNano()))

	sig, code, err := signData(ctx, signURL, keyID, data)
	if err != nil || code != http.StatusOK {
		t.Fatalf("sign %q on %s failed: status=%d err=%v", keyID, signURL, code, err)
	}
	if len(sig) == 0 {
		t.Fatalf("sign %q on %s returned an empty signature", keyID, signURL)
	}

	valid, code, err := verifySig(ctx, verifyURL, keyID, data, sig)
	if err != nil || code != http.StatusOK {
		t.Fatalf("verify %q on %s failed: status=%d err=%v", keyID, verifyURL, code, err)
	}
	if !valid {
		t.Fatalf("signature for %q produced on %s did not verify on %s", keyID, signURL, verifyURL)
	}
}
