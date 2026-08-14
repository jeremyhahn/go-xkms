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

//go:build vault

package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// transitDouble is an in-process stand-in for the subset of the HashiCorp
// Vault Transit engine this backend uses: key create/read/delete/rotate,
// key config, and encrypt/decrypt.
//
// It performs real AES-256-GCM with the request "context" as additional
// authenticated data and returns Vault's "vault:v<n>:<base64>" ciphertext
// envelope, so a round trip through it proves the backend encodes requests and
// parses responses exactly as Vault expects. Tests therefore run offline and
// deterministically instead of against a Vault server that may or may not be
// reachable.
type transitDouble struct {
	mu   sync.Mutex
	keys map[string]*transitKey
}

// transitKey is a single Transit key.
type transitKey struct {
	material        []byte
	version         int
	deletionAllowed bool
}

// newTransitDouble starts the double and returns it with its base URL.
func newTransitDouble(t *testing.T) (*transitDouble, string) {
	t.Helper()

	d := &transitDouble{keys: make(map[string]*transitKey)}
	server := httptest.NewServer(http.HandlerFunc(d.serveHTTP))
	t.Cleanup(server.Close)

	return d, server.URL
}

// serveHTTP routes a Transit request. Paths look like
// /v1/transit/{operation}/{name} plus the /config suffix for key config.
func (d *transitDouble) serveHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/"), "/"), "/")
	if len(parts) < 3 {
		writeVaultError(w, http.StatusNotFound, "unsupported path")
		return
	}

	operation, name := parts[1], parts[2]

	switch {
	case operation == "keys" && len(parts) == 4 && parts[3] == "config":
		d.configureKey(w, r, name)
	case operation == "keys" && len(parts) == 4 && parts[3] == "rotate":
		d.rotateKey(w, name)
	case operation == "keys":
		d.handleKey(w, r, name)
	case operation == "encrypt":
		d.encrypt(w, r, name)
	case operation == "decrypt":
		d.decrypt(w, r, name)
	default:
		writeVaultError(w, http.StatusNotFound, "unsupported operation "+operation)
	}
}

// handleKey implements create (POST/PUT), read (GET) and delete (DELETE).
func (d *transitDouble) handleKey(w http.ResponseWriter, r *http.Request, name string) {
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		material := make([]byte, 32) // aes256-gcm96
		if _, err := rand.Read(material); err != nil {
			writeVaultError(w, http.StatusInternalServerError, err.Error())
			return
		}

		d.mu.Lock()
		if _, exists := d.keys[name]; !exists {
			d.keys[name] = &transitKey{material: material, version: 1}
		}
		d.mu.Unlock()

		w.WriteHeader(http.StatusNoContent)

	case http.MethodGet:
		d.mu.Lock()
		key, exists := d.keys[name]
		version := 0
		if exists {
			version = key.version
		}
		d.mu.Unlock()

		if !exists {
			writeVaultError(w, http.StatusNotFound, "no such key")
			return
		}
		writeVaultData(w, map[string]interface{}{
			"name":                 name,
			"type":                 "aes256-gcm96",
			"latest_version":       version,
			"deletion_allowed":     true,
			"supports_encryption":  true,
			"supports_decryption":  true,
			"min_decryption_versi": 1,
		})

	case http.MethodDelete:
		d.mu.Lock()
		key, exists := d.keys[name]
		allowed := exists && key.deletionAllowed
		if allowed {
			delete(d.keys, name)
		}
		d.mu.Unlock()

		if !exists {
			writeVaultError(w, http.StatusNotFound, "no such key")
			return
		}
		if !allowed {
			writeVaultError(w, http.StatusBadRequest, "deletion is not allowed for this key")
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		writeVaultError(w, http.StatusMethodNotAllowed, "unsupported method")
	}
}

// configureKey implements the keys/{name}/config endpoint, which the backend
// calls to enable deletion before removing a key.
func (d *transitDouble) configureKey(w http.ResponseWriter, r *http.Request, name string) {
	body, err := decodeRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	d.mu.Lock()
	key, exists := d.keys[name]
	if exists {
		if allowed, ok := body["deletion_allowed"].(bool); ok {
			key.deletionAllowed = allowed
		}
	}
	d.mu.Unlock()

	if !exists {
		writeVaultError(w, http.StatusNotFound, "no such key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotateKey bumps the key version, as Transit does.
func (d *transitDouble) rotateKey(w http.ResponseWriter, name string) {
	d.mu.Lock()
	key, exists := d.keys[name]
	if exists {
		key.version++
	}
	d.mu.Unlock()

	if !exists {
		writeVaultError(w, http.StatusNotFound, "no such key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// encrypt performs AES-256-GCM over the base64 plaintext, binding the
// base64 "context" field as additional authenticated data.
func (d *transitDouble) encrypt(w http.ResponseWriter, r *http.Request, name string) {
	body, err := decodeRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	gcm, version, err := d.aead(name)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	plaintext, err := decodeField(body, "plaintext", true)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	aad, err := decodeField(body, "context", false)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		writeVaultError(w, http.StatusInternalServerError, err.Error())
		return
	}

	blob := gcm.Seal(nonce, nonce, plaintext, aad)
	writeVaultData(w, map[string]interface{}{
		"ciphertext":  vaultCiphertextPrefix(version) + base64.StdEncoding.EncodeToString(blob),
		"key_version": version,
	})
}

// decrypt reverses encrypt, failing when the context does not match the value
// bound at encryption time.
func (d *transitDouble) decrypt(w http.ResponseWriter, r *http.Request, name string) {
	body, err := decodeRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	gcm, _, err := d.aead(name)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	envelope, _ := body["ciphertext"].(string)
	segments := strings.SplitN(envelope, ":", 3)
	if len(segments) != 3 || segments[0] != "vault" {
		writeVaultError(w, http.StatusBadRequest, "invalid ciphertext envelope")
		return
	}

	blob, err := base64.StdEncoding.DecodeString(segments[2])
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "invalid ciphertext encoding")
		return
	}
	if len(blob) < gcm.NonceSize() {
		writeVaultError(w, http.StatusBadRequest, "ciphertext too short")
		return
	}

	aad, err := decodeField(body, "context", false)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	plaintext, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], aad)
	if err != nil {
		// Vault reports an authentication failure the same way for a wrong
		// context and a tampered ciphertext.
		writeVaultError(w, http.StatusBadRequest, "message authentication failed")
		return
	}

	writeVaultData(w, map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
}

// aead returns the AES-GCM primitive for a key along with its version.
func (d *transitDouble) aead(name string) (cipher.AEAD, int, error) {
	d.mu.Lock()
	key, exists := d.keys[name]
	d.mu.Unlock()

	if !exists {
		return nil, 0, errTransitKeyNotFound
	}

	block, err := aes.NewCipher(key.material)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	return gcm, key.version, nil
}

// keyCount reports how many keys the double currently holds, so a test can
// assert that a delete really removed the key from the engine.
func (d *transitDouble) keyCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.keys)
}

// errTransitKeyNotFound mirrors Vault's "encryption key not found" condition.
var errTransitKeyNotFound = &transitError{msg: "encryption key not found"}

// transitError is the double's error type.
type transitError struct{ msg string }

func (e *transitError) Error() string { return e.msg }

// vaultCiphertextPrefix renders Transit's ciphertext version prefix.
func vaultCiphertextPrefix(version int) string {
	return "vault:v" + itoa(version) + ":"
}

// itoa converts a small non-negative int to its decimal string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// decodeRequest parses a Transit JSON request body.
func decodeRequest(r *http.Request) (map[string]interface{}, error) {
	body := make(map[string]interface{})
	if r.Body == nil {
		return body, nil
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err.Error() != "EOF" {
		return nil, err
	}
	return body, nil
}

// decodeField base64-decodes a request field. Required fields must be present.
func decodeField(body map[string]interface{}, field string, required bool) ([]byte, error) {
	raw, ok := body[field].(string)
	if !ok {
		if required {
			return nil, &transitError{msg: "missing field " + field}
		}
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, &transitError{msg: "field " + field + " is not valid base64"}
	}
	return decoded, nil
}

// writeVaultData renders a Vault success response envelope.
func writeVaultData(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
}

// writeVaultError renders a Vault error response envelope.
func writeVaultError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{message}})
}
