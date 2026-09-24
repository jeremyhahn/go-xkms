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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// transitDouble is an in-process stand-in for the subset of the HashiCorp
// Vault Transit engine this backend uses: key create/read/delete/rotate,
// key config, sign, and encrypt/decrypt.
//
// It performs real AES-256-GCM (as the stand-in cipher for encrypt/decrypt
// regardless of the key's declared type) and real RSA (for sign, on
// "rsa-*" keys), retaining every rotated version's material the way Vault
// does, and returns Vault's "vault:v<n>:<base64>" envelope for both
// ciphertext and signatures. A round trip through it proves the backend
// encodes requests and parses responses exactly as Vault expects, including
// which key version a request lands on. Tests therefore run offline and
// deterministically instead of against a Vault server that may or may not
// be reachable.
type transitDouble struct {
	mu   sync.Mutex
	keys map[string]*transitKey

	// wrappingRSAKey is the double's stand-in for Vault Transit's own BYOK
	// wrapping key (transit/wrapping_key): a real RSA keypair, generated
	// lazily on first use and held only inside the double, exactly as real
	// Vault never exposes its wrapping private key outside the service
	// boundary. 2048 bits rather than the 4096 bits real Vault uses, purely
	// for test speed -- the BYOK wire format this double proves (RSA-OAEP
	// concatenated with AES-GCM) does not depend on the modulus size.
	wrappingRSAKey *rsa.PrivateKey
}

// transitKey is a single Transit key, with every version's material
// retained -- as real Vault Transit does -- so a request that names an
// older version (embedded in a ciphertext envelope, or an explicit
// key_version on sign) is served from that version and not silently
// upgraded to the latest one.
type transitKey struct {
	keyType         string
	deletionAllowed bool
	exportable      bool
	version         int
	materials       map[int][]byte          // version -> AES-256 material, used by encrypt/decrypt regardless of keyType
	rsaKeys         map[int]*rsa.PrivateKey // version -> RSA keypair, populated only for "rsa-*" keyType
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
// /v1/transit/{operation}/{name} plus the /config suffix for key config and
// an optional /{hash} suffix for sign. wrapping_key has no name segment
// (/v1/transit/wrapping_key), and export takes an extra type segment
// (/v1/transit/export/{type}/{name}[/{version}]).
func (d *transitDouble) serveHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/"), "/"), "/")
	if len(parts) < 2 {
		writeVaultError(w, http.StatusNotFound, "unsupported path")
		return
	}

	if parts[1] == "wrapping_key" && len(parts) == 2 {
		d.wrappingKey(w)
		return
	}

	if parts[1] == "export" {
		if len(parts) < 4 {
			writeVaultError(w, http.StatusNotFound, "unsupported path")
			return
		}
		d.export(w, parts[2], parts[3])
		return
	}

	// LIST /v1/transit/keys has no name segment, unlike every other keys
	// operation this double serves -- it must be routed before the
	// len(parts) < 3 guard below, which every named operation relies on.
	//
	// The vault/api client's Logical.list rewrites the wire method to GET
	// with ?list=true (see logical.go's comment: "Set this for broader
	// compatibility") rather than sending the literal LIST verb its own
	// ListWithContext constructs, so the method to match here is GET, not
	// LIST; the path shape (no name segment) is what disambiguates this from
	// an ordinary single-key read.
	if parts[1] == "keys" && len(parts) == 2 && r.Method == http.MethodGet {
		d.listKeys(w)
		return
	}

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
	case operation == "keys" && len(parts) == 4 && parts[3] == "import":
		d.importKey(w, r, name)
	case operation == "keys":
		d.handleKey(w, r, name)
	case operation == "encrypt":
		d.encrypt(w, r, name)
	case operation == "decrypt":
		d.decrypt(w, r, name)
	case operation == "sign":
		d.sign(w, r, name)
	default:
		writeVaultError(w, http.StatusNotFound, "unsupported operation "+operation)
	}
}

// listKeys implements LIST /v1/transit/keys, returning every key name this
// double currently holds under the same {"data":{"keys":[...]}} envelope
// real Vault Transit uses, which is the shape (*Backend).ListKeys parses.
func (d *transitDouble) listKeys(w http.ResponseWriter) {
	d.mu.Lock()
	names := make([]string, 0, len(d.keys))
	for name := range d.keys {
		names = append(names, name)
	}
	d.mu.Unlock()

	keys := make([]interface{}, len(names))
	for i, name := range names {
		keys[i] = name
	}

	writeVaultData(w, map[string]interface{}{
		"keys": keys,
	})
}

// handleKey implements create (POST/PUT), read (GET) and delete (DELETE).
func (d *transitDouble) handleKey(w http.ResponseWriter, r *http.Request, name string) {
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		body, err := decodeRequest(r)
		if err != nil {
			writeVaultError(w, http.StatusBadRequest, err.Error())
			return
		}

		keyType, _ := body["type"].(string)
		if keyType == "" {
			keyType = "aes256-gcm96"
		}
		exportable, _ := body["exportable"].(bool)

		material := make([]byte, 32) // aes256-gcm96
		if _, err := rand.Read(material); err != nil {
			writeVaultError(w, http.StatusInternalServerError, err.Error())
			return
		}

		key := &transitKey{
			keyType:    keyType,
			exportable: exportable,
			version:    1,
			materials:  map[int][]byte{1: material},
		}

		if strings.HasPrefix(keyType, "rsa") {
			priv, err := rsa.GenerateKey(rand.Reader, rsaBitsForType(keyType))
			if err != nil {
				writeVaultError(w, http.StatusInternalServerError, err.Error())
				return
			}
			key.rsaKeys = map[int]*rsa.PrivateKey{1: priv}
		}

		d.mu.Lock()
		if _, exists := d.keys[name]; !exists {
			d.keys[name] = key
		}
		d.mu.Unlock()

		w.WriteHeader(http.StatusNoContent)

	case http.MethodGet:
		d.mu.Lock()
		key, exists := d.keys[name]
		var snapshot transitKey
		if exists {
			snapshot = *key
		}
		d.mu.Unlock()

		if !exists {
			writeVaultError(w, http.StatusNotFound, "no such key")
			return
		}

		keysMap := map[string]interface{}{}
		for version := range snapshot.materials {
			entry := map[string]interface{}{}
			if priv, ok := snapshot.rsaKeys[version]; ok {
				pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
				if err != nil {
					writeVaultError(w, http.StatusInternalServerError, err.Error())
					return
				}
				entry["public_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
			}
			keysMap[strconv.Itoa(version)] = entry
		}

		writeVaultData(w, map[string]interface{}{
			"name":                 name,
			"type":                 snapshot.keyType,
			"latest_version":       snapshot.version,
			"deletion_allowed":     snapshot.deletionAllowed,
			"supports_encryption":  true,
			"supports_decryption":  true,
			"min_decryption_versi": 1,
			"keys":                 keysMap,
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

// rsaBitsForType maps a Vault Transit RSA key type to its modulus size.
func rsaBitsForType(keyType string) int {
	switch keyType {
	case "rsa-3072":
		return 3072
	case "rsa-4096":
		return 4096
	default:
		return 2048
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

// rotateKey bumps the key version and generates genuinely new key material
// for it -- as real Vault Transit does -- while retaining every earlier
// version's material so ciphertext and signatures produced under it remain
// valid.
func (d *transitDouble) rotateKey(w http.ResponseWriter, name string) {
	d.mu.Lock()
	key, exists := d.keys[name]
	if !exists {
		d.mu.Unlock()
		writeVaultError(w, http.StatusNotFound, "no such key")
		return
	}

	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		d.mu.Unlock()
		writeVaultError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var newRSAKey *rsa.PrivateKey
	if key.rsaKeys != nil {
		priv, err := rsa.GenerateKey(rand.Reader, rsaBitsForType(key.keyType))
		if err != nil {
			d.mu.Unlock()
			writeVaultError(w, http.StatusInternalServerError, err.Error())
			return
		}
		newRSAKey = priv
	}

	key.version++
	key.materials[key.version] = material
	if newRSAKey != nil {
		key.rsaKeys[key.version] = newRSAKey
	}
	d.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// wrappingKey implements GET transit/wrapping_key, generating the double's
// stand-in RSA wrapping keypair on first use and returning its public half
// as PEM, exactly as real Vault's response is shaped.
func (d *transitDouble) wrappingKey(w http.ResponseWriter) {
	d.mu.Lock()
	if d.wrappingRSAKey == nil {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			d.mu.Unlock()
			writeVaultError(w, http.StatusInternalServerError, err.Error())
			return
		}
		d.wrappingRSAKey = priv
	}
	priv := d.wrappingRSAKey
	d.mu.Unlock()

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeVaultData(w, map[string]interface{}{
		"public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
	})
}

// importKey implements POST transit/keys/{name}/import, the server side of
// the BYOK ceremony this backend's WrapKey prepares the ciphertext for: it
// splits the ciphertext at the wrapping key's own modulus size (recovering
// the split point the same way real Vault does, from the key it generated
// rather than from anything the caller sends), RSA-OAEP-decrypts the
// ephemeral AES key, and AES-GCM-opens the target key material with it
// under the all-zero nonce the format specifies. A key that already exists
// is refused, matching real Vault's import (as opposed to import_version)
// endpoint, and creates the key at version 1 -- this double does not model
// import_version.
func (d *transitDouble) importKey(w http.ResponseWriter, r *http.Request, name string) {
	body, err := decodeRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	d.mu.Lock()
	_, exists := d.keys[name]
	wrappingKey := d.wrappingRSAKey
	d.mu.Unlock()

	if exists {
		writeVaultError(w, http.StatusBadRequest, "key already exists")
		return
	}
	if wrappingKey == nil {
		writeVaultError(w, http.StatusBadRequest, "no wrapping key has been issued for this token")
		return
	}

	keyType, _ := body["type"].(string)
	if keyType == "" {
		writeVaultError(w, http.StatusBadRequest, "missing type")
		return
	}

	ciphertextB64, _ := body["ciphertext"].(string)
	if ciphertextB64 == "" {
		writeVaultError(w, http.StatusBadRequest, "missing ciphertext")
		return
	}
	combined, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "ciphertext is not valid base64")
		return
	}

	rsaLen := wrappingKey.PublicKey.Size()
	if len(combined) <= rsaLen {
		writeVaultError(w, http.StatusBadRequest, "ciphertext too short for wrapping key")
		return
	}
	wrappedEphemeral, sealed := combined[:rsaLen], combined[rsaLen:]

	ephemeralKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrappingKey, wrappedEphemeral, nil)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "failed to unwrap ephemeral key: "+err.Error())
		return
	}

	block, err := aes.NewCipher(ephemeralKey)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, err.Error())
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, err.Error())
		return
	}
	material, err := gcm.Open(nil, make([]byte, gcm.NonceSize()), sealed, nil)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "failed to unwrap target key material: "+err.Error())
		return
	}
	if len(material) != 32 {
		writeVaultError(w, http.StatusBadRequest, fmt.Sprintf("imported key material is %d bytes, want 32 for %s", len(material), keyType))
		return
	}

	exportable, _ := body["exportable"].(bool)

	d.mu.Lock()
	d.keys[name] = &transitKey{
		keyType:    keyType,
		exportable: exportable,
		version:    1,
		materials:  map[int][]byte{1: material},
	}
	d.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// export implements GET transit/export/{type}/{name}/{version}, returning
// the base64 raw key material for one key version. Real Vault refuses this
// for a key that was not created with exportable:true; this double enforces
// the same rule so a test proves the backend never asks for material Vault
// would refuse to give it.
func (d *transitDouble) export(w http.ResponseWriter, keyType, rest string) {
	segments := strings.SplitN(rest, "/", 2)
	name := segments[0]
	version := "latest"
	if len(segments) == 2 {
		version = segments[1]
	}

	d.mu.Lock()
	key, exists := d.keys[name]
	var snapshot transitKey
	if exists {
		snapshot = *key
	}
	d.mu.Unlock()

	if !exists {
		writeVaultError(w, http.StatusNotFound, "no such key")
		return
	}
	if keyType != "encryption-key" {
		writeVaultError(w, http.StatusBadRequest, "unsupported export type "+keyType)
		return
	}
	if !snapshot.exportable {
		writeVaultError(w, http.StatusBadRequest, "requested key is not exportable")
		return
	}

	v := snapshot.version
	if version != "latest" {
		parsed, err := strconv.Atoi(version)
		if err != nil {
			writeVaultError(w, http.StatusBadRequest, "invalid version")
			return
		}
		v = parsed
	}

	material, ok := snapshot.materials[v]
	if !ok {
		writeVaultError(w, http.StatusBadRequest, fmt.Sprintf("version %d not found", v))
		return
	}

	writeVaultData(w, map[string]interface{}{
		"name": name,
		"type": snapshot.keyType,
		"keys": map[string]interface{}{
			strconv.Itoa(v): base64.StdEncoding.EncodeToString(material),
		},
	})
}

// encrypt performs AES-256-GCM over the base64 plaintext using the key's
// latest version, binding the base64 "context" field as additional
// authenticated data.
func (d *transitDouble) encrypt(w http.ResponseWriter, r *http.Request, name string) {
	body, err := decodeRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	gcm, version, err := d.latestAEAD(name)
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

	blob := gcm.Seal(nil, nil, plaintext, aad)
	writeVaultData(w, map[string]interface{}{
		"ciphertext":  vaultVersionPrefix(version) + base64.StdEncoding.EncodeToString(blob),
		"key_version": version,
	})
}

// decrypt reverses encrypt. It decrypts with the version embedded in the
// ciphertext envelope -- not the key's current version -- exactly as real
// Vault does, so a caller that preserves the envelope (rather than
// discarding it) can still decrypt ciphertext produced before a rotation.
func (d *transitDouble) decrypt(w http.ResponseWriter, r *http.Request, name string) {
	body, err := decodeRequest(r)
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

	version, err := parseVaultVersion(segments[1])
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	gcm, err := d.aeadForVersion(name, version)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	blob, err := base64.StdEncoding.DecodeString(segments[2])
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "invalid ciphertext encoding")
		return
	}
	if len(blob) < gcm.Overhead() {
		writeVaultError(w, http.StatusBadRequest, "ciphertext too short")
		return
	}

	aad, err := decodeField(body, "context", false)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	plaintext, err := gcm.Open(nil, nil, blob, aad)
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

// sign produces an RSA signature (PKCS#1 v1.5, or PSS when requested) over
// a prehashed digest, using the key version named by the request's
// key_version field, defaulting to the key's latest version when absent.
// This lets a test prove a Signer built before a rotation keeps signing
// with the version it was constructed against.
func (d *transitDouble) sign(w http.ResponseWriter, r *http.Request, name string) {
	body, err := decodeRequest(r)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	d.mu.Lock()
	key, exists := d.keys[name]
	var version int
	if exists {
		version = key.version
	}
	d.mu.Unlock()

	if !exists {
		writeVaultError(w, http.StatusNotFound, "no such key")
		return
	}

	if raw, ok := body["key_version"]; ok {
		v, err := coerceInt(raw)
		if err != nil {
			writeVaultError(w, http.StatusBadRequest, "invalid key_version")
			return
		}
		version = v
	}

	d.mu.Lock()
	priv, ok := key.rsaKeys[version]
	d.mu.Unlock()
	if !ok {
		writeVaultError(w, http.StatusBadRequest, fmt.Sprintf("version %d not found", version))
		return
	}

	input, err := decodeField(body, "input", true)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}

	var hashType crypto.Hash
	switch len(input) {
	case 32:
		hashType = crypto.SHA256
	case 48:
		hashType = crypto.SHA384
	case 64:
		hashType = crypto.SHA512
	default:
		writeVaultError(w, http.StatusBadRequest, fmt.Sprintf("unsupported prehashed digest size: %d bytes", len(input)))
		return
	}

	var sig []byte
	if alg, _ := body["signature_algorithm"].(string); alg == "pss" {
		sig, err = rsa.SignPSS(rand.Reader, priv, hashType, input, &rsa.PSSOptions{Hash: hashType, SaltLength: rsa.PSSSaltLengthAuto})
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, hashType, input)
	}
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeVaultData(w, map[string]interface{}{
		"signature":   vaultVersionPrefix(version) + base64.StdEncoding.EncodeToString(sig),
		"key_version": version,
	})
}

// coerceInt converts a decoded JSON value (float64, or a numeric string) to
// an int.
func coerceInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case string:
		return strconv.Atoi(n)
	default:
		return 0, &transitError{msg: "not a number"}
	}
}

// latestAEAD returns the AES-GCM primitive for a key's latest version,
// along with that version number.
func (d *transitDouble) latestAEAD(name string) (cipher.AEAD, int, error) {
	d.mu.Lock()
	key, exists := d.keys[name]
	d.mu.Unlock()

	if !exists {
		return nil, 0, errTransitKeyNotFound
	}

	gcm, err := d.aeadForVersion(name, key.version)
	if err != nil {
		return nil, 0, err
	}
	return gcm, key.version, nil
}

// aeadForVersion returns the AES-GCM primitive for one specific version of
// a key's material, failing if that version was never created (or has
// since exceeded the key's min_decryption_version, which this double does
// not model).
func (d *transitDouble) aeadForVersion(name string, version int) (cipher.AEAD, error) {
	d.mu.Lock()
	key, exists := d.keys[name]
	d.mu.Unlock()

	if !exists {
		return nil, errTransitKeyNotFound
	}

	material, ok := key.materials[version]
	if !ok {
		return nil, &transitError{msg: fmt.Sprintf("version %d not found", version)}
	}

	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	// NewGCMWithRandomNonce, not NewGCM: this double runs in-process, so
	// GODEBUG=fips140=only applies to it and refuses an externally supplied
	// IV. The layout it emulates is unaffected -- Vault Transit's
	// aes256-gcm96 envelope is nonce || ciphertext || tag, which is exactly
	// what Seal prepends and Open strips.
	return cipher.NewGCMWithRandomNonce(block)
}

// keyCount reports how many keys the double currently holds, so a test can
// assert that a delete really removed the key from the engine.
func (d *transitDouble) keyCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.keys)
}

// exportable reports the exportable flag Transit recorded when name was
// created, so a test can assert the backend never asks Vault for an
// exportable key (H8). It returns false, along with false, when the key
// does not exist.
func (d *transitDouble) exportable(name string) (exportable, exists bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key, exists := d.keys[name]
	if !exists {
		return false, false
	}
	return key.exportable, true
}

// errTransitKeyNotFound mirrors Vault's "encryption key not found" condition.
var errTransitKeyNotFound = &transitError{msg: "encryption key not found"}

// transitError is the double's error type.
type transitError struct{ msg string }

func (e *transitError) Error() string { return e.msg }

// vaultVersionPrefix renders Transit's ciphertext/signature version prefix.
func vaultVersionPrefix(version int) string {
	return "vault:v" + strconv.Itoa(version) + ":"
}

// parseVaultVersion extracts the version number from a "v<n>" segment of a
// Vault envelope.
func parseVaultVersion(segment string) (int, error) {
	n, err := strconv.Atoi(strings.TrimPrefix(segment, "v"))
	if err != nil {
		return 0, &transitError{msg: "invalid version segment " + segment}
	}
	return n, nil
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
