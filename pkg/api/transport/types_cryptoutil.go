// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package transport

const (
	// MaxBatchItems bounds the items of one EncryptBatch or DecryptBatch
	// request; a larger batch is refused.
	MaxBatchItems = 100

	// MaxRandomBytes bounds the length of one GenerateRandom request; a
	// larger length is refused.
	MaxRandomBytes = 1024
)

// RewrapRequest unwraps Source under its key and wraps the plaintext under
// the target key. An empty TargetKeyID rewraps under the source key's
// current version; an empty TargetBackend uses Source.Backend. The source
// AdditionalData authenticates the new ciphertext too. The plaintext never
// leaves the service.
type RewrapRequest struct {
	Source        *DecryptRequest `json:"source"`
	TargetKeyID   string          `json:"target_key_id,omitempty"`
	TargetBackend string          `json:"target_backend,omitempty"`
}

// RewrapResponse carries the ciphertext under the target key.
type RewrapResponse struct {
	// SourceKeyVersion is the source key version that decrypted the input.
	SourceKeyVersion uint32           `json:"source_key_version,omitempty"`
	Wrapped          *EncryptResponse `json:"wrapped"`
}

// EncryptBatchItem is one plaintext of an EncryptBatchRequest.
type EncryptBatchItem struct {
	Plaintext      []byte `json:"plaintext"`
	AdditionalData []byte `json:"additional_data,omitempty"`
}

// EncryptBatchRequest encrypts up to MaxBatchItems plaintexts with one key.
type EncryptBatchRequest struct {
	Backend  string             `json:"backend"`
	KeyID    string             `json:"key_id"`
	Items    []EncryptBatchItem `json:"items"`
	TenantID string             `json:"tenant_id,omitempty"`
}

// EncryptBatchResult is one item's outcome: Result on success, Error
// otherwise.
type EncryptBatchResult struct {
	Result *EncryptResponse `json:"result,omitempty"`
	Error  string           `json:"error,omitempty"`
}

// EncryptBatchResponse holds one result per request item, in order.
type EncryptBatchResponse struct {
	Results []EncryptBatchResult `json:"results"`
}

// DecryptBatchItem is one AEAD ciphertext of a DecryptBatchRequest; its
// fields mean what the DecryptRequest fields of the same name mean.
type DecryptBatchItem struct {
	Ciphertext     []byte `json:"ciphertext"`
	AdditionalData []byte `json:"additional_data,omitempty"`
	Nonce          []byte `json:"nonce,omitempty"`
	Tag            []byte `json:"tag,omitempty"`
	GCMNonceMode   string `json:"gcm_nonce_mode,omitempty"`
	KeyVersion     uint32 `json:"key_version,omitempty"`
}

// DecryptBatchRequest decrypts up to MaxBatchItems ciphertexts with one key.
type DecryptBatchRequest struct {
	Backend  string             `json:"backend"`
	KeyID    string             `json:"key_id"`
	Items    []DecryptBatchItem `json:"items"`
	TenantID string             `json:"tenant_id,omitempty"`
}

// DecryptBatchResult is one item's outcome: Plaintext and KeyVersion on
// success, Error otherwise.
type DecryptBatchResult struct {
	Plaintext  []byte `json:"plaintext,omitempty"`
	KeyVersion uint32 `json:"key_version,omitempty"`
	Error      string `json:"error,omitempty"`
}

// DecryptBatchResponse holds one result per request item, in order.
type DecryptBatchResponse struct {
	Results []DecryptBatchResult `json:"results"`
}

// GenerateDataKeyRequest names the wrapping key and the data key's size in
// bytes: 16, 24 or 32, with 0 meaning 32.
type GenerateDataKeyRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	KeySize        int    `json:"key_size,omitempty"`
	AdditionalData []byte `json:"additional_data,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
}

// GenerateDataKeyResponse carries the data key in plaintext and wrapped.
type GenerateDataKeyResponse struct {
	Plaintext []byte           `json:"plaintext"`
	Wrapped   *EncryptResponse `json:"wrapped"`
}

// GenerateWrappedDataKeyResponse carries the data key only wrapped.
type GenerateWrappedDataKeyResponse struct {
	Wrapped *EncryptResponse `json:"wrapped"`
}

// GenerateHMACRequest computes an HMAC of Data with a symmetric key. An
// empty Hash selects SHA-256.
type GenerateHMACRequest struct {
	Backend  string `json:"backend"`
	KeyID    string `json:"key_id"`
	Data     []byte `json:"data"`
	Hash     string `json:"hash,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// GenerateHMACResponse carries the MAC, the key version that computed it and
// the hash function's name.
type GenerateHMACResponse struct {
	MAC        []byte `json:"mac"`
	KeyVersion uint32 `json:"key_version,omitempty"`
	Hash       string `json:"hash"`
}

// VerifyHMACRequest checks MAC against Data. KeyVersion 0 tries the enabled
// versions newest first.
type VerifyHMACRequest struct {
	Backend    string `json:"backend"`
	KeyID      string `json:"key_id"`
	Data       []byte `json:"data"`
	MAC        []byte `json:"mac"`
	Hash       string `json:"hash,omitempty"`
	KeyVersion uint32 `json:"key_version,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
}

// VerifyHMACResponse reports whether the MAC verified and, if so, under
// which key version.
type VerifyHMACResponse struct {
	Valid      bool   `json:"valid"`
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// GenerateRandomRequest asks for Length random bytes, at most MaxRandomBytes.
type GenerateRandomRequest struct {
	Length int `json:"length"`
}

// GenerateRandomResponse carries the random bytes.
type GenerateRandomResponse struct {
	Random []byte `json:"random"`
}

// HashRequest computes the digest of Data. An empty Hash selects SHA-256.
type HashRequest struct {
	Data []byte `json:"data"`
	Hash string `json:"hash,omitempty"`
}

// HashResponse carries the digest and the hash function's name.
type HashResponse struct {
	Digest []byte `json:"digest"`
	Hash   string `json:"hash"`
}
