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

package xkms

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// defaultDataKeySize is the data key size, in bytes, when a request names
// none: an AES-256 key.
const defaultDataKeySize = 32

// Rewrap decrypts req.Source under its key and encrypts the plaintext under
// the target key. Both keys are resolved in the source's tenant, and the
// plaintext is wiped before Rewrap returns.
func (s *XKMSService) Rewrap(ctx context.Context, req *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	if req == nil || req.Source == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil rewrap request"}
	}

	opened, err := s.Decrypt(ctx, req.Source)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(opened.Plaintext)

	target := &transport.EncryptRequest{
		Backend:        req.TargetBackend,
		KeyID:          req.TargetKeyID,
		Plaintext:      opened.Plaintext,
		AdditionalData: req.Source.AdditionalData,
		TenantID:       req.Source.TenantID,
	}
	if target.KeyID == "" {
		target.KeyID = req.Source.KeyID
	}
	if target.Backend == "" {
		target.Backend = req.Source.Backend
	}

	wrapped, err := s.Encrypt(ctx, target)
	if err != nil {
		return nil, err
	}
	return &transport.RewrapResponse{SourceKeyVersion: opened.KeyVersion, Wrapped: wrapped}, nil
}

// EncryptBatch encrypts each item with the key's current version. A request
// the key cannot serve at all (an unknown or another tenant's key, a bad
// batch size) is refused whole; an item that fails carries its own error.
func (s *XKMSService) EncryptBatch(ctx context.Context, req *transport.EncryptBatchRequest) (resp *transport.EncryptBatchResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpEncrypt, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil encrypt batch request"}
	}
	if err := checkBatchSize(len(req.Items)); err != nil {
		return nil, err
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	sizes := make([]uint64, len(req.Items))
	for i, item := range req.Items {
		sizes[i] = uint64(len(item.Plaintext))
	}
	if err := s.admitKey(ctx, k, keypolicy.OpEncrypt, sizes...); err != nil {
		return nil, err
	}
	cur, err := k.current()
	if err != nil {
		return nil, err
	}

	results := make([]transport.EncryptBatchResult, len(req.Items))
	for i, item := range req.Items {
		sealed, err := encryptVersion(ctx, k.backend, cur, &transport.EncryptRequest{
			Backend:        req.Backend,
			KeyID:          req.KeyID,
			Plaintext:      item.Plaintext,
			AdditionalData: item.AdditionalData,
			TenantID:       req.TenantID,
		})
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		results[i].Result = sealed
	}
	return &transport.EncryptBatchResponse{Results: results}, nil
}

// DecryptBatch decrypts each item with the key's selected versions. A
// request the key cannot serve at all is refused whole; an item that fails
// carries its own error.
func (s *XKMSService) DecryptBatch(ctx context.Context, req *transport.DecryptBatchRequest) (resp *transport.DecryptBatchResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpDecrypt, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil decrypt batch request"}
	}
	if err := checkBatchSize(len(req.Items)); err != nil {
		return nil, err
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	// Each ciphertext is one decryption.
	if err := s.admitKey(ctx, k, keypolicy.OpDecrypt, make([]uint64, len(req.Items))...); err != nil {
		return nil, err
	}

	results := make([]transport.DecryptBatchResult, len(req.Items))
	for i, item := range req.Items {
		opened, err := decryptVersioned(ctx, k, &transport.DecryptRequest{
			Backend:        req.Backend,
			KeyID:          req.KeyID,
			Ciphertext:     item.Ciphertext,
			AdditionalData: item.AdditionalData,
			Nonce:          item.Nonce,
			Tag:            item.Tag,
			GCMNonceMode:   item.GCMNonceMode,
			KeyVersion:     item.KeyVersion,
			TenantID:       req.TenantID,
		})
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		results[i] = transport.DecryptBatchResult{Plaintext: opened.Plaintext, KeyVersion: opened.KeyVersion}
	}
	return &transport.DecryptBatchResponse{Results: results}, nil
}

// checkBatchSize refuses an empty batch and one over transport.MaxBatchItems.
func checkBatchSize(n int) error {
	if n == 0 || n > transport.MaxBatchItems {
		return &ErrValidation{
			Sentinel: ErrBatchSize,
			Detail:   "batch has " + strconv.Itoa(n) + " items; want 1 to " + strconv.Itoa(transport.MaxBatchItems),
		}
	}
	return nil
}

// GenerateDataKey returns a random data key and the same key wrapped under
// the named key's current version.
func (s *XKMSService) GenerateDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	plaintext, wrapped, err := s.generateDataKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return &transport.GenerateDataKeyResponse{Plaintext: plaintext, Wrapped: wrapped}, nil
}

// GenerateWrappedDataKey returns a random data key only wrapped under the
// named key's current version; the plaintext is wiped before it returns.
func (s *XKMSService) GenerateWrappedDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	plaintext, wrapped, err := s.generateDataKey(ctx, req)
	if err != nil {
		return nil, err
	}
	secure.Wipe(plaintext)
	return &transport.GenerateWrappedDataKeyResponse{Wrapped: wrapped}, nil
}

// generateDataKey draws a data key from crypto/rand and wraps it. On error
// it wipes the key and returns none.
func (s *XKMSService) generateDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) ([]byte, *transport.EncryptResponse, error) {
	if req == nil {
		return nil, nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil data key request"}
	}
	size, err := dataKeySize(req.KeySize)
	if err != nil {
		return nil, nil, err
	}

	plaintext := make([]byte, size)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, &ErrKeyOperation{Operation: "generate data key", KeyID: req.KeyID, Err: err}
	}

	wrapped, err := s.Encrypt(ctx, &transport.EncryptRequest{
		Backend:        req.Backend,
		KeyID:          req.KeyID,
		Plaintext:      plaintext,
		AdditionalData: req.AdditionalData,
		TenantID:       req.TenantID,
	})
	if err != nil {
		secure.Wipe(plaintext)
		return nil, nil, err
	}
	return plaintext, wrapped, nil
}

// dataKeySize returns the data key size in bytes: an AES key size, with 0
// meaning defaultDataKeySize.
func dataKeySize(requested int) (int, error) {
	switch requested {
	case 0:
		return defaultDataKeySize, nil
	case 16, 24, 32:
		return requested, nil
	}
	return 0, &ErrValidation{
		Sentinel: ErrDataKeySize,
		Detail:   "data key size " + strconv.Itoa(requested) + " bytes; want 16, 24 or 32",
	}
}

// GenerateHMAC computes an HMAC (RFC 2104) of req.Data with the key's
// current version.
func (s *XKMSService) GenerateHMAC(ctx context.Context, req *transport.GenerateHMACRequest) (resp *transport.GenerateHMACResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpSign, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil hmac request"}
	}
	h, err := usableHash(req.Hash)
	if err != nil {
		return nil, err
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	if err := s.admitKey(ctx, k, keypolicy.OpGenerateMAC); err != nil {
		return nil, err
	}
	cur, err := k.current()
	if err != nil {
		return nil, err
	}

	mac, err := computeHMAC(ctx, k.backend, cur.attrs, h, req.Data)
	if err != nil {
		return nil, err
	}
	return &transport.GenerateHMACResponse{MAC: mac, KeyVersion: cur.number, Hash: h.String()}, nil
}

// VerifyHMAC checks req.MAC against req.Data. A MAC that does not verify is
// a valid response with Valid false, not an error.
func (s *XKMSService) VerifyHMAC(ctx context.Context, req *transport.VerifyHMACRequest) (resp *transport.VerifyHMACResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpVerify, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil verify hmac request"}
	}
	h, err := usableHash(req.Hash)
	if err != nil {
		return nil, err
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	if err := s.admitKey(ctx, k, keypolicy.OpVerifyMAC); err != nil {
		return nil, err
	}
	versions, err := k.selectVersions(req.KeyVersion, true)
	if err != nil {
		return nil, err
	}

	for _, v := range versions {
		mac, err := computeHMAC(ctx, k.backend, v.attrs, h, req.Data)
		if err != nil {
			return nil, err
		}
		if hmac.Equal(mac, req.MAC) {
			return &transport.VerifyHMACResponse{Valid: true, KeyVersion: v.number}, nil
		}
	}
	return &transport.VerifyHMACResponse{}, nil
}

// computeHMAC computes an HMAC with a symmetric key version's raw material,
// which is wiped before it returns. A backend that cannot release the
// material in-process (a hardware key) is refused.
func computeHMAC(ctx context.Context, b Backend, attrs *types.KeyAttributes, h crypto.Hash, data []byte) ([]byte, error) {
	raw, err := rawSymmetricWrappingKey(ctx, b, attrs)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(raw)
	return hmacSum(h, raw, data)
}

// hmacSum runs crypto/hmac. Under GODEBUG=fips140=only the standard library
// panics on an HMAC it does not approve (a key under 112 bits); that panic is
// returned as ErrHMACRefused.
func hmacSum(h crypto.Hash, key, data []byte) (mac []byte, err error) {
	defer func() {
		if recover() != nil {
			mac = nil
			err = &ErrValidation{Sentinel: ErrHMACRefused, Detail: "the standard library refused HMAC-" + h.String()}
		}
	}()
	m := hmac.New(h.New, key)
	m.Write(data)
	return m.Sum(nil), nil
}

// GenerateRandom returns req.Length bytes from crypto/rand.
func (s *XKMSService) GenerateRandom(_ context.Context, req *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil random request"}
	}
	if req.Length < 1 || req.Length > transport.MaxRandomBytes {
		return nil, &ErrValidation{
			Sentinel: ErrRandomLength,
			Detail:   "random length " + strconv.Itoa(req.Length) + "; want 1 to " + strconv.Itoa(transport.MaxRandomBytes),
		}
	}
	random := make([]byte, req.Length)
	if _, err := rand.Read(random); err != nil {
		return nil, &ErrKeyOperation{Operation: "generate random", Err: err}
	}
	return &transport.GenerateRandomResponse{Random: random}, nil
}

// Hash returns the digest of req.Data.
func (s *XKMSService) Hash(_ context.Context, req *transport.HashRequest) (*transport.HashResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil hash request"}
	}
	h, err := usableHash(req.Hash)
	if err != nil {
		return nil, err
	}
	digest := h.New()
	digest.Write(req.Data)
	return &transport.HashResponse{Digest: digest.Sum(nil), Hash: h.String()}, nil
}

// usableHash resolves a hash name and refuses one the standard library will
// not run: unlinked, or not approved under GODEBUG=fips140=only.
func usableHash(name string) (crypto.Hash, error) {
	h, err := ResolveHash(name)
	if err != nil {
		return 0, err
	}
	if h == 0 || !types.HashUsable(h) {
		return 0, &ErrValidation{Sentinel: ErrInvalidHashFunction, Detail: "hash algorithm not available: " + name}
	}
	return h, nil
}
