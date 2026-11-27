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

package rest

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

func cryptoUtilityCases() []verbCase {
	wrapped := &transport.EncryptResponse{Ciphertext: []byte{1, 2}, Nonce: []byte{3}}
	wrappedJSON := `{"ciphertext":"AQI=","nonce":"Aw=="}`
	dataKey := &transport.GenerateDataKeyRequest{Backend: "pkcs#11", KeyID: "a b", KeySize: 24, AdditionalData: []byte{7}}

	return []verbCase{
		newVerbCase("Rewrap", (*Transport).Rewrap,
			&transport.RewrapRequest{Source: &transport.DecryptRequest{KeyID: "a b", Ciphertext: []byte{1}}, TargetKeyID: "c d", TargetBackend: "software"}, true,
			"POST /api/v1/keys/rewrap",
			`{"source_key_version":2,"wrapped":`+wrappedJSON+`}`,
			&transport.RewrapResponse{SourceKeyVersion: 2, Wrapped: wrapped}),
		newVerbCase("EncryptBatch", (*Transport).EncryptBatch,
			&transport.EncryptBatchRequest{Backend: "pkcs#11", KeyID: "a b", Items: []transport.EncryptBatchItem{{Plaintext: []byte{5}, AdditionalData: []byte{6}}, {Plaintext: []byte{8}}}}, true,
			"POST /api/v1/keys/a%20b/encrypt-batch",
			`{"results":[{"result":`+wrappedJSON+`},{"error":"plaintext too large"}]}`,
			&transport.EncryptBatchResponse{Results: []transport.EncryptBatchResult{{Result: wrapped}, {Error: "plaintext too large"}}}),
		newVerbCase("DecryptBatch", (*Transport).DecryptBatch,
			&transport.DecryptBatchRequest{Backend: "pkcs#11", KeyID: "a b", Items: []transport.DecryptBatchItem{{Ciphertext: []byte{1, 2}, AdditionalData: []byte{6}}}}, true,
			"POST /api/v1/keys/a%20b/decrypt-batch",
			`{"results":[{"plaintext":"BQ==","key_version":3},{"error":"authentication failed"}]}`,
			&transport.DecryptBatchResponse{Results: []transport.DecryptBatchResult{{Plaintext: []byte{5}, KeyVersion: 3}, {Error: "authentication failed"}}}),
		newVerbCase("GenerateDataKey", (*Transport).GenerateDataKey, dataKey, true,
			"POST /api/v1/keys/a%20b/data-key",
			`{"plaintext":"CQ==","wrapped":`+wrappedJSON+`}`,
			&transport.GenerateDataKeyResponse{Plaintext: []byte{9}, Wrapped: wrapped}),
		newVerbCase("GenerateWrappedDataKey", (*Transport).GenerateWrappedDataKey, dataKey, true,
			"POST /api/v1/keys/a%20b/wrapped-data-key",
			`{"wrapped":`+wrappedJSON+`}`,
			&transport.GenerateWrappedDataKeyResponse{Wrapped: wrapped}),
		newVerbCase("GenerateHMAC", (*Transport).GenerateHMAC,
			&transport.GenerateHMACRequest{Backend: "pkcs#11", KeyID: "a b", Data: []byte{4}, Hash: "SHA-384"}, true,
			"POST /api/v1/keys/a%20b/hmac",
			`{"mac":"AQI=","key_version":2,"hash":"SHA-384"}`,
			&transport.GenerateHMACResponse{MAC: []byte{1, 2}, KeyVersion: 2, Hash: "SHA-384"}),
		newVerbCase("VerifyHMAC", (*Transport).VerifyHMAC,
			&transport.VerifyHMACRequest{Backend: "pkcs#11", KeyID: "a b", Data: []byte{4}, MAC: []byte{1, 2}, KeyVersion: 2}, true,
			"POST /api/v1/keys/a%20b/hmac/verify",
			`{"valid":true,"key_version":2}`,
			&transport.VerifyHMACResponse{Valid: true, KeyVersion: 2}),
		newVerbCase("GenerateRandom", (*Transport).GenerateRandom,
			&transport.GenerateRandomRequest{Length: 2}, true,
			"POST /api/v1/random",
			`{"random":"AQI="}`,
			&transport.GenerateRandomResponse{Random: []byte{1, 2}}),
		newVerbCase("Hash", (*Transport).Hash,
			&transport.HashRequest{Data: []byte{4}, Hash: "SHA-512"}, true,
			"POST /api/v1/hash",
			`{"digest":"AQI=","hash":"SHA-512"}`,
			&transport.HashResponse{Digest: []byte{1, 2}, Hash: "SHA-512"}),
	}
}

func TestCryptoUtilityVerbs_Routes(t *testing.T) {
	runVerbRoutes(t, cryptoUtilityCases())
}

func TestCryptoUtilityVerbs_Errors(t *testing.T) {
	runVerbErrors(t, cryptoUtilityCases())
}
