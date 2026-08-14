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

package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// errSentinel is a reusable inner error for wrapping tests.
var errSentinel = errors.New("inner error")

func TestErrChallengeSetupFailed(t *testing.T) {
	err := ErrChallengeSetupFailed{ChallengeType: "http-01", Reason: "port in use"}
	assert.Contains(t, err.Error(), "http-01")
	assert.Contains(t, err.Error(), "port in use")
}

func TestErrUnsupportedChallengeType(t *testing.T) {
	err := ErrUnsupportedChallengeType{ChallengeType: "tls-sni-01"}
	assert.Contains(t, err.Error(), "tls-sni-01")
	assert.Contains(t, err.Error(), "unsupported")
}

func TestErrTPMModuleRequired(t *testing.T) {
	err := ErrTPMModuleRequired{}
	assert.Contains(t, err.Error(), "TPM")
}

func TestErrMissingEmail(t *testing.T) {
	err := ErrMissingEmail{}
	assert.Contains(t, err.Error(), "email")
}

func TestErrMissingDomain(t *testing.T) {
	err := ErrMissingDomain{}
	assert.Contains(t, err.Error(), "domain")
}

func TestErrMissingCertFile(t *testing.T) {
	err := ErrMissingCertFile{}
	assert.Contains(t, err.Error(), "certificate file")
}

func TestErrMissingDeviceID(t *testing.T) {
	err := ErrMissingDeviceID{}
	assert.Contains(t, err.Error(), "device ID")
}

func TestErrUnsupportedKeyType(t *testing.T) {
	err := ErrUnsupportedKeyType{KeyType: "dsa"}
	assert.Contains(t, err.Error(), "dsa")
	assert.Contains(t, err.Error(), "unsupported")
}

func TestErrInvalidPCRIndex(t *testing.T) {
	err := ErrInvalidPCRIndex{Index: 42}
	assert.Contains(t, err.Error(), "42")
	assert.Contains(t, err.Error(), "out of range")
}

func TestErrInvalidPCRFormat(t *testing.T) {
	err := ErrInvalidPCRFormat{Value: "abc"}
	assert.Contains(t, err.Error(), "abc")
	assert.Contains(t, err.Error(), "invalid")
}

func TestErrUnsupportedConfigFormat(t *testing.T) {
	err := ErrUnsupportedConfigFormat{Extension: ".xml"}
	assert.Contains(t, err.Error(), ".xml")
	assert.Contains(t, err.Error(), "unsupported")
}

func TestErrUnsupportedTransport(t *testing.T) {
	err := ErrUnsupportedTransport{Transport: "websocket"}
	assert.Contains(t, err.Error(), "websocket")
	assert.Contains(t, err.Error(), "unsupported")
}

func TestErrSDKClientCreation(t *testing.T) {
	err := ErrSDKClientCreation{Err: errSentinel}
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrSDKOrderFailed(t *testing.T) {
	err := ErrSDKOrderFailed{Operation: "finalize", Err: errSentinel}
	assert.Contains(t, err.Error(), "finalize")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrSDKAuthorizationFailed(t *testing.T) {
	err := ErrSDKAuthorizationFailed{Err: errSentinel}
	assert.Contains(t, err.Error(), "authorization")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrSDKChallengeFailed(t *testing.T) {
	err := ErrSDKChallengeFailed{Err: errSentinel}
	assert.Contains(t, err.Error(), "challenge")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrSDKCertificateFailed(t *testing.T) {
	err := ErrSDKCertificateFailed{Operation: "download", Err: errSentinel}
	assert.Contains(t, err.Error(), "download")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrSDKAccountFailed(t *testing.T) {
	err := ErrSDKAccountFailed{Err: errSentinel}
	assert.Contains(t, err.Error(), "account")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrCertificateParseFailed(t *testing.T) {
	err := ErrCertificateParseFailed{Err: errSentinel}
	assert.Contains(t, err.Error(), "parse")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrSDKOrderPollTimeout(t *testing.T) {
	err := ErrSDKOrderPollTimeout{OrderURL: "https://acme.example/order/1", Status: "pending"}
	assert.Contains(t, err.Error(), "https://acme.example/order/1")
	assert.Contains(t, err.Error(), "pending")
}

func TestErrSDKChallengeNotFound(t *testing.T) {
	err := ErrSDKChallengeNotFound{ChallengeType: "dns-01"}
	assert.Contains(t, err.Error(), "dns-01")
	assert.Contains(t, err.Error(), "not found")
}

func TestErrAccountNotFound(t *testing.T) {
	err := ErrAccountNotFound{Name: "prod-account"}
	assert.Contains(t, err.Error(), "prod-account")
	assert.Contains(t, err.Error(), "not found")
}

func TestErrAccountAlreadyExists(t *testing.T) {
	err := ErrAccountAlreadyExists{Name: "prod-account"}
	assert.Contains(t, err.Error(), "prod-account")
	assert.Contains(t, err.Error(), "already exists")
}

func TestErrCertSpecNotFound(t *testing.T) {
	err := ErrCertSpecNotFound{Name: "web-cert"}
	assert.Contains(t, err.Error(), "web-cert")
	assert.Contains(t, err.Error(), "not found")
}

func TestErrCertSpecAlreadyExists(t *testing.T) {
	err := ErrCertSpecAlreadyExists{Name: "web-cert"}
	assert.Contains(t, err.Error(), "web-cert")
	assert.Contains(t, err.Error(), "already exists")
}

func TestErrInvalidAccountConfig(t *testing.T) {
	err := ErrInvalidAccountConfig{Name: "staging", Reason: "missing server URL"}
	assert.Contains(t, err.Error(), "staging")
	assert.Contains(t, err.Error(), "missing server URL")
}

func TestErrInvalidCertSpec(t *testing.T) {
	err := ErrInvalidCertSpec{Name: "api-cert", Reason: "no domains"}
	assert.Contains(t, err.Error(), "api-cert")
	assert.Contains(t, err.Error(), "no domains")
}

func TestErrKeyGeneration(t *testing.T) {
	err := ErrKeyGeneration{Algorithm: "EC-P521", Err: errSentinel}
	assert.Contains(t, err.Error(), "EC-P521")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrStorageFactory(t *testing.T) {
	err := ErrStorageFactory{Err: errSentinel}
	assert.Contains(t, err.Error(), "storage factory")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrClientCreation(t *testing.T) {
	err := ErrClientCreation{Account: "prod", Err: errSentinel}
	assert.Contains(t, err.Error(), "prod")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrDeployFailed(t *testing.T) {
	err := ErrDeployFailed{CertName: "api-tls", Err: errSentinel}
	assert.Contains(t, err.Error(), "api-tls")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrPostHookFailed(t *testing.T) {
	err := ErrPostHookFailed{Hook: "reload-nginx", Err: errSentinel}
	assert.Contains(t, err.Error(), "reload-nginx")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrInvalidKeyConfig(t *testing.T) {
	err := ErrInvalidKeyConfig{Reason: "key size too small"}
	assert.Contains(t, err.Error(), "key size too small")
}

func TestErrValidation(t *testing.T) {
	err := &ErrValidation{Field: "server_url", Reason: "must be https"}
	assert.Contains(t, err.Error(), "server_url")
	assert.Contains(t, err.Error(), "must be https")
}

func TestErrCSRCreation(t *testing.T) {
	err := ErrCSRCreation{Err: errSentinel}
	assert.Contains(t, err.Error(), "CSR")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrKeyEncoding(t *testing.T) {
	err := ErrKeyEncoding{Err: errSentinel}
	assert.Contains(t, err.Error(), "key encoding")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrInvalidIP(t *testing.T) {
	err := ErrInvalidIP{Value: "999.999.999.999"}
	assert.Contains(t, err.Error(), "999.999.999.999")
	assert.Contains(t, err.Error(), "invalid")
}

func TestErrInvalidURI(t *testing.T) {
	err := ErrInvalidURI{Value: "://bad", Err: errSentinel}
	assert.Contains(t, err.Error(), "://bad")
	assert.Contains(t, err.Error(), "inner error")
	assert.Equal(t, errSentinel, err.Unwrap())
}

func TestErrNothingToDeploy(t *testing.T) {
	err := ErrNothingToDeploy{Name: "api-tls"}
	assert.Contains(t, err.Error(), "api-tls")
	assert.Contains(t, err.Error(), "no deploy")
}

func TestErrMissingKeyConfig(t *testing.T) {
	err := ErrMissingKeyConfig{Context: "staging-cert"}
	assert.Contains(t, err.Error(), "staging-cert")
	assert.Contains(t, err.Error(), "missing key")
}

func TestErrNoIssuedCertificate(t *testing.T) {
	err := ErrNoIssuedCertificate{Name: "web-tls"}
	assert.Contains(t, err.Error(), "web-tls")
	assert.Contains(t, err.Error(), "no issued certificate")
}

// Verify errors.Is works correctly for wrapped error types.
func TestErrWrapping_ErrorsIs(t *testing.T) {
	target := errors.New("target")
	wrapped := ErrSDKClientCreation{Err: target}
	assert.True(t, errors.Is(wrapped, target))
}
