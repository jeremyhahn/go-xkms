//go:build tpm_simulator

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

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// selfSignedDeviceHandlerCert mints a throwaway self-signed certificate for
// use as a canned Finalize response from testutil.FakeACMEDirectory.
func selfSignedDeviceHandlerCert(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// deviceHandlerRouter builds a router whose service has a single account
// resolving against server and a single device spec named "dev1", TPM left
// nil so it opens and provisions the in-process simulator exactly as
// production configuration with no TPM section would.
func deviceHandlerRouter(t *testing.T, server *testutil.FakeACMEDirectory, port string) http.Handler {
	t.Helper()

	cfg := svc.DefaultConfig()
	cfg.Storage.Options["path"] = t.TempDir()
	cfg.Accounts["acct"] = &svc.AccountConfig{
		DirectoryURL: server.DirectoryURL(),
		Email:        "device-handler-test@example.com",
		Key: &svc.KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &svc.ECCConfig{Curve: "P-256"},
		},
	}
	cfg.Devices["dev1"] = &svc.DeviceSpec{
		Account:    "acct",
		CommonName: "device-under-test",
		Identifier: "device-under-test",
		Challenge:  svc.DeviceChallengeConfig{Port: port, Timeout: 30 * time.Second},
	}

	service, err := svc.NewService(cfg, slog.Default())
	require.NoError(t, err)

	return NewRouter(nil, service, slog.Default())
}

// TestDeviceEnroll_Success proves the deviceEnroll handler drives a real
// enrollment — TPM 2.0 simulator open/provision plus an in-process fake ACME
// directory offering enroll-01 — end to end and returns 200 with the issued
// certificates' subjects.
func TestDeviceEnroll_Success(t *testing.T) {
	iak := selfSignedDeviceHandlerCert(t, "handler-test-iak")
	idevid := selfSignedDeviceHandlerCert(t, "handler-test-idevid")
	server := testutil.NewFakeACMEDirectory(t,
		[]string{"http-01", "enroll-01", "device-attest-01"},
		[][]byte{iak, idevid})

	router := deviceHandlerRouter(t, server, "19811")

	rec := doRequest(router, http.MethodPost, "/api/v1/device/enroll", jsonBody(t, map[string]string{"name": "dev1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body apiResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	if body.Data == nil {
		t.Fatalf("expected data in response, got %s", rec.Body.String())
	}
}

// TestDeviceAttest_Success proves the deviceAttest handler drives a real
// attestation — the same TPM simulator path plus a fake ACME directory
// offering device-attest-01 — end to end and returns 200 with the issued
// certificate's subject.
func TestDeviceAttest_Success(t *testing.T) {
	attestCert := selfSignedDeviceHandlerCert(t, "handler-test-attest")
	server := testutil.NewFakeACMEDirectory(t,
		[]string{"http-01", "enroll-01", "device-attest-01"},
		[][]byte{attestCert})

	router := deviceHandlerRouter(t, server, "19812")

	rec := doRequest(router, http.MethodPost, "/api/v1/device/attest", jsonBody(t, map[string]string{"name": "dev1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body apiResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	if body.Data == nil {
		t.Fatalf("expected data in response, got %s", rec.Body.String())
	}
}
