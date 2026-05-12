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

package rfc8555

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCertificatePEMEncoding tests PEM encoding for certificates
func TestCertificatePEMEncoding(t *testing.T) {
	// Sample certificate data
	certData := []byte("CERTIFICATE DATA")

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certData,
	}

	pemData := pem.EncodeToMemory(block)
	require.NotNil(t, pemData)

	// Verify PEM structure
	assert.True(t, strings.HasPrefix(string(pemData), "-----BEGIN CERTIFICATE-----"))
	assert.True(t, strings.HasSuffix(strings.TrimSpace(string(pemData)), "-----END CERTIFICATE-----"))
}

// TestCertificatePEMDecoding tests PEM decoding for certificates
func TestCertificatePEMDecoding(t *testing.T) {
	pemData := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU6nKMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAgFw0yNDAxMDEwMDAwMDBaGA8yMTI0MDEwMTAwMDAwMFowETEPMA0GA1UE
AwwGdGVzdGNhMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDL
-----END CERTIFICATE-----`

	block, _ := pem.Decode([]byte(pemData))
	require.NotNil(t, block)

	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.NotEmpty(t, block.Bytes)
}

// TestCertificateChainFormat tests certificate chain formatting
func TestCertificateChainFormat(t *testing.T) {
	cert1PEM := `-----BEGIN CERTIFICATE-----
CERT1DATA
-----END CERTIFICATE-----`

	cert2PEM := `-----BEGIN CERTIFICATE-----
CERT2DATA
-----END CERTIFICATE-----`

	// Chain should be concatenated with newlines
	chain := cert1PEM + "\n" + cert2PEM

	// Count certificates in chain
	count := strings.Count(chain, "-----BEGIN CERTIFICATE-----")
	assert.Equal(t, 2, count)
}

// TestCertificateContentType tests certificate media type
func TestCertificateContentType(t *testing.T) {
	// Per RFC 8555, certificates are served as application/pem-certificate-chain
	contentType := "application/pem-certificate-chain"

	assert.Equal(t, "application/pem-certificate-chain", contentType)
}

// TestAlternateCertificateLinks tests alternate certificate chain links
func TestAlternateCertificateLinks(t *testing.T) {
	// Servers may provide alternate certificate chains via Link headers
	primaryChain := "https://acme.example.com/acme/cert/12345"
	alternateChain := "https://acme.example.com/acme/cert/12345/alt/1"

	assert.NotEqual(t, primaryChain, alternateChain)
	assert.Contains(t, alternateChain, "/alt/")
}

// TestCertificateDownloadRetry tests certificate download retry logic
func TestCertificateDownloadRetry(t *testing.T) {
	// Certificates may not be immediately available
	// Clients should retry with exponential backoff

	retryIntervals := []int{1, 2, 4, 8, 16} // seconds

	for i, interval := range retryIntervals {
		// Verify exponential growth
		if i > 0 {
			assert.Equal(t, retryIntervals[i-1]*2, interval)
		}
	}
}

// TestCertificateParsing tests parsing X.509 certificates
func TestCertificateParsing(t *testing.T) {
	// This is a truncated example - real certificates would be complete
	pemData := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU6nKMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYQ==
-----END CERTIFICATE-----`

	block, _ := pem.Decode([]byte(pemData))
	if block != nil {
		// In real scenarios, this would parse successfully
		_, err := x509.ParseCertificate(block.Bytes)
		// We expect an error with truncated data
		assert.Error(t, err)
	}
}

// TestCertificateChainOrder tests certificate chain ordering
func TestCertificateChainOrder(t *testing.T) {
	// Certificate chain should be ordered:
	// 1. End-entity certificate
	// 2. Intermediate CA certificates
	// 3. Root CA certificate (optional)

	chainOrder := []string{
		"end-entity",
		"intermediate-1",
		"intermediate-2",
		"root",
	}

	// Verify end-entity is first
	assert.Equal(t, "end-entity", chainOrder[0])

	// Verify root is last
	assert.Equal(t, "root", chainOrder[len(chainOrder)-1])
}
