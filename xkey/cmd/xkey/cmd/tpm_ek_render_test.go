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

package cmd

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// rsaEKAttributes returns EK key attributes describing an RSA-2048 EK held
// in the TPM at the standard persistent handle.
func rsaEKAttributes() *xkms.KeyAttributes {
	return &xkms.KeyAttributes{
		CN:            "ek",
		KeyType:       xkms.KeyTypeEndorsement,
		KeyAlgorithm:  x509.RSA,
		StoreType:     xkms.StoreTPM2,
		RSAAttributes: &xkms.RSAAttributes{KeySize: 2048},
		TPMAttributes: &xkms.TPMAttributes{
			Handle:     0x81010001,
			CertHandle: 0x01C00002,
		},
	}
}

func TestOutputEKText_RendersKeyAttributes(t *testing.T) {
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())

	var buf bytes.Buffer
	require.NoError(t, outputEKText(&buf, rsaEKAttributes(), nil))
	out := buf.String()

	assert.Contains(t, out, "Key Information:")
	assert.Contains(t, out, "CN:        ek")
	assert.Contains(t, out, "Handle:    0x81010001")
	assert.Contains(t, out, "Cert NV:   0x01C00002")
	assert.Contains(t, out, "RSA Size:  2048 bits")
	assert.Contains(t, out, "Certificate: Not available")
	assert.NotContains(t, out, "ECC Curve:")
}

func TestOutputEKText_ECCAndNoCertHandle(t *testing.T) {
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())

	attrs := rsaEKAttributes()
	attrs.KeyAlgorithm = x509.ECDSA
	attrs.RSAAttributes = nil
	attrs.ECCAttributes = &xkms.ECCAttributes{Curve: elliptic.P256()}
	attrs.TPMAttributes.CertHandle = 0

	var buf bytes.Buffer
	require.NoError(t, outputEKText(&buf, attrs, nil))
	out := buf.String()

	assert.Contains(t, out, "ECC Curve: P-256")
	assert.NotContains(t, out, "RSA Size:")
	assert.NotContains(t, out, "Cert NV:",
		"a zero cert handle means no NV certificate slot and must be omitted")
}

func TestOutputEKText_WithCertificateRunsVerification(t *testing.T) {
	resetViperForTest(t)
	// An unusable trust-store path forces the "skipped" verification branch,
	// which must degrade gracefully rather than abort the command.
	viper.Set("trust.store_path", "/nonexistent/path/\x00invalid")

	cert := generateTrustTestCert(t)

	var buf bytes.Buffer
	require.NoError(t, outputEKText(&buf, rsaEKAttributes(), cert))
	out := buf.String()

	assert.Contains(t, out, "Key Information:")
	assert.Contains(t, out, "EK Certificate Verification:")
	assert.Contains(t, out, "Skipped (trust store not available)")
	assert.NotContains(t, out, "Certificate: Not available")
}

func TestOutputEKJSON_WithoutCertificate(t *testing.T) {
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())

	var buf bytes.Buffer
	require.NoError(t, outputEKJSON(&buf, rsaEKAttributes(), nil))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	assert.Equal(t, "ek", decoded["cn"])
	assert.Equal(t, "0x81010001", decoded["handle"])
	assert.Equal(t, "0x01C00002", decoded["cert_handle"])
	assert.EqualValues(t, 2048, decoded["rsa_key_size"])
	assert.NotContains(t, decoded, "certificate")
	assert.NotContains(t, decoded, "ecc_curve")
}

func TestOutputEKJSON_WithCertificateIncludesVerification(t *testing.T) {
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())

	cert := generateTrustTestCert(t)

	var buf bytes.Buffer
	require.NoError(t, outputEKJSON(&buf, rsaEKAttributes(), cert))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	certInfo, ok := decoded["certificate"].(map[string]any)
	require.True(t, ok, "certificate block missing from %s", buf.String())
	assert.Equal(t, cert.Subject.String(), certInfo["subject"])
	assert.Equal(t, cert.SerialNumber.String(), certInfo["serial_number"])

	verification, ok := certInfo["verification"].(map[string]any)
	require.True(t, ok, "verification block missing")
	assert.Equal(t, false, verification["verified"],
		"a self-signed test cert must not verify against the empty trust store")
}

func TestOutputEKJSON_ECCCurveReported(t *testing.T) {
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())

	attrs := rsaEKAttributes()
	attrs.RSAAttributes = nil
	attrs.ECCAttributes = &xkms.ECCAttributes{Curve: elliptic.P384()}
	attrs.TPMAttributes.CertHandle = 0

	var buf bytes.Buffer
	require.NoError(t, outputEKJSON(&buf, attrs, nil))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, "P-384", decoded["ecc_curve"])
	assert.NotContains(t, decoded, "cert_handle")
	assert.NotContains(t, decoded, "rsa_key_size")
}

// --- device config Duration ---

func TestDuration_YAMLRoundTrip(t *testing.T) {
	type holder struct {
		Grace Duration `yaml:"grace"`
	}

	var decoded holder
	require.NoError(t, yaml.Unmarshal([]byte("grace: 90s\n"), &decoded))
	assert.Equal(t, 90*time.Second, time.Duration(decoded.Grace))

	encoded, err := yaml.Marshal(holder{Grace: Duration(5 * time.Minute)})
	require.NoError(t, err)
	assert.Equal(t, "grace: 5m0s\n", string(encoded))

	// Round-tripping must be lossless so a rewritten config keeps its values.
	var again holder
	require.NoError(t, yaml.Unmarshal(encoded, &again))
	assert.Equal(t, 5*time.Minute, time.Duration(again.Grace))
}

func TestDuration_RejectsInvalidYAML(t *testing.T) {
	type holder struct {
		Grace Duration `yaml:"grace"`
	}

	var decoded holder
	assert.Error(t, yaml.Unmarshal([]byte("grace: not-a-duration\n"), &decoded),
		"an unparseable duration must be reported, not silently zeroed")

	assert.Error(t, yaml.Unmarshal([]byte("grace: [1,2]\n"), &decoded),
		"a non-scalar node must be rejected")
}

func TestGetTrustNewDevices(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("trust-new-devices", false, "")

	assert.False(t, GetTrustNewDevices(cmd))

	require.NoError(t, setFlagForTest(t, cmd.Flags(), "trust-new-devices", "true"))
	assert.True(t, GetTrustNewDevices(cmd))

	// A command without the flag must report the safe default rather than
	// panicking.
	assert.False(t, GetTrustNewDevices(&cobra.Command{}))
}

func TestDecodePublicKey(t *testing.T) {
	got, err := decodePublicKey("aGVsbG8=")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)

	_, err = decodePublicKey("!!!not-base64!!!")
	assert.Error(t, err)
}
