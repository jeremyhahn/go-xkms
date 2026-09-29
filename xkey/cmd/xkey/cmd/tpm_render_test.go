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
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// withTPMOutputFormat pins the shared tpmCfg.outputFormat for a test.
func withTPMOutputFormat(t *testing.T, format string) {
	t.Helper()
	previous := tpmCfg.outputFormat
	tpmCfg.outputFormat = format
	t.Cleanup(func() { tpmCfg.outputFormat = previous })
}

// --- PCR index parsing ---

func TestParsePCRIndices_Valid(t *testing.T) {
	tests := []struct {
		in   string
		want []uint
	}{
		{"0", []uint{0}},
		{"0,1,7", []uint{0, 1, 7}},
		{" 0 , 1 , 7 ", []uint{0, 1, 7}},
		{"23", []uint{23}},
		{"0,,7", []uint{0, 7}},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parsePCRIndices(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParsePCRIndices_Invalid(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"only separators", ",,,"},
		{"non numeric", "abc"},
		{"negative", "-1"},
		{"above range", "24"},
		{"one bad among good", "0,1,99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePCRIndices(tt.in)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidPCRIndices)
		})
	}
}

func TestParsePCRIndicesForPCRs_SupportsRanges(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []uint
	}{
		{"single", "7", []uint{7}},
		{"list", "0,1,7", []uint{0, 1, 7}},
		{"range", "0-3", []uint{0, 1, 2, 3}},
		{"range with spaces", " 0 - 3 ", []uint{0, 1, 2, 3}},
		{"mixed", "0-2,7,23", []uint{0, 1, 2, 7, 23}},
		{"degenerate range", "5-5", []uint{5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePCRIndicesForPCRs(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParsePCRIndicesForPCRs_Invalid(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"three-part range", "0-1-2"},
		{"bad range start", "a-3"},
		{"bad range end", "0-b"},
		{"reversed range", "7-3"},
		{"range beyond 23", "20-30"},
		{"index beyond 23", "24"},
		{"non numeric", "pcr7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePCRIndicesForPCRs(tt.in)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidPCRIndices)
		})
	}
}

func TestParseGoldenPCRs(t *testing.T) {
	got, err := parseGoldenPCRs("")
	require.NoError(t, err)
	assert.Nil(t, got, "an unset --golden-pcrs must leave the config default in place")

	got, err = parseGoldenPCRs("0, 1 ,7,,23")
	require.NoError(t, err)
	assert.Equal(t, []uint{0, 1, 7, 23}, got)
}

func TestParseGoldenPCRs_Invalid(t *testing.T) {
	for _, in := range []string{"abc", "24", "0,99", "-1"} {
		_, err := parseGoldenPCRs(in)
		require.Error(t, err, "parseGoldenPCRs(%q)", in)
		assert.ErrorIs(t, err, ErrInvalidPCRIndices)
	}
}

func TestValidatePCRBank(t *testing.T) {
	for _, bank := range []string{"", "sha1", "sha256", "SHA256", "sha384", "sha512"} {
		assert.NoError(t, validatePCRBank(bank), "bank %q must be accepted", bank)
	}

	for _, bank := range []string{"sha3", "md5", "sha-256"} {
		err := validatePCRBank(bank)
		require.Error(t, err, "bank %q must be rejected", bank)
		assert.ErrorIs(t, err, ErrInvalidPCRBank)
		assert.Contains(t, err.Error(), "valid: sha1, sha256, sha384, sha512")
	}
}

// --- status formatting helpers ---

func TestFormatBoolStatus(t *testing.T) {
	assert.Equal(t, "Yes", formatBoolStatus(true))
	assert.Equal(t, "No", formatBoolStatus(false))
}

func TestFormatKeyAlgorithmFromAttrs(t *testing.T) {
	assert.Equal(t, "Unknown", formatKeyAlgorithmFromAttrs(nil))

	rsa := &xkms.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &xkms.RSAAttributes{KeySize: 2048},
	}
	assert.Equal(t, "RSA-2048", formatKeyAlgorithmFromAttrs(rsa))

	ecc := &xkms.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &xkms.ECCAttributes{Curve: elliptic.P256()},
	}
	assert.Equal(t, "ECDSA-P-256", formatKeyAlgorithmFromAttrs(ecc))

	// A zero-size RSA block must not produce a bogus "-0" suffix.
	bare := &xkms.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &xkms.RSAAttributes{KeySize: 0},
	}
	assert.Equal(t, "RSA", formatKeyAlgorithmFromAttrs(bare))
}

func TestSimplifyError(t *testing.T) {
	assert.Empty(t, simplifyError(nil))

	// TPM handle errors are the normal "key was never provisioned" case and
	// must not be surfaced as scary raw rc codes.
	assert.Equal(t, "not found", simplifyError(errors.New("TPM_RC_HANDLE (0x18b)")))
	assert.Equal(t, "not found", simplifyError(errors.New("bad handle")))
	assert.Equal(t, "not found", simplifyError(errors.New("rc 0x184")))
	assert.Equal(t, "not initialized", simplifyError(errors.New("tpm: not initialized")))

	short := errors.New("plain failure")
	assert.Equal(t, "plain failure", simplifyError(short))

	long := errors.New(strings.Repeat("x", 80))
	got := simplifyError(long)
	assert.Len(t, got, 50)
	assert.True(t, strings.HasSuffix(got, "..."))
}

// --- outputStatusText / outputStatusJSON ---

func TestOutputStatusText_RendersEverySection(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, outputStatusText(&buf, sampleTPMStatus()))
	out := buf.String()

	assert.Contains(t, out, "TPM Provisioning Status")
	assert.Contains(t, out, "Device:          /dev/tpmrm0")
	assert.Contains(t, out, "Vendor ID:       SLB9670")
	assert.Contains(t, out, "Provisioned:     Yes")

	// Present keys carry their algorithm, and the signature algorithm when set.
	assert.Contains(t, out, "EK     (0x81010001): + Present (RSA-2048)")
	assert.Contains(t, out, "IAK    (0x81010002): + Present (RSA-2048, SHA256-RSA-PSS)")

	// "not found" is the ordinary unprovisioned case and must render as a
	// plain absence, whereas a real error must be surfaced.
	assert.Contains(t, out, "IDevID (0x81020000): x Not Present")
	assert.Contains(t, out, "SSRK   (0x81000001): x Error: transport reset")

	assert.Contains(t, out, "EK Cert      (NV 0x01C00002): + Present (CN=EK)")
	assert.Contains(t, out, "IDevID Cert  (NV 0x01C90000): x Not Present")
	assert.Contains(t, out, "Extra Cert   (NV 0x01C90001): x Error: nv read denied")

	assert.Contains(t, out, "PCR Bank:        sha256")
	assert.Contains(t, out, "Golden PCRs:     [0 1 7]")
	assert.Contains(t, out, "Platform PCR:    16")

	// A configured 64-char digest is truncated to 32 chars plus an ellipsis.
	assert.Contains(t, out, "Policy Digest:   "+strings.Repeat("ab", 16)+"...")

	assert.Contains(t, out, "Current PCR Values (sha256):")
	assert.Contains(t, out, "PCR[ 0]: "+strings.Repeat("cd", 32))
	assert.Contains(t, out, "PCR[ 7]: short")
}

func TestOutputStatusText_TruncatesLongSubjectAndValues(t *testing.T) {
	status := sampleTPMStatus()
	status.Certificates = []CertStatus{{
		Name:    "EK Cert",
		NVIndex: "0x01C00002",
		Present: true,
		Subject: strings.Repeat("S", 60),
	}}
	status.GoldenPCRValues = []PCRValueStatus{{Index: 1, Value: strings.Repeat("f", 100)}}

	var buf bytes.Buffer
	require.NoError(t, outputStatusText(&buf, status))
	out := buf.String()

	assert.Contains(t, out, strings.Repeat("S", 37)+"...")
	assert.NotContains(t, out, strings.Repeat("S", 41))
	assert.Contains(t, out, strings.Repeat("f", 64)+"...")
}

func TestOutputStatusText_UnconfiguredPolicyAndEmptyVendor(t *testing.T) {
	status := sampleTPMStatus()
	status.VendorID = ""
	status.Provisioned = false
	status.PlatformPolicy.Configured = false
	status.PlatformPolicy.PolicyDigest = "not configured"
	status.GoldenPCRValues = nil

	var buf bytes.Buffer
	require.NoError(t, outputStatusText(&buf, status))
	out := buf.String()

	assert.NotContains(t, out, "Vendor ID:")
	assert.Contains(t, out, "Provisioned:     No")
	assert.Contains(t, out, "Policy Digest:   not configured")
	assert.NotContains(t, out, "Current PCR Values")
}

func TestOutputStatusJSON_RoundTrips(t *testing.T) {
	var buf bytes.Buffer
	status := sampleTPMStatus()
	require.NoError(t, outputStatusJSON(&buf, status))

	var decoded TPMStatusOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, *status, decoded)
	assert.Contains(t, buf.String(), "\n  \"device\"", "JSON output must be indented for humans")
}

// --- tpm info rendering ---

func sampleTPMInfo() *TPMInfo {
	return &TPMInfo{
		Manufacturer:  "IFX",
		VendorID:      "SLB9670",
		Family:        "2.0",
		Revision:      "1.38",
		FirmwareMajor: 7,
		FirmwareMinor: 85,
		Model:         "SLB9670",
		FIPS1402:      true,
		Type:          "hardware",
		Device:        "/dev/tpmrm0",
		Provisioned:   true,
		MaxAuthFail:   32,
		NVBufferMax:   2048,
		EKPresent:     true,
		SRKPresent:    true,
		IAKPresent:    false,
		IDevIDPresent: false,
	}
}

func TestOutputText_TPMInfoRendersAllSections(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, outputText(&buf, sampleTPMInfo()))
	out := buf.String()

	assert.Contains(t, out, "TPM Information")
	assert.Contains(t, out, "Manufacturer:     IFX")
	assert.Contains(t, out, "Firmware:         7.85")
	assert.Contains(t, out, "FIPS 140-2:       true")
	assert.Contains(t, out, "Provisioning State:")
	assert.Contains(t, out, "EK Present:       true")
	assert.Contains(t, out, "IAK Present:      false")
	assert.Contains(t, out, "Capabilities:")
	assert.Contains(t, out, "Max Auth Failures:     32")
	assert.Contains(t, out, "NV Buffer Max:         2048")
}

func TestOutputJSON_TPMInfoRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	info := sampleTPMInfo()
	require.NoError(t, outputJSON(&buf, info))

	var decoded TPMInfo
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, *info, decoded)
}

// --- IAK / IDevID rendering ---

func TestOutputIAKText_WithAndWithoutCertificate(t *testing.T) {
	rsa := &IAKInfo{
		Handle:             "0x81010002",
		Algorithm:          "RSA",
		KeySize:            2048,
		SignatureAlgorithm: "SHA256-RSA-PSS",
		HasCert:            true,
		CertSubject:        "CN=iak",
		CertIssuer:         "CN=ca",
		CertSerial:         "01",
		CertNotAfter:       "2030-01-01",
	}

	var buf bytes.Buffer
	require.NoError(t, outputIAKText(&buf, rsa))
	out := buf.String()
	assert.Contains(t, out, "Initial Attestation Key (IAK) Information")
	assert.Contains(t, out, "Handle:              0x81010002")
	assert.Contains(t, out, "Key Size:            2048 bits")
	assert.NotContains(t, out, "Curve:")
	assert.Contains(t, out, "Certificate Details:")
	assert.Contains(t, out, "Subject:    CN=iak")

	ecc := &IAKInfo{
		Handle:             "0x81010002",
		Algorithm:          "ECDSA",
		Curve:              "P-256",
		SignatureAlgorithm: "SHA256-ECDSA",
	}

	buf.Reset()
	require.NoError(t, outputIAKText(&buf, ecc))
	out = buf.String()
	assert.Contains(t, out, "Curve:               P-256")
	assert.NotContains(t, out, "Key Size:")
	assert.Contains(t, out, "Certificate: Not available")
}

func TestOutputIDevIDText_WithAndWithoutCertificate(t *testing.T) {
	rsa := &IDevIDInfo{
		Handle:             "0x81020000",
		Algorithm:          "RSA",
		KeySize:            2048,
		SignatureAlgorithm: "SHA256-RSA-PSS",
		HasCert:            true,
		CertSubject:        "CN=idevid",
		CertIssuer:         "CN=ca",
		CertSerial:         "02",
		CertNotAfter:       "2031-01-01",
	}

	var buf bytes.Buffer
	require.NoError(t, outputIDevIDText(&buf, rsa))
	out := buf.String()
	assert.Contains(t, out, "Initial Device Identity (IDevID) Information")
	assert.Contains(t, out, "Key Size:            2048 bits")
	assert.Contains(t, out, "Not After:  2031-01-01")

	ecc := &IDevIDInfo{Handle: "0x81020000", Algorithm: "ECDSA", Curve: "P-384"}
	buf.Reset()
	require.NoError(t, outputIDevIDText(&buf, ecc))
	out = buf.String()
	assert.Contains(t, out, "Curve:               P-384")
	assert.Contains(t, out, "Certificate: Not available")
}

// --- quote rendering / export ---

func sampleQuote() *QuoteResult {
	return &QuoteResult{
		Quoted:       "cXVvdGVk",
		QuotedHex:    "71756f746564",
		Signature:    "c2ln",
		SignatureHex: "736967",
		Nonce:        "bm9uY2U=",
		NonceHex:     "6e6f6e6365",
		PCRs:         "cGNycw==",
		PCRsHex:      "70637273",
	}
}

func TestOutputQuoteText_WithAndWithoutEventLog(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, outputQuoteText(&buf, sampleQuote(), []uint{0, 1, 7}))
	out := buf.String()

	assert.Contains(t, out, "TPM Quote")
	assert.Contains(t, out, "PCRs:       [0 1 7]")
	assert.Contains(t, out, "Nonce:      6e6f6e6365")
	assert.Contains(t, out, "Quoted (TPMS_ATTEST):")
	assert.Contains(t, out, "Hex:    71756f746564")
	assert.Contains(t, out, "Base64: cXVvdGVk")
	assert.Contains(t, out, "Event Log: Not available")

	withLog := sampleQuote()
	withLog.HasEventLog = true
	withLog.EventLogSize = 4096

	buf.Reset()
	require.NoError(t, outputQuoteText(&buf, withLog, []uint{7}))
	assert.Contains(t, buf.String(), "Event Log: Available (4096 bytes)")
}

func TestWriteQuoteToFile_WritesPrivateJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quote.json")

	previousPath, previousLog := quoteOutputFile, quoteIncludeLog
	quoteOutputFile, quoteIncludeLog = path, false
	t.Cleanup(func() { quoteOutputFile, quoteIncludeLog = previousPath, previousLog })

	var buf bytes.Buffer
	require.NoError(t, writeQuoteToFile(&buf, sampleQuote(), []byte("eventlog")))
	assert.Contains(t, buf.String(), "Quote written to: "+path)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"an attestation quote must not be world-readable")

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "cXVvdGVk", decoded["quoted"])
	assert.NotContains(t, decoded, "event_log", "the event log is omitted unless --include-log is set")
}

func TestWriteQuoteToFile_EmbedsEventLogWhenRequested(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quote.json")

	previousPath, previousLog := quoteOutputFile, quoteIncludeLog
	quoteOutputFile, quoteIncludeLog = path, true
	t.Cleanup(func() { quoteOutputFile, quoteIncludeLog = previousPath, previousLog })

	var buf bytes.Buffer
	require.NoError(t, writeQuoteToFile(&buf, sampleQuote(), []byte("eventlog")))

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("eventlog")), decoded["event_log"])
}

func TestWriteQuoteToFile_ReportsWriteFailure(t *testing.T) {
	previousPath, previousLog := quoteOutputFile, quoteIncludeLog
	quoteOutputFile = filepath.Join(t.TempDir(), "no-such-dir", "quote.json")
	quoteIncludeLog = false
	t.Cleanup(func() { quoteOutputFile, quoteIncludeLog = previousPath, previousLog })

	var buf bytes.Buffer
	err := writeQuoteToFile(&buf, sampleQuote(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrExportFailed)
}

// --- PCR listing ---

func TestOutputPCRsText_AnnotatesWellKnownPCRs(t *testing.T) {
	output := &PCRsOutput{Banks: []PCRBankOutput{{
		Algorithm: "sha256",
		PCRs: []PCRValue{
			{Index: 0, ValueHex: "aa"},
			{Index: 7, ValueHex: "bb"},
			{Index: 10, ValueHex: "cc"},
			{Index: 16, ValueHex: "dd"},
			{Index: 23, ValueHex: "ee"},
			{Index: 11, ValueHex: "ff"},
		},
	}}}

	var buf bytes.Buffer
	require.NoError(t, outputPCRsText(&buf, output))
	out := buf.String()

	assert.Contains(t, out, "Bank: sha256")
	assert.Contains(t, out, "PCR[ 0]: aa (BIOS/UEFI firmware)")
	assert.Contains(t, out, "PCR[ 7]: bb (Secure Boot policy)")
	assert.Contains(t, out, "PCR[10]: cc (Linux IMA)")
	assert.Contains(t, out, "PCR[16]: dd (Debug)")
	assert.Contains(t, out, "PCR[23]: ee (Application)")
	// PCR 11 has no well-known meaning and must render without annotation.
	assert.Contains(t, out, "PCR[11]: ff\n")
}

func TestOutputPCRsText_TruncatesLongValues(t *testing.T) {
	output := &PCRsOutput{Banks: []PCRBankOutput{{
		Algorithm: "sha512",
		PCRs:      []PCRValue{{Index: 4, ValueHex: strings.Repeat("9", 128)}},
	}}}

	var buf bytes.Buffer
	require.NoError(t, outputPCRsText(&buf, output))
	assert.Contains(t, buf.String(), strings.Repeat("9", 64)+"... (MBR/IPL code)")
}

func TestOutputPCRsText_MultipleBanks(t *testing.T) {
	output := &PCRsOutput{Banks: []PCRBankOutput{
		{Algorithm: "sha1", PCRs: []PCRValue{{Index: 0, ValueHex: "11"}}},
		{Algorithm: "sha256", PCRs: []PCRValue{{Index: 0, ValueHex: "22"}}},
	}}

	var buf bytes.Buffer
	require.NoError(t, outputPCRsText(&buf, output))
	out := buf.String()
	assert.Contains(t, out, "Bank: sha1")
	assert.Contains(t, out, "Bank: sha256")
}

// --- provision result ---

func TestOutputProvisionResult_Text(t *testing.T) {
	withTPMOutputFormat(t, "text")

	var buf bytes.Buffer
	require.NoError(t, outputProvisionResult(&buf, &ProvisionResult{
		Success:       true,
		Message:       "provisioned",
		EKCreated:     true,
		SRKCreated:    true,
		IAKCreated:    true,
		IDevIDCreated: false,
	}))
	out := buf.String()

	assert.Contains(t, out, "Provisioning Result")
	assert.Contains(t, out, "Success:        true")
	assert.Contains(t, out, "EK Created:     true")
	assert.Contains(t, out, "IDevID Created: false")
}

func TestOutputProvisionResult_PreservedEK(t *testing.T) {
	withTPMOutputFormat(t, "text")

	var buf bytes.Buffer
	require.NoError(t, outputProvisionResult(&buf, &ProvisionResult{
		Success:     true,
		Message:     "provisioned",
		EKPreserved: true,
	}))

	out := buf.String()
	assert.Contains(t, out, "EK:             preserved (manufacturer)",
		"a manufacturer EK must be reported as preserved, never as created")
	assert.NotContains(t, out, "EK Created:")
}

func TestOutputProvisionResult_JSON(t *testing.T) {
	withTPMOutputFormat(t, "json")

	var buf bytes.Buffer
	result := &ProvisionResult{Success: true, Message: "ok", SRKCreated: true}
	require.NoError(t, outputProvisionResult(&buf, result))

	var decoded ProvisionResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, *result, decoded)
}

// --- tpm clear confirmation ---

func TestConfirmClear_AcceptsOnlyYes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"lowercase yes", "yes\n", true},
		{"uppercase yes", "YES\n", true},
		{"padded yes", "  yes  \n", true},
		{"y is not enough", "y\n", false},
		{"no", "no\n", false},
		{"empty", "\n", false},
		{"eof", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeStdin(t, tt.input)

			var buf bytes.Buffer
			assert.Equal(t, tt.want, confirmClear(&buf, false))
			assert.Contains(t, buf.String(), "WARNING: TPM CLEAR OPERATION")
			assert.Contains(t, buf.String(), "This action CANNOT be undone!")
			assert.NotContains(t, buf.String(), "Mode: FORCE")
		})
	}
}

func TestConfirmClear_ForceWarnsAboutReboot(t *testing.T) {
	pipeStdin(t, "yes\n")

	var buf bytes.Buffer
	assert.True(t, confirmClear(&buf, true))
	assert.Contains(t, buf.String(), "Mode: FORCE (UEFI Physical Presence Interface)")
	assert.Contains(t, buf.String(), "System will REBOOT")
}

// --- log level ---

func TestGetLogLevel_FollowsVerboseFlag(t *testing.T) {
	previous := tpmCfg.verbose
	t.Cleanup(func() { tpmCfg.verbose = previous })

	tpmCfg.verbose = false
	assert.Equal(t, "INFO", getLogLevel().String())

	tpmCfg.verbose = true
	assert.Equal(t, "DEBUG", getLogLevel().String())
}

func sampleTPMStatus() *TPMStatusOutput {
	return &TPMStatusOutput{
		Device:       "/dev/tpmrm0",
		Manufacturer: "IFX",
		VendorID:     "SLB9670",
		Firmware:     "7.85",
		Type:         "hardware",
		Provisioned:  true,
		Keys: []KeyStatus{
			{Name: "EK", Handle: "0x81010001", Present: true, Algorithm: "RSA-2048"},
			{Name: "IAK", Handle: "0x81010002", Present: true, Algorithm: "RSA-2048", SignatureAlgorithm: "SHA256-RSA-PSS"},
			{Name: "IDevID", Handle: "0x81020000", Present: false, Error: "not found"},
			{Name: "SSRK", Handle: "0x81000001", Present: false, Error: "transport reset"},
		},
		Certificates: []CertStatus{
			{Name: "EK Cert", NVIndex: "0x01C00002", Present: true, Subject: "CN=EK"},
			{Name: "IDevID Cert", NVIndex: "0x01C90000", Present: false, Error: "not found"},
			{Name: "Extra Cert", NVIndex: "0x01C90001", Present: false, Error: "nv read denied"},
		},
		PlatformPolicy: PlatformPolicyStatus{
			PCRBank:      "sha256",
			GoldenPCRs:   []uint{0, 1, 7},
			PlatformPCR:  16,
			PolicyDigest: strings.Repeat("ab", 32),
			Configured:   true,
		},
		GoldenPCRValues: []PCRValueStatus{
			{Index: 0, Value: strings.Repeat("cd", 32)},
			{Index: 7, Value: "short"},
		},
	}
}
