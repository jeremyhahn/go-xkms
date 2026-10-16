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

//go:build tpm_simulator

package cmd

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/go-tpm/tpm2"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

var (
	// errInjected is the failure faultTPM reports from an operation a
	// test chose to fail.
	errInjected = errors.New("injected TPM failure")

	errNotAQuote         = errors.New("attestation is not a TPM-generated quote")
	errQuoteNonce        = errors.New("quote does not carry the nonce")
	errQuotePCRDigest    = errors.New("quote PCR digest does not match the PCR values")
	errQuoteKeyNotRSAPSS = errors.New("quote verification needs the RSA IAK")
)

// verifyQuote checks a quote as a remote verifier does: attest is a
// TPM-generated TPMS_ATTEST of type quote, it carries nonce as extraData,
// its PCR digest is SHA-256 over pcrValues in selection order, and
// signature is the IAK's RSASSA-PSS signature over it.
func verifyQuote(attest, signature []byte, iak crypto.PublicKey, nonce []byte, pcrValues ...[]byte) error {
	info, err := tpm2.Unmarshal[tpm2.TPMSAttest](attest)
	if err != nil {
		return err
	}
	if info.Magic != tpm2.TPMGeneratedValue || info.Type != tpm2.TPMSTAttestQuote {
		return errNotAQuote
	}
	if !bytes.Equal(info.ExtraData.Buffer, nonce) {
		return errQuoteNonce
	}
	quoteInfo, err := info.Attested.Quote()
	if err != nil {
		return err
	}
	pcrDigest := sha256.New()
	for _, value := range pcrValues {
		pcrDigest.Write(value)
	}
	if !bytes.Equal(quoteInfo.PCRDigest.Buffer, pcrDigest.Sum(nil)) {
		return errQuotePCRDigest
	}
	key, ok := iak.(*rsa.PublicKey)
	if !ok {
		return errQuoteKeyNotRSAPSS
	}
	digest := sha256.Sum256(attest)
	return rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
}

// faultTPM is the provisioned simulator with chosen operations failing or
// reporting what a healthy in-process simulator cannot: a read error, a
// missing IAK, a failing Close, or a platform measurement log.
type faultTPM struct {
	sharedTPM
	readPCRsErr error
	iakErr      error
	closeErr    error
	eventLog    []byte
	closed      bool
}

func (f *faultTPM) ReadPCRs(pcrs []uint) ([]xkms.PCRBank, error) {
	if f.readPCRsErr != nil {
		return nil, f.readPCRsErr
	}
	return f.sharedTPM.ReadPCRs(pcrs)
}

func (f *faultTPM) IAKAttributes() (*xkms.KeyAttributes, error) {
	if f.iakErr != nil {
		return nil, f.iakErr
	}
	return f.sharedTPM.IAKAttributes()
}

func (f *faultTPM) Quote(pcrs []uint, nonce []byte) (xkms.Quote, error) {
	quote, err := f.sharedTPM.Quote(pcrs, nonce)
	if err == nil && f.eventLog != nil {
		quote.EventLog = f.eventLog
	}
	return quote, err
}

func (f *faultTPM) Close() error {
	f.closed = true
	return f.closeErr
}

// withFaultTPM routes every `tpm` subcommand's opener through a faultTPM
// wrapping the provisioned simulator until the test ends.
func withFaultTPM(t *testing.T, sim *provisionedSimulator) *faultTPM {
	t.Helper()
	f := &faultTPM{sharedTPM: sharedTPM{sim.tpm}}
	setVar(t, &openTPM, func() (xkms.TrustedPlatformModule, error) { return f, nil })
	setVar(t, &openTPMForProvisioningWithPCROverrides, func(string, []uint, []uint) (xkms.TrustedPlatformModule, error) {
		return f, nil
	})
	return f
}

// decodeQuoteJSON decodes the QuoteResult runTPMQuote printed after its
// "Generating quote" progress line.
func decodeQuoteJSON(t *testing.T, stdout string) QuoteResult {
	t.Helper()
	jsonStart := bytes.IndexByte([]byte(stdout), '{')
	require.GreaterOrEqual(t, jsonStart, 0, "no JSON in %q", stdout)
	var result QuoteResult
	require.NoError(t, json.Unmarshal([]byte(stdout[jsonStart:]), &result))
	return result
}

// pcrIndicesOf runs `tpm pcrs` in JSON for the given selection and returns
// the indices it reported, bank by bank.
func pcrIndicesOf(t *testing.T, selection string) map[string][]int {
	t.Helper()
	setVar(t, &tpmCfg.outputFormat, "json")
	setVar(t, &pcrsIndices, selection)
	setVar(t, &pcrsBank, "")
	stdout, _, err := runTPMSubcommand(runTPMPCRs)
	require.NoError(t, err)

	var output PCRsOutput
	require.NoError(t, json.Unmarshal([]byte(stdout), &output))
	indices := map[string][]int{}
	for _, bank := range output.Banks {
		for _, pcr := range bank.PCRs {
			indices[bank.Algorithm] = append(indices[bank.Algorithm], pcr.Index)
		}
	}
	return indices
}

func TestRunTPMPCRs_Selection(t *testing.T) {
	withProvisionedSimulatorTPM(t)

	tests := []struct {
		name      string
		selection string
		want      []int
	}{
		{"range", "0-3", []int{0, 1, 2, 3}},
		{"range and single indices", " 7, 0-2 ,23", []int{7, 0, 1, 2, 23}},
		{"single-register range", "4-4", []int{4}},
		{"empty items are ignored", "0,,7,", []int{0, 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indices := pcrIndicesOf(t, tt.selection)
			require.NotEmpty(t, indices["SHA256"], "banks = %v", indices)
			for bank, got := range indices {
				assert.Equal(t, tt.want, got, "bank %s", bank)
			}
		})
	}
}

func TestRunTPMPCRs_TextShowsEveryRequestedRegister(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, &pcrsIndices, "0,7")
	setVar(t, &pcrsBank, "sha256")

	stdout, _, err := runTPMSubcommand(runTPMPCRs)
	require.NoError(t, err)

	banks, err := sim.tpm.ReadPCRs([]uint{0, 7})
	require.NoError(t, err)
	for _, bank := range banks {
		if !strings.EqualFold(bank.Algorithm, "sha256") {
			assert.NotContains(t, stdout, bank.Algorithm, "the bank filter drops %s", bank.Algorithm)
			continue
		}
		for _, pcr := range bank.PCRs {
			assert.Contains(t, stdout, hex.EncodeToString(pcr.Value), "PCR %d", pcr.ID)
		}
	}
}

func TestRunTPMPCRs_RejectsBadSelection(t *testing.T) {
	setVar(t, &pcrsBank, "")
	for _, selection := range []string{
		"1-2-3", // more than one dash
		"a-3",   // bad range start
		"3-b",   // bad range end
		"5-2",   // reversed range
		"20-24", // range past PCR 23
		"x",     // not a number
		"-1",    // negative
		"24",    // past PCR 23
		" , ,",  // nothing selected
	} {
		t.Run(selection, func(t *testing.T) {
			setVar(t, &pcrsIndices, selection)
			stdout, _, err := runTPMSubcommand(runTPMPCRs)
			assert.ErrorIs(t, err, ErrInvalidPCRIndices)
			assert.Empty(t, stdout)
		})
	}
}

// TestRunTPMPCRs_FreshSimulator proves reading PCRs needs no provisioning:
// `tpm pcrs` goes through the provisioning opener, which accepts a TPM that
// has no EK or SRK yet.
func TestRunTPMPCRs_FreshSimulator(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = ""
		c.useSimulator = true
		c.outputFormat = "json"
		c.hierarchyAuth = ""
	})
	setVar(t, &pcrsIndices, "0")
	setVar(t, &pcrsBank, "sha256")

	stdout, _, err := runTPMSubcommand(runTPMPCRs)
	require.NoError(t, err)

	var output PCRsOutput
	require.NoError(t, json.Unmarshal([]byte(stdout), &output))
	require.Len(t, output.Banks, 1)
	require.Len(t, output.Banks[0].PCRs, 1)
	assert.Equal(t, 0, output.Banks[0].PCRs[0].Index)
}

func TestRunTPMPCRsAndQuote_MissingDevice(t *testing.T) {
	withTPMCfg(t, func(c *tpmConfig) {
		c.device = "/nonexistent/xkey-test-tpm0"
		c.useSimulator = false
		c.outputFormat = "text"
		c.hierarchyAuth = ""
	})
	setVar(t, &pcrsIndices, "")
	setVar(t, &pcrsBank, "")
	setVar(t, &quotePCRs, "0")
	setVar(t, &quoteNonce, "")

	t.Run("pcrs", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runTPMPCRs)
		require.Error(t, err)
		assert.Empty(t, stdout)
	})

	t.Run("quote", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		require.Error(t, err)
		assert.NotContains(t, stdout, "Generating quote")
	})
}

func TestRunTPMPCRs_TPMFailures(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, &pcrsIndices, "0")
	setVar(t, &pcrsBank, "")

	t.Run("read", func(t *testing.T) {
		f := withFaultTPM(t, sim)
		f.readPCRsErr = errInjected
		stdout, _, err := runTPMSubcommand(runTPMPCRs)
		require.ErrorIs(t, err, ErrTPMOperationFailed)
		assert.ErrorContains(t, err, errInjected.Error())
		assert.Empty(t, stdout)
		assert.True(t, f.closed, "a failed read still closes the TPM")
	})

	t.Run("close", func(t *testing.T) {
		f := withFaultTPM(t, sim)
		f.closeErr = errInjected
		stdout, _, err := runTPMSubcommand(runTPMPCRs)
		assert.ErrorIs(t, err, errInjected, "a failed close is reported")
		assert.Contains(t, stdout, "SHA256", "the PCRs read before the close are still printed")
	})
}

// TestRunTPMQuote_SignedByTheIAK checks the quote the command prints is
// evidence a remote verifier accepts: a TPMS_ATTEST signed by the IAK,
// carrying the caller's nonce and the digest of the quoted PCR values.
func TestRunTPMQuote_SignedByTheIAK(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	const nonceHex = "00112233445566778899aabbccddeeff"
	setVar(t, &tpmCfg.outputFormat, "json")
	setVar(t, &quotePCRs, "0,7")
	setVar(t, &quoteNonce, nonceHex)
	setVar(t, &quoteOutputFile, "")

	stdout, _, err := runTPMSubcommand(runTPMQuote)
	require.NoError(t, err)
	result := decodeQuoteJSON(t, stdout)
	assert.False(t, result.HasEventLog, "the simulator has no measurement log")

	attest, err := hex.DecodeString(result.QuotedHex)
	require.NoError(t, err)
	signature, err := hex.DecodeString(result.SignatureHex)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(nonceHex)
	require.NoError(t, err)
	iak, err := sim.tpm.IAK()
	require.NoError(t, err)

	banks, err := sim.tpm.ReadPCRs([]uint{0, 7})
	require.NoError(t, err)
	var pcrValues [][]byte
	for _, bank := range banks {
		if strings.EqualFold(bank.Algorithm, "sha256") {
			for _, pcr := range bank.PCRs {
				pcrValues = append(pcrValues, pcr.Value)
			}
		}
	}
	require.Len(t, pcrValues, 2)

	t.Run("verifies", func(t *testing.T) {
		assert.NoError(t, verifyQuote(attest, signature, iak, nonce, pcrValues...))
	})

	t.Run("tampered attestation fails", func(t *testing.T) {
		tampered := bytes.Clone(attest)
		tampered[len(tampered)-1] ^= 0xff
		assert.Error(t, verifyQuote(tampered, signature, iak, nonce, pcrValues...))
	})

	t.Run("another key fails", func(t *testing.T) {
		assert.ErrorIs(t, verifyQuote(attest, signature, foreignRSAKey(t), nonce, pcrValues...), rsa.ErrVerification)
	})

	t.Run("another nonce fails", func(t *testing.T) {
		assert.ErrorIs(t, verifyQuote(attest, signature, iak, []byte("replayed-nonce"), pcrValues...), errQuoteNonce)
	})

	t.Run("other PCR values fail", func(t *testing.T) {
		assert.ErrorIs(t, verifyQuote(attest, signature, iak, nonce, bytes.Repeat([]byte{0xff}, 32), pcrValues[1]), errQuotePCRDigest)
	})
}

func TestRunTPMQuote_WithoutNonce(t *testing.T) {
	withProvisionedSimulatorTPM(t)
	setVar(t, &tpmCfg.outputFormat, "text")
	setVar(t, &quotePCRs, "7")
	setVar(t, &quoteNonce, "")
	setVar(t, &quoteOutputFile, "")

	stdout, _, err := runTPMSubcommand(runTPMQuote)
	require.NoError(t, err)
	assert.Contains(t, stdout, "PCRs:       [7]")
	assert.Contains(t, stdout, "Nonce:      \n", "no nonce was supplied")
	assert.Contains(t, stdout, "Event Log: Not available")
}

func TestRunTPMQuote_ReportsTheEventLog(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	eventLog := []byte("measured boot event log")
	f := withFaultTPM(t, sim)
	f.eventLog = eventLog
	setVar(t, &quotePCRs, "0")
	setVar(t, &quoteNonce, "c0ffee")
	setVar(t, &quoteOutputFile, "")
	setVar(t, &quoteIncludeLog, false)

	t.Run("text", func(t *testing.T) {
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		require.NoError(t, err)
		assert.Contains(t, stdout, "Event Log: Available (23 bytes)")
	})

	t.Run("json", func(t *testing.T) {
		setVar(t, &tpmCfg.outputFormat, "json")
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		require.NoError(t, err)
		result := decodeQuoteJSON(t, stdout)
		assert.True(t, result.HasEventLog)
		assert.Equal(t, len(eventLog), result.EventLogSize)
	})

	readQuoteFile := func(t *testing.T) map[string]any {
		t.Helper()
		path := filepath.Join(t.TempDir(), "quote.json")
		setVar(t, &quoteOutputFile, path)
		_, _, err := runTPMSubcommand(runTPMQuote)
		require.NoError(t, err)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var written map[string]any
		require.NoError(t, json.Unmarshal(data, &written))
		return written
	}

	t.Run("file includes the log on request", func(t *testing.T) {
		setVar(t, &quoteIncludeLog, true)
		written := readQuoteFile(t)
		assert.Equal(t, base64.StdEncoding.EncodeToString(eventLog), written["event_log"])
	})

	t.Run("file omits the log by default", func(t *testing.T) {
		written := readQuoteFile(t)
		assert.NotContains(t, written, "event_log")
		assert.Equal(t, true, written["has_event_log"])
	})
}

func TestRunTPMQuote_RejectsBadPCRSelection(t *testing.T) {
	setVar(t, &quoteNonce, "")
	for _, selection := range []string{"24", "", " , ", "0-7", "-1"} {
		t.Run(selection, func(t *testing.T) {
			setVar(t, &quotePCRs, selection)
			stdout, _, err := runTPMSubcommand(runTPMQuote)
			assert.ErrorIs(t, err, ErrInvalidPCRIndices)
			assert.Empty(t, stdout)
		})
	}
}

func TestRunTPMQuote_TPMFailures(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, &quotePCRs, "0")
	setVar(t, &quoteNonce, "c0ffee")
	setVar(t, &quoteOutputFile, "")

	t.Run("missing IAK", func(t *testing.T) {
		f := withFaultTPM(t, sim)
		f.iakErr = errInjected
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		require.ErrorIs(t, err, errInjected)
		assert.ErrorContains(t, err, "tpm provision")
		assert.NotContains(t, stdout, "Generating quote")
		assert.True(t, f.closed)
	})

	t.Run("oversized nonce", func(t *testing.T) {
		// TPM2B_DATA holds at most one digest, so the TPM refuses a
		// 128-byte qualifying-data buffer.
		setVar(t, &quoteNonce, strings.Repeat("ab", 128))
		_, _, err := runTPMSubcommand(runTPMQuote)
		assert.ErrorIs(t, err, ErrTPMOperationFailed)
	})

	t.Run("close", func(t *testing.T) {
		f := withFaultTPM(t, sim)
		f.closeErr = errInjected
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		assert.ErrorIs(t, err, errInjected, "a failed close is reported")
		assert.Contains(t, stdout, "TPM Quote", "the quote taken before the close is still printed")
	})

	t.Run("output file not writable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing-dir", "quote.json")
		setVar(t, &quoteOutputFile, path)
		stdout, _, err := runTPMSubcommand(runTPMQuote)
		assert.ErrorIs(t, err, ErrExportFailed)
		assert.NotContains(t, stdout, "Quote written to")
		assert.NoFileExists(t, path)
	})
}

// TestRunTPMQuote_ClosesAnUninitializedTPM covers openTPM handing back a
// live TPM together with ErrTPMNotInitialized: the command must close that
// handle, or the device (and the in-process simulator's lock) stays held.
func TestRunTPMQuote_ClosesAnUninitializedTPM(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	f := &faultTPM{sharedTPM: sharedTPM{sim.tpm}}
	setVar(t, &openTPM, func() (xkms.TrustedPlatformModule, error) { return f, ErrTPMNotInitialized })
	setVar(t, &quotePCRs, "0")
	setVar(t, &quoteNonce, "")

	stdout, _, err := runTPMSubcommand(runTPMQuote)
	require.ErrorIs(t, err, ErrTPMNotInitialized)
	assert.NotContains(t, stdout, "Generating quote")
	assert.True(t, f.closed, "the TPM handle openTPM returned is closed")
}
