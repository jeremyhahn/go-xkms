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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// mockAppraiseClient records AppraiseAttestationQuote calls and answers with
// a settable result.
type mockAppraiseClient struct {
	mockBackendsClient

	fail   bool
	calls  int
	last   *client.AppraiseAttestationQuoteRequest
	result *client.AttestationAppraisalResult
}

func (m *mockAppraiseClient) AppraiseAttestationQuote(_ context.Context, req *client.AppraiseAttestationQuoteRequest) (*client.AttestationAppraisalResult, error) {
	m.calls++
	m.last = req
	if m.fail {
		return nil, errors.New("appraisal unavailable")
	}
	if m.result != nil {
		return m.result, nil
	}
	return &client.AttestationAppraisalResult{Verified: true, ReferenceValues: req.ReferenceValues}, nil
}

// appraiseEvidence is the evidence files of one appraisal.
type appraiseEvidence struct {
	akCert, quote, signature, eventLog string
}

func writeAppraiseFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func writeAppraiseEvidence(t *testing.T) appraiseEvidence {
	t.Helper()
	dir := t.TempDir()
	return appraiseEvidence{
		akCert:    writeAppraiseFile(t, dir, "ak.pem", []byte("ak-cert-pem")),
		quote:     writeAppraiseFile(t, dir, "q.bin", []byte("quote-bytes")),
		signature: writeAppraiseFile(t, dir, "s.bin", []byte("signature-bytes")),
		eventLog:  writeAppraiseFile(t, dir, "el.bin", []byte("event-log-bytes")),
	}
}

// appraiseFlags is a complete, valid flag set without the event log.
func appraiseFlags(ev appraiseEvidence) map[string]string {
	return map[string]string{
		"reference-values": "rv1",
		"ak-cert":          ev.akCert,
		"quote":            ev.quote,
		"signature":        ev.signature,
		"nonce":            "0a0b",
		"pcr":              "0=00ff,7=aa",
	}
}

func TestAttestationAppraiseCmd_Registered(t *testing.T) {
	assert.True(t, hasSubcommand(attestationCmd, attestationAppraiseCmd))
}

func TestAttestationAppraiseCmd_SendsEvidence(t *testing.T) {
	ev := writeAppraiseEvidence(t)

	flags := appraiseFlags(ev)
	flags["event-log"] = ev.eventLog
	mock := &mockAppraiseClient{}
	_, _, code := runEndorsementCmd(t, mock, attestationAppraiseCmd, "text", nil, flags)
	assert.Equal(t, -1, code)
	require.Equal(t, 1, mock.calls)
	assert.Equal(t, &client.AppraiseAttestationQuoteRequest{
		AKCertificatePEM: []byte("ak-cert-pem"),
		Quote:            []byte("quote-bytes"),
		Signature:        []byte("signature-bytes"),
		Nonce:            []byte{0x0a, 0x0b},
		PCRs:             map[uint32][]byte{0: {0x00, 0xff}, 7: {0xaa}},
		EventLog:         []byte("event-log-bytes"),
		ReferenceValues:  "rv1",
	}, mock.last)

	mock = &mockAppraiseClient{}
	_, _, code = runEndorsementCmd(t, mock, attestationAppraiseCmd, "text", nil, appraiseFlags(ev))
	assert.Equal(t, -1, code)
	require.Equal(t, 1, mock.calls)
	assert.Nil(t, mock.last.EventLog)
}

func TestAttestationAppraiseCmd_Verified(t *testing.T) {
	ev := writeAppraiseEvidence(t)
	result := &client.AttestationAppraisalResult{
		Verified: true,
		Checks: []client.AttestationAppraisalCheck{
			{Name: "ak_certificate", Outcome: client.AttestationAppraisalPass},
			{Name: "quote", Outcome: client.AttestationAppraisalPass},
		},
		ReferenceValues: "rv1",
		ManifestID:      "manifest-42",
		Signer:          "release-signer",
		BaselineSource:  "signed",
		AppraisedAt:     time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC),
	}

	mock := &mockAppraiseClient{result: result}
	out, _, code := runEndorsementCmd(t, mock, attestationAppraiseCmd, "text", nil, appraiseFlags(ev))
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "verified")
	assert.Contains(t, out, "ak_certificate")
	assert.Contains(t, out, "quote")
	assert.Contains(t, out, "pass")
	assert.Contains(t, out, "rv1")
	assert.Contains(t, out, "manifest-42")
	assert.Contains(t, out, "release-signer")

	mock = &mockAppraiseClient{result: result}
	out, _, code = runEndorsementCmd(t, mock, attestationAppraiseCmd, "json", nil, appraiseFlags(ev))
	assert.Equal(t, -1, code)
	var got client.AttestationAppraisalResult
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.True(t, got.Verified)
	assert.Equal(t, "manifest-42", got.ManifestID)
	assert.Len(t, got.Checks, 2)
}

func TestAttestationAppraiseCmd_NotVerified(t *testing.T) {
	ev := writeAppraiseEvidence(t)

	mock := &mockAppraiseClient{result: &client.AttestationAppraisalResult{
		Verified:             false,
		CryptographicFailure: true,
		Checks: []client.AttestationAppraisalCheck{
			{Name: "ak_certificate", Outcome: client.AttestationAppraisalPass},
			{Name: "baseline", Outcome: client.AttestationAppraisalForged, Reason: "PCR 7 diverges"},
		},
		ReferenceValues: "rv1",
	}}
	out, stderr, code := runEndorsementCmd(t, mock, attestationAppraiseCmd, "text", nil, appraiseFlags(ev))
	assert.NotEqual(t, -1, code)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "baseline")
	assert.Contains(t, out, "forged")
	assert.Contains(t, out, "PCR 7 diverges")
	assert.Contains(t, stderr, ErrAttestationNotVerified.Error())
	assert.Contains(t, stderr, "cryptographic")

	mock = &mockAppraiseClient{result: &client.AttestationAppraisalResult{
		Verified: false,
		Checks: []client.AttestationAppraisalCheck{
			{Name: "ak_certificate", Outcome: client.AttestationAppraisalAbsent, Reason: "no ak-root endorsement"},
		},
		ReferenceValues: "rv1",
	}}
	out, stderr, code = runEndorsementCmd(t, mock, attestationAppraiseCmd, "text", nil, appraiseFlags(ev))
	assert.NotEqual(t, -1, code)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "absent")
	assert.Contains(t, stderr, ErrAttestationNotVerified.Error())
	assert.NotContains(t, stderr, "cryptographic")
}

func TestAttestationAppraiseCmd_Refusals(t *testing.T) {
	ev := writeAppraiseEvidence(t)
	empty := writeAppraiseFile(t, t.TempDir(), "empty.bin", nil)
	missing := filepath.Join(t.TempDir(), "missing.bin")

	cases := map[string]func(map[string]string){
		"no reference values":    func(f map[string]string) { delete(f, "reference-values") },
		"no ak-cert":             func(f map[string]string) { delete(f, "ak-cert") },
		"missing ak-cert":        func(f map[string]string) { f["ak-cert"] = missing },
		"empty ak-cert":          func(f map[string]string) { f["ak-cert"] = empty },
		"no quote":               func(f map[string]string) { delete(f, "quote") },
		"missing quote":          func(f map[string]string) { f["quote"] = missing },
		"empty quote":            func(f map[string]string) { f["quote"] = empty },
		"no signature":           func(f map[string]string) { delete(f, "signature") },
		"missing signature":      func(f map[string]string) { f["signature"] = missing },
		"empty signature":        func(f map[string]string) { f["signature"] = empty },
		"missing event log":      func(f map[string]string) { f["event-log"] = missing },
		"empty event log":        func(f map[string]string) { f["event-log"] = empty },
		"no nonce":               func(f map[string]string) { delete(f, "nonce") },
		"nonce not hex":          func(f map[string]string) { f["nonce"] = "zz" },
		"no pcr":                 func(f map[string]string) { delete(f, "pcr") },
		"pcr without equals":     func(f map[string]string) { f["pcr"] = "0" },
		"pcr index not a number": func(f map[string]string) { f["pcr"] = "x=00" },
		"pcr index over 23":      func(f map[string]string) { f["pcr"] = "24=00" },
		"pcr value not hex":      func(f map[string]string) { f["pcr"] = "0=zz" },
		"pcr value empty":        func(f map[string]string) { f["pcr"] = "0=" },
		"pcr index twice":        func(f map[string]string) { f["pcr"] = "7=aa,7=bb" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			flags := appraiseFlags(ev)
			mutate(flags)
			mock := &mockAppraiseClient{}
			_, stderr, code := runEndorsementCmd(t, mock, attestationAppraiseCmd, "text", nil, flags)
			assert.NotEqual(t, -1, code)
			assert.NotEqual(t, 0, code)
			assert.NotEmpty(t, stderr)
			assert.Equal(t, 0, mock.calls)
		})
	}
}

func TestAttestationAppraiseCmd_CallFails(t *testing.T) {
	ev := writeAppraiseEvidence(t)
	mock := &mockAppraiseClient{fail: true}
	_, stderr, code := runEndorsementCmd(t, mock, attestationAppraiseCmd, "text", nil, appraiseFlags(ev))
	assert.NotEqual(t, -1, code)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, ErrAppraiseAttestationQuoteFailed.Error())
	assert.Equal(t, 1, mock.calls)
}
