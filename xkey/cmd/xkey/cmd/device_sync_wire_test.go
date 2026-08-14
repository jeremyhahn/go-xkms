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

//go:build ble

package cmd

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
)

// --- mode semantics ---

func TestSyncMode_Halves(t *testing.T) {
	tests := []struct {
		name    string
		mode    syncMode
		sends   bool
		applies bool
		verb    string
	}{
		{"both", syncModeBoth, true, true, "Syncing"},
		{"push", syncModePush, true, false, "Pushing"},
		{"pull", syncModePull, false, true, "Pulling"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.sends, tc.mode.sends())
			assert.Equal(t, tc.applies, tc.mode.applies())
			assert.Equal(t, tc.verb, tc.mode.verb())
		})
	}
}

// --- wire conversions ---

func TestWireCertificates_RoundTrip(t *testing.T) {
	delta := &xkeysync.TrustStoreDelta{
		Certificates: []xkeysync.TrustStoreCertSync{{
			PEM:         "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
			Fingerprint: "abc123",
			Purpose:     "tpm-manufacturer",
			Source:      "file:ca.pem",
			Tags:        []string{"root"},
		}},
	}

	wire := wireCertificates(delta)
	require.Len(t, wire, 1)
	assert.Equal(t, "abc123", wire[0].Fingerprint)
	assert.Equal(t, "tpm-manufacturer", wire[0].Purpose)

	back := localCertificates(wire)
	assert.Equal(t, delta.Certificates, back)
}

func TestWireCertificates_NilDeltaSendsEmptyList(t *testing.T) {
	wire := wireCertificates(nil)
	assert.NotNil(t, wire, "a nil delta must marshal as [] so the phone sees an empty push")
	assert.Empty(t, wire)
}

func TestWireOATH_RoundTripPreservesTimestamp(t *testing.T) {
	updated := time.Date(2026, 8, 4, 12, 30, 0, 0, time.UTC)
	delta := &xkeysync.OATHDelta{
		Credentials: []xkeysync.OATHCredentialSync{{
			ID:          "github:alice",
			Name:        "GitHub",
			Issuer:      "GitHub",
			AccountName: "alice",
			Secret:      "JBSWY3DPEHPK3PXP",
			Type:        "totp",
			Algorithm:   "SHA1",
			Digits:      6,
			Period:      30,
			Counter:     0,
			UpdatedAt:   updated,
		}},
	}

	wire := wireOATH(delta)
	require.Len(t, wire, 1)
	assert.Equal(t, "2026-08-04T12:30:00Z", wire[0].UpdatedAt)

	back := localOATH(wire)
	require.Len(t, back, 1)
	assert.True(t, updated.Equal(back[0].UpdatedAt))
	assert.Equal(t, "JBSWY3DPEHPK3PXP", back[0].Secret)
}

func TestWirePasswords_RoundTrip(t *testing.T) {
	updated := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	delta := &xkeysync.PasswordDelta{
		Passwords: []xkeysync.PasswordSync{{
			ID:         "pw-1",
			Name:       "AWS",
			Title:      "AWS console",
			Username:   "alice",
			Password:   "hunter2",
			URL:        "https://aws.amazon.com",
			Notes:      "prod",
			FolderPath: "/work",
			UpdatedAt:  updated,
		}},
	}

	wire := wirePasswords(delta)
	require.Len(t, wire, 1)
	assert.Equal(t, "2026-01-02T03:04:05Z", wire[0].UpdatedAt)

	back := localPasswords(wire)
	require.Len(t, back, 1)
	assert.Equal(t, delta.Passwords[0].ID, back[0].ID)
	assert.Equal(t, delta.Passwords[0].FolderPath, back[0].FolderPath)
	assert.True(t, updated.Equal(back[0].UpdatedAt))
}

func TestSyncTimeHelpers(t *testing.T) {
	assert.Empty(t, formatSyncTime(time.Time{}), "the zero time is sent as absent")
	assert.True(t, parseSyncTime("").IsZero())
	assert.True(t, parseSyncTime("not-a-timestamp").IsZero(),
		"a malformed timestamp must read as zero so the merge never treats it as newer")

	parsed := parseSyncTime("2026-08-04T12:30:00Z")
	assert.Equal(t, "2026-08-04T12:30:00Z", formatSyncTime(parsed))
}

// --- reporting ---

func TestItemCounts_NilResult(t *testing.T) {
	assert.Equal(t, syncCounts{}, itemCounts(nil))
}

func TestItemCounts_ProjectsServiceResult(t *testing.T) {
	counts := itemCounts(&xkeysync.SyncItemResult{Added: 2, Updated: 3, Skipped: 4})
	assert.Equal(t, syncCounts{Added: 2, Updated: 3, Skipped: 4}, counts)
}

func TestSyncSummary_WriteReportsBothHalves(t *testing.T) {
	var summary syncSummary
	summary.set("oath", syncResult{
		Pushed: syncCounts{Added: 1, Skipped: 2},
		Pulled: syncCounts{Added: 3, Updated: 4},
	})

	var buf bytes.Buffer
	summary.write(&buf, syncScope{OATH: true}, syncModeBoth)

	out := buf.String()
	assert.Contains(t, out, "phone applied 1 added, 0 updated, 2 skipped")
	assert.Contains(t, out, "locally applied 3 added, 4 updated, 0 skipped")
}

func TestSyncSummary_WriteOmitsUnusedHalf(t *testing.T) {
	var summary syncSummary
	summary.set("passwords", syncResult{
		Pushed: syncCounts{Added: 5},
		Pulled: syncCounts{Added: 9},
	})

	var pushBuf bytes.Buffer
	summary.write(&pushBuf, syncScope{Passwords: true}, syncModePush)
	assert.Contains(t, pushBuf.String(), "phone applied 5 added")
	assert.NotContains(t, pushBuf.String(), "locally applied")

	var pullBuf bytes.Buffer
	summary.write(&pullBuf, syncScope{Passwords: true}, syncModePull)
	assert.Contains(t, pullBuf.String(), "locally applied 9 added")
	assert.NotContains(t, pullBuf.String(), "phone applied")
}

func TestSelectedSyncStores_OrderAndScope(t *testing.T) {
	stores := selectedSyncStores(syncScope{TrustStore: true, OATH: true, Passwords: true})
	require.Len(t, stores, 3)
	assert.Equal(t, "trust-store", stores[0].label)
	assert.Equal(t, "oath", stores[1].label)
	assert.Equal(t, "passwords", stores[2].label)

	only := selectedSyncStores(syncScope{OATH: true})
	require.Len(t, only, 1)
	assert.Equal(t, "oath", only[0].label)
	assert.NotNil(t, only[0].exchange)
}

func TestOrNever(t *testing.T) {
	assert.Equal(t, "never", orNever(""))
	assert.Equal(t, "2026-08-04T12:30:00Z", orNever("2026-08-04T12:30:00Z"))
}
