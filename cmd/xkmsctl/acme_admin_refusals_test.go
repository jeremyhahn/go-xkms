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

// acme_admin_refusals_test.go pins that every ACME admin verb reports an
// admin client it cannot open, that disable and revoke refuse a bad
// identifier before connecting, and how a single EAB is rendered.
package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acmeadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

// withACMEAdminFactory swaps the ACME admin client factory for one test.
func withACMEAdminFactory(t *testing.T, factory ACMEAdminClientFactory) {
	t.Helper()
	original := acmeAdminClientFactory
	acmeAdminClientFactory = factory
	t.Cleanup(func() { acmeAdminClientFactory = original })
}

// runACMEVerb runs fn and returns its exit code and what it wrote to stderr.
func runACMEVerb(t *testing.T, fn func()) (int, string) {
	t.Helper()
	code := -1
	stderr := captureStderr(t, func() { code = captureExit(t, fn) })
	return code, stderr
}

func TestACMEAdminVerbs_ClientFailures(t *testing.T) {
	original := acmeEABTenant
	acmeEABTenant = "tenant-a"
	t.Cleanup(func() { acmeEABTenant = original })
	cfg := &Config{OutputFormat: "text"}

	verbs := map[string]func(){
		"account list":    func() { acmeAccountList(cfg) },
		"account get":     func() { acmeAccountGet(cfg, "7") },
		"account disable": func() { acmeAccountDisable(cfg, "7") },
		"cert list":       func() { acmeCertList(cfg) },
		"cert get":        func() { acmeCertGet(cfg, "01:02") },
		"cert revoke":     func() { acmeCertRevoke(cfg, "01:02") },
		"eab create":      func() { acmeEABCreate(cfg) },
		"eab get":         func() { acmeEABGet(cfg, "kid-1") },
		"eab delete":      func() { acmeEABDelete(cfg, "kid-1") },
		"eab list":        func() { acmeEABList(cfg) },
	}
	factories := []struct {
		name    string
		factory ACMEAdminClientFactory
		want    string
	}{
		{"no factory", nil, (&ACMEAdminClientMissingError{}).Error()},
		{"factory fails", func(context.Context) (acmeadmin.Client, func() error, error) {
			return nil, nil, errUserExtBoom
		}, errUserExtBoom.Error()},
	}
	for name, verb := range verbs {
		for _, f := range factories {
			t.Run(name+"/"+f.name, func(t *testing.T) {
				withACMEAdminFactory(t, f.factory)
				code, stderr := runACMEVerb(t, verb)
				assert.Equal(t, 1, code)
				assert.Contains(t, stderr, f.want)
			})
		}
	}
}

func TestACMEAdminVerbs_RefuseBadIdentifierBeforeConnecting(t *testing.T) {
	cases := []struct {
		name     string
		verb     func()
		sentinel error
	}{
		{"account disable", func() { acmeAccountDisable(&Config{OutputFormat: "text"}, "not-a-number") }, ErrInvalidAccountID},
		{"cert revoke", func() { acmeCertRevoke(&Config{OutputFormat: "text"}, "") }, ErrInvalidACMESerial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opened := false
			withACMEAdminFactory(t, func(context.Context) (acmeadmin.Client, func() error, error) {
				opened = true
				return nil, nil, errUserExtBoom
			})
			code, stderr := runACMEVerb(t, tc.verb)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.False(t, opened, "no admin client is opened for a bad identifier")
		})
	}
}

func TestPrintACMEEABInfo(t *testing.T) {
	created := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	used := created.Add(time.Hour)
	expires := created.Add(24 * time.Hour)
	eab := &acmeadmin.EABInfo{ID: "kid-1", Status: "used", Purpose: "server", AccountID: 42, CreatedAt: created, UsedAt: &used, ExpiresAt: &expires}

	var text bytes.Buffer
	printACMEEABInfo(NewPrinter("text", &text), eab)
	assert.Contains(t, text.String(), "  Account: 42\n")
	assert.Contains(t, text.String(), "  Used:    2026-09-01 11:00:00\n")
	assert.Contains(t, text.String(), "  Expires: 2026-09-02 10:00:00\n")

	var js bytes.Buffer
	printACMEEABInfo(NewPrinter("json", &js), &acmeadmin.EABInfo{ID: "kid-2", CreatedAt: created})
	require.NotEmpty(t, js.String())
	assert.Contains(t, js.String(), `"kid-2"`)
	assert.NotContains(t, js.String(), "Account:", "JSON output carries no text labels")
}
