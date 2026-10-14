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

package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acmeadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
)

// acmeListPrinter is one ACME admin list printer with a populated and an
// empty response.
type acmeListPrinter struct {
	name string
	// jsonKey is the field the JSON output nests the list under.
	jsonKey string
	empty   string
	// textWant and tableWant are lines the populated output must carry.
	textWant  string
	tableWant []string
	print     func(p *Printer, populated bool, pagination *acmeadmin.Pagination)
}

func acmeListPrinters() []acmeListPrinter {
	created := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	longSubject := "CN=a-very-long-subject-name-for-truncation.example.com"
	return []acmeListPrinter{
		{
			name:      "accounts",
			jsonKey:   "accounts",
			empty:     "No accounts found",
			textWant:  "  - 42 (valid, 3 order(s))",
			tableWant: []string{"ID", "STATUS", "42", "valid", "2026-10-14 09:30"},
			print: func(p *Printer, populated bool, pg *acmeadmin.Pagination) {
				resp := &acmeadmin.ListAccountsResponse{Pagination: pg}
				if populated {
					resp.Accounts = []*acmeadmin.AccountInfo{{ID: 42, Status: "valid", OrderCount: 3, CreatedAt: created}}
				}
				printACMEAccountList(p, resp)
			},
		},
		{
			name:      "eabs",
			jsonKey:   "eabs",
			empty:     "No EABs found",
			textWant:  "  - kid-1 (unused, device enrollment)",
			tableWant: []string{"KEY ID", "PURPOSE", "kid-1", "unused", "2026-10-14 09:30"},
			print: func(p *Printer, populated bool, pg *acmeadmin.Pagination) {
				resp := &acmeadmin.ListEABResponse{Pagination: pg}
				if populated {
					resp.EABs = []*acmeadmin.EABInfo{{ID: "kid-1", Status: "unused", Purpose: "device enrollment", CreatedAt: created}}
				}
				printACMEEABList(p, resp)
			},
		},
		{
			name:      "certificates",
			jsonKey:   "certificates",
			empty:     "No certificates found",
			textWant:  "  - 0A1B (" + longSubject + ", valid)",
			tableWant: []string{"SERIAL", "NOT AFTER", "0A1B", longSubject[:37] + "...", "2026-10-14 09:30"},
			print: func(p *Printer, populated bool, pg *acmeadmin.Pagination) {
				resp := &acmeadmin.ListCertificatesResponse{Pagination: pg}
				if populated {
					resp.Certificates = []*acmeadmin.CertificateInfo{{SerialNumber: "0A1B", Subject: longSubject, Status: "valid", NotAfter: created}}
				}
				printACMECertList(p, resp)
			},
		},
	}
}

func TestACMEListPrinters_Text(t *testing.T) {
	for _, lp := range acmeListPrinters() {
		t.Run(lp.name, func(t *testing.T) {
			var buf bytes.Buffer
			lp.print(NewPrinter("text", &buf), true, nil)
			assert.Contains(t, buf.String(), lp.textWant)
		})
	}
}

func TestACMEListPrinters_Table(t *testing.T) {
	for _, lp := range acmeListPrinters() {
		t.Run(lp.name, func(t *testing.T) {
			var buf bytes.Buffer
			lp.print(NewPrinter("table", &buf), true, nil)
			for _, want := range lp.tableWant {
				assert.Contains(t, buf.String(), want)
			}
		})
	}
}

func TestACMEListPrinters_Empty(t *testing.T) {
	for _, lp := range acmeListPrinters() {
		for _, format := range []string{"text", "table"} {
			t.Run(lp.name+"/"+format, func(t *testing.T) {
				var buf bytes.Buffer
				lp.print(NewPrinter(format, &buf), false, nil)
				assert.Equal(t, lp.empty+"\n", buf.String())
			})
		}
	}
}

func TestACMEListPrinters_JSONPagination(t *testing.T) {
	for _, lp := range acmeListPrinters() {
		t.Run(lp.name, func(t *testing.T) {
			var withPage bytes.Buffer
			lp.print(NewPrinter("json", &withPage), true, &acmeadmin.Pagination{Page: 2, PerPage: 10, Total: 11})
			var got map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(withPage.Bytes(), &got))
			assert.Contains(t, got, lp.jsonKey)
			assert.JSONEq(t, `{"page":2,"per_page":10,"total":11}`, string(got["pagination"]))

			var withoutPage bytes.Buffer
			lp.print(NewPrinter("json", &withoutPage), true, nil)
			got = nil
			require.NoError(t, json.Unmarshal(withoutPage.Bytes(), &got))
			assert.Contains(t, got, lp.jsonKey)
			assert.NotContains(t, got, "pagination", "an unpaged list carries no pagination object")
		})
	}
}
