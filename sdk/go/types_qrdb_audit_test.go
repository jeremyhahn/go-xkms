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

package xkms

import (
	"context"
	"path/filepath"
	"testing"
)

// TestQRDBNodeAuditSinks_EmitThenQuery proves the go-qrdb node audit sinks
// re-exported for xkey store what is emitted and return it from Query.
func TestQRDBNodeAuditSinks_EmitThenQuery(t *testing.T) {
	file, err := NewQRDBAuditFileLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewQRDBAuditFileLogger: %v", err)
	}
	sinks := map[string]QRDBNodeAuditLogger{
		"ring": NewQRDBAuditRingBuffer(8),
		"file": file,
	}
	for name, sink := range sinks {
		t.Run(name, func(t *testing.T) {
			defer func() { _ = sink.Close() }()
			ctx := context.Background()
			ev := QRDBNodeAuditEvent{Actor: "xkey", Resource: "key:k1", Action: "key_created", Outcome: "success"}
			if err := sink.Emit(ctx, ev); err != nil {
				t.Fatalf("Emit: %v", err)
			}
			page, err := sink.Query(ctx, QRDBNodeAuditFilter{Action: "key_created"})
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			// The query's page is the re-exported QRDBNodeAuditPage.
			p := func(p *QRDBNodeAuditPage) *QRDBNodeAuditPage { return p }(page)
			if p == nil || len(p.Events) != 1 || p.Events[0].Resource != "key:k1" {
				t.Fatalf("Query page = %+v, want the one emitted event", p)
			}
		})
	}
}
