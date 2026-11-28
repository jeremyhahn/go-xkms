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

package localca

import (
	"context"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestNewClient_ReopensTheSameCA(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	first, err := NewClient(dir, nil)
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}
	firstCA, err := first.GetCACertificate(ctx, &xkmssdk.GetCACertificateRequest{})
	if err != nil {
		t.Fatalf("GetCACertificate() returned error: %v", err)
	}
	if !firstCA.IsCA {
		t.Error("expected IsCA == true")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	second, err := NewClient(dir, nil)
	if err != nil {
		t.Fatalf("second NewClient() returned error: %v", err)
	}
	defer func() { _ = second.Close() }()
	secondCA, err := second.GetCACertificate(ctx, &xkmssdk.GetCACertificateRequest{})
	if err != nil {
		t.Fatalf("second GetCACertificate() returned error: %v", err)
	}
	if secondCA.SerialNumber != firstCA.SerialNumber {
		t.Errorf("reopen minted a new root: serial %q, want %q", secondCA.SerialNumber, firstCA.SerialNumber)
	}
}
