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

package sharestore

import (
	"errors"
	"testing"
)

func TestShareEntry_Validate_Valid(t *testing.T) {
	entry := &ShareEntry{
		ServerURL: "https://xkms.example.com",
		GroupID:   "custodians-1",
		ShareData: []byte("share-data-bytes"),
	}

	if err := entry.Validate(); err != nil {
		t.Fatalf("expected nil error for valid entry, got: %v", err)
	}
}

func TestShareEntry_Validate_EmptyServerURL(t *testing.T) {
	entry := &ShareEntry{
		ServerURL: "",
		GroupID:   "custodians-1",
		ShareData: []byte("share-data-bytes"),
	}

	err := entry.Validate()
	if err == nil {
		t.Fatal("expected error for empty server URL, got nil")
	}
	if !errors.Is(err, ErrInvalidServerURL) {
		t.Fatalf("expected ErrInvalidServerURL, got: %v", err)
	}
}

func TestShareEntry_Validate_EmptyGroupID(t *testing.T) {
	entry := &ShareEntry{
		ServerURL: "https://xkms.example.com",
		GroupID:   "",
		ShareData: []byte("share-data-bytes"),
	}

	err := entry.Validate()
	if err == nil {
		t.Fatal("expected error for empty group ID, got nil")
	}
	if !errors.Is(err, ErrInvalidGroupID) {
		t.Fatalf("expected ErrInvalidGroupID, got: %v", err)
	}
}

func TestShareEntry_Validate_EmptyShareData(t *testing.T) {
	entry := &ShareEntry{
		ServerURL: "https://xkms.example.com",
		GroupID:   "custodians-1",
		ShareData: nil,
	}

	err := entry.Validate()
	if err == nil {
		t.Fatal("expected error for empty share data, got nil")
	}
	if !errors.Is(err, ErrEmptyShare) {
		t.Fatalf("expected ErrEmptyShare, got: %v", err)
	}
}

func TestShareEntry_Validate_EmptyShareDataSlice(t *testing.T) {
	entry := &ShareEntry{
		ServerURL: "https://xkms.example.com",
		GroupID:   "custodians-1",
		ShareData: []byte{},
	}

	err := entry.Validate()
	if err == nil {
		t.Fatal("expected error for zero-length share data, got nil")
	}
	if !errors.Is(err, ErrEmptyShare) {
		t.Fatalf("expected ErrEmptyShare, got: %v", err)
	}
}

func TestShareEntry_Key(t *testing.T) {
	entry := &ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "custodians-1",
		ShareIndex: 0,
	}

	expected := "https://xkms.example.com/custodians-1/0"
	if got := entry.Key(); got != expected {
		t.Fatalf("expected key %q, got %q", expected, got)
	}
}

func TestShareEntry_Key_WithShareIndex(t *testing.T) {
	entry := &ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "custodians-1",
		ShareIndex: 3,
	}

	expected := "https://xkms.example.com/custodians-1/3"
	if got := entry.Key(); got != expected {
		t.Fatalf("expected key %q, got %q", expected, got)
	}
}

func TestShareEntry_Key_DifferentValues(t *testing.T) {
	entry := &ShareEntry{
		ServerURL:  "https://other-server.com:8443",
		GroupID:    "group-abc",
		ShareIndex: 5,
	}

	expected := "https://other-server.com:8443/group-abc/5"
	if got := entry.Key(); got != expected {
		t.Fatalf("expected key %q, got %q", expected, got)
	}
}

func TestShareEntry_Validate_AllFieldsPresent(t *testing.T) {
	entry := &ShareEntry{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "custodians-1",
		GroupName:  "Primary Custodians",
		ShareIndex: 2,
		ShareData:  []byte("share-data-bytes"),
		Purpose:    "barrier",
		TenantID:   "tenant-42",
	}

	if err := entry.Validate(); err != nil {
		t.Fatalf("expected nil error for fully populated entry, got: %v", err)
	}
}
