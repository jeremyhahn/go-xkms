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

package spiffe

import (
	"errors"
	"net/url"
	"testing"
)

func TestID_String_Success(t *testing.T) {
	id := ID{TrustDomain: "example.com", TenantID: "acme", Kind: KindUser, Name: "alice"}
	want := "spiffe://example.com/tenant/acme/user/alice"
	if got := id.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestID_String_Invalid(t *testing.T) {
	id := ID{TrustDomain: "", TenantID: "acme", Kind: KindUser, Name: "alice"}
	if got := id.String(); got != "" {
		t.Fatalf("String() on invalid ID = %q, want empty string", got)
	}
}

func TestParseID_NilURL(t *testing.T) {
	id, ok, err := ParseID(nil)
	if ok || err != nil {
		t.Fatalf("ParseID(nil) = %+v, ok=%v, err=%v; want ok=false, err=nil", id, ok, err)
	}
}

func TestParseID_EmptyTrustDomain(t *testing.T) {
	u := &url.URL{Scheme: "spiffe", Host: "", Path: "/tenant/t1/user/name"}
	_, ok, err := ParseID(u)
	if ok {
		t.Fatalf("expected ok=false for empty trust domain")
	}
	if !errors.Is(err, ErrTrustDomainEmpty) {
		t.Fatalf("err = %v, want ErrTrustDomainEmpty", err)
	}
}

func TestParseID_TooFewPathSegments(t *testing.T) {
	u := &url.URL{Scheme: "spiffe", Host: "example.com", Path: "/tenant/t1"}
	_, ok, err := ParseID(u)
	if ok || err != nil {
		t.Fatalf("short path should be skipped as non-tenant: ok=%v err=%v", ok, err)
	}
}

func TestParseID_ValidateErrorPropagated(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		wantErr error
	}{
		{"bad kind in path", "/tenant/t1/bogus/name", ErrKindInvalid},
		{"empty tenant segment", "/tenant//user/name", ErrTenantEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &url.URL{Scheme: "spiffe", Host: "example.com", Path: tc.path}
			_, ok, err := ParseID(u)
			if ok {
				t.Fatalf("expected ok=false when validation fails")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestTenantFromURIs_EmptyPinAcceptsAnyTrustDomain(t *testing.T) {
	u, err := BuildURI("any-domain.internal", "tenant-x", KindService, "worker")
	if err != nil {
		t.Fatalf("BuildURI: %v", err)
	}
	id, err := TenantFromURIs([]*url.URL{u}, "")
	if err != nil {
		t.Fatalf("expected resolution with empty pin, got %v", err)
	}
	if id.TenantID != "tenant-x" || id.TrustDomain != "any-domain.internal" {
		t.Fatalf("id = %+v", id)
	}
}

func TestTenantFromURIs_MalformedSANPropagatesParseError(t *testing.T) {
	malformed := &url.URL{Scheme: "spiffe", Host: "example.com", Path: "/tenant/t1/bogus/name"}
	_, err := TenantFromURIs([]*url.URL{malformed}, "example.com")
	if !errors.Is(err, ErrKindInvalid) {
		t.Fatalf("err = %v, want ErrKindInvalid", err)
	}
}
