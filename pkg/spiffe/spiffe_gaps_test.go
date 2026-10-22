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
	id := ID{TenantID: "acme", Kind: KindUser, Name: "alice"}
	want := "spiffe://acme/user/alice"
	if got := id.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestID_String_Invalid(t *testing.T) {
	id := ID{TenantID: "", Kind: KindUser, Name: "alice"}
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
	u := &url.URL{Scheme: "spiffe", Host: "", Path: "/user/name"}
	_, ok, err := ParseID(u)
	if ok {
		t.Fatalf("expected ok=false for empty trust domain")
	}
	if !errors.Is(err, ErrTrustDomainEmpty) {
		t.Fatalf("err = %v, want ErrTrustDomainEmpty", err)
	}
}

// TestParseID_NonPrincipalPathSkipped proves a SPIFFE ID whose path is not
// exactly /<user|svc>/<name> is another workload's identity, not a tenant
// principal, and is skipped rather than refused.
func TestParseID_NonPrincipalPathSkipped(t *testing.T) {
	for _, path := range []string{"/user", "/bogus/name", "/user/name/extra", "/tenant/t1/user/name"} {
		t.Run(path, func(t *testing.T) {
			u := &url.URL{Scheme: "spiffe", Host: "example.com", Path: path}
			_, ok, err := ParseID(u)
			if ok || err != nil {
				t.Fatalf("path %q should be skipped: ok=%v err=%v", path, ok, err)
			}
		})
	}
}

func TestTenantFromURIs_EmptyPinResolves(t *testing.T) {
	u, err := BuildURI("cluster.internal", "tenant-x", KindService, "worker")
	if err != nil {
		t.Fatalf("BuildURI: %v", err)
	}
	id, err := TenantFromURIs([]*url.URL{u}, "")
	if err != nil {
		t.Fatalf("expected resolution with empty pin, got %v", err)
	}
	if id.TenantID != "tenant-x" || id.Kind != KindService || id.Name != "worker" {
		t.Fatalf("id = %+v", id)
	}
}

func TestTenantFromURIs_MalformedSANPropagatesParseError(t *testing.T) {
	malformed := &url.URL{Scheme: "spiffe", Host: "example.com", Path: "/user//name"}
	_, err := TenantFromURIs([]*url.URL{malformed}, "example.com")
	if !errors.Is(err, ErrSegmentEmpty) {
		t.Fatalf("err = %v, want ErrSegmentEmpty", err)
	}
}
