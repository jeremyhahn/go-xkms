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

func TestBuildURI_Canonical(t *testing.T) {
	u, err := BuildURI("example.com", "tenant-acme", KindUser, "alice")
	if err != nil {
		t.Fatalf("BuildURI: %v", err)
	}
	if got, want := u.String(), "spiffe://tenant-acme/user/alice"; got != want {
		t.Fatalf("URI = %q, want %q", got, want)
	}
}

func TestBuildURI_Validation(t *testing.T) {
	cases := []struct {
		name    string
		td      string
		tenant  string
		kind    string
		wl      string
		wantErr error
	}{
		{"empty trust domain", "", "t", KindUser, "n", ErrTrustDomainEmpty},
		{"empty tenant", "td", "", KindUser, "n", ErrTenantEmpty},
		{"bad kind", "td", "t", "bogus", "n", ErrKindInvalid},
		{"empty name", "td", "t", KindUser, "", ErrNameEmpty},
		{"tenant is the cluster trust domain", "td", "td", KindUser, "n", ErrTenantIsClusterTrustDomain},
		{"tenant is not a trust domain name", "td", "Tenant A", KindUser, "n", ErrTrustDomainCharacters},
		{"name is not a path segment", "td", "t", KindUser, "a/b", ErrSegmentCharacters},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildURI(tc.td, tc.tenant, tc.kind, tc.wl)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateName_AcceptsSegmentNames checks the names a workload may carry:
// one path segment of [A-Za-z0-9._-].
func TestValidateName_AcceptsSegmentNames(t *testing.T) {
	for _, name := range []string{"fleet-agent", "node_01", "a.b", "X9"} {
		if err := ValidateName(name); err != nil {
			t.Fatalf("ValidateName(%q) = %v, want nil", name, err)
		}
	}
}

// TestValidateName_RefusesNonSegmentNames checks each refusal carries the
// sentinel naming its cause.
func TestValidateName_RefusesNonSegmentNames(t *testing.T) {
	cases := []struct {
		name    string
		wantErr error
	}{
		{"", ErrNameEmpty},
		{"  ", ErrNameEmpty},
		{"a/b", ErrSegmentCharacters},
		{"agent one", ErrSegmentCharacters},
		{"agent@x", ErrSegmentCharacters},
		{"..", ErrSegmentDotted},
	}
	for _, tc := range cases {
		if err := ValidateName(tc.name); !errors.Is(err, tc.wantErr) {
			t.Fatalf("ValidateName(%q) = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestParseID_RoundTrip(t *testing.T) {
	u, _ := BuildURI("trust.internal", "t1", KindService, "billing")
	id, ok, err := ParseID(u)
	if err != nil || !ok {
		t.Fatalf("ParseID ok=%v err=%v", ok, err)
	}
	if id.TenantID != "t1" || id.Kind != KindService || id.Name != "billing" {
		t.Fatalf("parsed = %+v", id)
	}
}

func TestParseID_NonSPIFFESkipped(t *testing.T) {
	u, _ := url.Parse("https://example.com/foo")
	_, ok, err := ParseID(u)
	if ok || err != nil {
		t.Fatalf("non-spiffe URI should be skipped: ok=%v err=%v", ok, err)
	}
}

func TestParseID_NonTenantSPIFFESkipped(t *testing.T) {
	u, _ := url.Parse("spiffe://example.com/ns/default/sa/web")
	_, ok, err := ParseID(u)
	if ok || err != nil {
		t.Fatalf("non-tenant spiffe should be skipped: ok=%v err=%v", ok, err)
	}
}

// Scenario (b): TenantFromURIs extracts the tenant and REJECTS a foreign /
// absent trust domain (fail-closed).
func TestTenantFromURIs_TrustDomainPin(t *testing.T) {
	good, _ := BuildURI("example.com", "tenant-acme", KindUser, "alice")

	// Correct pin resolves.
	id, err := TenantFromURIs([]*url.URL{good}, "example.com")
	if err != nil {
		t.Fatalf("expected resolution, got %v", err)
	}
	if id.TenantID != "tenant-acme" {
		t.Fatalf("tenant = %q", id.TenantID)
	}

	// A tenant naming the cluster trust domain is refused.
	cluster, err := ID{TenantID: "example.com", Kind: KindUser, Name: "alice"}.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}
	if _, err := TenantFromURIs([]*url.URL{cluster}, "example.com"); !errors.Is(err, ErrTenantIsClusterTrustDomain) {
		t.Fatalf("expected ErrTenantIsClusterTrustDomain, got %v", err)
	}

	// SANs naming two tenants are refused rather than resolved to either.
	other, _ := BuildURI("example.com", "tenant-globex", KindUser, "alice")
	if _, err := TenantFromURIs([]*url.URL{good, other}, "example.com"); !errors.Is(err, ErrAmbiguousTenant) {
		t.Fatalf("expected ErrAmbiguousTenant, got %v", err)
	}

	// No SPIFFE SAN present.
	https, _ := url.Parse("https://example.com/x")
	if _, err := TenantFromURIs([]*url.URL{https}, "example.com"); !errors.Is(err, ErrNoTenantSPIFFEID) {
		t.Fatalf("expected ErrNoTenantSPIFFEID, got %v", err)
	}
}
