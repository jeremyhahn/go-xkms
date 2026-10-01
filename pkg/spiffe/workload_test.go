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

package spiffe

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestParseTrustDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{name: "simple", input: "example.org"},
		{name: "digits dashes underscores", input: "td-1_a.example"},
		{name: "empty", input: "", wantErr: ErrTrustDomainEmpty},
		{name: "uppercase", input: "Example.org", wantErr: ErrTrustDomainCharacters},
		{name: "scheme included", input: "spiffe://example.org", wantErr: ErrTrustDomainCharacters},
		{name: "port", input: "example.org:443", wantErr: ErrTrustDomainCharacters},
		{name: "too long", input: strings.Repeat("a", 256), wantErr: ErrTrustDomainTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td, err := ParseTrustDomain(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseTrustDomain(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTrustDomain(%q) unexpected error: %v", tt.input, err)
			}
			if td.Name() != tt.input || td.String() != "spiffe://"+tt.input {
				t.Fatalf("got name %q string %q", td.Name(), td.String())
			}
		})
	}
}

func TestTrustDomainID(t *testing.T) {
	td, err := ParseTrustDomain("example.org")
	if err != nil {
		t.Fatal(err)
	}

	id, err := td.ID("tenant", "acme", "svc", "web")
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if got, want := id.String(), "spiffe://example.org/tenant/acme/svc/web"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if id.Path() != "/tenant/acme/svc/web" || !id.MemberOf(td) {
		t.Fatalf("path %q member %v", id.Path(), id.MemberOf(td))
	}
	if u := id.URL(); u.String() != id.String() {
		t.Fatalf("URL() = %q, want %q", u.String(), id.String())
	}

	root, err := td.ID()
	if err != nil || root.String() != "spiffe://example.org" {
		t.Fatalf("trust-domain ID = %q, %v", root.String(), err)
	}

	for _, bad := range []struct {
		segments []string
		want     error
	}{
		{[]string{"a/b"}, ErrSegmentCharacters},
		{[]string{""}, ErrSegmentEmpty},
		{[]string{".."}, ErrSegmentDotted},
		{[]string{"user@example"}, ErrSegmentCharacters},
	} {
		if _, err := td.ID(bad.segments...); !errors.Is(err, bad.want) {
			t.Errorf("ID(%q) error = %v, want %v", bad.segments, err, bad.want)
		}
	}

	if _, err := (TrustDomain{}).ID("a"); !errors.Is(err, ErrTrustDomainEmpty) {
		t.Fatalf("zero trust domain error = %v", err)
	}
	if _, err := (TrustDomain{}).IDFromPath("/a"); !errors.Is(err, ErrTrustDomainEmpty) {
		t.Fatalf("zero trust domain IDFromPath error = %v", err)
	}

	long := strings.Repeat("a", 250)
	segments := make([]string, 0, 9)
	for i := 0; i < 9; i++ {
		segments = append(segments, long)
	}
	if _, err := td.ID(segments...); !errors.Is(err, ErrIDTooLong) {
		t.Fatalf("over-long ID error = %v", err)
	}
}

func TestParseWorkloadID(t *testing.T) {
	tests := []struct {
		input   string
		wantErr error
	}{
		{input: "spiffe://example.org/ns/prod/sa/web"},
		{input: "spiffe://example.org"},
		{input: "https://example.org/a", wantErr: ErrSchemeInvalid},
		{input: "spiffe://example.org/a/", wantErr: ErrSegmentEmpty},
		{input: "spiffe://example.org//a", wantErr: ErrSegmentEmpty},
		{input: "spiffe://example.org/a/../b", wantErr: ErrSegmentDotted},
		{input: "spiffe://example.org/a?x=1", wantErr: ErrIDComponents},
		{input: "spiffe://example.org/a#frag", wantErr: ErrIDComponents},
		{input: "spiffe://user@example.org/a", wantErr: ErrIDComponents},
		{input: "spiffe://example.org:8443/a", wantErr: ErrTrustDomainCharacters},
		{input: "spiffe:///a", wantErr: ErrTrustDomainEmpty},
		{input: "spiffe://example.org/" + strings.Repeat("a", 2048), wantErr: ErrIDTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.input[:min(len(tt.input), 48)], func(t *testing.T) {
			id, err := ParseWorkloadID(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseWorkloadID error = %v, want %v", err, tt.wantErr)
				}
				var invalid *InvalidIDError
				if errors.As(err, &invalid) && invalid.Error() == "" {
					t.Fatal("InvalidIDError renders an empty message")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseWorkloadID: %v", err)
			}
			if id.String() != tt.input {
				t.Fatalf("round trip %q -> %q", tt.input, id.String())
			}
		})
	}
}

func TestWorkloadIDFromURL(t *testing.T) {
	u, err := url.Parse("spiffe://example.org/tenant/a/svc/b")
	if err != nil {
		t.Fatal(err)
	}
	id, err := WorkloadIDFromURL(u)
	if err != nil || id.String() != u.String() {
		t.Fatalf("WorkloadIDFromURL = %q, %v", id.String(), err)
	}

	if _, err := WorkloadIDFromURL(nil); !errors.Is(err, ErrSchemeInvalid) {
		t.Fatalf("nil URL error = %v", err)
	}
	withQuery := &url.URL{Scheme: "spiffe", Host: "example.org", Path: "/a", RawQuery: "x=1"}
	if _, err := WorkloadIDFromURL(withQuery); !errors.Is(err, ErrIDComponents) {
		t.Fatalf("query URL error = %v", err)
	}
	withPort := &url.URL{Scheme: "spiffe", Host: "example.org:1", Path: "/a"}
	if _, err := WorkloadIDFromURL(withPort); !errors.Is(err, ErrIDComponents) {
		t.Fatalf("port URL error = %v", err)
	}
	opaque := &url.URL{Scheme: "spiffe", Opaque: "example.org/a"}
	if _, err := WorkloadIDFromURL(opaque); !errors.Is(err, ErrIDComponents) {
		t.Fatalf("opaque URL error = %v", err)
	}
}

func TestHasPathPrefix(t *testing.T) {
	id, err := ParseWorkloadID("spiffe://example.org/tenant/acme/svc/web")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"/":                         true,
		"/tenant":                   true,
		"/tenant/acme":              true,
		"/tenant/acme/svc/web":      true,
		"/tenant/ac":                false,
		"/tenant/acme/svc/web/more": false,
		"/other":                    false,
		"":                          false,
		"/tenant/":                  false,
		"tenant":                    false,
	}
	for prefix, want := range cases {
		if got := id.HasPathPrefix(prefix); got != want {
			t.Errorf("HasPathPrefix(%q) = %v, want %v", prefix, got, want)
		}
	}
	if (WorkloadID{}).HasPathPrefix("/") {
		t.Fatal("zero ID must not match any prefix")
	}
}

func TestValidatePathPrefix(t *testing.T) {
	if err := ValidatePathPrefix("/"); err != nil {
		t.Fatalf("root prefix: %v", err)
	}
	if err := ValidatePathPrefix("/tenant/acme"); err != nil {
		t.Fatalf("valid prefix: %v", err)
	}
	for _, bad := range []string{"", "tenant", "/tenant/", "/a//b"} {
		if err := ValidatePathPrefix(bad); !errors.Is(err, ErrPathPrefixInvalid) {
			t.Errorf("ValidatePathPrefix(%q) = %v, want ErrPathPrefixInvalid", bad, err)
		}
	}
}

func TestWorkloadIDZeroAndMembership(t *testing.T) {
	var zero WorkloadID
	if !zero.IsZero() || zero.String() != "" {
		t.Fatalf("zero ID: IsZero %v String %q", zero.IsZero(), zero.String())
	}
	a, err := ParseTrustDomain("a.example")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseTrustDomain("b.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.IDFromPath("/x")
	if err != nil {
		t.Fatal(err)
	}
	if !id.MemberOf(a) || id.MemberOf(b) || zero.MemberOf(a) {
		t.Fatal("MemberOf returned the wrong answer")
	}
	if id.TrustDomain() != a {
		t.Fatal("TrustDomain() does not return the issuing trust domain")
	}
	if _, err := a.IDFromPath("x"); !errors.Is(err, ErrSegmentEmpty) {
		t.Fatalf("relative path error = %v", err)
	}
}
