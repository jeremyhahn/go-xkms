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

package spiffe_test

import (
	"errors"
	"testing"

	pkgspiffe "github.com/jeremyhahn/go-xkms/pkg/spiffe"
	"github.com/jeremyhahn/go-xkms/sdk/go/spiffe"
)

// TestReexportsAreTheCanonicalTypes pins the aliases: a value built through the
// SDK is the pkg/spiffe value, so consumers and the CA agree on one type.
func TestReexportsAreTheCanonicalTypes(t *testing.T) {
	td, err := spiffe.ParseTrustDomain("example.org")
	if err != nil {
		t.Fatal(err)
	}
	id, err := buildCanonical(td)
	if err != nil {
		t.Fatal(err)
	}
	if !underTenant(id, "/tenant/acme") {
		t.Fatal("SDK WorkloadID lost its path")
	}
}

// buildCanonical takes the pkg/spiffe type; passing an SDK value to it only
// compiles while the SDK name is an alias.
func buildCanonical(td pkgspiffe.TrustDomain) (pkgspiffe.WorkloadID, error) {
	return td.ID("tenant", "acme", "svc", "web")
}

// underTenant takes the SDK type, closing the loop the other way.
func underTenant(id spiffe.WorkloadID, prefix string) bool {
	return id.HasPathPrefix(prefix)
}

func TestReexportedValidationErrors(t *testing.T) {
	if _, err := spiffe.ParseWorkloadID("spiffe://example.org/a/"); !errors.Is(err, spiffe.ErrSegmentEmpty) {
		t.Fatalf("trailing slash error = %v, want ErrSegmentEmpty", err)
	}
	var invalid *spiffe.InvalidIDError
	if _, err := spiffe.ParseTrustDomain("Bad"); !errors.As(err, &invalid) {
		t.Fatalf("ParseTrustDomain error %v is not an InvalidIDError", err)
	}
	if _, err := spiffe.BuildURI("example.org", "", spiffe.KindService, "web"); !errors.Is(err, spiffe.ErrTenantEmpty) {
		t.Fatalf("BuildURI error = %v, want ErrTenantEmpty", err)
	}
}
