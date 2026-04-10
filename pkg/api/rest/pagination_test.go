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

package rest

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

func TestParsePageRequest_Defaults(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: ""}}
	pr := parsePageRequest(r)

	if pr.Page != 0 {
		t.Errorf("expected Page=0 (unpaginated), got %d", pr.Page)
	}
	if pr.PageSize != transport.DefaultPageSize {
		t.Errorf("expected PageSize=%d, got %d", transport.DefaultPageSize, pr.PageSize)
	}
	if pr.SortField != "" {
		t.Errorf("expected empty SortField, got %q", pr.SortField)
	}
	if pr.SortOrder != 0 {
		t.Errorf("expected SortOrder=0, got %d", pr.SortOrder)
	}
}

func TestParsePageRequest_AllParams(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "page=3&page_size=10&sort_field=name&sort_order=desc"}}
	pr := parsePageRequest(r)

	if pr.Page != 3 {
		t.Errorf("expected Page=3, got %d", pr.Page)
	}
	if pr.PageSize != 10 {
		t.Errorf("expected PageSize=10, got %d", pr.PageSize)
	}
	if pr.SortField != "name" {
		t.Errorf("expected SortField=name, got %q", pr.SortField)
	}
	if pr.SortOrder != 1 {
		t.Errorf("expected SortOrder=1 (desc), got %d", pr.SortOrder)
	}
}

func TestParsePageRequest_SortOrderNumeric(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "sort_order=1"}}
	pr := parsePageRequest(r)

	if pr.SortOrder != 1 {
		t.Errorf("expected SortOrder=1, got %d", pr.SortOrder)
	}
}

func TestParsePageRequest_SortOrderAscending(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "sort_order=asc"}}
	pr := parsePageRequest(r)

	if pr.SortOrder != 0 {
		t.Errorf("expected SortOrder=0 (asc), got %d", pr.SortOrder)
	}
}

func TestParsePageRequest_InvalidPage(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "page=abc&page_size=xyz"}}
	pr := parsePageRequest(r)

	// Invalid values default to 0 for page and DefaultPageSize for page_size
	if pr.Page != 0 {
		t.Errorf("expected Page=0 for invalid input, got %d", pr.Page)
	}
	if pr.PageSize != transport.DefaultPageSize {
		t.Errorf("expected PageSize=%d for invalid input, got %d", transport.DefaultPageSize, pr.PageSize)
	}
}

func TestParsePageRequest_NegativePage(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "page=-5"}}
	pr := parsePageRequest(r)

	if pr.Page != 0 {
		t.Errorf("expected Page=0 (clamped from negative), got %d", pr.Page)
	}
}

func TestApplyPagination_Unpaginated(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	pr := transport.PageRequest{Page: 0, PageSize: 25}
	pr.Normalize()

	result, pageResp := applyPagination(items, pr)

	if len(result) != 5 {
		t.Errorf("expected all 5 items, got %d", len(result))
	}
	if pageResp.Total != 5 {
		t.Errorf("expected Total=5, got %d", pageResp.Total)
	}
	if pageResp.HasMore {
		t.Error("expected HasMore=false for unpaginated")
	}
	if pageResp.Page != 1 {
		t.Errorf("expected Page=1, got %d", pageResp.Page)
	}
}

func TestApplyPagination_FirstPage(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	pr := transport.PageRequest{Page: 1, PageSize: 2}

	result, pageResp := applyPagination(items, pr)

	if len(result) != 2 {
		t.Errorf("expected 2 items, got %d", len(result))
	}
	if result[0] != "a" || result[1] != "b" {
		t.Errorf("expected [a b], got %v", result)
	}
	if pageResp.Total != 5 {
		t.Errorf("expected Total=5, got %d", pageResp.Total)
	}
	if !pageResp.HasMore {
		t.Error("expected HasMore=true")
	}
}

func TestApplyPagination_MiddlePage(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	pr := transport.PageRequest{Page: 2, PageSize: 2}

	result, pageResp := applyPagination(items, pr)

	if len(result) != 2 {
		t.Errorf("expected 2 items, got %d", len(result))
	}
	if result[0] != "c" || result[1] != "d" {
		t.Errorf("expected [c d], got %v", result)
	}
	if !pageResp.HasMore {
		t.Error("expected HasMore=true")
	}
}

func TestApplyPagination_LastPage(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	pr := transport.PageRequest{Page: 3, PageSize: 2}

	result, pageResp := applyPagination(items, pr)

	if len(result) != 1 {
		t.Errorf("expected 1 item, got %d", len(result))
	}
	if result[0] != "e" {
		t.Errorf("expected [e], got %v", result)
	}
	if pageResp.HasMore {
		t.Error("expected HasMore=false on last page")
	}
}

func TestApplyPagination_BeyondRange(t *testing.T) {
	items := []string{"a", "b", "c"}
	pr := transport.PageRequest{Page: 10, PageSize: 2}

	result, pageResp := applyPagination(items, pr)

	if result != nil {
		t.Errorf("expected nil result for beyond-range page, got %v", result)
	}
	if pageResp.Total != 3 {
		t.Errorf("expected Total=3, got %d", pageResp.Total)
	}
	if pageResp.HasMore {
		t.Error("expected HasMore=false for beyond-range page")
	}
}

func TestApplyPagination_EmptySlice(t *testing.T) {
	var items []string
	pr := transport.PageRequest{Page: 1, PageSize: 10}

	result, pageResp := applyPagination(items, pr)

	if result != nil {
		t.Errorf("expected nil result for empty slice, got %v", result)
	}
	if pageResp.Total != 0 {
		t.Errorf("expected Total=0, got %d", pageResp.Total)
	}
	if pageResp.HasMore {
		t.Error("expected HasMore=false for empty slice")
	}
}

func TestApplyPagination_ExactFit(t *testing.T) {
	items := []string{"a", "b", "c", "d"}
	pr := transport.PageRequest{Page: 2, PageSize: 2}

	result, pageResp := applyPagination(items, pr)

	if len(result) != 2 {
		t.Errorf("expected 2 items, got %d", len(result))
	}
	if pageResp.HasMore {
		t.Error("expected HasMore=false when items fit exactly")
	}
}

func TestApplyPagination_SingleItemPage(t *testing.T) {
	items := []string{"a", "b", "c"}
	pr := transport.PageRequest{Page: 2, PageSize: 1}

	result, pageResp := applyPagination(items, pr)

	if len(result) != 1 {
		t.Errorf("expected 1 item, got %d", len(result))
	}
	if result[0] != "b" {
		t.Errorf("expected b, got %s", result[0])
	}
	if !pageResp.HasMore {
		t.Error("expected HasMore=true")
	}
	if pageResp.Total != 3 {
		t.Errorf("expected Total=3, got %d", pageResp.Total)
	}
}

func TestApplyPagination_UnpaginatedEmpty(t *testing.T) {
	var items []int
	pr := transport.PageRequest{Page: 0, PageSize: 25}
	pr.Normalize()

	result, pageResp := applyPagination(items, pr)

	if len(result) != 0 {
		t.Errorf("expected 0 items, got %d", len(result))
	}
	if pageResp.Total != 0 {
		t.Errorf("expected Total=0, got %d", pageResp.Total)
	}
	if pageResp.HasMore {
		t.Error("expected HasMore=false")
	}
}

func TestApplyPagination_LargePageSize(t *testing.T) {
	items := []string{"a", "b"}
	pr := transport.PageRequest{Page: 1, PageSize: 1000}

	result, pageResp := applyPagination(items, pr)

	if len(result) != 2 {
		t.Errorf("expected 2 items, got %d", len(result))
	}
	if pageResp.HasMore {
		t.Error("expected HasMore=false when page size exceeds total")
	}
}
