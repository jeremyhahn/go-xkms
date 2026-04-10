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

package transport

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
)

func TestPageRequest_Normalize_Defaults(t *testing.T) {
	p := PageRequest{}
	p.Normalize()

	if p.PageSize != DefaultPageSize {
		t.Errorf("expected PageSize=%d, got %d", DefaultPageSize, p.PageSize)
	}
	if p.Page != 0 {
		t.Errorf("expected Page=0, got %d", p.Page)
	}
}

func TestPageRequest_Normalize_NegativePage(t *testing.T) {
	p := PageRequest{Page: -5, PageSize: 10}
	p.Normalize()

	if p.Page != 0 {
		t.Errorf("expected Page=0 after clamping, got %d", p.Page)
	}
	if p.PageSize != 10 {
		t.Errorf("expected PageSize=10, got %d", p.PageSize)
	}
}

func TestPageRequest_Normalize_PreservesValid(t *testing.T) {
	p := PageRequest{Page: 3, PageSize: 50, SortField: "Name", SortOrder: 1}
	p.Normalize()

	if p.Page != 3 {
		t.Errorf("expected Page=3, got %d", p.Page)
	}
	if p.PageSize != 50 {
		t.Errorf("expected PageSize=50, got %d", p.PageSize)
	}
	if p.SortField != "Name" {
		t.Errorf("expected SortField=Name, got %s", p.SortField)
	}
	if p.SortOrder != 1 {
		t.Errorf("expected SortOrder=1, got %d", p.SortOrder)
	}
}

func TestPageRequest_Normalize_ZeroPageSize(t *testing.T) {
	p := PageRequest{Page: 1, PageSize: 0}
	p.Normalize()

	if p.PageSize != DefaultPageSize {
		t.Errorf("expected PageSize=%d for zero input, got %d", DefaultPageSize, p.PageSize)
	}
}

func TestPageRequest_Normalize_NegativePageSize(t *testing.T) {
	p := PageRequest{Page: 1, PageSize: -10}
	p.Normalize()

	if p.PageSize != DefaultPageSize {
		t.Errorf("expected PageSize=%d for negative input, got %d", DefaultPageSize, p.PageSize)
	}
}

func TestPageRequest_IsUnpaginated(t *testing.T) {
	tests := []struct {
		name     string
		page     int
		expected bool
	}{
		{"page zero is unpaginated", 0, true},
		{"page one is paginated", 1, false},
		{"page two is paginated", 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PageRequest{Page: tt.page}
			if got := p.IsUnpaginated(); got != tt.expected {
				t.Errorf("IsUnpaginated()=%v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPageRequest_ToDAOPageQuery_Paginated(t *testing.T) {
	p := PageRequest{Page: 2, PageSize: 10, SortField: "ID", SortOrder: 1}
	q := p.ToDAOPageQuery()

	if q.Page != 2 {
		t.Errorf("expected Page=2, got %d", q.Page)
	}
	if q.PageSize != 10 {
		t.Errorf("expected PageSize=10, got %d", q.PageSize)
	}
	if q.SortField != "ID" {
		t.Errorf("expected SortField=ID, got %s", q.SortField)
	}
	if q.SortOrder != 1 {
		t.Errorf("expected SortOrder=1, got %d", q.SortOrder)
	}
}

func TestPageRequest_ToDAOPageQuery_Unpaginated(t *testing.T) {
	p := PageRequest{Page: 0, PageSize: 25, SortField: "Name"}
	q := p.ToDAOPageQuery()

	if q.Page != 1 {
		t.Errorf("expected Page=1 for unpaginated, got %d", q.Page)
	}
	if q.PageSize != 100000 {
		t.Errorf("expected large PageSize for unpaginated, got %d", q.PageSize)
	}
	if q.SortField != "Name" {
		t.Errorf("expected SortField=Name, got %s", q.SortField)
	}
}

func TestPageResponseFromDAO(t *testing.T) {
	result := dao.PageResult[string]{
		Entities: []string{"a", "b", "c"},
		Page:     2,
		PageSize: 3,
		Total:    10,
		HasMore:  true,
	}

	resp := PageResponseFromDAO(result)

	if resp.Page != 2 {
		t.Errorf("expected Page=2, got %d", resp.Page)
	}
	if resp.PageSize != 3 {
		t.Errorf("expected PageSize=3, got %d", resp.PageSize)
	}
	if resp.Total != 10 {
		t.Errorf("expected Total=10, got %d", resp.Total)
	}
	if !resp.HasMore {
		t.Error("expected HasMore=true")
	}
}

func TestPageResponseFromDAO_Empty(t *testing.T) {
	result := dao.PageResult[int]{
		Entities: nil,
		Page:     1,
		PageSize: 25,
		Total:    0,
		HasMore:  false,
	}

	resp := PageResponseFromDAO(result)

	if resp.Page != 1 {
		t.Errorf("expected Page=1, got %d", resp.Page)
	}
	if resp.PageSize != 25 {
		t.Errorf("expected PageSize=25, got %d", resp.PageSize)
	}
	if resp.Total != 0 {
		t.Errorf("expected Total=0, got %d", resp.Total)
	}
	if resp.HasMore {
		t.Error("expected HasMore=false")
	}
}

func TestPageResponseFromDAO_RoundTrip(t *testing.T) {
	// Build a PageRequest, convert to DAO query, simulate a DAO result, convert back.
	req := PageRequest{Page: 3, PageSize: 5, SortField: "Created", SortOrder: 1}
	req.Normalize()
	q := req.ToDAOPageQuery()

	// Simulate DAO returning a page.
	daoResult := dao.PageResult[string]{
		Entities: []string{"x", "y"},
		Page:     q.Page,
		PageSize: q.PageSize,
		Total:    12,
		HasMore:  false,
	}

	resp := PageResponseFromDAO(daoResult)

	if resp.Page != 3 {
		t.Errorf("round-trip Page: expected 3, got %d", resp.Page)
	}
	if resp.PageSize != 5 {
		t.Errorf("round-trip PageSize: expected 5, got %d", resp.PageSize)
	}
	if resp.Total != 12 {
		t.Errorf("round-trip Total: expected 12, got %d", resp.Total)
	}
	if resp.HasMore {
		t.Error("round-trip: expected HasMore=false")
	}
}

func TestApplyPagination_Unpaginated(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	pr := PageRequest{Page: 0}

	result, resp := ApplyPagination(items, pr)

	if len(result) != 5 {
		t.Errorf("expected 5 items, got %d", len(result))
	}
	if resp.Total != 5 {
		t.Errorf("expected Total=5, got %d", resp.Total)
	}
	if resp.HasMore {
		t.Error("expected HasMore=false for unpaginated")
	}
	if resp.Page != 1 {
		t.Errorf("expected Page=1, got %d", resp.Page)
	}
}

func TestApplyPagination_FirstPage(t *testing.T) {
	items := []int{1, 2, 3, 4, 5, 6, 7}
	pr := PageRequest{Page: 1, PageSize: 3}

	result, resp := ApplyPagination(items, pr)

	if len(result) != 3 {
		t.Fatalf("expected 3 items, got %d", len(result))
	}
	if result[0] != 1 || result[2] != 3 {
		t.Errorf("expected [1,2,3], got %v", result)
	}
	if resp.Total != 7 {
		t.Errorf("expected Total=7, got %d", resp.Total)
	}
	if !resp.HasMore {
		t.Error("expected HasMore=true")
	}
}

func TestApplyPagination_LastPage(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}
	pr := PageRequest{Page: 2, PageSize: 3}

	result, resp := ApplyPagination(items, pr)

	if len(result) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result))
	}
	if result[0] != 4 || result[1] != 5 {
		t.Errorf("expected [4,5], got %v", result)
	}
	if resp.HasMore {
		t.Error("expected HasMore=false on last page")
	}
}

func TestApplyPagination_BeyondRange(t *testing.T) {
	items := []string{"a", "b"}
	pr := PageRequest{Page: 10, PageSize: 5}

	result, resp := ApplyPagination(items, pr)

	if result != nil {
		t.Errorf("expected nil result for out-of-range page, got %v", result)
	}
	if resp.Total != 2 {
		t.Errorf("expected Total=2, got %d", resp.Total)
	}
	if resp.HasMore {
		t.Error("expected HasMore=false")
	}
}

func TestApplyPagination_EmptySlice(t *testing.T) {
	var items []string
	pr := PageRequest{Page: 1, PageSize: 10}

	result, resp := ApplyPagination(items, pr)

	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
	if resp.Total != 0 {
		t.Errorf("expected Total=0, got %d", resp.Total)
	}
}

func TestApplyPagination_ExactPageBoundary(t *testing.T) {
	items := []int{1, 2, 3, 4, 5, 6}
	pr := PageRequest{Page: 2, PageSize: 3}

	result, resp := ApplyPagination(items, pr)

	if len(result) != 3 {
		t.Fatalf("expected 3 items, got %d", len(result))
	}
	if resp.HasMore {
		t.Error("expected HasMore=false when last item is at page boundary")
	}
}

func TestApplyPagination_DefaultPageSize(t *testing.T) {
	// Page=1 with PageSize=0 triggers Normalize to set DefaultPageSize
	items := make([]int, 50)
	for i := range items {
		items[i] = i
	}
	pr := PageRequest{Page: 1, PageSize: 0}

	result, resp := ApplyPagination(items, pr)

	if len(result) != DefaultPageSize {
		t.Errorf("expected %d items with default page size, got %d", DefaultPageSize, len(result))
	}
	if resp.PageSize != DefaultPageSize {
		t.Errorf("expected PageSize=%d, got %d", DefaultPageSize, resp.PageSize)
	}
	if !resp.HasMore {
		t.Error("expected HasMore=true with 50 items and default page size")
	}
}

func TestPageRequestFromQuery_AllParams(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "page=2&page_size=10&sort_field=name&sort_order=1",
		},
	}

	pr := PageRequestFromQuery(r)

	if pr.Page != 2 {
		t.Errorf("expected Page=2, got %d", pr.Page)
	}
	if pr.PageSize != 10 {
		t.Errorf("expected PageSize=10, got %d", pr.PageSize)
	}
	if pr.SortField != "name" {
		t.Errorf("expected SortField=name, got %s", pr.SortField)
	}
	if pr.SortOrder != 1 {
		t.Errorf("expected SortOrder=1, got %d", pr.SortOrder)
	}
}

func TestPageRequestFromQuery_NoParams(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{RawQuery: ""},
	}

	pr := PageRequestFromQuery(r)

	if pr.Page != 0 {
		t.Errorf("expected Page=0 (unpaginated), got %d", pr.Page)
	}
	if pr.PageSize != 0 {
		t.Errorf("expected PageSize=0 (will be normalized), got %d", pr.PageSize)
	}
}

func TestPageRequestFromQuery_InvalidValues(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "page=abc&page_size=xyz",
		},
	}

	pr := PageRequestFromQuery(r)

	// Invalid values should parse to zero
	if pr.Page != 0 {
		t.Errorf("expected Page=0 for invalid input, got %d", pr.Page)
	}
	if pr.PageSize != 0 {
		t.Errorf("expected PageSize=0 for invalid input, got %d", pr.PageSize)
	}
}

func TestPageRequestFromQuery_PartialParams(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "page=3&sort_field=created",
		},
	}

	pr := PageRequestFromQuery(r)

	if pr.Page != 3 {
		t.Errorf("expected Page=3, got %d", pr.Page)
	}
	if pr.PageSize != 0 {
		t.Errorf("expected PageSize=0 (missing), got %d", pr.PageSize)
	}
	if pr.SortField != "created" {
		t.Errorf("expected SortField=created, got %s", pr.SortField)
	}
	if pr.SortOrder != 0 {
		t.Errorf("expected SortOrder=0 (default), got %d", pr.SortOrder)
	}
}

// Tests for ListOption and BuildPageRequest

func TestBuildPageRequest_NoOptions(t *testing.T) {
	pr := BuildPageRequest()
	if pr.Page != 0 {
		t.Errorf("expected Page=0, got %d", pr.Page)
	}
	if pr.PageSize != 0 {
		t.Errorf("expected PageSize=0, got %d", pr.PageSize)
	}
	if !pr.IsUnpaginated() {
		t.Error("expected unpaginated request when no options provided")
	}
}

func TestBuildPageRequest_WithPage(t *testing.T) {
	pr := BuildPageRequest(WithPage(3))
	if pr.Page != 3 {
		t.Errorf("expected Page=3, got %d", pr.Page)
	}
}

func TestBuildPageRequest_WithPageSize(t *testing.T) {
	pr := BuildPageRequest(WithPageSize(50))
	if pr.PageSize != 50 {
		t.Errorf("expected PageSize=50, got %d", pr.PageSize)
	}
}

func TestBuildPageRequest_WithSortField(t *testing.T) {
	pr := BuildPageRequest(WithSortField("key_id"))
	if pr.SortField != "key_id" {
		t.Errorf("expected SortField=key_id, got %s", pr.SortField)
	}
}

func TestBuildPageRequest_WithSortDesc(t *testing.T) {
	pr := BuildPageRequest(WithSortDesc())
	if pr.SortOrder != SortOrderDesc {
		t.Errorf("expected SortOrder=%d, got %d", SortOrderDesc, pr.SortOrder)
	}
}

func TestBuildPageRequest_WithSortAsc(t *testing.T) {
	pr := BuildPageRequest(WithSortDesc(), WithSortAsc())
	if pr.SortOrder != SortOrderAsc {
		t.Errorf("expected SortOrder=%d, got %d", SortOrderAsc, pr.SortOrder)
	}
}

func TestBuildPageRequest_AllOptions(t *testing.T) {
	pr := BuildPageRequest(
		WithPage(2),
		WithPageSize(10),
		WithSortField("created_at"),
		WithSortDesc(),
	)
	if pr.Page != 2 {
		t.Errorf("expected Page=2, got %d", pr.Page)
	}
	if pr.PageSize != 10 {
		t.Errorf("expected PageSize=10, got %d", pr.PageSize)
	}
	if pr.SortField != "created_at" {
		t.Errorf("expected SortField=created_at, got %s", pr.SortField)
	}
	if pr.SortOrder != SortOrderDesc {
		t.Errorf("expected SortOrder=%d, got %d", SortOrderDesc, pr.SortOrder)
	}
}

// Tests for AppendPaginationQuery

func TestAppendPaginationQuery_Unpaginated(t *testing.T) {
	path := AppendPaginationQuery("/api/v1/keys", PageRequest{}, false)
	if path != "/api/v1/keys" {
		t.Errorf("expected unchanged path, got %s", path)
	}
}

func TestAppendPaginationQuery_WithPagination(t *testing.T) {
	pr := PageRequest{Page: 2, PageSize: 10}
	path := AppendPaginationQuery("/api/v1/keys", pr, false)
	expected := "/api/v1/keys?page=2&page_size=10"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestAppendPaginationQuery_ExistingQuery(t *testing.T) {
	pr := PageRequest{Page: 1, PageSize: 25}
	path := AppendPaginationQuery("/api/v1/keys?backend=software", pr, true)
	expected := "/api/v1/keys?backend=software&page=1&page_size=25"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestAppendPaginationQuery_WithSortField(t *testing.T) {
	pr := PageRequest{Page: 1, PageSize: 25, SortField: "key_id"}
	path := AppendPaginationQuery("/api/v1/keys", pr, false)
	expected := "/api/v1/keys?page=1&page_size=25&sort_field=key_id"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestAppendPaginationQuery_WithSortDesc(t *testing.T) {
	pr := PageRequest{Page: 1, PageSize: 25, SortOrder: SortOrderDesc}
	path := AppendPaginationQuery("/api/v1/keys", pr, false)
	expected := "/api/v1/keys?page=1&page_size=25&sort_order=1"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestAppendPaginationQuery_AllParams(t *testing.T) {
	pr := PageRequest{Page: 3, PageSize: 50, SortField: "algorithm", SortOrder: SortOrderDesc}
	path := AppendPaginationQuery("/api/v1/certs?backend=tpm2", pr, true)
	expected := "/api/v1/certs?backend=tpm2&page=3&page_size=50&sort_field=algorithm&sort_order=1"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestAppendPaginationQuery_UnpaginatedWithExistingQuery(t *testing.T) {
	pr := PageRequest{}
	path := AppendPaginationQuery("/api/v1/keys?backend=software", pr, true)
	if path != "/api/v1/keys?backend=software" {
		t.Errorf("expected unchanged path for unpaginated request, got %s", path)
	}
}
