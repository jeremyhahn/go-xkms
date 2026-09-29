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
	"errors"
	"math"
	"net/http"
	"net/url"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
	result := qrdbsdk.PageResult[string]{
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
	result := qrdbsdk.PageResult[int]{
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
	daoResult := qrdbsdk.PageResult[string]{
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

	pr, err := PageRequestFromQuery(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

// TestPageRequestFromQuery_SortOrderStringForms proves sort_order accepts
// the "asc"/"desc" string convention the REST API and its TypeScript SDK
// send on the wire, in addition to the plain integer form other transports
// use.
func TestPageRequestFromQuery_SortOrderStringForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    string
		want int
	}{
		{"desc", "desc", SortOrderDesc},
		{"asc", "asc", SortOrderAsc},
		{"numeric 1", "1", SortOrderDesc},
		{"numeric 0", "0", SortOrderAsc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{URL: &url.URL{RawQuery: "sort_order=" + tc.v}}

			pr, err := PageRequestFromQuery(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pr.SortOrder != tc.want {
				t.Errorf("expected SortOrder=%d, got %d", tc.want, pr.SortOrder)
			}
		})
	}
}

func TestPageRequestFromQuery_NoParams(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{RawQuery: ""},
	}

	pr, err := PageRequestFromQuery(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pr.Page != 0 {
		t.Errorf("expected Page=0 (unpaginated), got %d", pr.Page)
	}
	if pr.PageSize != 0 {
		t.Errorf("expected PageSize=0 (will be normalized), got %d", pr.PageSize)
	}
}

// TestPageRequestFromQuery_InvalidValues proves an unparsable pagination
// query parameter is rejected with a typed error instead of silently
// parsing to zero, which used to turn a caller's typo into an unpaginated
// "return everything" request (#701).
func TestPageRequestFromQuery_InvalidValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rawQuery  string
		wantParam string
	}{
		{"bad page", "page=abc", "page"},
		{"bad page_size", "page_size=xyz", "page_size"},
		{"bad sort_order", "sort_order=nope", "sort_order"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{URL: &url.URL{RawQuery: tc.rawQuery}}

			_, err := PageRequestFromQuery(r)
			if err == nil {
				t.Fatal("expected an error for an unparsable pagination parameter")
			}

			var invalid *InvalidPaginationParamError
			if !errors.As(err, &invalid) {
				t.Fatalf("expected *InvalidPaginationParamError, got %T", err)
			}
			if invalid.Param != tc.wantParam {
				t.Errorf("expected Param=%s, got %s", tc.wantParam, invalid.Param)
			}
		})
	}
}

func TestPageRequestFromQuery_PartialParams(t *testing.T) {
	r := &http.Request{
		URL: &url.URL{
			RawQuery: "page=3&sort_field=created",
		},
	}

	pr, err := PageRequestFromQuery(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

// TestWithPageRequest_AppliesEveryField proves the option copies a decoded
// PageRequest whole, so a transport handing its caller's pagination to a
// servicer loses neither the page nor the sort.
func TestWithPageRequest_AppliesEveryField(t *testing.T) {
	want := PageRequest{Page: 3, PageSize: 10, SortField: "KeyID", SortOrder: SortOrderDesc}
	if got := BuildPageRequest(WithPageRequest(want)); got != want {
		t.Fatalf("BuildPageRequest(WithPageRequest(%+v)) = %+v", want, got)
	}
}

// TestWithPageRequest_ZeroValueIsUnpaginated proves the zero PageRequest --
// what a transport decodes when its caller sent no pagination -- still asks
// for every result.
func TestWithPageRequest_ZeroValueIsUnpaginated(t *testing.T) {
	got := BuildPageRequest(WithPageSize(5), WithPageRequest(PageRequest{}))
	if !got.IsUnpaginated() || got.PageSize != 0 {
		t.Fatalf("expected an unpaginated request, got %+v", got)
	}
}

// Tests for hostile input to ApplyPagination (go-xkms#1262).
//
// ApplyPagination used to check IsUnpaginated (Page==0) before calling
// Normalize, which clamps a negative Page to zero. A Page of -1 was not
// unpaginated when checked, so it fell through to Normalize, came out as
// zero, and start := (0-1)*PageSize went negative -- items[start:end] then
// panicked. A page_size large enough that (Page-1)*PageSize itself
// overflowed int reached the same panic from the other direction. These
// prove every one of those inputs, plus the case actually reported in the
// issue, returns a PageResponse instead of panicking.

func TestApplyPagination_NoPanicOnHostileInput(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}

	for _, tc := range []struct {
		name string
		pr   PageRequest
	}{
		{"negative page", PageRequest{Page: -1, PageSize: 10}},
		{"negative page with normal page_size", PageRequest{Page: -1, PageSize: 2}},
		{"page one, negative page_size", PageRequest{Page: 1, PageSize: -10}},
		{"page zero is unpaginated, not hostile", PageRequest{Page: 0, PageSize: -10}},
		{"page_size larger than MaxPageSize", PageRequest{Page: 1, PageSize: math.MaxInt}},
		{"page far beyond range with oversized page_size", PageRequest{Page: 3, PageSize: math.MaxInt}},
		{"page large enough to overflow (page-1)*page_size", PageRequest{Page: math.MaxInt, PageSize: 10}},
		{"both page and page_size at their max", PageRequest{Page: math.MaxInt, PageSize: math.MaxInt}},
		{"page two beyond MaxInt/PageSize, would overflow with an uncapped page_size", PageRequest{Page: math.MaxInt / 5, PageSize: math.MaxInt}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ApplyPagination(%+v) panicked: %v", tc.pr, r)
				}
			}()

			result, resp := ApplyPagination(items, tc.pr)

			if len(result) > len(items) {
				t.Errorf("ApplyPagination(%+v) returned %d items, more than the %d available", tc.pr, len(result), len(items))
			}
			if resp.Total != len(items) {
				t.Errorf("ApplyPagination(%+v) resp.Total = %d, want %d", tc.pr, resp.Total, len(items))
			}
			if resp.PageSize > MaxPageSize {
				t.Errorf("ApplyPagination(%+v) resp.PageSize = %d, want <= MaxPageSize (%d)", tc.pr, resp.PageSize, MaxPageSize)
			}
		})
	}
}

// TestApplyPagination_NegativePageClampsToFirstPage proves the specific
// regression from the issue: a negative Page returns page one instead of
// panicking on a negative slice start.
func TestApplyPagination_NegativePageClampsToFirstPage(t *testing.T) {
	items := []int{1, 2, 3}
	result, resp := ApplyPagination(items, PageRequest{Page: -1, PageSize: 2})

	if resp.Page != 1 {
		t.Errorf("expected Page=1, got %d", resp.Page)
	}
	if len(result) != 2 || result[0] != 1 || result[1] != 2 {
		t.Errorf("expected first page [1,2], got %v", result)
	}
}

// TestApplyPagination_PageSizeCappedAtMaxPageSize proves ApplyPagination
// never hands back a page larger than MaxPageSize, even when the caller
// asked for one, regardless of how the PageRequest was built.
func TestApplyPagination_PageSizeCappedAtMaxPageSize(t *testing.T) {
	items := make([]int, MaxPageSize+500)
	for i := range items {
		items[i] = i
	}

	result, resp := ApplyPagination(items, PageRequest{Page: 1, PageSize: math.MaxInt})

	if len(result) != MaxPageSize {
		t.Errorf("expected %d items, got %d", MaxPageSize, len(result))
	}
	if resp.PageSize != MaxPageSize {
		t.Errorf("expected resp.PageSize=%d, got %d", MaxPageSize, resp.PageSize)
	}
	if !resp.HasMore {
		t.Error("expected HasMore=true with more items than MaxPageSize")
	}
}

func TestPageRequest_Normalize_CapsPageSizeAtMax(t *testing.T) {
	p := PageRequest{Page: 1, PageSize: MaxPageSize + 1}
	p.Normalize()

	if p.PageSize != MaxPageSize {
		t.Errorf("expected PageSize capped to MaxPageSize (%d), got %d", MaxPageSize, p.PageSize)
	}
}

func TestPageRequest_Normalize_PreservesPageSizeAtMax(t *testing.T) {
	p := PageRequest{Page: 1, PageSize: MaxPageSize}
	p.Normalize()

	if p.PageSize != MaxPageSize {
		t.Errorf("expected PageSize to stay at MaxPageSize (%d), got %d", MaxPageSize, p.PageSize)
	}
}

// Tests for ValidatePageRequest and PageRequestFromQuery's negative-value
// rejection (go-xkms#1262).

func TestValidatePageRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pr      PageRequest
		wantErr bool
		param   string
	}{
		{"zero page is valid (unpaginated)", PageRequest{Page: 0, PageSize: 0}, false, ""},
		{"page one is valid", PageRequest{Page: 1, PageSize: 25}, false, ""},
		{"negative page is invalid", PageRequest{Page: -1, PageSize: 25}, true, "page"},
		{"negative page_size is invalid", PageRequest{Page: 1, PageSize: -1}, true, "page_size"},
		{"huge page_size is valid, capping happens later", PageRequest{Page: 1, PageSize: math.MaxInt}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePageRequest(tc.pr)
			if tc.wantErr {
				var invalid *InvalidPaginationParamError
				if !errors.As(err, &invalid) {
					t.Fatalf("expected *InvalidPaginationParamError, got %v (%T)", err, err)
				}
				if invalid.Param != tc.param {
					t.Errorf("expected Param=%s, got %s", tc.param, invalid.Param)
				}
				if !errors.Is(err, ErrNegativePaginationValue) {
					t.Errorf("expected errors.Is(err, ErrNegativePaginationValue), got %v", err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestPageRequestFromQuery_NegativeValuesRejected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rawQuery  string
		wantParam string
	}{
		{"negative page", "page=-1", "page"},
		{"negative page_size", "page_size=-1", "page_size"},
		{"negative page with a huge page_size, page checked first", "page=-1&page_size=999999999", "page"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{URL: &url.URL{RawQuery: tc.rawQuery}}

			_, err := PageRequestFromQuery(r)
			if err == nil {
				t.Fatal("expected an error for a negative pagination parameter")
			}

			var invalid *InvalidPaginationParamError
			if !errors.As(err, &invalid) {
				t.Fatalf("expected *InvalidPaginationParamError, got %T", err)
			}
			if invalid.Param != tc.wantParam {
				t.Errorf("expected Param=%s, got %s", tc.wantParam, invalid.Param)
			}
			if !errors.Is(err, ErrNegativePaginationValue) {
				t.Errorf("expected errors.Is(err, ErrNegativePaginationValue), got %v", err)
			}
		})
	}
}

// TestPageRequestFromQuery_OversizedPageSizeAccepted proves an oversized
// page_size is not rejected at parse time -- it is capped downstream by
// Normalize (see TestPageRequest_Normalize_CapsPageSizeAtMax), consistent
// with MaxPageSize's doc: a caller asking for "as many as possible" gets
// the largest page this API is willing to hand back, not an error.
func TestPageRequestFromQuery_OversizedPageSizeAccepted(t *testing.T) {
	r := &http.Request{URL: &url.URL{RawQuery: "page_size=999999999"}}

	pr, err := PageRequestFromQuery(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.PageSize != 999999999 {
		t.Errorf("expected the raw PageSize to survive parsing uncapped, got %d", pr.PageSize)
	}
}
