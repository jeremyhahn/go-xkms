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
	"fmt"
	"net/http"
	"strconv"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// SortOrderAsc represents ascending sort order.
const SortOrderAsc = 0

// SortOrderDesc represents descending sort order.
const SortOrderDesc = 1

// DefaultPageSize is used when PageSize is not specified.
const DefaultPageSize = 25

// PageRequest represents pagination parameters for list endpoints.
// Page==0 means return all results (backward compatibility).
type PageRequest struct {
	Page      int    `json:"page,omitempty"`       // 1-based page number, 0 = all
	PageSize  int    `json:"page_size,omitempty"`  // items per page, default 25
	SortField string `json:"sort_field,omitempty"` // struct field name to sort by
	SortOrder int    `json:"sort_order,omitempty"` // 0=ascending, 1=descending
}

// PageResponse contains pagination metadata in list responses.
type PageResponse struct {
	Page     int  `json:"page"`
	PageSize int  `json:"page_size"`
	Total    int  `json:"total"`
	HasMore  bool `json:"has_more"`
}

// ListOption configures pagination parameters for list operations.
// When no options are provided, all results are returned (Page==0).
type ListOption func(*PageRequest)

// WithPage sets the 1-based page number to retrieve. Page 0 means return all
// results, which is the default when no options are provided.
func WithPage(page int) ListOption {
	return func(pr *PageRequest) {
		pr.Page = page
	}
}

// WithPageSize sets the maximum number of items to return per page.
func WithPageSize(size int) ListOption {
	return func(pr *PageRequest) {
		pr.PageSize = size
	}
}

// WithSortField sets the field name to sort results by.
func WithSortField(field string) ListOption {
	return func(pr *PageRequest) {
		pr.SortField = field
	}
}

// WithSortDesc sets the sort order to descending.
func WithSortDesc() ListOption {
	return func(pr *PageRequest) {
		pr.SortOrder = SortOrderDesc
	}
}

// WithSortAsc sets the sort order to ascending. This is the default.
func WithSortAsc() ListOption {
	return func(pr *PageRequest) {
		pr.SortOrder = SortOrderAsc
	}
}

// WithPageRequest applies every field of an already-built PageRequest, for a
// transport that decodes its pagination parameters into a PageRequest (from
// an HTTP query, or a proto's limit/offset) and hands them to a servicer.
func WithPageRequest(req PageRequest) ListOption {
	return func(pr *PageRequest) {
		*pr = req
	}
}

// BuildPageRequest constructs a PageRequest from the given list options.
// When no options are provided, an unpaginated request (Page==0) is returned.
func BuildPageRequest(opts ...ListOption) PageRequest {
	var pr PageRequest
	for _, opt := range opts {
		opt(&pr)
	}
	return pr
}

// Normalize applies defaults to a PageRequest. If PageSize is not set it
// defaults to DefaultPageSize. Negative Page values are clamped to zero.
func (p *PageRequest) Normalize() {
	if p.PageSize <= 0 {
		p.PageSize = DefaultPageSize
	}
	if p.Page < 0 {
		p.Page = 0
	}
}

// IsUnpaginated returns true if the request asks for all results.
func (p *PageRequest) IsUnpaginated() bool {
	return p.Page == 0
}

// ToDAOPageQuery converts a PageRequest to a qrdbsdk.PageQuery.
// When unpaginated, it returns a query for a single large page so that callers
// that only speak PageQuery still receive every entity.
func (p *PageRequest) ToDAOPageQuery() qrdbsdk.PageQuery {
	if p.IsUnpaginated() {
		return qrdbsdk.PageQuery{
			Page:      1,
			PageSize:  100000,
			SortField: p.SortField,
			SortOrder: p.SortOrder,
		}
	}
	return qrdbsdk.PageQuery{
		Page:      p.Page,
		PageSize:  p.PageSize,
		SortField: p.SortField,
		SortOrder: p.SortOrder,
	}
}

// PageResponseFromDAO creates a PageResponse from a qrdbsdk.PageResult.
func PageResponseFromDAO[E any](result qrdbsdk.PageResult[E]) PageResponse {
	return PageResponse{
		Page:     result.Page,
		PageSize: result.PageSize,
		Total:    result.Total,
		HasMore:  result.HasMore,
	}
}

// ApplyPagination slices an in-memory list according to the given PageRequest
// and returns the page of items along with pagination metadata.
// When the request is unpaginated (Page==0), all items are returned.
func ApplyPagination[T any](items []T, pr PageRequest) ([]T, PageResponse) {
	total := len(items)

	if pr.IsUnpaginated() {
		return items, PageResponse{
			Page:     1,
			PageSize: total,
			Total:    total,
			HasMore:  false,
		}
	}

	pr.Normalize()

	start := (pr.Page - 1) * pr.PageSize
	if start >= total {
		return nil, PageResponse{
			Page:     pr.Page,
			PageSize: pr.PageSize,
			Total:    total,
			HasMore:  false,
		}
	}

	end := start + pr.PageSize
	if end > total {
		end = total
	}

	return items[start:end], PageResponse{
		Page:     pr.Page,
		PageSize: pr.PageSize,
		Total:    total,
		HasMore:  end < total,
	}
}

// InvalidPaginationParamError reports an HTTP query pagination parameter
// that could not be parsed as an integer. Silently treating it as absent
// used to turn a caller's typo into an unpaginated "return everything"
// request instead of a rejection.
type InvalidPaginationParamError struct {
	// Param is the query parameter name.
	Param string

	// Value is the unparsable value that was supplied.
	Value string

	// Err is the underlying strconv error.
	Err error
}

// Error implements the error interface.
func (e *InvalidPaginationParamError) Error() string {
	return fmt.Sprintf("transport: invalid %s query parameter %q: %v", e.Param, e.Value, e.Err)
}

// Unwrap returns the underlying strconv error.
func (e *InvalidPaginationParamError) Unwrap() error { return e.Err }

// PageRequestFromQuery extracts pagination parameters from HTTP query
// strings. This is the one implementation every HTTP-based transport --
// REST, QUIC, and any other package that receives pagination via URL query
// parameters -- calls; none of them keeps its own copy. page and page_size
// must be integers; sort_order accepts either an integer (SortOrderAsc/
// SortOrderDesc) or the "asc"/"desc" strings the REST API and its
// TypeScript SDK use on the wire. A parameter that is present but matches
// none of its accepted forms is reported as an *InvalidPaginationParamError
// rather than silently defaulting to zero.
func PageRequestFromQuery(r *http.Request) (PageRequest, error) {
	var pr PageRequest

	if v := r.URL.Query().Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return PageRequest{}, &InvalidPaginationParamError{Param: "page", Value: v, Err: err}
		}
		pr.Page = n
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return PageRequest{}, &InvalidPaginationParamError{Param: "page_size", Value: v, Err: err}
		}
		pr.PageSize = n
	}
	if v := r.URL.Query().Get("sort_field"); v != "" {
		pr.SortField = v
	}
	if v := r.URL.Query().Get("sort_order"); v != "" {
		n, err := parseSortOrder(v)
		if err != nil {
			return PageRequest{}, &InvalidPaginationParamError{Param: "sort_order", Value: v, Err: err}
		}
		pr.SortOrder = n
	}

	return pr, nil
}

// parseSortOrder accepts both the integer form of sort_order
// (SortOrderAsc/SortOrderDesc) and the "asc"/"desc" string form the REST
// API and its TypeScript SDK send on the wire.
func parseSortOrder(v string) (int, error) {
	switch v {
	case "desc":
		return SortOrderDesc, nil
	case "asc":
		return SortOrderAsc, nil
	default:
		return strconv.Atoi(v)
	}
}

// AppendPaginationQuery appends pagination parameters to a URL path as query
// string parameters. If the PageRequest is unpaginated, the path is returned
// unchanged. The sep parameter indicates whether to use '?' or '&' as the
// first separator (use '&' if the path already contains a query string).
func AppendPaginationQuery(path string, pr PageRequest, hasQuery bool) string {
	if pr.IsUnpaginated() {
		return path
	}

	sep := '?'
	if hasQuery {
		sep = '&'
	}

	path = fmt.Sprintf("%s%cpage=%d&page_size=%d", path, sep, pr.Page, pr.PageSize)

	if pr.SortField != "" {
		path = fmt.Sprintf("%s&sort_field=%s", path, pr.SortField)
	}
	if pr.SortOrder != SortOrderAsc {
		path = fmt.Sprintf("%s&sort_order=%d", path, pr.SortOrder)
	}

	return path
}
