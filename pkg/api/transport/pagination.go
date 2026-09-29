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

// MaxPageSize is the largest PageSize a caller may request through
// Normalize. Requests above it are capped, not rejected -- a caller asking
// for "as many as possible" gets the largest page this API hands back in
// one response, not an error. Capping it also keeps ApplyPagination's
// (page-1)*pageSize slice arithmetic within a range that cannot overflow
// int on any platform Go supports, which combined with the ceilings
// ApplyPagination applies is what turned a page_size large enough to
// overflow the multiplication into an ordinary bounded page instead of a
// panic (go-xkms#1262). qrdbsdk.PageQuery, the DAO-level equivalent this
// package converts to, defines no such ceiling of its own.
const MaxPageSize = 1000

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
// defaults to DefaultPageSize. PageSize above MaxPageSize is capped to
// MaxPageSize. Negative Page values are clamped to zero.
func (p *PageRequest) Normalize() {
	if p.PageSize <= 0 {
		p.PageSize = DefaultPageSize
	}
	if p.PageSize > MaxPageSize {
		p.PageSize = MaxPageSize
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
// that only speak PageQuery still receive every entity. That page size is
// deliberately not MaxPageSize-capped like Normalize's paginated path: no
// production caller converts an unpaginated PageRequest through this method
// today (every list handler paginates in memory through ApplyPagination
// instead), and capping it would silently truncate a future caller's "give
// me everything" query to MaxPageSize entities with no error -- trading a
// panic for silent data loss is not a fix. A caller that starts exercising
// this path for a real DAO query should size it deliberately for that
// query, not inherit an in-memory-pagination default.
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
//
// pr is treated as untrusted regardless of where it came from -- a validated
// HTTP query, or a PageRequest built programmatically with a ListOption,
// which callers such as pkg/xkms's servicers and the MCP handlers can
// construct with any Page or PageSize at all. Normalize applies its usual
// defaults and caps PageSize at MaxPageSize; Page is checked again
// afterward because Normalize clamps a negative Page to zero, which is
// IsUnpaginated's value for "return everything", not a valid first page --
// left unchecked here that zero produced a negative slice start
// (go-xkms#1262). The final range arithmetic is overflow-checked before it
// indexes items, since Page carries no upper bound of its own. A caller
// that wants negative input rejected outright, rather than silently
// clamped to the first page, should validate the PageRequest before calling
// ApplyPagination; see ValidatePageRequest.
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
	if pr.Page < 1 {
		pr.Page = 1
	}

	start, overflowed := multiplyWithoutOverflow(pr.Page-1, pr.PageSize)
	if overflowed || start < 0 || start >= total {
		return nil, PageResponse{
			Page:     pr.Page,
			PageSize: pr.PageSize,
			Total:    total,
			HasMore:  false,
		}
	}

	end, overflowed := addWithoutOverflow(start, pr.PageSize)
	if overflowed || end > total {
		end = total
	}

	return items[start:end], PageResponse{
		Page:     pr.Page,
		PageSize: pr.PageSize,
		Total:    total,
		HasMore:  end < total,
	}
}

// multiplyWithoutOverflow returns a*b and whether the multiplication
// overflowed the int type. ApplyPagination uses it to keep
// (Page-1)*PageSize from wrapping into a value it would then use, wrapped or
// not, to slice a Go slice.
func multiplyWithoutOverflow(a, b int) (product int, overflowed bool) {
	if a == 0 || b == 0 {
		return 0, false
	}
	product = a * b
	return product, product/b != a
}

// addWithoutOverflow returns a+b and whether the addition overflowed the int
// type. ApplyPagination uses it to keep start+PageSize from wrapping past
// the platform's maximum int before it is used to slice items.
func addWithoutOverflow(a, b int) (sum int, overflowed bool) {
	sum = a + b
	return sum, (b > 0 && sum < a) || (b < 0 && sum > a)
}

// ErrNegativePaginationValue is the Err a *InvalidPaginationParamError
// carries when a page or page_size parameter parsed as an integer but was
// negative. Unlike an oversized page_size, which Normalize caps rather than
// rejects, a negative value has no sensible page to clamp to, so it is
// reported rather than silently reinterpreted (go-xkms#1262).
var ErrNegativePaginationValue = errors.New("must not be negative")

// InvalidPaginationParamError reports an HTTP query pagination parameter,
// or a PageRequest field validated through ValidatePageRequest, that either
// could not be parsed as an integer or parsed to a negative value. Silently
// treating it as absent, or as its clamped-to-zero equivalent, used to turn
// a caller's typo or malicious input into an unpaginated "return
// everything" request, or a panic, instead of a rejection.
type InvalidPaginationParamError struct {
	// Param is the query parameter, or PageRequest field, name.
	Param string

	// Value is the invalid value that was supplied.
	Value string

	// Err is the underlying strconv error, or ErrNegativePaginationValue.
	Err error
}

// Error implements the error interface.
func (e *InvalidPaginationParamError) Error() string {
	return fmt.Sprintf("transport: invalid %s query parameter %q: %v", e.Param, e.Value, e.Err)
}

// Unwrap returns the underlying error.
func (e *InvalidPaginationParamError) Unwrap() error { return e.Err }

// ValidatePageRequest rejects a PageRequest whose Page or PageSize is
// negative. It is PageRequestFromQuery's rejection, exported for a
// transport that decodes a PageRequest from somewhere other than an HTTP
// query string -- the MCP JSON-RPC server decodes one directly from a
// request's JSON params -- so every transport rejects the same malformed
// input instead of only the HTTP query path doing so and every other
// caller depending on ApplyPagination's more permissive clamp-to-first-page
// behavior for defense in depth alone.
func ValidatePageRequest(pr PageRequest) error {
	if pr.Page < 0 {
		return &InvalidPaginationParamError{Param: "page", Value: strconv.Itoa(pr.Page), Err: ErrNegativePaginationValue}
	}
	if pr.PageSize < 0 {
		return &InvalidPaginationParamError{Param: "page_size", Value: strconv.Itoa(pr.PageSize), Err: ErrNegativePaginationValue}
	}
	return nil
}

// PageRequestFromQuery extracts pagination parameters from HTTP query
// strings. This is the one implementation every HTTP-based transport --
// REST, QUIC, and any other package that receives pagination via URL query
// parameters -- calls; none of them keeps its own copy. page and page_size
// must be non-negative integers; sort_order accepts either an integer
// (SortOrderAsc/SortOrderDesc) or the "asc"/"desc" strings the REST API and
// its TypeScript SDK use on the wire. A parameter that is present but
// matches none of its accepted forms, including a negative page or
// page_size, is reported as an *InvalidPaginationParamError rather than
// silently defaulting to zero or clamping (go-xkms#1262). page_size has no
// upper bound rejected here -- an oversized one is capped by Normalize
// instead of failing the request.
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

	if err := ValidatePageRequest(pr); err != nil {
		return PageRequest{}, err
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
