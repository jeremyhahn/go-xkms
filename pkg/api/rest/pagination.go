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
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// parsePageRequest extracts pagination parameters from URL query string.
// Supported query parameters: page, page_size, sort_field, sort_order.
// Missing or invalid values use defaults. page=0 (the default) means
// return all results for backward compatibility with existing clients.
func parsePageRequest(r *http.Request) transport.PageRequest {
	q := r.URL.Query()
	pr := transport.PageRequest{}
	if v := q.Get("page"); v != "" {
		pr.Page, _ = strconv.Atoi(v)
	}
	if v := q.Get("page_size"); v != "" {
		pr.PageSize, _ = strconv.Atoi(v)
	}
	pr.SortField = q.Get("sort_field")
	if v := q.Get("sort_order"); v == "desc" || v == "1" {
		pr.SortOrder = 1
	}
	pr.Normalize()
	return pr
}

// applyPagination slices items according to the page request and returns
// the page along with metadata. When the request is unpaginated (page==0),
// all items are returned with a single-page PageResponse so that existing
// clients that do not send pagination parameters receive the full list.
func applyPagination[T any](items []T, pr transport.PageRequest) ([]T, transport.PageResponse) {
	total := len(items)
	if pr.IsUnpaginated() {
		return items, transport.PageResponse{
			Page:     1,
			PageSize: total,
			Total:    total,
			HasMore:  false,
		}
	}
	start := (pr.Page - 1) * pr.PageSize
	if start >= total {
		return nil, transport.PageResponse{
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
	return items[start:end], transport.PageResponse{
		Page:     pr.Page,
		PageSize: pr.PageSize,
		Total:    total,
		HasMore:  end < total,
	}
}
