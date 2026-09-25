// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * Shared wire primitives. Go `[]byte` members marshal as standard base64
 * strings; Go `time.Time` members marshal as RFC 3339 strings.
 */

/** A Go []byte on the wire: standard base64 (encoding/json default). */
export type Base64 = string;

/** A Go time.Time on the wire: RFC 3339 timestamp string. */
export type RFC3339 = string;

/**
 * Pagination query parameters accepted by list endpoints
 * (pkg/api/transport/pagination.go PageRequestFromQuery): page, page_size,
 * sort_field, sort_order ('desc'/'1' = descending). page and page_size must
 * be integers on the wire -- a non-numeric value is rejected with 400
 * rather than silently defaulting to an unpaginated request.
 */
export interface PageQuery {
  page?: number;
  page_size?: number;
  sort_field?: string;
  sort_order?: 'asc' | 'desc';
}

/** Mirrors pkg/api/transport/pagination.go PageResponse. */
export interface PageResponse {
  page: number;
  page_size: number;
  total: number;
  has_more: boolean;
}

/** Mirrors pkg/api/rest/types.go SuccessResponse. */
export interface SuccessResponse {
  success: boolean;
  message?: string;
}
