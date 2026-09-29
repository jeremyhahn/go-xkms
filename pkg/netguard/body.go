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

package netguard

import (
	"io"
	"strconv"
)

// ResponseTooLargeError is returned when a response body exceeds Limit
// bytes.
type ResponseTooLargeError struct {
	Limit int64
}

// Error implements the error interface.
func (e *ResponseTooLargeError) Error() string {
	return "netguard: response exceeds " + strconv.FormatInt(e.Limit, 10) + " bytes"
}

// ReadLimited reads at most limit bytes of r and returns
// *ResponseTooLargeError when the stream continues past limit bytes,
// refusing an oversized body rather than silently truncating it. It reads
// one byte past limit so a body of exactly limit bytes is accepted without
// buffering anything beyond it.
func ReadLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, &ResponseTooLargeError{Limit: limit}
	}
	return body, nil
}
