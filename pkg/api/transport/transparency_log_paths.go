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

package transport

import (
	"net/url"
	"strconv"
)

// TransparencyLogHeadPath is the HTTP path of the CA transparency log's
// signed tree head, which the REST and QUIC clients share.
const TransparencyLogHeadPath = "/api/v1/ca/transparency-log/head"

// TransparencyLogEntryPath returns the HTTP path of the log entry at index.
func TransparencyLogEntryPath(index uint64) string {
	return "/api/v1/ca/transparency-log/entries/" + strconv.FormatUint(index, 10)
}

// TransparencyLogInclusionProofPath returns the HTTP path of the inclusion
// proof req names.
func TransparencyLogInclusionProofPath(req *GetTransparencyLogInclusionProofRequest) string {
	params := url.Values{}
	params.Set("index", strconv.FormatUint(req.Index, 10))
	params.Set("tree_size", strconv.FormatUint(req.TreeSize, 10))
	return "/api/v1/ca/transparency-log/proofs/inclusion?" + params.Encode()
}

// TransparencyLogConsistencyProofPath returns the HTTP path of the
// consistency proof req names.
func TransparencyLogConsistencyProofPath(req *GetTransparencyLogConsistencyProofRequest) string {
	params := url.Values{}
	params.Set("first_size", strconv.FormatUint(req.FirstSize, 10))
	params.Set("second_size", strconv.FormatUint(req.SecondSize, 10))
	return "/api/v1/ca/transparency-log/proofs/consistency?" + params.Encode()
}
