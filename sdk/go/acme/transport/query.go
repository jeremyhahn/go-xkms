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
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// QueryParam maps a request field, by its JSON name, to the URL query key
// the server reads it from.
type QueryParam struct {
	Field string
	Key   string
}

// TenantListQuery is how a tenant list request reaches the core tenant
// collection: page, per_page as page_size, and the status filter.
var TenantListQuery = []QueryParam{
	{Field: "page", Key: "page"},
	{Field: "per_page", Key: "page_size"},
	{Field: "status", Key: "status"},
}

// EncodeQuery returns the query string, with its leading "?", for the
// params req sets. It returns "" when there are no params, req is nil, or
// req sets none of them.
func EncodeQuery(req interface{}, params []QueryParam) (string, error) {
	if len(params) == 0 || req == nil {
		return "", nil
	}
	data, err := json.Marshal(req)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInvalidInput, "transport.EncodeQuery",
			"failed to marshal request")
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", errors.Wrap(err, errors.CodeInvalidInput, "transport.EncodeQuery",
			"request is not a JSON object")
	}

	query := url.Values{}
	for _, param := range params {
		switch value := fields[param.Field].(type) {
		case string:
			if value != "" {
				query.Set(param.Key, value)
			}
		case float64:
			if value != 0 {
				query.Set(param.Key, strconv.FormatInt(int64(value), 10))
			}
		}
	}
	if len(query) == 0 {
		return "", nil
	}
	return "?" + query.Encode(), nil
}
