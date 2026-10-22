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

package api

import (
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantPath_EscapesTheID(t *testing.T) {
	assert.Equal(t, "/api/v1/tenants/tenant-1", TenantPath("tenant-1"))
	assert.Equal(t, "/api/v1/tenants/a%2Fb", TenantPath("a/b"), "a slash must not reach a nested route")
}

func TestTenantListPath(t *testing.T) {
	assert.Equal(t, "/api/v1/tenants/?page=2&page_size=10",
		TenantListPath(&admin.ListTenantsRequest{Page: 2, PerPage: 10}))
	assert.Equal(t, "/api/v1/tenants/?page=1&page_size=5&status=suspended",
		TenantListPath(&admin.ListTenantsRequest{Page: 1, PerPage: 5, Status: "suspended"}))
}

func TestTenantListEnvelope_DecodesTheCoreBody(t *testing.T) {
	body := `{"tenants":[{"id":"t1","name":"One","status":"active"}],"pagination":{"page":1,"page_size":25,"total":1,"has_more":false}}`

	var list TenantListEnvelope
	require.NoError(t, json.Unmarshal([]byte(body), &list))

	require.Len(t, list.Tenants, 1)
	assert.Equal(t, "t1", list.Tenants[0].ID)
	assert.Equal(t, "active", list.Tenants[0].Status)
	assert.Equal(t, &admin.Pagination{Page: 1, PerPage: 25, Total: 1}, list.Pagination.AdminPagination())
}

func TestTenantListEnvelope_RejectsAMalformedBody(t *testing.T) {
	var list TenantListEnvelope
	assert.Error(t, json.Unmarshal([]byte(`{"tenants":"not an array"}`), &list))
}
