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

import "testing"

type tenantListRequest struct {
	Page    int    `json:"page,omitempty"`
	PerPage int    `json:"per_page,omitempty"`
	Status  string `json:"status,omitempty"`
}

func TestEncodeQuery_TenantList(t *testing.T) {
	cases := []struct {
		name string
		req  interface{}
		want string
	}{
		{"all set", &tenantListRequest{Page: 2, PerPage: 25, Status: "active"}, "?page=2&page_size=25&status=active"},
		{"per_page becomes page_size", &tenantListRequest{PerPage: 10}, "?page_size=10"},
		{"nothing set", &tenantListRequest{}, ""},
		{"nil request", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncodeQuery(tc.req, TenantListQuery)
			if err != nil {
				t.Fatalf("EncodeQuery() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("EncodeQuery() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEncodeQuery_RejectsARequestThatIsNotAnObject(t *testing.T) {
	if _, err := EncodeQuery([]int{1}, TenantListQuery); err == nil {
		t.Error("EncodeQuery() of a JSON array: want an error")
	}
	if _, err := EncodeQuery(make(chan int), TenantListQuery); err == nil {
		t.Error("EncodeQuery() of an unmarshalable value: want an error")
	}
}

func TestEncodeQuery_NoParamsLeavesTheRequestAlone(t *testing.T) {
	got, err := EncodeQuery(make(chan int), nil)
	if err != nil || got != "" {
		t.Errorf("EncodeQuery() with no params = %q, %v; want \"\", nil", got, err)
	}
}
