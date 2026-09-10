// Copyright (C) 2026 Jeremy Hahn
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdvertisedURL_DerivesFromListenAddress proves that every listen address
// shape derives a reachable origin: a wildcard host becomes localhost and a
// named or literal host is kept, with IPv6 literals bracketed.
func TestAdvertisedURL_DerivesFromListenAddress(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
		addr   string
		want   string
	}{
		{"bare port", "https", ":8443", "https://localhost:8443"},
		{"ipv4 wildcard", "https", "0.0.0.0:9443", "https://localhost:9443"},
		{"ipv6 wildcard", "https", "[::]:8443", "https://localhost:8443"},
		{"loopback", "http", "127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"hostname", "https", "acme.example.com:8443", "https://acme.example.com:8443"},
		{"ipv6 literal", "https", "[fd00::1]:8443", "https://[fd00::1]:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AdvertisedURL(tc.scheme, tc.addr)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestAdvertisedURL_RejectsAddressesWithoutAPort proves that an address no
// client could dial is refused with a typed error naming the address, rather
// than advertised as a URL that will never resolve.
func TestAdvertisedURL_RejectsAddressesWithoutAPort(t *testing.T) {
	cases := []struct {
		name string
		addr string
		port bool
	}{
		{"no separator", "8443", false},
		{"host only", "acme.example.com", false},
		{"empty", "", false},
		{"unbracketed ipv6", "fd00::1:8443", false},
		{"empty port", "acme.example.com:", true},
		{"separator only", ":", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AdvertisedURL("https", tc.addr)
			require.Error(t, err)
			assert.Empty(t, got)

			var derived *AdvertisedURLError
			require.True(t, errors.As(err, &derived))
			assert.Equal(t, tc.addr, derived.ListenAddr)
			assert.Contains(t, err.Error(), tc.addr)
			if tc.port {
				assert.True(t, errors.Is(err, ErrAdvertisedURLMissingPort))
			}
		})
	}
}
