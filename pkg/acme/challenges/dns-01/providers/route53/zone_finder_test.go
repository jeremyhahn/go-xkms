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

package route53

import "context"

// Zone discovery in these tests is answered locally.
//
// They used to climb the real DNS tree for a SOA record on google.com -- the
// comments said so outright, "using real DNS lookups for well-known domains" --
// which made the Unit Tests gate depend on the public internet and on a third
// party's zone continuing to look the way the fixtures assume (go-xkms#243).
//
// The fixtures are unchanged: the mocks still describe google.com zones and the
// assertions still expect them, so what each test proves is exactly what it
// proved before. Only the resolution step is local now.
//
// Because a ZoneFinder replaces providers.FindZoneByFQDN entirely rather than
// just its DNS query, none of this touches the package-global zone cache, so
// these tests cannot pollute each other or be served another test's answer.

// staticZoneFinder answers with the zone apex a real SOA climb would return for
// the *.google.com fixtures used here.
func staticZoneFinder(_ context.Context, _ string, _ []string) (string, error) {
	return "google.com.", nil
}

// newDiscoveryProvider builds a Provider whose zone discovery is answered by
// staticZoneFinder instead of by DNS.
func newDiscoveryProvider(client Route53API, hostedZoneID string) *Provider {
	return NewWithClientAndConfig(client, Config{
		HostedZoneID: hostedZoneID,
		ZoneFinder:   staticZoneFinder,
	})
}
