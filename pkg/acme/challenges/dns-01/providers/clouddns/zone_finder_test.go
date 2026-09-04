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

package clouddns

import "context"

// Zone discovery in these tests is answered locally; see the route53 provider's
// equivalent for the full reasoning. In short: these climbed the real DNS tree
// for a SOA record on google.com, which made a gate depend on the public
// internet (go-xkms#243). The fixtures are unchanged, so each test proves what
// it proved before; only the resolution step is local.

// staticZoneFinder answers with the zone apex a real SOA climb would return for
// the *.google.com fixtures used here.
func staticZoneFinder(_ context.Context, _ string, _ []string) (string, error) {
	return "google.com.", nil
}

// newDiscoveryProvider builds a Provider whose zone discovery is answered by
// staticZoneFinder instead of by DNS.
func newDiscoveryProvider(client CloudDNSAPI, project, hostedZoneName string) *Provider {
	return NewWithClientAndConfig(client, Config{
		Project:        project,
		HostedZoneName: hostedZoneName,
		ZoneFinder:     staticZoneFinder,
	})
}
