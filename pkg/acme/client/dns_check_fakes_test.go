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

package client

import (
	"context"
	"errors"
)

// Fakes for the DNS pre-check seam.
//
// The tests these serve used to resolve real public domains -- google.com,
// example.com -- and query 8.8.8.8 through the global resolver, inside the Unit
// Tests gate. That made a gate depend on the public internet: it fails on any
// network hiccup, on an air-gapped runner, and on any host with egress
// filtering, and it always looks like a defect in whatever PR happens to be
// running (go-xkms#243).
//
// Injecting these keeps every assertion the tests already made -- an unmatched
// value is ErrDNSRecordNotPresent, a failed nameserver lookup is wrapped -- and
// removes the dependency, along with the multi-second timeouts the network
// paths needed.

// errNameserverLookupFailed stands in for whatever the resolver reports for a
// domain with no NS records.
var errNameserverLookupFailed = errors.New("no such host")

// errPropagationQueryFailed stands in for an unreachable nameserver.
var errPropagationQueryFailed = errors.New("dns query failed: i/o timeout")

// staticNameservers returns a lookup that always answers with ns.
func staticNameservers(ns ...string) NameserverLookup {
	return func(string) ([]string, error) {
		return ns, nil
	}
}

// failingNameservers returns a lookup that always fails, standing in for a
// domain that has no authoritative nameservers.
func failingNameservers() NameserverLookup {
	return func(string) ([]string, error) {
		return nil, errNameserverLookupFailed
	}
}

// propagationResult returns a query that always reports found, without asking
// any nameserver.
func propagationResult(found bool) PropagationQuery {
	return func(context.Context, string, string, []string) (bool, error) {
		return found, nil
	}
}

// propagationFailure returns a query that always fails, standing in for a
// nameserver that did not answer.
func propagationFailure() PropagationQuery {
	return func(context.Context, string, string, []string) (bool, error) {
		return false, errPropagationQueryFailed
	}
}
