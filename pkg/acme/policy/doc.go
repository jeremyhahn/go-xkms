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

// Package policy provides multi-tier domain and IP blocklisting for ACME certificate
// issuance policy enforcement. It implements domain validation according to RFC 1035
// and IP validation according to RFC 8738.
//
// The package provides three tiers of blocklisting:
//
//   - Domain blocklist: High-risk domains blocked using label-wise suffix matching.
//     Blocking "example.com" also blocks "www.example.com" and "mail.example.com".
//
//   - FQDN blocklist: Exact FQDN matches only. Blocking "www.example.com" does not
//     affect "example.com" or "mail.example.com".
//
//   - Wildcard FQDN blocklist: Controls wildcard certificate issuance. Blocking
//     "example.com" here prevents issuance of "*.example.com" certificates.
//
//   - IP prefix blocklist: CIDR ranges of blocked IP addresses.
//
// Wildcard cascade behavior: blocking a domain in the domain blocklist automatically
// blocks wildcard certificates for that domain.
//
// Usage:
//
//	blocklist := policy.NewBlocklist()
//	err := blocklist.LoadFromFile("/path/to/blocklist.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	blocked, reason := blocklist.IsDomainBlocked("example.com")
//	if blocked {
//	    log.Printf("Domain blocked: %s", reason)
//	}
//
// Configuration file format (YAML):
//
//	highRiskBlockedNames:
//	  - example.com
//	  - malicious-domain.net
//	exactBlockedNames:
//	  - specific-host.example.org
//	adminBlockedPrefixes:
//	  - 192.168.0.0/16
//	  - 10.0.0.0/8
package policy
