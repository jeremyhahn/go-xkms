// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package ct implements Certificate Transparency (RFC 6962) support for go-trusted-ca.
//
// This package provides:
//   - CT log submission with multi-operator SCT requirements
//   - SCT list extension encoding for certificate embedding
//   - Precert poison extension for pre-certificate creation
//   - CT policy enforcement with temporal shard filtering
//
// The implementation follows Boulder's approach to CT log management:
//   - Submit to multiple CT logs in parallel
//   - Require SCTs from multiple operators for diversity
//   - Filter logs by temporal validity (certificate expiry within log's time window)
//   - Support both RFC6962-compliant and tiled CT logs
//
// Key OIDs:
//   - CT Precert Poison: 1.3.6.1.4.1.11129.2.4.3
//   - CT SCT List: 1.3.6.1.4.1.11129.2.4.2
//
// Example usage:
//
//	policy := ct.NewCTPolicy(ct.PolicyConfig{
//	    MinSCTs:      2,
//	    MinOperators: 2,
//	    LogGroups:    myLogGroups,
//	})
//
//	scts, err := policy.GetSCTs(ctx, precertDER, expiry)
//	if err != nil {
//	    return err
//	}
//
//	ext, err := ct.MakeSCTListExtension(scts)
//	if err != nil {
//	    return err
//	}
package ct
