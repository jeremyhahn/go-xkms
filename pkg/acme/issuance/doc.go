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

// Package issuance implements Boulder-style two-phase certificate issuance
// with Certificate Transparency (CT) integration.
//
// This package provides a secure certificate issuance flow that:
//   - Validates CSRs and keys before signing
//   - Persists serial numbers to storage BEFORE signing (prevents duplicates on retry)
//   - Runs zlint validation on precertificates
//   - Submits precertificates to CT logs and collects SCTs
//   - Creates final certificates with embedded SCTs
//   - Verifies TBS determinism between lint cert and actual cert
//
// The two-phase issuance flow:
//
//  1. Validate CSR (subject, SANs, extensions)
//  2. Validate key using goodkey checks
//  3. Generate unique serial number
//  4. Persist serial to storage (BEFORE signing!)
//  5. Create lint precertificate for validation
//  6. Run zlint validation (reject if fails)
//  7. Record precert intent for audit
//  8. Sign the precertificate (with poison extension)
//  9. Verify TBS determinism (lint cert vs actual cert)
//  10. Submit precert to CT logs, collect SCTs
//  11. Create final certificate template with SCT list extension
//  12. Sign the final certificate
//  13. Verify TBS determinism
//  14. Persist final certificate
//
// Example usage:
//
//	issuer, err := issuance.NewIssuer(issuance.Config{
//	    CA:          myCA,
//	    Linter:      linter,
//	    CTPolicy:    ctPolicy,
//	    Storage:     storage,
//	})
//	if err != nil {
//	    return err
//	}
//
//	result, err := issuer.Issue(ctx, &issuance.Request{
//	    CSR:       csr,
//	    Template:  template,
//	    NotBefore: time.Now(),
//	    NotAfter:  time.Now().AddDate(1, 0, 0),
//	    Profile:   "default",
//	})
//	if err != nil {
//	    return err
//	}
//
// The precertificate contains the CT poison extension (OID 1.3.6.1.4.1.11129.2.4.3)
// which is replaced with the SCT list extension (OID 1.3.6.1.4.1.11129.2.4.2)
// in the final certificate.
package issuance
