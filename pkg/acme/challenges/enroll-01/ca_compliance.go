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

package enroll01

import "github.com/jeremyhahn/go-xkms/pkg/ca"

// The production CA must satisfy TCGCSRVerifier.
//
// enroll-01 reaches the CA through a runtime type assertion
// (sdk/go/acme/attestation.go), which fails silently: a CA that does not
// satisfy this interface yields ErrACMEEnrollCAUnsupported and the challenge
// is refused, rather than anything failing to compile.
//
// That is exactly what shipped. This interface declared sigAlg as interface{}
// while ca.TCGCA declares x509.SignatureAlgorithm, and Go requires an exact
// method signature match -- so *ca.CA never satisfied it, the assertion always
// failed, and TPM IDevID enrollment could not succeed on any deployment. The
// package's own tests passed because the mock was written against the
// unsatisfiable declaration.
//
// This assertion turns that class of drift into a build failure. It is the
// reason the interface must be kept signature-identical to ca.TCGCA.
var _ TCGCSRVerifier = (*ca.CA)(nil)
