// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package dane

import "github.com/jeremyhahn/go-truststrap/pkg/dane"

// RFC 6698 TLSA field constants re-exported from go-truststrap. xkms is the
// single composition point for go-truststrap in the stack; DANE publishers
// in consumer projects use these instead of importing go-truststrap.
const (
	// UsageDANETA is Certificate Usage 2 (DANE-TA): trust anchor assertion.
	UsageDANETA = dane.UsageDANETA

	// UsageDANEEE is Certificate Usage 3 (DANE-EE): end-entity assertion.
	UsageDANEEE = dane.UsageDANEEE

	// SelectorFullCert is Selector 0: match the full certificate.
	SelectorFullCert = dane.SelectorFullCert

	// SelectorSPKI is Selector 1: match the SubjectPublicKeyInfo.
	SelectorSPKI = dane.SelectorSPKI

	// MatchingSHA256 is Matching Type 1: SHA-256 of the selected content.
	MatchingSHA256 = dane.MatchingSHA256

	// MatchingSHA512 is Matching Type 2: SHA-512 of the selected content.
	MatchingSHA512 = dane.MatchingSHA512
)

// ErrInvalidCertificate is returned when a nil or malformed certificate is
// supplied to a TLSA derivation function.
var ErrInvalidCertificate = dane.ErrInvalidCertificate

// ComputeTLSAData computes the RFC 6698 Certificate Association Data for
// cert using the given selector and matching type. This is the only
// cryptographic hashing in the DANE pipeline and it is performed by
// go-truststrap.
var ComputeTLSAData = dane.ComputeTLSAData
