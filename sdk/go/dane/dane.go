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

// Package dane is the SDK re-export of the canonical DANE TLSA publication
// hook (pkg/trust/dane). It exposes the publisher interface, the TLSA
// Record type, and the cert→record derivation so applications (quicbaas,
// go-trusted-platform) can register a DNS publisher and build records
// without importing pkg/trust/dane directly. xkms provides NO DNS
// implementation — the publisher is supplied by the embedding app.
package dane

import pkgdane "github.com/jeremyhahn/go-xkms/pkg/trust/dane"

// Re-exported types.
type (
	// Record is a fully-formed DANE TLSA resource record.
	Record = pkgdane.Record

	// DANEPublisher publishes DANE TLSA records to a DNS provider.
	DANEPublisher = pkgdane.DANEPublisher
)

// DefaultTTL is the TTL (seconds) applied to records produced by
// BuildRecords.
const DefaultTTL = pkgdane.DefaultTTL

// ErrNoDANEPublisher is returned (typically wrapped) when a DANE
// publication is requested but no DANEPublisher has been registered.
var ErrNoDANEPublisher = pkgdane.ErrNoDANEPublisher

// BuildRecords derives the common set of DANE TLSA records for cert at the
// given hostname/port via go-truststrap. See pkg/trust/dane.BuildRecords.
var BuildRecords = pkgdane.BuildRecords

// RFC 6698 TLSA field constants. See pkg/trust/dane.
const (
	// UsageDANETA is Certificate Usage 2 (DANE-TA): trust anchor assertion.
	UsageDANETA = pkgdane.UsageDANETA

	// UsageDANEEE is Certificate Usage 3 (DANE-EE): end-entity assertion.
	UsageDANEEE = pkgdane.UsageDANEEE

	// SelectorFullCert is Selector 0: match the full certificate.
	SelectorFullCert = pkgdane.SelectorFullCert

	// SelectorSPKI is Selector 1: match the SubjectPublicKeyInfo.
	SelectorSPKI = pkgdane.SelectorSPKI

	// MatchingSHA256 is Matching Type 1: SHA-256 of the selected content.
	MatchingSHA256 = pkgdane.MatchingSHA256

	// MatchingSHA512 is Matching Type 2: SHA-512 of the selected content.
	MatchingSHA512 = pkgdane.MatchingSHA512
)

// ErrInvalidCertificate is returned when a nil or malformed certificate is
// supplied to a TLSA derivation function.
var ErrInvalidCertificate = pkgdane.ErrInvalidCertificate

// ComputeTLSAData computes the RFC 6698 Certificate Association Data for
// cert using the given selector and matching type.
var ComputeTLSAData = pkgdane.ComputeTLSAData
