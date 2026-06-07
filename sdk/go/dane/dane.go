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
