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

// Package dane defines the DANE TLSA publication hook. xkms owns the
// TLSA-record *modelling* and the cert→record derivation (delegated to
// go-truststrap, which performs the only hashing), but it deliberately
// provides NO DNS implementation: publishing a TLSA RR is an
// application/deployment concern (the DNS provider, zone, credentials,
// and update protocol vary per operator). Applications such as quicbaas
// or go-trusted-platform supply a DANEPublisher; xkms ships none.
package dane

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
)

// DefaultTTL is the TTL (seconds) applied to records produced by
// BuildRecords. One hour is the common DANE TLSA default — short enough
// to allow timely certificate rotation, long enough to avoid excessive
// resolver churn. Callers that need a different TTL may rewrite the field
// on each Record before publishing.
const DefaultTTL uint32 = 3600

// Record is a fully-formed DANE TLSA resource record ready to be written
// into a DNS zone. It is the wire-level unit a DANEPublisher consumes;
// the (Usage, Selector, MatchingType, Data) tuple is exactly the RFC 6698
// RDATA, and Name is the TLSA owner name (e.g.
// "_443._tcp.kms.example.com.").
type Record struct {
	// Name is the DNS owner name for the TLSA record.
	Name string

	// Usage is the RFC 6698 Certificate Usage field (e.g. 2 = DANE-TA).
	Usage uint8

	// Selector is the RFC 6698 Selector field (0 = full cert, 1 = SPKI).
	Selector uint8

	// MatchingType is the RFC 6698 Matching Type field
	// (1 = SHA-256, 2 = SHA-512).
	MatchingType uint8

	// Data is the hex-encoded Certificate Association Data.
	Data string

	// TTL is the record time-to-live in seconds.
	TTL uint32
}

// DANEPublisher publishes DANE TLSA records to a DNS provider. xkms
// defines this interface but provides NO implementation: the DNS provider,
// zone management, credentials, and update mechanism (nsupdate, a cloud
// DNS API, a static zone file, ...) are owned by the embedding application.
// Apps register a publisher with their server; until one is registered,
// callers receive ErrNoDANEPublisher.
type DANEPublisher interface {
	// PublishDANE writes the supplied TLSA records to the configured DNS
	// provider. Implementations must be safe for concurrent use.
	PublishDANE(ctx context.Context, records []Record) error
}

// ErrNoDANEPublisher is returned (typically wrapped) when a DANE
// publication is requested but no DANEPublisher has been registered.
var ErrNoDANEPublisher = errors.New("dane: no publisher configured")

// BuildRecords derives the common set of DANE TLSA records for cert at the
// given hostname/port. It delegates record generation — including the only
// cryptographic hashing involved — to go-truststrap's
// GenerateCommonTLSARecords (DANE-TA over both selectors and both SHA
// variants), then maps the result to []Record with DefaultTTL. No hashing
// or TLSA construction is performed here.
func BuildRecords(cert *x509.Certificate, hostname string, port uint16) ([]Record, error) {
	generated, err := dane.GenerateCommonTLSARecords(cert, hostname, port)
	if err != nil {
		return nil, err
	}

	records := make([]Record, 0, len(generated))
	for _, g := range generated {
		records = append(records, Record{
			Name:         g.Name,
			Usage:        g.Usage,
			Selector:     g.Selector,
			MatchingType: g.MatchingType,
			Data:         g.HexData,
			TTL:          DefaultTTL,
		})
	}
	return records, nil
}
