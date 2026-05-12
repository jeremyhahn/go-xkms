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

package ratelimits

import (
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Name represents a rate limit identifier.
type Name int

// Rate limit name constants.
const (
	Unknown Name = iota
	NewRegistrationsPerIPAddress
	NewRegistrationsPerIPv6Range
	NewOrdersPerAccount
	FailedAuthorizationsPerDomainPerAccount
	CertificatesPerDomain
	CertificatesPerDomainPerAccount
	CertificatesPerFQDNSet
	OverallRequestsPerIPAddress
)

// String returns the string representation of the rate limit name.
func (n Name) String() string {
	names := map[Name]string{
		Unknown:                                 "Unknown",
		NewRegistrationsPerIPAddress:            "NewRegistrationsPerIPAddress",
		NewRegistrationsPerIPv6Range:            "NewRegistrationsPerIPv6Range",
		NewOrdersPerAccount:                     "NewOrdersPerAccount",
		FailedAuthorizationsPerDomainPerAccount: "FailedAuthorizationsPerDomainPerAccount",
		CertificatesPerDomain:                   "CertificatesPerDomain",
		CertificatesPerDomainPerAccount:         "CertificatesPerDomainPerAccount",
		CertificatesPerFQDNSet:                  "CertificatesPerFQDNSet",
		OverallRequestsPerIPAddress:             "OverallRequestsPerIPAddress",
	}
	if s, ok := names[n]; ok {
		return s
	}
	return "Unknown"
}

// IsValid returns true if the name is a valid rate limit name.
func (n Name) IsValid() bool {
	return n > Unknown && n <= OverallRequestsPerIPAddress
}

// Limit defines the configuration for a rate limit.
type Limit struct {
	// Name identifies this rate limit.
	Name Name

	// Burst specifies maximum concurrent allowed requests at any given time.
	// Must be greater than zero.
	Burst int64

	// Count is the number of requests allowed per period.
	// Must be greater than zero.
	Count int64

	// Period is the duration of time in which the count is allowed.
	// Must be greater than zero.
	Period time.Duration

	// emissionInterval is the interval, in nanoseconds, at which tokens are
	// added to a bucket (period / count). This is precomputed for performance.
	emissionInterval int64

	// burstOffset is the duration of time, in nanoseconds, it takes for a
	// bucket to go from empty to full (burst * emissionInterval).
	// This is precomputed for performance.
	burstOffset int64

	// isOverride indicates if this limit is an override of a default.
	isOverride bool
}

// NewLimit creates a new Limit with the given parameters.
// The limit is validated and precomputed values are calculated.
func NewLimit(name Name, burst, count int64, period time.Duration) (*Limit, error) {
	l := &Limit{
		Name:   name,
		Burst:  burst,
		Count:  count,
		Period: period,
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	l.precompute()
	return l, nil
}

// Validate checks that the limit configuration is valid.
func (l *Limit) Validate() error {
	if l.Burst <= 0 {
		return errors.ErrInvalidBurst
	}
	if l.Count <= 0 {
		return errors.ErrInvalidCount
	}
	if l.Period <= 0 {
		return errors.ErrInvalidPeriod
	}
	return nil
}

// precompute calculates the emission interval and burst offset.
func (l *Limit) precompute() {
	l.emissionInterval = l.Period.Nanoseconds() / l.Count
	l.burstOffset = l.emissionInterval * l.Burst
}

// EmissionInterval returns the interval between token emissions.
func (l *Limit) EmissionInterval() time.Duration {
	return time.Duration(l.emissionInterval)
}

// BurstOffset returns the time to refill from empty to full.
func (l *Limit) BurstOffset() time.Duration {
	return time.Duration(l.burstOffset)
}

// IsOverride returns true if this limit is an override.
func (l *Limit) IsOverride() bool {
	return l.isOverride
}

// Clone creates a deep copy of the Limit.
func (l *Limit) Clone() *Limit {
	return &Limit{
		Name:             l.Name,
		Burst:            l.Burst,
		Count:            l.Count,
		Period:           l.Period,
		emissionInterval: l.emissionInterval,
		burstOffset:      l.burstOffset,
		isOverride:       l.isOverride,
	}
}

// DefaultLimits returns a map of default rate limits for ACME operations.
func DefaultLimits() map[Name]*Limit {
	limits := make(map[Name]*Limit)

	// 10 new registrations per IP per hour
	limits[NewRegistrationsPerIPAddress] = mustNewLimit(
		NewRegistrationsPerIPAddress, 10, 10, time.Hour,
	)

	// 10 new registrations per /48 IPv6 range per hour
	limits[NewRegistrationsPerIPv6Range] = mustNewLimit(
		NewRegistrationsPerIPv6Range, 10, 10, time.Hour,
	)

	// 300 new orders per account per 3 hours
	limits[NewOrdersPerAccount] = mustNewLimit(
		NewOrdersPerAccount, 300, 300, 3*time.Hour,
	)

	// 5 failed authorizations per domain per account per hour
	limits[FailedAuthorizationsPerDomainPerAccount] = mustNewLimit(
		FailedAuthorizationsPerDomainPerAccount, 5, 5, time.Hour,
	)

	// 50 certificates per domain per week
	limits[CertificatesPerDomain] = mustNewLimit(
		CertificatesPerDomain, 50, 50, 7*24*time.Hour,
	)

	// 5 duplicate certificates per FQDN set per week
	limits[CertificatesPerFQDNSet] = mustNewLimit(
		CertificatesPerFQDNSet, 5, 5, 7*24*time.Hour,
	)

	// 20 overall requests per IP per second
	limits[OverallRequestsPerIPAddress] = mustNewLimit(
		OverallRequestsPerIPAddress, 20, 20, time.Second,
	)

	return limits
}

// mustNewLimit creates a new limit or panics. Used for default initialization.
func mustNewLimit(name Name, burst, count int64, period time.Duration) *Limit {
	l, err := NewLimit(name, burst, count, period)
	if err != nil {
		panic(err)
	}
	return l
}
