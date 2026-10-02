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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/ratelimit"

// Pre-authentication rate limiting. xkmsd limits requests per client IP
// before authentication runs, so an unauthenticated flood never reaches the
// credential checks. The client IP honours X-Forwarded-For only from
// configured trusted proxies, and IPv6 clients are limited per /64. A host
// fronting the same planes installs the same limiter through these aliases.
// Identifiers carry an IPRateLimit prefix because the flat namespace already
// holds an autofill rate limiter.

// IPRateLimiter is a per-client token-bucket limiter with a bounded client
// table and background eviction. Stop releases its eviction goroutine.
type IPRateLimiter = ratelimit.Limiter

// IPRateLimitConfig configures an IPRateLimiter.
type IPRateLimitConfig = ratelimit.Config

// IPRateLimitCapacityError reports a limiter whose client table is full; the
// request is refused rather than tracked without bound.
type IPRateLimitCapacityError = ratelimit.CapacityError

// IPRateLimitDefaultMaxClients is the client-table bound when the config
// leaves it zero.
const IPRateLimitDefaultMaxClients = ratelimit.DefaultMaxClients

// NewIPRateLimiter constructs an IPRateLimiter.
var NewIPRateLimiter = ratelimit.New

// TrustedProxies is the set of proxy networks whose X-Forwarded-For header is
// believed when deriving a request's client IP.
type TrustedProxies = ratelimit.TrustedProxies

// InvalidTrustedProxyError reports a trusted-proxy entry that is neither an
// IP address nor a CIDR network.
type InvalidTrustedProxyError = ratelimit.InvalidTrustedProxyError

// ParseTrustedProxies parses IP addresses and CIDR networks into a
// TrustedProxies set.
var ParseTrustedProxies = ratelimit.ParseTrustedProxies

// IPRateLimitKey returns the limiter key for a client IP: the address itself,
// or its /64 network for IPv6.
var IPRateLimitKey = ratelimit.RateLimitKey

// IPRateLimitMiddleware returns HTTP middleware that refuses a request over
// its client's limit with 429, deriving the client IP through the trusted
// proxies.
var IPRateLimitMiddleware = ratelimit.Middleware

// IPRateLimitUnaryServerInterceptor limits gRPC unary calls by peer address.
var IPRateLimitUnaryServerInterceptor = ratelimit.UnaryServerInterceptor

// IPRateLimitStreamServerInterceptor limits gRPC streams by peer address.
var IPRateLimitStreamServerInterceptor = ratelimit.StreamServerInterceptor
