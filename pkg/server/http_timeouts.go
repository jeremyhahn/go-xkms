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

package server

import (
	"net/http"
	"time"
)

// Hardened{Read,ReadHeader,Write,Idle}Timeout are the timeouts every plain
// http.Server this process starts applies unless it has its own per-request
// tuned configuration (the REST server's rest.Config timeout fields, set
// from config.Config and adjustable per deployment). They bound a
// slow-header or slow-body client (ReadHeaderTimeout, ReadTimeout), a
// stalled response write (WriteTimeout), and an idle keep-alive connection
// (IdleTimeout) -- all Slowloris-class attacks against a listener that
// otherwise has no request deadline at all (go-xkms#1262).
const (
	HardenedReadHeaderTimeout = 10 * time.Second
	HardenedReadTimeout       = 30 * time.Second
	HardenedWriteTimeout      = 30 * time.Second
	HardenedIdleTimeout       = 120 * time.Second
)

// ApplyHardenedTimeouts sets srv's ReadHeaderTimeout, ReadTimeout,
// WriteTimeout and IdleTimeout to the Hardened* values above. The metrics
// server (startMetrics, this package) and xkmsd's dedicated ACME listener
// (cmd/xkmsd/acme.go) are both plain http.Server values with no
// per-deployment timeout configuration of their own, so they share this one
// definition instead of each hand-copying the same four-field literal --
// which is how the metrics server ended up with only ReadHeaderTimeout set
// while the ACME listener carried the full set.
func ApplyHardenedTimeouts(srv *http.Server) {
	srv.ReadHeaderTimeout = HardenedReadHeaderTimeout
	srv.ReadTimeout = HardenedReadTimeout
	srv.WriteTimeout = HardenedWriteTimeout
	srv.IdleTimeout = HardenedIdleTimeout
}
