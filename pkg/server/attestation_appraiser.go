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
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// buildAttestationAppraiser composes the attestation Verifier xkmsd serves:
// the tenant-scoped endorsement, reference-value and signing-key store over
// the appraisal database on the server's datastore, and the Appraiser over
// it. Without it every endorsement, reference-value and appraise call
// answers ErrNotConfigured.
func (s *Server) buildAttestationAppraiser() (*appraisal.Appraiser, error) {
	daos, err := s.daoFactory(appraisal.DatabaseName)
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "attestation appraisal storage", Err: err}
	}
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: daos})
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "attestation appraisal storage", Err: err}
	}
	// The XKMSService, initialized with the key store before this call,
	// holds each tenant's repository signing keys: without it as the
	// source, every repository-signed CoRIM fails as a ConfigError.
	var opts []appraisal.Option
	if svc, err := xkms.Get(); err == nil {
		opts = append(opts, appraisal.WithSigningKeySource(svc))
	}
	return appraisal.NewAppraiser(store, opts...)
}
