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
	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
	// Each tenant's Android application allow-list is server
	// configuration; a tenant without one keeps Android appraisal refused.
	if policies, err := s.androidApplicationPolicies(); err != nil {
		return nil, err
	} else if policies != nil {
		opts = append(opts, appraisal.WithAndroidApplications(policies))
	}
	return appraisal.NewAppraiser(store, opts...)
}

// androidApplicationPolicies converts attestation.android_applications to
// the Appraiser's static per-tenant source; nil when none is configured.
func (s *Server) androidApplicationPolicies() (appraisal.AndroidApplicationPolicies, error) {
	if s.config == nil || s.config.Attestation == nil || len(s.config.Attestation.AndroidApplications) == 0 {
		return nil, nil
	}
	if err := s.config.Attestation.ValidateAndroidApplications(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid attestation.android_applications", Err: err}
	}
	policies := make(appraisal.AndroidApplicationPolicies, len(s.config.Attestation.AndroidApplications))
	for tenant, packages := range s.config.Attestation.AndroidApplications {
		allow := make(appraisal.AndroidApplicationAllowList, len(packages))
		for pkg, digests := range packages {
			allow[pkg] = append([]string(nil), digests...)
		}
		policies[tenant] = allow
	}
	return policies, nil
}
