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

package server

import (
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
)

// buildOIDCCredentials builds the server-side OIDC credential service over
// the tenant barrier registry and the embedded qrdb node's lease primitive,
// through compose.BuildOIDCCredentialService -- the path an embedding
// host's module takes -- and starts its refresh scheduler. Without a
// barrier registry or a qrdb node the feature stays off, logged.
func (s *Server) buildOIDCCredentials() {
	if s.oidcCredentials != nil {
		return
	}
	if s.barrierRegistry == nil || s.qrdbClient == nil {
		disabled := &compose.FeatureDisabledError{Feature: compose.FeatureOIDCCredentials, Missing: "barrier registry and qrdb node"}
		s.logger.Info("xkms feature off", "feature", compose.FeatureOIDCCredentials, "reason", disabled.Error())
		return
	}
	coord, err := s.qrdbClient.Coordination()
	if err != nil {
		s.logger.Warn("xkms feature off", "feature", compose.FeatureOIDCCredentials, "reason", err.Error())
		return
	}
	params := compose.OIDCCredentialParams{
		Registry: s.barrierRegistry,
		Leases:   coord,
		Audit:    s.auditLogger,
		Logger:   s.logger,
	}
	// The refresh leases are xkms's own coordination: over the embedded node
	// they run as its service principal, as they run as xkms's mTLS identity
	// against a remote datastore.
	if s.qrdbNode != nil {
		params.LeaseContext = s.qrdbNode.ServiceContext
	}
	svc, err := compose.BuildOIDCCredentialService(params)
	if err != nil {
		s.logger.Error("xkms feature failed to build; it stays off", "feature", compose.FeatureOIDCCredentials, "error", err)
		return
	}
	s.oidcCredentials = svc
	s.logger.Info("xkms feature on", "feature", compose.FeatureOIDCCredentials)
}

// closeOIDCCredentials stops the OIDC credential scheduler. Idempotent.
func (s *Server) closeOIDCCredentials() {
	if s.oidcCredentials == nil {
		return
	}
	svc := s.oidcCredentials
	s.oidcCredentials = nil
	if err := svc.Close(); err != nil {
		s.logger.Error("Error closing the OIDC credential service", "error", err)
	}
}

// OIDCCredentialService returns the OIDC credential service, or nil when it
// is off.
func (s *Server) OIDCCredentialService() *credential.Service {
	return s.oidcCredentials
}
