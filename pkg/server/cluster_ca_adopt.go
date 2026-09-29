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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
)

// clusterCACacheSubdir is the data-dir subdirectory the cluster-enrollment
// provisioner (pkg/trust/clusterca) writes its first-node CA cache into.
const clusterCACacheSubdir = "cluster-ca"

// adoptStagedClusterCACerts imports the full CA certificate set the cluster
// ACME first-node pre-stage persisted (StagedCACertsPath) into the runtime CA's
// certificate store, so the CA's Load — which verifies every configured
// intermediate — succeeds without re-running Init (which would fork a second
// root). It is a no-op when no staged material is present (the normal case:
// non-cluster deployments, joining nodes, or the first node on a subsequent
// boot after adoption), so it is safe to call unconditionally before Load.
func (s *Server) adoptStagedClusterCACerts(certStore certstore.CertStore) error {
	path := clusterca.StagedCACertsPath(filepath.Join(s.config.Datastore.Path, clusterCACacheSubdir))
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	count := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return parseErr
		}
		// StoreCertificate is idempotent for our purpose: a certificate already
		// present from a prior boot's adoption is harmless. Log-and-continue so
		// a duplicate never fails startup.
		if storeErr := certStore.StoreCertificate(cert); storeErr != nil {
			s.logger.Debug("staged cluster CA certificate already present or unstorable",
				"cn", cert.Subject.CommonName, "error", storeErr.Error())
			continue
		}
		count++
	}
	if count > 0 {
		s.logger.Info("adopted pre-staged cluster CA certificates into the runtime CA store",
			"count", count, "path", path)
	}
	return nil
}
