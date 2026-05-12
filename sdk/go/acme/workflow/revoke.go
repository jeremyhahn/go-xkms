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

package workflow

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/certificate"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// RevokeCertificate revokes a previously issued certificate via the ACME server.
func (w *workflow) RevokeCertificate(ctx context.Context, req *RevokeRequest) error {
	const op = "workflow.RevokeCertificate"

	if req == nil {
		return errors.NewInvalidInput(op, "revoke request cannot be nil")
	}
	if req.Certificate == "" {
		return errors.NewInvalidInput(op, "certificate is required")
	}

	_, err := w.client.Certificate().Revoke(ctx, &certificate.RevokeRequest{
		Certificate: req.Certificate,
		Reason:      certificate.RevocationReason(req.Reason),
	})
	if err != nil {
		return WrapRevocationError(err, op, "failed to revoke certificate")
	}

	return nil
}
