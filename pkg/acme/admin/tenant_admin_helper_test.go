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

package admin

import (
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
	acmestorage "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/require"
)

// mustTenantAwareAdminService constructs a TenantAwareAdminService and fails
// the test immediately if construction errors. It exists so the ~130 call
// sites across this package's test files don't each need to thread a second
// return value through NewTenantAwareAdminService, which refuses to
// construct a service when a storageFactory claims tenant-aware support
// (storage.TenantAwareFactory) but fails to produce its TenantDAO (see
// TenantDAOInitError). Every test file in this package passes either a nil
// storageFactory or a working TenantAwareFactory, so that refusal path
// never fires through this helper;
// TestNewTenantAwareAdminService_TenantDAOFailure in tenant_service_test.go
// exercises it directly against the two-return-value constructor instead.
//
// This file carries no build tag deliberately: certpolicy_test.go and
// tenant_qrdb_test.go call this helper and are themselves unconstrained, so
// the helper must build under every tag combination too.
func mustTenantAwareAdminService(
	t testing.TB,
	certificateAuthority ca.TCGCA,
	storageFactory acmestorage.Factory,
	qrdbService qrdb.Service,
	logger *slog.Logger,
	version string,
) *TenantAwareAdminService {
	t.Helper()
	svc, err := NewTenantAwareAdminService(certificateAuthority, storageFactory, qrdbService, logger, version)
	require.NoError(t, err)
	return svc
}
