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

package compose

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func TestBuildVerdictStore(t *testing.T) {
	store, err := BuildVerdictStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	require.NotNil(t, store)

	_, err = BuildVerdictStore(nil)
	var nilDep *NilDependencyError
	require.ErrorAs(t, err, &nilDep)
	assert.Equal(t, FeatureVerdicts, nilDep.Feature)

	_, err = BuildVerdictStore(dao.NewStoreFactory(nil))
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureVerdicts, buildErr.Feature)
}

func TestBuild_VerdictsNeedTheDAOFactory(t *testing.T) {
	st, err := Build(context.Background(), Deps{Service: hostdeps.NewService(t)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	assert.Nil(t, st.Verdicts)
	assert.Contains(t, reasonsFor(st, FeatureVerdicts), "DAO factory")

	full, err := Build(context.Background(), fullDeps(t, hostdeps.NewService(t)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, full.Close()) })
	assert.NotNil(t, full.Verdicts)
}

func TestWire_ServesStoredVerdictsWithoutEngine(t *testing.T) {
	svc := hostdeps.NewService(t)
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}

	_, err := svc.ListAttestationVerdicts(platformCtx(), req)
	require.ErrorIs(t, err, xkms.ErrNotConfigured)

	st, err := Build(context.Background(), fullDeps(t, svc))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	st.Wire(svc)

	resp, err := svc.ListAttestationVerdicts(platformCtx(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Verdicts)

	_, err = svc.ReattestDevice(platformCtx(), req)
	assert.ErrorIs(t, err, xkms.ErrNotConfigured)
}
