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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	clustercapkg "github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newTLogCAServer returns a minimal server with a one-identity CA whose keys
// the cluster barrier strategy routes, as
// TestInitializeCA_ClusterKeyStrategyRoutesKeystore does, and the given
// transparency_log.enabled.
func newTLogCAServer(t *testing.T, enabled bool) *Server {
	t.Helper()
	s := newMinimalServer(t, &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
		CA: &ca.MultiIdentityCAConfig{
			SelectedCA: 0,
			Identity: []ca.Identity{{
				IsRoot:  true,
				Valid:   1,
				Subject: ca.Subject{CommonName: "TLog Test CA"},
				Keys: []*types.KeyConfig{{
					KeyAlgorithm: types.AlgorithmECDSA,
					ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
				}},
			}},
		},
		Cluster: config.ClusterConfig{
			RaftEnrollment: config.RaftEnrollmentConfig{CAKeyProtection: "none"},
		},
		TransparencyLog: config.TransparencyLogConfig{Enabled: &enabled},
	})
	openInMemoryDatastore(t, s)
	strategy, err := clustercapkg.NewKeyStrategy(clustercapkg.KeyStrategyBarrier)
	require.NoError(t, err)
	s.clusterCAKeyStrategy = strategy
	return s
}

func TestTransparencyLogOrigin(t *testing.T) {
	s := newTLogCAServer(t, true)
	require.Equal(t, "TLog-Test-CA/tlog", s.transparencyLogOrigin(), "derived from the CA common name, without spaces")

	s.config.TransparencyLog.Origin = "ca.example.com/tlog"
	require.Equal(t, "ca.example.com/tlog", s.transparencyLogOrigin(), "the configured origin wins")
}

func TestTransparencyLogNodeOptions(t *testing.T) {
	t.Run("on", func(t *testing.T) {
		s := newTLogCAServer(t, true)
		opts, err := s.transparencyLogNodeOptions()
		require.NoError(t, err)
		require.Len(t, opts, 1, "the head signer option")
		require.NotNil(t, s.tlogKeys)
		require.NotNil(t, s.tlogSigners)
	})
	t.Run("off", func(t *testing.T) {
		s := newTLogCAServer(t, false)
		opts, err := s.transparencyLogNodeOptions()
		require.NoError(t, err)
		require.Empty(t, opts)
		require.Nil(t, s.tlogSigners)
	})
	t.Run("no CA", func(t *testing.T) {
		on := true
		s := newMinimalServer(t, &config.Config{TransparencyLog: config.TransparencyLogConfig{Enabled: &on}})
		opts, err := s.transparencyLogNodeOptions()
		require.NoError(t, err)
		require.Empty(t, opts)
	})
}

// With the switch off, initializeCA composes the CA exactly as before: no
// node, no head signer, no log.
func TestInitializeCA_TransparencyLogOff(t *testing.T) {
	s := newTLogCAServer(t, false)
	require.NoError(t, s.initializeCA())
	require.NotNil(t, s.ca)

	issued, err := s.ca.IssueCertificate(context.Background(), &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "tlog-off"}, Valid: 30, TenantID: "tenant-a"})
	require.NoError(t, err, "no log, no append")
	require.NotNil(t, issued.Certificate)

	svc := &xkms.XKMSService{}
	s.wireTransparencyLog(svc)
	_, err = svc.GetTransparencyLogHead(context.Background(), &transport.GetTransparencyLogHeadRequest{})
	require.ErrorIs(t, err, xkms.ErrTransparencyLogNotConfigured, "no log, nothing to read")
}

// Switched on with no embedded node to open the log on, start-up fails with
// the typed error, before the CA issues anything.
func TestInitializeCA_TransparencyLogUnavailable(t *testing.T) {
	s := newTLogCAServer(t, true)
	opts, err := s.transparencyLogNodeOptions()
	require.NoError(t, err)
	require.Len(t, opts, 1)

	err = s.initializeCA()
	var tlogErr *ErrTransparencyLog
	require.True(t, errors.As(err, &tlogErr), "got %v", err)
	require.ErrorIs(t, err, ErrTransparencyLogUnavailable)
}
