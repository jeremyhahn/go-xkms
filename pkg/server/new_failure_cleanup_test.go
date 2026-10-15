package server

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// pebbleMinimalConfig is createMinimalConfig over a Pebble datastore, which
// holds an exclusive lock on its directory for as long as the node is open.
func pebbleMinimalConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := createMinimalConfig(t)
	cfg.Datastore.Engine = "pebble"
	cfg.Datastore.Mode = "standalone"
	// The node serves its data plane, the feature databases New creates
	// included, only once first boot binds the admin a certificate, which
	// needs the CA. Without it New fails at the first feature database,
	// before the config under test is read.
	cfg.CA = testFirstBootCAConfig()
	return cfg
}

// requireDatastoreReleased opens a second server on cfg's datastore. It only
// succeeds when the failed New released the embedded node and its lock.
func requireDatastoreReleased(t *testing.T, cfg *config.Config) {
	t.Helper()
	cfg.Invite = nil
	cfg.Attestation = nil
	srv, err := New(cfg)
	require.NoError(t, err, "a failed New left the datastore open")
	require.NoError(t, srv.Shutdown())
}

func TestXKMSInviteConfigFromOperator(t *testing.T) {
	got, err := xkmsInviteConfigFromOperator(&config.InviteConfig{
		PublicBaseURL: "https://xkms.example.com",
		DefaultTTL:    "24h",
		MaxTTL:        "168h",
	})
	require.NoError(t, err)
	require.Equal(t, "https://xkms.example.com", got.PublicBaseURL)
	require.Equal(t, 24*time.Hour, got.DefaultTTL)
	require.Equal(t, 168*time.Hour, got.MaxTTL)

	got, err = xkmsInviteConfigFromOperator(&config.InviteConfig{})
	require.NoError(t, err)
	require.Zero(t, got.DefaultTTL, "an unset TTL must stay zero so the service default applies")
	require.Zero(t, got.MaxTTL)
}

func TestXKMSInviteConfigFromOperator_InvalidDurations(t *testing.T) {
	cases := []struct {
		name  string
		cfg   config.InviteConfig
		field string
	}{
		{name: "default_ttl", cfg: config.InviteConfig{DefaultTTL: "a day"}, field: "default_ttl"},
		{name: "max_ttl", cfg: config.InviteConfig{DefaultTTL: "1h", MaxTTL: "forever"}, field: "max_ttl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xkmsInviteConfigFromOperator(&tc.cfg)
			var parseErr *InviteConfigParseError
			require.ErrorAs(t, err, &parseErr)
			require.Equal(t, tc.field, parseErr.Field)
			require.Contains(t, err.Error(), "invite."+tc.field)
			require.NotNil(t, errors.Unwrap(err), "the time.ParseDuration cause must stay reachable")
		})
	}
}

// TestNew_InvalidInviteConfigReleasesDatastore is the regression test for New
// returning on a bad invite TTL without closing the embedded node, which kept
// the datastore locked for the life of the process.
func TestNew_InvalidInviteConfigReleasesDatastore(t *testing.T) {
	cfg := pebbleMinimalConfig(t)
	cfg.Invite = &config.InviteConfig{DefaultTTL: "a day"}

	srv, err := New(cfg)
	require.Nil(t, srv)
	var parseErr *InviteConfigParseError
	require.ErrorAs(t, err, &parseErr)

	requireDatastoreReleased(t, cfg)
}

// TestNew_InvalidAttestationConfigReleasesDatastore covers the same leak on
// the attestation trust-anchor path: a format with no trust store is fatal.
func TestNew_InvalidAttestationConfigReleasesDatastore(t *testing.T) {
	cfg := pebbleMinimalConfig(t)
	cfg.Attestation = &config.AttestationConfig{Formats: map[string]*truststore.Config{"tpm2": nil}}

	srv, err := New(cfg)
	require.Nil(t, srv)
	require.ErrorIs(t, err, config.ErrAttestationTrustStoreMissing)

	requireDatastoreReleased(t, cfg)
}
