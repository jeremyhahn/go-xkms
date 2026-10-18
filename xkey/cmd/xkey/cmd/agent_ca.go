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

package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

// ErrAgentCAUnavailable indicates no xkmsd certificate authority could be
// reached. Agent enrollment issues real client certificates, so the agent
// server refuses to start without one.
var ErrAgentCAUnavailable = errors.New("agent: enrollment requires a reachable xkmsd certificate authority; " +
	"set --xkmsd-url or XKMSD_URL (xkey never signs certificates locally)")

// newAgentCA connects to the configured xkmsd certificate authority and
// verifies it can serve agent enrollment by retrieving its CA certificate.
// It fails closed - returning ErrAgentCAUnavailable - when no server URL is
// configured, when the server cannot be reached, or when the server has no
// usable CA certificate. The returned CA owns a connected transport client
// that the caller must Close.
//
// The endpoint is resolved without consulting cmd so that "agent start
// --tls-ca", which supplies the agent server's own client-verification
// bundle, is never mistaken for the trust bundle used to reach xkmsd; that
// one comes from XKMSD_TLS_CA or the xkey config.
func newAgentCA(profile string, validityDays int) (*agent.XKMSdCA, error) {
	client, err := connectXKMSdClient(nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentCAUnavailable, Cause: err}
	}

	ca, err := agent.NewXKMSdCA(client, profile, validityDays)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentCAUnavailable, Cause: err}
	}

	// Prove the authority is usable before the listener accepts agents.
	if _, err := ca.GetCACertificate(); err != nil {
		if closeErr := ca.Close(); closeErr != nil {
			return nil, &SentinelCauseError{Sentinel: ErrAgentCAUnavailable, Cause: closeErr}
		}
		return nil, &SentinelCauseError{Sentinel: ErrAgentCAUnavailable, Cause: err}
	}
	return ca, nil
}

// agentCertProfile returns the CA profile requested for agent
// certificates, falling back to the client profile.
func agentCertProfile(cmd *cobra.Command) string {
	profile, _ := cmd.Flags().GetString("cert-profile")
	if profile == "" {
		return agent.CertProfileDefault
	}
	return profile
}
