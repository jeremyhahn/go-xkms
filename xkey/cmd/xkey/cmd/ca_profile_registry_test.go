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

package cmd

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helpProfileNames extracts the profile names a command's long help lists
// under its "Available profiles:" block: the first token of every indented
// line up to the next blank line. It returns nil when the help has no such
// block.
func helpProfileNames(long string) []string {
	const header = "Available profiles:"

	start := strings.Index(long, header)
	if start < 0 {
		return nil
	}

	var names []string
	for _, line := range strings.Split(long[start+len(header):], "\n") {
		if strings.TrimSpace(line) == "" {
			if len(names) > 0 {
				break
			}
			continue
		}
		names = append(names, strings.Fields(line)[0])
	}
	return names
}

func TestHelpProfileNames_ParsesTheBlock(t *testing.T) {
	long := "Issue a certificate.\n\nAvailable profiles:\n  server   TLS server\n  client   TLS client\n\nSANs follow.\n  DNS:example.com\n"

	assert.Equal(t, []string{"server", "client"}, helpProfileNames(long))
}

func TestHelpProfileNames_NoBlockYieldsNothing(t *testing.T) {
	assert.Nil(t, helpProfileNames("Issue a certificate.\n\nSANs follow.\n  DNS:example.com\n"))
	assert.Nil(t, helpProfileNames(""))
}

// TestCAIssueHelpProfilesAreRegistered pins every profile name `xkey ca issue`
// advertises to the default profile registry the CA resolves it against. The
// help used to list "idevid", which no registry entry matched, so a user who
// followed it got ErrProfileNotFound at the CA (#241): documentation that
// names a profile is a promise the registry has to keep.
func TestCAIssueHelpProfilesAreRegistered(t *testing.T) {
	names := helpProfileNames(caIssueCmd.Long)
	require.NotEmpty(t, names, "ca issue help must advertise at least one profile")

	registry := ca.NewDefaultProfileRegistry()
	for _, name := range names {
		profile, err := registry.Get(name)
		require.NoError(t, err, "profile %q is advertised by ca issue but not registered", name)
		assert.Equal(t, name, profile.Name())
	}
}

// TestCertProfileDefaultsAreRegistered pins the profile names this package
// requests on the user's behalf without a flag to the same registry, so a
// default that drifts from the registry fails here rather than at the CA.
func TestCertProfileDefaultsAreRegistered(t *testing.T) {
	registry := ca.NewDefaultProfileRegistry()

	for _, name := range []string{agent.CertProfileDefault, defaultCertProfile} {
		profile, err := registry.Get(name)
		require.NoError(t, err, "default profile %q is not registered", name)
		assert.Equal(t, name, profile.Name())
	}
}
