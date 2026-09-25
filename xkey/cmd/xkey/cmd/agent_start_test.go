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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

// TestRunAgentStart_InvalidListenAddressFailsValidation exercises the real
// config-validation guard before any listener is bound: an explicitly empty
// --listen fails cfg.Validate() immediately, so runAgentStart never claims
// run-state, opens an enrollment store, or binds a socket.
func TestRunAgentStart_InvalidListenAddressFailsValidation(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("listen", "", "")
	cmd.Flags().String("tls-cert", "", "")
	cmd.Flags().String("tls-key", "", "")
	cmd.Flags().String("tls-ca", "", "")
	require.NoError(t, cmd.Flags().Set("listen", ""))

	err := runAgentStart(cmd, nil)
	require.ErrorIs(t, err, agent.ErrInvalidAddress)
}
