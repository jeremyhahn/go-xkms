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

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// serviceStartCmd runs the certificate auto-renewal daemon.
var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the auto-renewal service daemon",
	Long: `Start the certificate auto-renewal service as a long-running daemon.

The service monitors all certificates with auto-renewal enabled and
renews them when they approach expiration based on their days_before
configuration.

The service runs until interrupted by SIGINT, SIGTERM, or SIGQUIT.

Examples:
  trusted-acme-client service start
  trusted-acme-client --config /etc/trusted-acme/client.yaml service start`,
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		ctx := cmd.Context()

		if err := svc.StartRenewal(ctx); err != nil {
			return err
		}

		cmd.Println("Renewal service started. Press Ctrl+C to stop.")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

		sig := <-sigChan
		cmd.Printf("Received signal %s, shutting down...\n", sig)

		if err := svc.StopRenewal(); err != nil {
			return err
		}

		cmd.Println("Renewal service stopped.")
		return nil
	},
}

// serviceStatusCmd shows the renewal service status.
var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show renewal service status",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		certs := svc.Certificates().List("")
		autoCount := 0
		for _, spec := range certs {
			if spec.Renewal != nil && spec.Renewal.Auto {
				autoCount++
			}
		}

		cmd.Printf("Certificates: %d total, %d auto-renew\n", len(certs), autoCount)
		return nil
	},
}

func init() {
	serviceCmd.AddCommand(serviceStartCmd)
	serviceCmd.AddCommand(serviceStatusCmd)
}
