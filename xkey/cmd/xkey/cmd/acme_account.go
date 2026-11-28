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
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newACMEAccountCmd(flags *acmeFlags) *cobra.Command {
	c := &cobra.Command{
		Use:   "account",
		Short: "Register, update or deactivate the ACME account",
	}
	c.AddCommand(newACMEAccountRegisterCmd(flags))
	c.AddCommand(newACMEAccountUpdateCmd(flags))
	c.AddCommand(newACMEAccountDeactivateCmd(flags))
	return c
}

func newACMEAccountRegisterCmd(flags *acmeFlags) *cobra.Command {
	var contact string
	c := &cobra.Command{
		Use:   "register",
		Short: "Register the account key with the ACME server (idempotent)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return flags.withACMEClient(c, stripMailto(contact), func(client acmeClient) error {
				account, err := client.RegisterAccount()
				if err != nil {
					return fmt.Errorf("acme: register account: %w", err)
				}
				printACMEAccount(c, account)
				return nil
			})
		},
	}
	c.Flags().StringVar(&contact, "contact", "", "account contact, e.g. mailto:admin@example.com")
	return c
}

func newACMEAccountUpdateCmd(flags *acmeFlags) *cobra.Command {
	var contacts []string
	c := &cobra.Command{
		Use:   "update",
		Short: "Replace the account contacts",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if len(contacts) == 0 {
				return errors.New("acme: account update needs at least one --contact")
			}
			return flags.withACMEClient(c, "", func(client acmeClient) error {
				account, err := client.UpdateAccount(c.Context(), contacts)
				if err != nil {
					return fmt.Errorf("acme: update account: %w", err)
				}
				printACMEAccount(c, account)
				return nil
			})
		},
	}
	c.Flags().StringArrayVar(&contacts, "contact", nil, "account contact (repeatable); mailto: is added when missing")
	return c
}

func newACMEAccountDeactivateCmd(flags *acmeFlags) *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "deactivate",
		Short: "Permanently deactivate the ACME account (irreversible)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if !yes {
				return errors.New("acme: account deactivation is irreversible; pass --yes to confirm")
			}
			return flags.withACMEClient(c, "", func(client acmeClient) error {
				if err := client.DeactivateAccount(c.Context()); err != nil {
					return fmt.Errorf("acme: deactivate account: %w", err)
				}
				_, _ = fmt.Fprintln(c.OutOrStdout(), "account deactivated")
				return nil
			})
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "confirm the irreversible deactivation")
	return c
}
