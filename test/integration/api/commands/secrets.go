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

package commands

// Values the password, pin and piv families of the CLI matrix use. The
// workflow in cli_secrets_matrix_test.go overrides the ones that come from
// an earlier step (entry IDs, factor IDs, the recovery code, cert files).
const (
	// SecretsVaultPassphrase is the vault passphrase the workflow enrolls
	// first and unlocks with on every transport.
	SecretsVaultPassphrase = "it-matrix-vault-passphrase-1"
	// SecretsVaultSecondPassphrase is the factor "password vault enroll" adds.
	SecretsVaultSecondPassphrase = "it-matrix-vault-passphrase-2"
	// SecretsVaultRotatedPassphrase replaces the second factor in "rotate".
	SecretsVaultRotatedPassphrase = "it-matrix-vault-passphrase-3"
	// SecretsVaultRecoveredPassphrase is the factor "recover" enrolls.
	SecretsVaultRecoveredPassphrase = "it-matrix-vault-passphrase-4"

	// SecretsPasswordEntry is the name of the entry "password add" creates.
	SecretsPasswordEntry = "it-matrix-password-entry"

	// SecretsSOPIN and SecretsSOPINAlt are the SO PINs; so-change moves
	// from the first to the second and the workflow moves back.
	SecretsSOPIN    = "73915820"
	SecretsSOPINAlt = "73915821"
	// SecretsUserPIN and SecretsUserPINAlt are the user PINs.
	SecretsUserPIN    = "461902"
	SecretsUserPINAlt = "461903"

	// SecretsPIVSlot is the slot "piv generate" fills; csr, export, get and
	// delete use it. Store and import write the exported certificate to
	// SecretsPIVStoreSlot and SecretsPIVImportSlot.
	SecretsPIVSlot       = "9a"
	SecretsPIVStoreSlot  = "9c"
	SecretsPIVImportSlot = "9d"

	// Override keys for positional arguments that come from an earlier step.
	ArgEntryID = "Entry ID"
	ArgPIVSlot = "PIV slot"
)

func positionalArg(value, description string) ArgDefinition {
	return ArgDefinition{Value: value, Description: description, IsPositional: true}
}

func flagArg(name, value, description string) ArgDefinition {
	return ArgDefinition{Flag: name, Value: value, Description: description}
}

var jsonOutput = []ArgDefinition{flagArg("output", "json", "Output format")}

// PasswordCommands returns the password and password vault commands.
func PasswordCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name: "password-vault-status", Category: CategoryPassword,
			Command:        []string{"password", "vault", "status"},
			Description:    "Show the personal vault and its factors",
			RequiresServer: true,
		},
		{
			Name: "password-unlock", Category: CategoryPassword,
			Command:        []string{"password", "unlock"},
			Description:    "Open a vault session with the passphrase",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{flagArg("passphrase", SecretsVaultPassphrase, "Vault passphrase")},
		},
		{
			Name: "password-status", Category: CategoryPassword,
			Command:        []string{"password", "status"},
			Description:    "Show the password store session status",
			RequiresServer: true,
		},
		{
			Name: "password-access-mode", Category: CategoryPassword,
			Command:        []string{"password", "access-mode"},
			Description:    "Set the password store access mode",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{positionalArg("session_based", "Access mode")},
		},
		{
			Name: "password-add", Category: CategoryPassword,
			Command:        []string{"password", "add"},
			Description:    "Add a password entry",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				positionalArg(SecretsPasswordEntry, "Entry name"),
				flagArg("password", "it-matrix-S3cret-value", "Password value"),
				flagArg("username", "it-matrix-user", "Username"),
			},
			OptionalArgs: jsonOutput,
		},
		{
			Name: "password-get", Category: CategoryPassword,
			Command:        []string{"password", "get"},
			Description:    "Show a password entry",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs:           []ArgDefinition{positionalArg("", ArgEntryID)},
			ExpectedOutputContains: []string{SecretsPasswordEntry},
		},
		{
			Name: "password-list", Category: CategoryPassword,
			Command:        []string{"password", "list"},
			Description:    "List password entries",
			RequiresServer: true, RequiresSetup: true,
			ExpectedOutputContains: []string{SecretsPasswordEntry},
		},
		{
			Name: "password-update", Category: CategoryPassword,
			Command:        []string{"password", "update"},
			Description:    "Update a password entry",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				positionalArg("", ArgEntryID),
				flagArg("notes", "updated by the CLI matrix", "New notes"),
			},
		},
		{
			Name: "password-generate", Category: CategoryPassword,
			Command:        []string{"password", "generate"},
			Description:    "Generate a random password",
			RequiresServer: true, RequiresSetup: true,
			OptionalArgs: []ArgDefinition{flagArg("length", "24", "Password length")},
		},
		{
			Name: "password-vault-enroll", Category: CategoryPassword,
			Command:        []string{"password", "vault", "enroll"},
			Description:    "Enroll a second passphrase factor",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				flagArg("passphrase", SecretsVaultSecondPassphrase, "Passphrase to enroll"),
				flagArg("label", "it-matrix-second", "Factor label"),
			},
			OptionalArgs: jsonOutput,
		},
		{
			Name: "password-vault-rotate", Category: CategoryPassword,
			Command:        []string{"password", "vault", "rotate"},
			Description:    "Rotate the second passphrase factor",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				flagArg("factor-id", "", "Factor ID"),
				flagArg("passphrase", SecretsVaultRotatedPassphrase, "New passphrase"),
			},
			OptionalArgs: jsonOutput,
		},
		{
			Name: "password-vault-remove", Category: CategoryPassword,
			Command:        []string{"password", "vault", "remove"},
			Description:    "Remove the rotated factor",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{flagArg("factor-id", "", "Factor ID")},
		},
		{
			Name: "password-vault-recover", Category: CategoryPassword,
			Command:        []string{"password", "vault", "recover"},
			Description:    "Enroll a passphrase with the one-time recovery code",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				flagArg("recovery-code", "", "Recovery code"),
				flagArg("passphrase", SecretsVaultRecoveredPassphrase, "New passphrase"),
				flagArg("label", "it-matrix-recovered", "Factor label"),
			},
			OptionalArgs: jsonOutput,
		},
		{
			Name: "password-delete", Category: CategoryPassword,
			Command:        []string{"password", "delete"},
			Description:    "Delete a password entry",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{positionalArg("", ArgEntryID)},
		},
		{
			Name: "password-lock", Category: CategoryPassword,
			Command:        []string{"password", "lock"},
			Description:    "Close the vault session",
			RequiresServer: true, RequiresSetup: true,
		},
	}
}

// PINCommands returns the SO and user PIN commands.
func PINCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name: "pin-so-set", Category: CategoryPIN,
			Command:        []string{"pin", "so-set"},
			Description:    "Set the SO PIN",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{flagArg("new-pin", SecretsSOPIN, "New SO PIN")},
			// Sent only when overridden: a second so-set needs the current PIN.
			OptionalArgs: []ArgDefinition{flagArg("current-pin", "", "Current SO PIN")},
		},
		{
			Name: "pin-so-verify", Category: CategoryPIN,
			Command:        []string{"pin", "so-verify"},
			Description:    "Verify the SO PIN",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{flagArg("pin", SecretsSOPIN, "SO PIN")},
		},
		{
			Name: "pin-so-change", Category: CategoryPIN,
			Command:        []string{"pin", "so-change"},
			Description:    "Change the SO PIN",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				flagArg("current-pin", SecretsSOPIN, "Current SO PIN"),
				flagArg("new-pin", SecretsSOPINAlt, "New SO PIN"),
			},
		},
		{
			Name: "pin-user-set", Category: CategoryPIN,
			Command:        []string{"pin", "user-set"},
			Description:    "Set the user PIN with the SO PIN",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				flagArg("so-pin", SecretsSOPIN, "SO PIN"),
				flagArg("new-pin", SecretsUserPIN, "New user PIN"),
			},
		},
		{
			Name: "pin-user-verify", Category: CategoryPIN,
			Command:        []string{"pin", "user-verify"},
			Description:    "Verify the user PIN",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{flagArg("pin", SecretsUserPIN, "User PIN")},
		},
		{
			Name: "pin-user-change", Category: CategoryPIN,
			Command:        []string{"pin", "user-change"},
			Description:    "Change the user PIN",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				flagArg("current-pin", SecretsUserPIN, "Current user PIN"),
				flagArg("new-pin", SecretsUserPINAlt, "New user PIN"),
			},
		},
		{
			Name: "pin-lockout", Category: CategoryPIN,
			Command:        []string{"pin", "lockout"},
			Description:    "Show the PIN lockout state",
			RequiresServer: true,
		},
		{
			Name: "pin-lockout-reset", Category: CategoryPIN,
			Command:        []string{"pin", "lockout-reset"},
			Description:    "Reset the user PIN lockout with the SO PIN",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{flagArg("so-pin", SecretsSOPIN, "SO PIN")},
		},
	}
}

// PIVCommands returns the PIV slot commands. They run on the server's
// software backend (config.test.yaml default_backend), so no card is needed.
func PIVCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name: "piv-list", Category: CategoryPIV,
			Command:        []string{"piv", "list"},
			Description:    "List PIV slots",
			RequiresServer: true, RequiresBackend: true,
		},
		{
			Name: "piv-generate", Category: CategoryPIV,
			Command:        []string{"piv", "generate"},
			Description:    "Generate a key and self-signed certificate in a slot",
			RequiresServer: true, RequiresBackend: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				positionalArg(SecretsPIVSlot, ArgPIVSlot),
				flagArg("algorithm", "ecdsap256", "Key algorithm"),
				flagArg("subject", "CN=it-matrix-piv", "Certificate subject"),
			},
		},
		{
			Name: "piv-get", Category: CategoryPIV,
			Command:        []string{"piv", "get"},
			Description:    "Show the certificate in a slot",
			RequiresServer: true, RequiresBackend: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{positionalArg(SecretsPIVSlot, ArgPIVSlot)},
		},
		{
			Name: "piv-csr", Category: CategoryPIV,
			Command:        []string{"piv", "csr"},
			Description:    "Create a CSR with the key in a slot",
			RequiresServer: true, RequiresBackend: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				positionalArg(SecretsPIVSlot, ArgPIVSlot),
				flagArg("subject", "CN=it-matrix-piv,O=go-xkms", "CSR subject"),
			},
			ExpectedOutputContains: []string{"CERTIFICATE REQUEST"},
		},
		{
			Name: "piv-export", Category: CategoryPIV,
			Command:        []string{"piv", "export"},
			Description:    "Export the certificate in a slot",
			RequiresServer: true, RequiresBackend: true, RequiresSetup: true,
			RequiredArgs:           []ArgDefinition{positionalArg(SecretsPIVSlot, ArgPIVSlot)},
			ExpectedOutputContains: []string{"BEGIN CERTIFICATE"},
		},
		{
			Name: "piv-store", Category: CategoryPIV,
			Command:        []string{"piv", "store"},
			Description:    "Store a certificate file in a slot",
			RequiresServer: true, RequiresBackend: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				positionalArg(SecretsPIVStoreSlot, ArgPIVSlot),
				flagArg("cert-file", "", "Certificate file"),
			},
		},
		{
			Name: "piv-import", Category: CategoryPIV,
			Command:        []string{"piv", "import"},
			Description:    "Import a certificate file into a slot",
			RequiresServer: true, RequiresBackend: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				positionalArg(SecretsPIVImportSlot, ArgPIVSlot),
				flagArg("cert-file", "", "Certificate file"),
			},
		},
		{
			Name: "piv-delete", Category: CategoryPIV,
			Command:        []string{"piv", "delete"},
			Description:    "Remove the certificate in a slot",
			RequiresServer: true, RequiresBackend: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{positionalArg(SecretsPIVSlot, ArgPIVSlot)},
		},
	}
}

// SecretsSetupOrder is the order the secrets workflow runs the password,
// pin and piv commands in: each command after the steps it needs.
func SecretsSetupOrder() []string {
	return []string{
		"password-vault-status", "password-unlock", "password-status",
		"password-access-mode", "password-add", "password-get", "password-list",
		"password-update", "password-generate", "password-vault-enroll",
		"password-vault-rotate", "password-vault-remove", "password-vault-recover",
		"password-delete", "password-lock",

		"pin-so-set", "pin-so-verify", "pin-so-change", "pin-user-set",
		"pin-user-verify", "pin-user-change", "pin-lockout", "pin-lockout-reset",

		"piv-list", "piv-generate", "piv-get", "piv-csr", "piv-export",
		"piv-store", "piv-import", "piv-delete",
	}
}

// SecretsCommand returns the password, pin or piv command named name.
func SecretsCommand(name string) (CommandDefinition, bool) {
	for _, family := range [][]CommandDefinition{PasswordCommands(), PINCommands(), PIVCommands()} {
		for _, cmd := range family {
			if cmd.Name == name {
				return cmd, true
			}
		}
	}
	return CommandDefinition{}, false
}
