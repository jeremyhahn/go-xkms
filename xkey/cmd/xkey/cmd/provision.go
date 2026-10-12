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
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// This file provisions a whole xkey instance for one agent in a single verb,
// by calling the exact service-layer functions "barrier init", "pin
// set-so"/"set-user", "fido2 init-token", "piv generate" and "ssh keys
// generate" each already call. There is no parallel implementation of any of
// those ceremonies here; this file only sequences them and resolves the
// three secrets they need.
//
// Three DISTINCT secrets go in, through the same input mechanisms every
// other xkey command already uses -- never one secret standing in for
// another:
//
//   - The user PIN: addPINFlags/resolvePINInput (--pin-stdin, then
//     XKEY_PIN). Sets the host PIN service's User PIN.
//   - The SO PIN: addSOPINFlags/resolveSOPINInput (--so-pin-stdin, then
//     XKEY_SO_PIN). Sets BOTH the host PIN service's SO PIN and the FIDO2
//     authenticator's own, separate Security Officer PIN -- the two already
//     share the name "SO PIN" without sharing a store (see pin_set.go and
//     fido2_init_token.go), so one input value naming that role satisfies
//     both without inventing a fourth input.
//   - The barrier password: addBarrierPasswordFlags/resolveBarrierPassword,
//     the same pair "xkey extension serve" and fido2's "--storage barrier"
//     mode already use (--barrier-password, --barrier-password-file, then
//     XKEY_BARRIER_PASSWORD, then an interactive terminal prompt as a last
//     resort).
//
// Making the SO PIN equal the user PIN would erase the SO/user separation
// the host PIN service exists to enforce (the SO can reset or unblock the
// user; the user cannot reset the SO) -- that is a security-policy decision
// this command must never make implicitly. All three are resolved and
// validated before any state is touched; a missing one refuses with its own
// typed error naming which secret is missing, never a silent fallback to
// one of the other two. Only one of the three inputs can come from stdin in
// a single invocation (stdin is one stream); supply the other two via their
// file or environment-variable form.
//
// Ordering is deliberate, not the order the steps are listed in the issue.
// SSH key generation runs BEFORE the barrier is initialized: once a barrier
// root key exists, xkeySSHBackend (ssh.go) refuses with
// ErrSSHStoreBarrierEncrypted, because the CLI has no barrier-unlock flow of
// its own. Running SSH key generation first is not a workaround that skips a
// check — it is the only order in which every step this command performs can
// actually complete non-interactively today, and both the barrier and the
// SSH store hold the same plaintext-then-encrypted semantics they would in
// either order for what is a brand-new home.
//
// FIDO2 token initialization normally waits on an interactive user-presence
// prompt (see pkg/authenticator/token.go, requestUserPresence). It uses
// authenticator.NewAutoGrantHandler() here instead of the interactive
// handler "fido2 init-token" installs — the same handler extension_serve.go
// already uses for exactly this reason (a headless process with no terminal
// to prompt): it is an explicit, sanctioned "no human, but consented"
// handler, not a fabricated approval.
//
// PIV key generation needs no such substitution: "piv generate" against the
// default software backend prompts for nothing, so it runs unmodified for
// each of the four primary slots.

var (
	// provisionHome is the --home flag: the target xkey home to provision.
	provisionHome string

	// provisionAgent is the --agent flag: the agent's display name.
	provisionAgent string

	// provisionForce is the --force flag: provision an already-initialized
	// home instead of refusing.
	provisionForce bool

	// provisionChromeProfileDir is the --chrome-profile-dir flag: also pair
	// a Chrome profile with this instance (see "xkey extension install
	// chrome --profile-dir").
	provisionChromeProfileDir string

	// provisionJSON is the --json flag.
	provisionJSON bool
)

// provisionCmd provisions a fresh xkey instance for one agent: it generates
// an SSH key, initializes the barrier, sets the host PIN service's SO and
// User PIN, records the agent's display name, establishes the FIDO2
// authenticator's Security Officer PIN, generates the four primary PIV slot
// keys, and prints what the agent needs to use this instance.
var provisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Provision a fresh xkey instance for one agent",
	Long: `Provision a fresh xkey instance for one agent in a single verb.

This runs the same ceremonies "barrier init", "pin set-so"/"set-user", "fido2
init-token", "piv generate" and "ssh keys generate" each already run, against
one target home. Nothing here is a shortcut or a simplified stand-in for
those commands: every step is the real thing, run non-interactively.

A target home is required, explicitly: either --home, or an inherited
XKEY_HOME. There is no fallback to xkey's own default home resolution
(~/.xkey), because provisioning into the operator's own default home by
accident is exactly the failure this command exists to prevent on a host
that runs one xkey instance per agent (see "One xkey per agent on a shared
host" in the agent-automation docs).

This command takes three separate secrets, each through the same input
xkey already uses elsewhere for it -- never one standing in for another:

  User PIN            --pin-stdin, then XKEY_PIN
  SO PIN              --so-pin-stdin, then XKEY_SO_PIN
  Barrier password     --barrier-password, --barrier-password-file, then
                        XKEY_BARRIER_PASSWORD, then an interactive prompt

The user PIN becomes the host PIN service's User PIN. The SO PIN becomes
BOTH the host PIN service's SO PIN and the FIDO2 authenticator's own,
separate Security Officer PIN -- two credentials that already share that
name without sharing a store. Making the SO PIN equal the user PIN would
erase the separation the host PIN service exists to enforce (the SO can
reset or unblock the user; the user cannot reset the SO), so this command
never does that: all three secrets are required, and a missing one refuses
by name rather than reusing another. Standard input is one stream, so only
one of the three flags above may read from it in a single invocation --
supply the other two via file or environment variable.

FIDO2 token initialization and PIV key generation both normally involve a
human at a terminal. FIDO2's user-presence prompt is satisfied here by the
same auto-grant handler "xkey extension serve" already uses for headless
operation (an explicit, sanctioned policy, not a fabricated approval); PIV
key generation against the default software backend needs no substitution
at all, since it prompts for nothing.

No secret is ever printed. The report names the socket, the FIDO2 AAGUID
and token state, the PIV slots that were set up, the SSH public key and
fingerprint, and the Chrome native-messaging manifest path when
--chrome-profile-dir was given.

Examples:
  # Provision a fresh agent home
  export XKEY_HOME=/srv/agents/builder/.xkey
  export XKEY_SO_PIN="$SO_PIN"
  export XKEY_BARRIER_PASSWORD="$BARRIER_PASSWORD"
  printf '%s' "$USER_PIN" | xkey provision --agent builder --pin-stdin

  # Provision into an explicit home without XKEY_HOME
  export XKEY_SO_PIN="$SO_PIN"
  export XKEY_BARRIER_PASSWORD="$BARRIER_PASSWORD"
  printf '%s' "$USER_PIN" | xkey provision --home /srv/agents/builder/.xkey \
      --agent builder --pin-stdin

  # Also pair a Chrome profile with this instance
  printf '%s' "$USER_PIN" | xkey provision --agent builder --pin-stdin \
      --chrome-profile-dir /srv/agents/builder/chrome-profile

  # Machine-readable report
  printf '%s' "$USER_PIN" | xkey provision --agent builder --pin-stdin --json`,
	Args:              cobra.NoArgs,
	PersistentPreRunE: runProvisionPersistentPreRun,
	RunE:              runProvision,
}

func init() {
	RootCmd.AddCommand(provisionCmd)

	provisionCmd.Flags().StringVar(&provisionHome, "home", "",
		"xkey home to provision (default: XKEY_HOME; one of the two is required)")
	provisionCmd.Flags().StringVar(&provisionAgent, "agent", "",
		"the agent's display name (required)")
	provisionCmd.Flags().BoolVar(&provisionForce, "force", false,
		"provision a home that is already initialized")
	provisionCmd.Flags().StringVar(&provisionChromeProfileDir, "chrome-profile-dir", "",
		"also pair a Chrome profile with this instance (see 'xkey extension install chrome --profile-dir')")
	provisionCmd.Flags().BoolVar(&provisionJSON, "json", false,
		"print the report as JSON")

	// Three distinct secrets, each through xkey's existing input mechanism
	// for it -- see the file-level comment for why none of the three ever
	// stands in for another.
	addPINFlags(provisionCmd)             // user PIN: --pin-stdin, XKEY_PIN
	addSOPINFlags(provisionCmd)           // SO PIN: --so-pin-stdin, XKEY_SO_PIN
	addBarrierPasswordFlags(provisionCmd) // barrier password: --barrier-password[-file], XKEY_BARRIER_PASSWORD
}

// runProvisionPersistentPreRun resolves --home/XKEY_HOME and exports it as
// XKEY_HOME before delegating to RootCmd's own PersistentPreRunE.
//
// Cobra only invokes the nearest PersistentPreRunE in the command chain, so
// defining one here replaces RootCmd's rather than running alongside it.
// Calling RootCmd.PersistentPreRunE directly, after XKEY_HOME is set, is
// what makes resolvedHome/loadedConfig (root.go) -- and everything that
// reads them, like the SSH command group's data directory resolution --
// agree with --home rather than whatever XKEY_HOME happened to be before
// this command ran.
func runProvisionPersistentPreRun(cmd *cobra.Command, args []string) error {
	home, err := resolveProvisionHome()
	if err != nil {
		return err
	}
	if err := os.Setenv(xhome.EnvHome, home); err != nil {
		return &ProvisionError{Step: "resolve_home", Err: err}
	}
	return RootCmd.PersistentPreRunE(cmd, args)
}

// resolveProvisionHome resolves the target home from --home, then XKEY_HOME.
// Neither xkey's normal default-home resolution (~/.xkey) nor any other
// fallback is consulted: an operator who wants that default already gets it
// by running "barrier init" etc. individually.
func resolveProvisionHome() (string, error) {
	home := strings.TrimSpace(provisionHome)
	if home == "" {
		home = strings.TrimSpace(os.Getenv(xhome.EnvHome))
	}
	if home == "" {
		return "", ErrProvisionHomeRequired
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", &ProvisionError{Step: "resolve_home", Err: err}
	}
	return abs, nil
}

// AgentProvisionResult is the shape of "xkey provision"'s report, in both its
// human-readable and --json forms. No field ever carries a secret.
type AgentProvisionResult struct {
	Agent           string                     `json:"agent"`
	Home            string                     `json:"home"`
	HomeExport      string                     `json:"home_export"`
	SocketPath      string                     `json:"socket_path"`
	BarrierStrategy string                     `json:"barrier_strategy"`
	PINStatus       string                     `json:"pin_status"`
	FIDO2           *AgentProvisionFIDO2Result `json:"fido2,omitempty"`
	PIV             []AgentProvisionPIVSlot    `json:"piv,omitempty"`
	SSH             *AgentProvisionSSHKey      `json:"ssh,omitempty"`
	SSHNote         string                     `json:"ssh_note,omitempty"`
	ChromeManifest  string                     `json:"chrome_manifest_path,omitempty"`
}

// AgentProvisionFIDO2Result reports the FIDO2 authenticator's identity and token
// state after provisioning. It never carries the Security Officer PIN.
type AgentProvisionFIDO2Result struct {
	AAGUID      string `json:"aaguid"`
	TokenState  string `json:"token_state"`
	StoragePath string `json:"storage_path"`
}

// AgentProvisionPIVSlot reports one PIV slot that provisioning set up.
type AgentProvisionPIVSlot struct {
	Slot      string `json:"slot"`
	SlotName  string `json:"slot_name"`
	Algorithm string `json:"algorithm"`
}

// AgentProvisionSSHKey reports the generated SSH key's public half. The private
// half never leaves the SSH store.
type AgentProvisionSSHKey struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
}

// runProvision runs every provisioning step in the order described at the
// top of this file and prints the report.
func runProvision(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	agent := strings.TrimSpace(provisionAgent)
	if agent == "" {
		return ErrProvisionAgentNameRequired
	}

	home := GetHome()
	if home == nil {
		return ErrProvisionHomeNotResolved
	}

	// Three distinct secrets, resolved and validated up front, before any
	// state is touched. See the file-level comment for why none of the
	// three may stand in for another.
	userPIN, err := resolvePINInput(cmd)
	if err != nil {
		return &ProvisionError{Step: "resolve_user_pin", Err: err}
	}
	if userPIN == "" {
		return ErrProvisionUserPINRequired
	}

	soPIN, err := resolveSOPINInput(cmd)
	if err != nil {
		return &ProvisionError{Step: "resolve_so_pin", Err: err}
	}
	if soPIN == "" {
		return ErrProvisionSOPINRequired
	}

	barrierPassword, err := resolveBarrierPassword(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrProvisionBarrierPasswordRequired, Cause: err}
	}

	// resolveBarrierDataDir/createBarrier read these barrier.go package
	// vars; resetting them here keeps provisioning's barrier identical to a
	// bare "xkey barrier init" regardless of what an earlier command in
	// this process left them set to.
	barrierDataDir = ""
	barrierStrategy = ""

	dataDir, err := resolveBarrierDataDir()
	if err != nil {
		return &ProvisionError{Step: "resolve_data_dir", Err: err}
	}

	alreadyInitialized := barrierRootKeyExists(dataDir)
	if alreadyInitialized && !provisionForce {
		return ErrProvisionAlreadyInitialized
	}

	result := &AgentProvisionResult{
		Agent:      agent,
		Home:       home.Root,
		HomeExport: fmt.Sprintf("export XKEY_HOME=%s", home.Root),
		SocketPath: resolvedSocketPath(cmd),
	}

	// The SSH store refuses every operation, including reads, once a
	// barrier root key exists (xkeySSHBackend, ssh.go): the CLI has no
	// barrier-unlock flow of its own. On a fresh home that has not happened
	// yet, so the key is generated first, before the barrier step below
	// creates it. On a --force re-provision of an already-initialized home,
	// generating (or even inspecting) an SSH key through this command is
	// simply not possible today; that is reported as a skipped step rather
	// than failing the whole run, so PIN/display-name/FIDO2/PIV still
	// complete.
	if alreadyInitialized {
		result.BarrierStrategy = "already initialized (--force)"
		result.SSHNote = "skipped: the local SSH store is barrier-encrypted once the barrier exists, and the CLI has no unlock flow of its own; " +
			"generate one through the xkey app, or provision a fresh home"
	} else {
		sshKey, err := provisionSSHKey(cmd, agent)
		if err != nil {
			return &ProvisionError{Step: "ssh", Err: err}
		}
		result.SSH = sshKey

		strategy, err := provisionBarrier(cmd.Context(), dataDir, barrierPassword)
		if err != nil {
			return &ProvisionError{Step: "barrier", Err: err}
		}
		result.BarrierStrategy = strategy
	}

	pinStatus, err := provisionPIN(soPIN, userPIN)
	if err != nil {
		return &ProvisionError{Step: "pin", Err: err}
	}
	result.PINStatus = pinStatus

	if err := provisionDisplayName(agent); err != nil {
		return &ProvisionError{Step: "display_name", Err: err}
	}

	fido2Result, err := provisionFIDO2(cmd, soPIN)
	if err != nil {
		return &ProvisionError{Step: "fido2", Err: err}
	}
	result.FIDO2 = fido2Result

	pivResult, err := provisionPIV(cmd, agent)
	if err != nil {
		return &ProvisionError{Step: "piv", Err: err}
	}
	result.PIV = pivResult

	if provisionChromeProfileDir != "" {
		manifestPath, err := nativemsg.InstallProfileManifest(home, mustExecutablePath(), provisionChromeProfileDir)
		if err != nil {
			return &ProvisionError{Step: "chrome_extension", Err: err}
		}
		result.ChromeManifest = manifestPath
	}

	return printProvisionResult(out, result)
}

// mustExecutablePath resolves the running binary's path the same way
// runExtensionInstall does. A failure here would mean os.Executable itself
// failed, which is reported through the chrome_extension step's own error
// path rather than a panic: InstallProfileManifest fails cleanly on an
// empty binary path.
func mustExecutablePath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}

// provisionSSHKey generates the agent's SSH key. It must run before the
// barrier is initialized; see the file-level comment for why.
func provisionSSHKey(cmd *cobra.Command, agent string) (*AgentProvisionSSHKey, error) {
	client, closer, err := sshClient(cmd)
	if err != nil {
		return nil, err
	}
	defer closer()

	// "service" is the SDK's canonical scope for an automated workload's own
	// key (pkg/ssh/scope.Service) — the SDK client interface takes it as a
	// plain string precisely so callers like this one never need to import
	// that package themselves (see sdk/go/client/ssh/console.go).
	key, err := client.Keys().Generate(cmd.Context(), sshsdk.GenerateRequest{
		Scope:     "service",
		Owner:     agent,
		Name:      "default",
		Algorithm: "ed25519",
		Comment:   fmt.Sprintf("xkey-agent:%s", agent),
	})
	if err != nil {
		return nil, err
	}

	return &AgentProvisionSSHKey{
		Scope:       key.Scope,
		Owner:       key.Owner,
		Name:        key.Name,
		Algorithm:   key.Algorithm,
		Fingerprint: key.Fingerprint,
		PublicKey:   key.PublicKey,
	}, nil
}

// provisionBarrier initializes the barrier from the operator's barrier
// password, exactly as "xkey barrier init" does, minus the interactive
// confirmation prompt (resolveBarrierPassword's sources are already
// unambiguous -- there is no second entry to confirm against).
func provisionBarrier(ctx context.Context, dataDir, barrierPassword string) (strategy string, err error) {
	barrier, closer, err := createBarrier(dataDir)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := barrier.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		if closer != nil {
			if cerr := closer.Close(); cerr != nil {
				err = errors.Join(err, cerr)
			}
		}
	}()

	creds, credErr := xkms.NewCredentials(ctx, []byte(barrierPassword))
	if credErr != nil {
		return "", credErr
	}
	defer func() { err = errors.Join(err, creds.Secret.Destroy()) }()

	if err := barrier.Initialize(ctx, creds); err != nil {
		return "", err
	}
	return strategyDisplayName(barrier.ActiveStrategy()), nil
}

// provisionPIN sets the host PIN service's SO and User PIN, exactly as
// "xkey pin set-so" followed by "xkey pin set-user" would: soPIN becomes the
// SO PIN, and also authorizes setting userPIN as the User PIN
// (SetUserPIN's own signature). If the SO PIN is already set (a --force
// re-provision), it reports that rather than failing: SetSOPIN would refuse
// with ErrPINAlreadySet for an empty current PIN, which is correct for
// "set-so" alone but would be a confusing failure for provisioning to
// surface as a hard error.
func provisionPIN(soPIN, userPIN string) (string, error) {
	pinDataDir = ""

	dataDir, err := resolvePINDataDir()
	if err != nil {
		return "", err
	}

	svc, err := createPINService(dataDir)
	if err != nil {
		return "", err
	}

	if svc.SOPINSet() {
		return "already set", nil
	}

	if err := svc.SetSOPIN("", soPIN); err != nil {
		return "", err
	}
	if err := svc.SetUserPIN(soPIN, userPIN); err != nil {
		return "", err
	}
	if err := services.ResetAppLockAttempts(dataDir); err != nil {
		return "", err
	}
	return "set", nil
}

// provisionDisplayName records the agent's display name in this home's own
// config file (<home>/config.yaml, fido2.device_name), the same field
// "xkey fido2 --name" documents as "Device name visible to OS". It is saved
// with SaveToPath against home.ConfigPath() rather than the package-level
// Save (which targets the operator's shared ~/.config/xkey/xkey.yaml):
// writing the shared XDG file would leak one agent's display name into
// every other agent's config on a host running one xkey instance per agent.
func provisionDisplayName(agent string) error {
	cfg := GetConfig()
	if cfg == nil {
		return ErrProvisionConfigNotLoaded
	}
	home := GetHome()
	if home == nil {
		return ErrProvisionHomeNotResolved
	}

	cfg.FIDO2.DeviceName = agent
	return xkeyconfig.SaveToPath(cfg, home.ConfigPath())
}

// ensureFIDO2PersistentStorage forces the FIDO2 storage type away from its
// default of "memory" for the duration of provisioning. A Security Officer
// PIN established in memory storage vanishes the moment this process exits,
// which "xkey fido2 init-token" already refuses outright
// (ErrTokenVolatileStorage): provisioning wants a persistent credential, so
// it makes the same choice an operator configuring a persistent instance
// would make, rather than surfacing that refusal to the caller. An operator
// who already configured "file" or "barrier" storage is left alone. The
// returned func restores the previous viper value; it is always safe to
// call, whether or not this function changed anything.
func ensureFIDO2PersistentStorage() func() {
	previous := viper.GetString("fido2.storage")
	if previous == "" || previous == string(FIDO2StorageTypeMemory) {
		viper.Set("fido2.storage", string(FIDO2StorageTypeFile))
	}
	return func() { viper.Set("fido2.storage", previous) }
}

// provisionFIDO2 establishes the FIDO2 authenticator's Security Officer PIN
// from soPIN -- the same SO PIN input that sets the host PIN service's SO
// PIN, an unrelated credential over an unrelated store that happens to share
// the name (see the file-level comment) -- using the same offline
// device-storage path "xkey fido2 init-token" uses (openTokenDevice,
// tokenInitialized), substituting authenticator.NewAutoGrantHandler() for
// the interactive user-presence handler that command installs. If the token
// is already initialized (a --force re-provision), it reports the existing
// state rather than failing.
func provisionFIDO2(cmd *cobra.Command, soPIN string) (result *AgentProvisionFIDO2Result, err error) {
	restoreStorage := ensureFIDO2PersistentStorage()
	defer restoreStorage()

	storage, err := openTokenDevice(cmd)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := storage.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	cfg := buildFIDO2Config()
	storagePath, err := resolveFIDO2StoragePath(cfg)
	if err != nil {
		return nil, err
	}

	initialized, err := tokenInitialized(storage)
	if err != nil {
		return nil, err
	}

	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		AAGUID:              authenticator.DefaultAAGUID,
		Storage:             storage,
		UserPresenceHandler: authenticator.NewAutoGrantHandler(),
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := auth.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	tokenState := "initialized"
	if !initialized {
		if err := auth.InitializeToken(cmd.Context(), soPIN); err != nil {
			return nil, err
		}
	} else {
		tokenState = "already initialized"
	}

	aaguid := auth.AAGUID()
	return &AgentProvisionFIDO2Result{
		AAGUID:      hex.EncodeToString(aaguid[:]),
		TokenState:  tokenState,
		StoragePath: storagePath,
	}, nil
}

// provisionPIV generates a key in each of the four primary PIV slots (9a,
// 9c, 9d, 9e), exactly as "xkey piv generate <slot>" does for each slot in
// turn. The default software backend prompts for nothing, so unlike FIDO2
// this needs no presence-handler substitution.
func provisionPIV(cmd *cobra.Command, agent string) ([]AgentProvisionPIVSlot, error) {
	logger := slog.Default()
	pivCfg, err := buildPIVConfig(cmd)
	if err != nil {
		return nil, err
	}

	if err := ensurePIVInitialized(cmd, pivCfg, logger); err != nil {
		return nil, err
	}

	slots := xkms.PIVPrimarySlots()
	results := make([]AgentProvisionPIVSlot, 0, len(slots))
	for _, slot := range slots {
		slotName := xkms.PIVSlotName(slot)
		_, err := xkms.GeneratePIVKey(cmd.Context(), &transport.GeneratePIVKeyRequest{
			Backend:      string(pivCfg.Backend),
			Slot:         string(slot),
			Algorithm:    "ecdsap256",
			Subject:      fmt.Sprintf("%s %s", agent, slotName),
			OutputFormat: "self-signed",
		})
		if err != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("slot %s (%s)", slot, slotName), Err: err}
		}
		results = append(results, AgentProvisionPIVSlot{
			Slot:      string(slot),
			SlotName:  slotName,
			Algorithm: "ECCP256",
		})
	}
	return results, nil
}

// printProvisionResult renders the report as JSON or as human-readable text.
func printProvisionResult(out io.Writer, result *AgentProvisionResult) error {
	if provisionJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	_, _ = fmt.Fprintf(out, "Provisioned agent %q\n", result.Agent)
	_, _ = fmt.Fprintf(out, "  Home:             %s\n", result.Home)
	_, _ = fmt.Fprintf(out, "  %s\n", result.HomeExport)
	_, _ = fmt.Fprintf(out, "  Socket:           %s\n", result.SocketPath)
	_, _ = fmt.Fprintf(out, "  Barrier strategy: %s\n", result.BarrierStrategy)
	_, _ = fmt.Fprintf(out, "  Host PIN:         %s\n", result.PINStatus)

	if result.FIDO2 != nil {
		_, _ = fmt.Fprintf(out, "  FIDO2 AAGUID:     %s\n", result.FIDO2.AAGUID)
		_, _ = fmt.Fprintf(out, "  FIDO2 token:      %s\n", result.FIDO2.TokenState)
		_, _ = fmt.Fprintf(out, "  FIDO2 storage:    %s\n", result.FIDO2.StoragePath)
	}

	for _, slot := range result.PIV {
		_, _ = fmt.Fprintf(out, "  PIV slot %s (%s): %s\n", slot.Slot, slot.SlotName, slot.Algorithm)
	}

	if result.SSH != nil {
		_, _ = fmt.Fprintf(out, "  SSH key:          %s/%s/%s (%s)\n",
			result.SSH.Scope, result.SSH.Owner, result.SSH.Name, result.SSH.Algorithm)
		_, _ = fmt.Fprintf(out, "  SSH fingerprint:  %s\n", result.SSH.Fingerprint)
		_, _ = fmt.Fprintf(out, "  SSH public key:   %s\n", result.SSH.PublicKey)
	} else if result.SSHNote != "" {
		_, _ = fmt.Fprintf(out, "  SSH key:          %s\n", result.SSHNote)
	}

	if result.ChromeManifest != "" {
		_, _ = fmt.Fprintf(out, "  Chrome manifest:  %s\n", result.ChromeManifest)
	}

	return nil
}
