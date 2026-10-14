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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
)

// This file holds the phone-initiated request handler and xkmsd bridge
// wiring shared by every surface that serves a phone-initiated session:
// `xkey device listen` (BLE, device_listen.go) and, since go-xkms#1306,
// `xkey device relay` (TCP, device_relay.go). Neither the handler nor the
// bridge wiring touches Bluetooth, so none of it needs the ble build tag --
// it lived in a ble-tagged file only because "xkey device listen" was its
// only caller when it was written.

// Device listen/relay command errors.
var (
	// ErrDeviceListenFailed indicates the listen command failed to start.
	ErrDeviceListenFailed = errors.New("device: listen failed")

	// ErrDeviceNoDefaultDevice indicates no default device is configured.
	ErrDeviceNoDefaultDevice = errors.New("device: no default device configured")

	// ErrTPM2InitFailed indicates TPM2 initialization failed.
	ErrTPM2InitFailed = errors.New("device: TPM2 initialization failed")

	// ErrDevicePinInvalid indicates the paired device record has no usable
	// pinned Noise static key -- empty or the wrong length -- so the
	// peripheral/relay would otherwise be built with nothing to pin, silently
	// accepting a handshake from any phone rather than only the paired one.
	// Re-pairing the device is the only recovery: there is no partial key to
	// repair.
	ErrDevicePinInvalid = errors.New("device: paired device has no valid pinned key; re-pair the device")

	// ErrXKMSdBridgeCreationFailed indicates the Bridge could not be created.
	ErrXKMSdBridgeCreationFailed = errors.New("xkmsd: bridge creation failed")
)

// defaultTPMDevice is the default TPM2 device path.
const defaultTPMDevice = "/dev/tpmrm0"

// resolveListenTargetDevice finds the paired device a phone-initiated
// session (`xkey device listen` or `xkey device relay`) pins to, decodes its
// stored Noise static public key, and unseals its local static private key
// under barrier. Shared so the two commands resolve identity exactly the
// same way (go-xkms#1306): the phone's advertised name/address is never
// enough on its own, and #1307's refusal of an ambiguous name applies to
// both.
//
// deviceFilter selects a specific record (--device); with none given, the
// devices file's own default device governs, then the sole paired device
// when there is exactly one, and otherwise the caller must disambiguate.
//
// The caller owns the returned *secure.Buffer and must Destroy it once the
// local static key has been reconstructed from it (pairing.LoadStaticKey)
// -- this function does not destroy it itself, matching every other
// resolver in this package that hands back protected memory.
func resolveListenTargetDevice(
	cfg *DevicesConfig,
	deviceFilter string,
	barrier pairing.NoiseKeyBarrier,
	logger *slog.Logger,
) (*PairedDevice, []byte, *secure.Buffer, error) {
	// Find the target device. findDeviceByName refuses an ambiguous name
	// (more than one record) instead of resolving it by taking the first
	// match -- the phone's advertised name is untrusted input, and a lookup
	// by name is how this command picks which pinned key to trust for the
	// whole session (#1307).
	var targetDevice *PairedDevice
	var err error
	switch {
	case deviceFilter != "":
		targetDevice, err = findDeviceByName(cfg, deviceFilter)
		if err != nil {
			return nil, nil, nil, err
		}
		if targetDevice == nil {
			return nil, nil, nil, &DetailError{Err: ErrDeviceNotFound, Detail: fmt.Sprintf(": %s", deviceFilter)}
		}
	case cfg.DefaultDevice != "":
		targetDevice, err = findDeviceByName(cfg, cfg.DefaultDevice)
		if err != nil {
			return nil, nil, nil, err
		}
		if targetDevice == nil {
			return nil, nil, nil, ErrDeviceNoDefaultDevice
		}
	case len(cfg.Devices) == 1:
		targetDevice = &cfg.Devices[0]
	default:
		fmt.Println("Multiple devices paired. Specify one with --device or set a default.")
		return nil, nil, nil, ErrDeviceNoDefaultDevice
	}

	// Decode the phone's public key
	expectedRemoteStatic, err := base64.StdEncoding.DecodeString(targetDevice.NoisePublicKey)
	if err != nil {
		return nil, nil, nil, &WrappedError{Msg: "failed to decode phone public key", Err: err}
	}
	// Refused here, before any of the TPM/bridge setup the caller runs next,
	// and again by NewBLEPeripheral/the TCP session's ExpectedRemoteStatic
	// check: an empty or wrong-length key is a corrupt paired-device record,
	// and proceeding with it would pin nothing (a zero-length PeerStaticKey
	// is treated as "no key to pin," not as an error), silently accepting a
	// handshake from any phone rather than the one that was paired.
	if len(expectedRemoteStatic) != pairing.NoiseKeySize {
		return nil, nil, nil, &DetailError{Err: ErrDevicePinInvalid, Detail: fmt.Sprintf(": %s", targetDevice.Name)}
	}

	// Unseal our local static key (#42). barrier is nil here only because
	// openDeviceBarrier found none initialized (any other resolution
	// failure already returned above); a nil barrier means this record is
	// expected to be the legacy plaintext form, logged once per operation.
	// pairing.UnsealLocalNoiseKey requires the stored form to match the
	// barrier's presence and returns pairing.ErrNoiseKeyFormMismatch
	// (telling the operator to re-pair) when it does not -- there is no
	// migration between the two forms.
	if barrier == nil && !pairing.IsSealedNoiseKey(targetDevice.LocalNoisePrivateKey) {
		logger.Warn(noBarrierConfiguredWarning, "device", targetDevice.Name)
	}
	localPrivateKey, err := pairing.UnsealLocalNoiseKey(barrier, targetDevice.LocalNoisePrivateKey)
	if err != nil {
		return nil, nil, nil, &SentinelCauseError{Sentinel: ErrDeviceListenFailed, Cause: err}
	}

	return targetDevice, expectedRemoteStatic, localPrivateKey, nil
}

// newSessionSyncApproval builds the SyncApprovalFunc for a CLI-driven
// listen/relay session (go-xkms#1306): a single session-level decision, not
// a live per-request prompt -- "xkey device listen"/"relay" runs as a
// foreground daemon with no UI thread available to interrupt for each
// request, so the operator's decision is made once, at session start
// (--allow-sync, gated by enterprise policy through allowPhoneSyncExport),
// and applies uniformly to every remote.sync* request the session serves.
//
// A GUI-driven surface wants the opposite shape -- a live prompt per
// request, using whatever approval/notification mechanism the GUI already
// has -- and should build its own pairing.SyncApprovalFunc rather than
// calling this one; none exists yet because the GUI does not currently
// build a phone-initiated bridge at all (see docs/phone-hsm/engineering.md).
func newSessionSyncApproval(deviceName string, allowed bool, logger *slog.Logger) pairing.SyncApprovalFunc {
	return func(_ context.Context, req *pairing.SyncApprovalRequest) error {
		if allowed {
			logger.Info("phone sync approved for this session",
				slog.String("method", req.Method), slog.String("device", deviceName))
			return nil
		}
		logger.Warn("phone sync refused: this session was not started with --allow-sync",
			slog.String("method", req.Method), slog.String("device", deviceName))
		return pairing.ErrSyncNotApproved
	}
}

// initTPMForAttestation attempts to initialize a TPM2 connection for attestation.
func initTPMForAttestation(devicePath string, logger *slog.Logger) (xkms.TrustedPlatformModule, error) {
	if devicePath == "" {
		devicePath = defaultTPMDevice
	}

	logger.Debug("initializing TPM2 for attestation", slog.String("device", devicePath))

	tpmCfg := &xkms.TPMConfig{
		Device: devicePath,
		Hash:   "SHA-256",
	}

	tpmModule, err := xkms.NewTPM2(&xkms.TPMParams{
		Config: tpmCfg,
		Logger: logger,
	})
	if err != nil {
		// Check if it's a "not initialized" error which means TPM is present but not provisioned
		if errors.Is(err, xkms.ErrTPMNotInitialized) {
			logger.Warn("TPM2 present but not initialized for attestation")
			return nil, err
		}
		return nil, err
	}

	logger.Info("TPM2 initialized for attestation", slog.String("device", devicePath))
	return tpmModule, nil
}

// resolveListenEnroller decides which TPM, if any, the bridge answers TCG
// device enrollment from, and reports whether this command owns the handle.
//
// Enrollment is off unless requested. When it is requested and the attestor
// already opened this host's TPM, that handle is shared rather than opening
// the device a second time, and the returned closer is nil because the
// attestor's deferred Close still owns it. Only when no TPM is open yet does
// this open one, in which case the caller must close it.
//
// A host with no reachable TPM yields a nil enroller and no error: the bridge
// still serves every other method, and OpenTPMEnroller has already said at
// INFO or WARN why enrollment is unavailable.
func resolveListenEnroller(
	enabled bool,
	attestTPM xkms.TrustedPlatformModule,
	devicePath string,
	pcrBank string,
	logger *slog.Logger,
) (pairing.TPMEnroller, io.Closer, error) {
	if !enabled {
		return nil, nil, nil
	}
	if attestTPM != nil {
		logger.Info("TCG device enrollment enabled on the attestation TPM")
		return attestTPM, nil, nil
	}

	// The reason is logged by OpenTPMEnroller, at INFO when this host simply
	// has no TPM and at WARN when it has one that cannot be opened.
	enroller, err := pairing.OpenTPMEnroller(&pairing.TPMEnrollerConfig{
		Device:          devicePath,
		PlatformPCRBank: pcrBank,
		Logger:          logger,
	})
	if err != nil {
		// A host with no TPM reports nothing to the phone beyond "unsupported".
		// A TPM we could not open is a fault someone can fix, so the cause is
		// carried to the bridge and reported distinctly.
		if errors.Is(err, pairing.ErrTPMNotConfigured) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	return enroller, enroller, nil
}

// listenBridgeCollaborators holds the long-lived Bridge collaborators
// buildListenBridgeConfig opens so the phone's remote.oath* and remote.sync*
// methods reach real xkey data instead of reporting the feature
// unconfigured. Unlike the PIV storage provider (opened fresh per request by
// the bridge itself), these are opened once, for the life of the daemon, and
// must be closed at shutdown.
//
// Shared, not "listen"-specific despite the name: connectXKMSdBridge
// (fido2_phone_bridge.go) opens the same collaborators for "xkey fido2"'s
// phone bridge (go-xkms#1041), and "xkey device relay" (go-xkms#1306) opens
// them too, following resolveListenEnroller's own precedent of staying
// "Listen"-named once shared rather than renaming for every new caller.
type listenBridgeCollaborators struct {
	oathStore   oath.Store
	syncSources *backupSources
}

// Close releases every collaborator resource this holds. A nil receiver is a
// safe no-op (no bridge was built, or nothing opened successfully). Errors
// are logged rather than returned: every call site is an unconditional
// deferred teardown with no error path of its own, matching
// backupSources.Close's own contract.
func (c *listenBridgeCollaborators) Close() {
	if c == nil {
		return
	}
	if c.oathStore != nil {
		if err := c.oathStore.Close(); err != nil {
			slog.Default().Warn("failed to close OATH store", slog.String("error", err.Error()))
		}
	}
	if c.syncSources != nil {
		c.syncSources.Close()
	}
}

// listenPIVStorageProvider returns a pairing.PIVStorageProvider that builds
// PIV certificate storage for a named backend using the exact same
// createPIVStorage construction "xkey piv" uses (piv.go), over the same
// flag/config-resolved configuration (--backend, --piv-storage,
// --storage-path, --tpm-device, --pkcs11-*): a certificate stored via
// "xkey piv store" is the certificate the phone sees through
// remote.pivGetCert/pivListSlots. Storage is opened fresh per request and
// closed by the bridge afterward (bridge_piv.go), matching how "xkey piv"
// itself opens storage once per invocation rather than holding a long-lived
// session. cmd is "xkey device listen"'s or "xkey device relay"'s own
// command, which declares none of PIVCmd's flags, so this resolves through
// the unified config only unless a future flag is added here too.
func listenPIVStorageProvider(cmd *cobra.Command, logger *slog.Logger) pairing.PIVStorageProvider {
	return func(backend string) (xkms.PIVCertificateStorage, error) {
		cfg, err := buildPIVConfig(cmd)
		if err != nil {
			return nil, err
		}
		cfg.Backend = PIVBackendType(backend)
		// Re-derive the storage type for the requested backend unless the
		// operator pinned one explicitly, matching buildPIVConfig's own
		// precedence (an explicit --piv-storage/config override always wins).
		if pivStorageOverride(cmd) == "" {
			cfg.StorageType = defaultPIVStorageTypeForBackend(cfg.Backend)
		}
		return createPIVStorage(cfg, logger)
	}
}

// buildListenBridgeConfig assembles the BridgeConfig a caller hands to
// pairing.NewBridge, opening every collaborator that config needs. Split out
// from connectListenBridge so the wiring can be exercised without an xkmsd
// connection: it takes no transport.Client and dials nothing.
//
// connectListenBridge ("xkey device listen" and "xkey device relay") and
// connectXKMSdBridge ("xkey fido2"'s phone bridge, fido2_phone_bridge.go)
// both call this unchanged (go-xkms#1041, go-xkms#1306): a phone reaches the
// identical OATH store, PIV certificate storage, and sync service through
// any of those bridges, not a second, differently-wired implementation that
// only forwards ping, attestation, and TPM enrollment. cmd is whichever
// cobra.Command the caller is running under; its
// --barrier-password/--barrier-password-file flags (registered by
// registerDeviceListenFlags on "xkey device listen" and "xkey device relay",
// and directly on fido2Cmd) are read the same way regardless of which command
// owns them.
//
// The OATH store and sync service are opened through the exact constructors
// "xkey oath" (openOATHStore, oath.go) and "xkey device sync"
// (openSyncService, device_sync_shared.go) already use, reading cmd's
// --barrier-password/--barrier-password-file flags the same way those
// commands do. The PIV certificate storage provider builds on the exact
// createPIVStorage construction "xkey piv" uses. A collaborator that fails to
// open is logged and left nil rather than aborting the daemon: the bridge
// already treats a nil collaborator as "feature unconfigured" for exactly
// this reason (go-xkms#690), and a host with, say, no OATH store yet should
// still pair, sync its trust store, and serve PIV and every other method.
//
// device is the paired phone the bridge serves. Every audited bridge call —
// crypto requests, policy denials, each remote.sync* write the phone makes
// into this host's stores, and each remote.sync* approval decision — is
// recorded against it: DeviceID is its BLE address or TCP relay identity and
// DeviceName its paired name, the same identity pkg/phone records connection
// events under. The audit sink is the slog-backed audit.Logger the headless
// "xkey extension serve" daemon uses (fido2.go), since neither command owns
// a persistent audit store.
//
// syncApproval gates the bridge's secret-exporting remote.sync* methods
// (go-xkms#1306); see pairing.BridgeConfig.SyncApproval. Every caller must
// supply one -- nil is a valid, explicit "refuse every sync request" choice
// (pairing.ErrSyncApprovalRequired), never an oversight silently read as
// "sync unchecked".
//
// The returned collaborators must be closed at shutdown by the caller
// (listenBridgeCollaborators.Close); connectListenBridge and
// connectXKMSdBridge both do this via defer, matching every other resource
// their respective commands own.
func buildListenBridgeConfig(
	cmd *cobra.Command,
	logger *slog.Logger,
	xkmsdCfg *XKMSdBridgeConfig,
	device *PairedDevice,
	enroller pairing.TPMEnroller,
	enrollerErr error,
	syncApproval pairing.SyncApprovalFunc,
) (*pairing.BridgeConfig, *listenBridgeCollaborators) {
	collaborators := &listenBridgeCollaborators{}

	if oathStore, oathErr := openOATHStore(cmd, ""); oathErr != nil {
		logger.Warn("OATH store unavailable; remote.oath* will report unconfigured",
			slog.String("error", oathErr.Error()))
	} else {
		collaborators.oathStore = oathStore
	}

	syncService, syncSources, syncErr := openSyncService(cmd)
	if syncErr != nil {
		logger.Warn("sync service unavailable; remote.sync* will report unconfigured",
			slog.String("error", syncErr.Error()))
	} else {
		collaborators.syncSources = syncSources
	}

	bridgeCfg := &pairing.BridgeConfig{
		AllowedBackends: xkmsdCfg.AllowedBackends,
		DeniedBackends:  xkmsdCfg.DeniedBackends,
		RequestTimeout:  xkmsdCfg.RequestTimeout,
		Logger:          logger,
		TPM:             enroller,
		TPMOpenErr:      enrollerErr,
		OATHStore:       collaborators.oathStore,
		PIVStorage:      listenPIVStorageProvider(cmd, logger),
		SyncService:     syncService,
		SyncApproval:    syncApproval,
		AuditLogger:     audit.NewSlogLogger(logger),
		DeviceID:        device.Address,
		DeviceName:      device.Name,
	}

	return bridgeCfg, collaborators
}

// connectListenBridge creates the xkmsd bridge that serves the phone's
// remote.* requests while this laptop is listening or relaying. It returns a
// nil client and bridge when xkmsd is not enabled, in which case only the
// locally handled methods are served. The enroller, when non-nil, is the TPM
// the bridge answers the TCG/IDevID enrollment methods from. See
// buildListenBridgeConfig for syncApproval.
func connectListenBridge(
	cmd *cobra.Command,
	logger *slog.Logger,
	device *PairedDevice,
	enroller pairing.TPMEnroller,
	enrollerErr error,
	syncApproval pairing.SyncApprovalFunc,
) (transport.Client, *pairing.Bridge, *listenBridgeCollaborators, error) {
	cfg := loadXKMSdBridgeConfig()
	if !cfg.Enabled {
		return nil, nil, nil, nil
	}

	client, err := dialXKMSd(cfg, logger)
	if err != nil {
		return nil, nil, nil, err
	}

	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, logger, cfg, device, enroller, enrollerErr, syncApproval)

	bridge, err := pairing.NewBridge(client, bridgeCfg)
	if err != nil {
		collaborators.Close()
		return nil, nil, nil, errors.Join(ErrXKMSdBridgeCreationFailed, err, client.Close())
	}

	return client, bridge, collaborators, nil
}

// listenRequestHandler handles incoming requests from the phone.
type listenRequestHandler struct {
	logger   *slog.Logger
	attestor pairing.LaptopAttestor
	bridge   *pairing.Bridge
}

// newListenRequestHandler creates a new listen request handler with
// attestation support. The bridge, when non-nil, serves every remote.* method
// the locally handled set does not cover.
func newListenRequestHandler(
	logger *slog.Logger,
	tpmModule xkms.TrustedPlatformModule,
	mode pairing.AttestationMode,
	bridge *pairing.Bridge,
) (*listenRequestHandler, error) {
	attestor, err := pairing.NewLaptopAttestor(&pairing.LaptopAttestorConfig{
		Mode:   mode,
		TPM:    tpmModule,
		Logger: logger,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create laptop attestor", Err: err}
	}

	return &listenRequestHandler{
		logger:   logger,
		attestor: attestor,
		bridge:   bridge,
	}, nil
}

// HandleRequest processes a JSON-RPC request from the phone.
func (h *listenRequestHandler) HandleRequest(ctx context.Context, request []byte) ([]byte, error) {
	h.logger.Debug("received request from phone", slog.Int("size", len(request)))

	// Decode the request
	req, err := pairing.DecodeRequest(request)
	if err != nil {
		h.logger.Error("failed to decode request", slog.String("error", err.Error()))
		return pairing.EncodeErrorResponse(0, pairing.ErrorCodeParseError, "Failed to parse request", nil)
	}

	h.logger.Info("processing request",
		slog.String("method", req.Method),
		slog.Uint64("id", req.ID),
	)

	// Route the request based on method using map-based dispatch. Locally
	// handled methods win: laptop attestation is produced by the TPM attestor
	// configured here, not by xkmsd.
	if handler, ok := h.methodHandlers()[req.Method]; ok {
		return handler(ctx, req)
	}

	// Everything else is a xkmsd operation, served by the bridge.
	if h.bridge != nil {
		return h.handleViaBridge(ctx, req)
	}

	h.logger.Warn("unsupported method", slog.String("method", req.Method))
	return pairing.EncodeErrorResponse(req.ID, pairing.ErrorCodeMethodNotFound, "Method not supported", nil)
}

// handleViaBridge dispatches a request to the xkmsd bridge and encodes the
// bridge's JSON-RPC response.
func (h *listenRequestHandler) handleViaBridge(ctx context.Context, req *pairing.Request) ([]byte, error) {
	resp := h.bridge.HandleRequest(ctx, req)
	if resp == nil {
		h.logger.Error("bridge returned no response", slog.String("method", req.Method))
		return pairing.EncodeErrorResponse(req.ID, pairing.ErrorCodeInternalError, "Bridge returned no response", nil)
	}
	return encodeBridgeResponse(resp)
}

// encodeBridgeResponse encodes a bridge response into the frame the transport
// encrypts. The encoded result can carry a decrypted plaintext or a shared
// secret, so it is wiped once copied into the frame; the transport wipes the
// frame after Noise has encrypted it.
func encodeBridgeResponse(resp *pairing.Response) ([]byte, error) {
	encoded, err := json.Marshal(resp)
	secure.Wipe(resp.Result)
	return encoded, err
}

// methodHandler is a function type for handling specific methods.
type methodHandler func(ctx context.Context, req *pairing.Request) ([]byte, error)

// methodHandlers returns the map of method names to handlers.
func (h *listenRequestHandler) methodHandlers() map[string]methodHandler {
	return map[string]methodHandler{
		pairing.MethodPing:               h.handlePing,
		pairing.MethodRemoteAttestDevice: h.handleRemoteAttestDevice,
	}
}

// handlePing handles the ping method.
func (h *listenRequestHandler) handlePing(_ context.Context, req *pairing.Request) ([]byte, error) {
	return pairing.EncodeResponse(req.ID, &pairing.PingResult{
		Pong: true,
	})
}

// handleRemoteAttestDevice handles the remote.attestDevice method.
// This is called when the phone requests the laptop to attest itself.
// The phone generates a nonce and sends it here; we generate our attestation
// (using TPM2 if available) and return it to the phone for verification.
func (h *listenRequestHandler) handleRemoteAttestDevice(_ context.Context, req *pairing.Request) ([]byte, error) {
	// Decode the parameters
	paramsJSON, err := json.Marshal(req.Params)
	if err != nil {
		return pairing.EncodeErrorResponse(req.ID, pairing.ErrorCodeInvalidParams, "Invalid parameters", nil)
	}

	var params pairing.RemoteAttestDeviceParams
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return pairing.EncodeErrorResponse(req.ID, pairing.ErrorCodeInvalidParams, "Failed to decode parameters", nil)
	}

	h.logger.Info("laptop attestation requested by phone",
		slog.Int("nonce_len", len(params.Nonce)),
		slog.String("attestation_mode", string(h.attestor.Mode())),
		slog.Bool("tpm2_available", h.attestor.IsTPM2Available()),
	)

	// Generate attestation using the configured attestor
	result, err := h.attestor.GenerateAttestation(params.Nonce)
	if err != nil {
		h.logger.Error("attestation generation failed", slog.String("error", err.Error()))

		// Map errors to appropriate RPC error codes
		switch {
		case errors.Is(err, phone.ErrInvalidAttestationNonce):
			return pairing.EncodeErrorResponse(req.ID, pairing.ErrorCodeInvalidParams, "Nonce must be 32 bytes", nil)
		case errors.Is(err, phone.ErrTPM2Required):
			return pairing.EncodeErrorResponse(req.ID, pairing.ErrorCodeAttestUnsupported, "TPM2 required but not available", nil)
		default:
			return pairing.EncodeErrorResponse(req.ID, pairing.ErrorCodeAttestFailed, err.Error(), nil)
		}
	}

	h.logger.Info("returning laptop attestation",
		slog.String("format", result.Format),
		slog.String("security_level", result.SecurityLevel),
		slog.Int("cert_chain_len", len(result.CertificateChain)),
		slog.Bool("boot_verified", result.BootStateVerified),
	)

	return pairing.EncodeResponse(req.ID, result)
}
