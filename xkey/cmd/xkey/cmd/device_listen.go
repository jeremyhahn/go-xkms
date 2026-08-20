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

//go:build ble

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Device listen command errors.
var (
	// ErrDeviceListenFailed indicates the listen command failed to start.
	ErrDeviceListenFailed = errors.New("device: listen failed")

	// ErrDeviceNoDefaultDevice indicates no default device is configured.
	ErrDeviceNoDefaultDevice = errors.New("device: no default device configured")

	// ErrInvalidNonceSize indicates the nonce size is invalid.
	ErrInvalidNonceSize = errors.New("device: nonce must be 32 bytes")

	// ErrTPM2InitFailed indicates TPM2 initialization failed.
	ErrTPM2InitFailed = errors.New("device: TPM2 initialization failed")
)

// Default TPM2 device path.
const defaultTPMDevice = "/dev/tpmrm0"

// deviceListenCmd starts the BLE peripheral to accept phone-initiated connections.
var deviceListenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen for phone-initiated connections",
	Long: `Start the BLE peripheral to accept connections from paired phones.

This command starts the laptop as a BLE peripheral (GATT server), allowing
the phone to initiate connections when it needs to perform operations like
re-attestation or key management.

The peripheral advertises the xKey service UUID and waits for the paired
phone to connect. Once connected, the phone can send requests through the
established Noise-encrypted channel.

When the phone sends a remote.attestDevice request, this laptop will generate
its attestation (using TPM2 if available, otherwise software attestation) and
return it to the phone for verification.

Attestation Modes:
  - auto (default): Use TPM2 if available, otherwise fall back to software
  - tpm2: Require TPM2 attestation, fail if TPM2 is not available
  - software: Always use software attestation, even if TPM2 is available

TCG Device Enrollment:
  --tpm-enrollment additionally offers this laptop's TPM to the phone acting
  as a Certificate Authority, so the phone can run the TCG-CSR-IDEVID
  enrollment ceremony against it. It is off by default: enrollment hands the
  phone the EK certificate and lets it drive TPM2_ActivateCredential, so it is
  an explicit decision. A host with no TPM still listens, pairs and serves
  every other method; it simply reports enrollment as unavailable.

This is useful when:
  - The phone needs to verify the laptop's integrity
  - Re-attestation is triggered from the phone
  - The phone wants to use keys on the laptop's xkms

Examples:
  # Start listening for the default paired device
  xkey device listen

  # Listen for a specific device
  xkey device listen --device "John's Pixel"

  # Listen with custom device name
  xkey device listen --name "My Laptop"

  # Listen with timeout (default: no timeout, runs until interrupted)
  xkey device listen --timeout 5m

  # Force TPM2 attestation (fail if TPM2 not available)
  xkey device listen --attestation-mode tpm2

  # Use software attestation only
  xkey device listen --attestation-mode software

  # Also let the phone enroll this laptop's TPM as a TCG device identity
  xkey device listen --tpm-enrollment`,
	RunE: runDeviceListen,
}

func init() {
	deviceCmd.AddCommand(deviceListenCmd)

	// Listen command flags
	deviceListenCmd.Flags().String("device", "", "Specific paired device to accept connections from")
	deviceListenCmd.Flags().String("name", "", "Advertised device name (default: hostname)")
	deviceListenCmd.Flags().Duration("timeout", 0, "Listen timeout (0 for indefinite)")
	deviceListenCmd.Flags().String("attestation-mode", "auto", "Attestation mode: auto, tpm2, software")
	deviceListenCmd.Flags().String("tpm-device", "", "TPM2 device path (default: /dev/tpmrm0)")
	deviceListenCmd.Flags().Bool("tpm-enrollment", false, "Serve TCG-CSR-IDEVID device enrollment from this host's TPM")
	deviceListenCmd.Flags().String("tpm-pcr-bank", "", "PCR bank for the platform policy digest (default: SHA-256); set only if this TPM's SHA-256 bank is not allocated")

	// Bind flags to viper
	_ = viper.BindPFlag("device.listen.device", deviceListenCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.listen.name", deviceListenCmd.Flags().Lookup("name"))
	_ = viper.BindPFlag("device.listen.timeout", deviceListenCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("device.listen.attestation-mode", deviceListenCmd.Flags().Lookup("attestation-mode"))
	_ = viper.BindPFlag("device.listen.tpm-device", deviceListenCmd.Flags().Lookup("tpm-device"))
	_ = viper.BindPFlag("device.listen.tpm-enrollment", deviceListenCmd.Flags().Lookup("tpm-enrollment"))
	_ = viper.BindPFlag("device.listen.tpm-pcr-bank", deviceListenCmd.Flags().Lookup("tpm-pcr-bank"))
}

// runDeviceListen executes the phone listen command.
func runDeviceListen(cmd *cobra.Command, args []string) (runErr error) {
	logger := slog.Default()

	deviceFilter, _ := cmd.Flags().GetString("device")
	deviceName, _ := cmd.Flags().GetString("name")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	attestModeStr, _ := cmd.Flags().GetString("attestation-mode")
	tpmDevice, _ := cmd.Flags().GetString("tpm-device")
	tpmPCRBank, _ := cmd.Flags().GetString("tpm-pcr-bank")
	tpmEnrollment, _ := cmd.Flags().GetBool("tpm-enrollment")

	// Parse attestation mode
	attestMode := phone.ParseAttestationMode(attestModeStr)

	// Load phone configuration
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No paired devices. Use 'xkey device pair' first.")
			return ErrDeviceNotPaired
		}
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	if len(cfg.Devices) == 0 {
		fmt.Println("No paired devices. Use 'xkey device pair' first.")
		return ErrDeviceNotPaired
	}

	// Find the target device
	var targetDevice *PairedDevice
	if deviceFilter != "" {
		targetDevice = findDeviceByName(cfg, deviceFilter)
		if targetDevice == nil {
			return &DetailError{Err: ErrDeviceNotFound, Detail: fmt.Sprintf(": %s", deviceFilter)}
		}
	} else if cfg.DefaultDevice != "" {
		targetDevice = findDeviceByName(cfg, cfg.DefaultDevice)
		if targetDevice == nil {
			return ErrDeviceNoDefaultDevice
		}
	} else if len(cfg.Devices) == 1 {
		targetDevice = &cfg.Devices[0]
	} else {
		fmt.Println("Multiple devices paired. Specify one with --device or set a default.")
		return ErrDeviceNoDefaultDevice
	}

	// Decode the phone's public key
	expectedRemoteStatic, err := base64.StdEncoding.DecodeString(targetDevice.NoisePublicKey)
	if err != nil {
		return &WrappedError{Msg: "failed to decode phone public key", Err: err}
	}

	// Decode our local static key
	localPrivateKey, err := base64.StdEncoding.DecodeString(targetDevice.LocalNoisePrivateKey)
	if err != nil {
		return &WrappedError{Msg: "failed to decode local private key", Err: err}
	}
	// Wiped here, at the decode, not at the LoadStaticKey below: a decode
	// failure on any other field returns in between, and the raw scalar
	// would be left sitting in garbage-collected memory.
	defer phone.WipeBytes(localPrivateKey)

	// Reconstruct the Noise static key from stored private key
	localStaticKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return &WrappedError{Msg: "failed to reconstruct local key", Err: err}
	}
	// Ownership transfers to the peripheral below. It is the only thing that
	// knows whether a reader is still live at shutdown: on an incomplete
	// shutdown it retains the key for the process lifetime, where a
	// caller-side destroy would free pages that reader is still using.
	//
	// Until that transfer the key is still ours, and there is real work in
	// between — TPM init, bridge and handler setup — every failure of which
	// used to be covered by the defer this replaced.
	transferred := false
	defer func() {
		if !transferred {
			localStaticKey.Destroy()
		}
	}()

	// Use hostname as default device name
	if deviceName == "" {
		deviceName = hostname()
	}

	// Initialize TPM2 if mode is not software-only
	var tpmModule xkms.TrustedPlatformModule
	if attestMode != phone.AttestationModeSoftware {
		tpmModule, err = initTPMForAttestation(tpmDevice, logger)
		if err != nil {
			if attestMode == phone.AttestationModeTPM2 {
				return &SentinelCauseError{Sentinel: ErrTPM2InitFailed, Cause: err}
			}
			logger.Warn("TPM2 not available, using software attestation",
				slog.String("error", err.Error()))
		}
	}

	// Close TPM when done
	if tpmModule != nil {
		defer func() {
			if closeErr := tpmModule.Close(); closeErr != nil {
				logger.Error("failed to close TPM", slog.String("error", closeErr.Error()))
			}
		}()
	}

	// Resolve the TPM the bridge answers TCG enrollment from. When the
	// attestor already holds this host's TPM open, that same handle is used —
	// the device is opened once per process, not once per feature.
	enroller, ownedEnroller, enrollerErr := resolveListenEnroller(tpmEnrollment, tpmModule, tpmDevice, tpmPCRBank, logger)
	if ownedEnroller != nil {
		defer func() {
			if closeErr := ownedEnroller.Close(); closeErr != nil {
				logger.Error("failed to close enrollment TPM", slog.String("error", closeErr.Error()))
			}
		}()
	}

	// Wire the xkmsd bridge so the phone's full remote.* method set is served,
	// not just ping and attestation.
	bridgeClient, bridge, err := connectListenBridge(logger, enroller, enrollerErr)
	if err != nil {
		return err
	}
	if bridgeClient != nil {
		defer func() {
			if closeErr := bridgeClient.Close(); closeErr != nil {
				logger.Warn("failed to close xkmsd client", slog.String("error", closeErr.Error()))
			}
		}()
	}

	// Create the request handler that processes phone requests
	handler, err := newListenRequestHandler(logger, tpmModule, attestMode, bridge)
	if err != nil {
		return &WrappedError{Msg: "failed to create request handler", Err: err}
	}

	// Create the BLE peripheral
	peripheral, err := phone.NewBLEPeripheral(&phone.BLEPeripheralConfig{
		LocalStaticKey:       localStaticKey,
		OwnsStaticKey:        true,
		ExpectedRemoteStatic: expectedRemoteStatic,
		DeviceName:           deviceName,
		Logger:               logger,
		RequestHandler:       handler,
	})
	if err == nil {
		// The constructor consumed the key; the peripheral releases it now.
		transferred = true
	}
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return ErrDeviceBLEUnavailable
		}
		return &SentinelCauseError{Sentinel: ErrDeviceListenFailed, Cause: err}
	}

	// Set up context with optional timeout
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	} else {
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
	}

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nStopping...")
		cancel()
		// Surfaced, not discarded: an incomplete stop means the peripheral
		// could not confirm it finished — a handler still running, or an
		// advertisement that would not come down. Only the first retains the
		// static key; either is a shutdown this command must not report as
		// clean.
		if err := peripheral.Stop(); err != nil {
			logger.Warn("peripheral stop did not complete cleanly", "error", err)
		}
	}()

	// Registered BEFORE Start, not after: a Start that fails still leaves the
	// peripheral holding the key whose ownership it just took, and returning
	// past an uninstalled defer stranded those protected pages for the life
	// of the process.
	// The result is kept, not dropped. A command that exits 0 after a
	// handler-drain timeout tells the operator the key was released when in
	// fact it was retained, so the stop result becomes the command's result
	// when nothing else already failed.
	defer func() {
		if err := peripheral.Stop(); err != nil {
			logger.Warn("peripheral stop did not complete cleanly", "error", err)
			if runErr == nil {
				runErr = err
			}
		}
	}()

	// Start the peripheral
	if err := peripheral.Start(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceListenFailed, Cause: err}
	}

	fmt.Printf("Listening for connections from \"%s\"...\n", targetDevice.Name)
	fmt.Printf("Advertising as \"%s\"\n", deviceName)
	if tpmModule != nil {
		fmt.Println("Attestation mode: TPM2 (hardware)")
	} else {
		fmt.Println("Attestation mode: software")
	}
	if bridge != nil {
		fmt.Println("xkmsd bridge: enabled (full remote.* method set)")
	} else {
		fmt.Println("xkmsd bridge: disabled (only ping and attestation are served)")
	}
	switch {
	case !tpmEnrollment:
		fmt.Println("TCG device enrollment: disabled (pass --tpm-enrollment to offer it)")
	case enroller != nil:
		fmt.Println("TCG device enrollment: enabled")
	default:
		fmt.Println("TCG device enrollment: requested but no TPM is reachable (see log)")
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Accept connections in a loop
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				fmt.Println("Listen timeout reached")
			}
			return nil
		default:
		}

		if err := peripheral.AcceptConnection(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			logger.Error("connection error", slog.String("error", err.Error()))
			// Continue listening for new connections
		}
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
) (phone.TPMEnroller, io.Closer, error) {
	if !enabled {
		return nil, nil, nil
	}
	if attestTPM != nil {
		logger.Info("TCG device enrollment enabled on the attestation TPM")
		return attestTPM, nil, nil
	}

	// The reason is logged by OpenTPMEnroller, at INFO when this host simply
	// has no TPM and at WARN when it has one that cannot be opened.
	enroller, err := phone.OpenTPMEnroller(&phone.TPMEnrollerConfig{
		Device:          devicePath,
		PlatformPCRBank: pcrBank,
		Logger:          logger,
	})
	if err != nil {
		// A host with no TPM reports nothing to the phone beyond "unsupported".
		// A TPM we could not open is a fault someone can fix, so the cause is
		// carried to the bridge and reported distinctly.
		if errors.Is(err, phone.ErrTPMNotConfigured) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	return enroller, enroller, nil
}

// connectListenBridge creates the xkmsd bridge that serves the phone's
// remote.* requests while this laptop is listening. It returns a nil client
// and bridge when xkmsd is not enabled, in which case only the locally
// handled methods are served. The enroller, when non-nil, is the TPM the
// bridge answers the TCG/IDevID enrollment methods from.
func connectListenBridge(
	logger *slog.Logger,
	enroller phone.TPMEnroller,
	enrollerErr error,
) (transport.Client, *phone.Bridge, error) {
	cfg := loadXKMSdBridgeConfig()
	if !cfg.Enabled {
		return nil, nil, nil
	}

	client, err := dialXKMSd(cfg, logger)
	if err != nil {
		return nil, nil, err
	}

	bridge, err := phone.NewBridge(client, &phone.BridgeConfig{
		AllowedBackends: cfg.AllowedBackends,
		DeniedBackends:  cfg.DeniedBackends,
		RequestTimeout:  cfg.RequestTimeout,
		Logger:          logger,
		TPM:             enroller,
		TPMOpenErr:      enrollerErr,
	})
	if err != nil {
		_ = client.Close()
		return nil, nil, errors.Join(ErrXKMSdBridgeCreationFailed, err)
	}

	return client, bridge, nil
}

// listenRequestHandler handles incoming requests from the phone.
type listenRequestHandler struct {
	logger   *slog.Logger
	attestor phone.LaptopAttestor
	bridge   *phone.Bridge
}

// newListenRequestHandler creates a new listen request handler with
// attestation support. The bridge, when non-nil, serves every remote.* method
// the locally handled set does not cover.
func newListenRequestHandler(
	logger *slog.Logger,
	tpmModule xkms.TrustedPlatformModule,
	mode phone.AttestationMode,
	bridge *phone.Bridge,
) (*listenRequestHandler, error) {
	attestor, err := phone.NewLaptopAttestor(&phone.LaptopAttestorConfig{
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
	req, err := phone.DecodeRequest(request)
	if err != nil {
		h.logger.Error("failed to decode request", slog.String("error", err.Error()))
		return phone.EncodeErrorResponse(0, phone.ErrorCodeParseError, "Failed to parse request", nil)
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
	return phone.EncodeErrorResponse(req.ID, phone.ErrorCodeMethodNotFound, "Method not supported", nil)
}

// handleViaBridge dispatches a request to the xkmsd bridge and encodes the
// bridge's JSON-RPC response.
func (h *listenRequestHandler) handleViaBridge(ctx context.Context, req *phone.Request) ([]byte, error) {
	resp := h.bridge.HandleRequest(ctx, req)
	if resp == nil {
		h.logger.Error("bridge returned no response", slog.String("method", req.Method))
		return phone.EncodeErrorResponse(req.ID, phone.ErrorCodeInternalError, "Bridge returned no response", nil)
	}
	return json.Marshal(resp)
}

// methodHandler is a function type for handling specific methods.
type methodHandler func(ctx context.Context, req *phone.Request) ([]byte, error)

// methodHandlers returns the map of method names to handlers.
func (h *listenRequestHandler) methodHandlers() map[string]methodHandler {
	return map[string]methodHandler{
		phone.MethodPing:               h.handlePing,
		phone.MethodRemoteAttestDevice: h.handleRemoteAttestDevice,
	}
}

// handlePing handles the ping method.
func (h *listenRequestHandler) handlePing(_ context.Context, req *phone.Request) ([]byte, error) {
	return phone.EncodeResponse(req.ID, &phone.PingResult{
		Pong: true,
	})
}

// handleRemoteAttestDevice handles the remote.attestDevice method.
// This is called when the phone requests the laptop to attest itself.
// The phone generates a nonce and sends it here; we generate our attestation
// (using TPM2 if available) and return it to the phone for verification.
func (h *listenRequestHandler) handleRemoteAttestDevice(_ context.Context, req *phone.Request) ([]byte, error) {
	// Decode the parameters
	paramsJSON, err := json.Marshal(req.Params)
	if err != nil {
		return phone.EncodeErrorResponse(req.ID, phone.ErrorCodeInvalidParams, "Invalid parameters", nil)
	}

	var params phone.RemoteAttestDeviceParams
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return phone.EncodeErrorResponse(req.ID, phone.ErrorCodeInvalidParams, "Failed to decode parameters", nil)
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
			return phone.EncodeErrorResponse(req.ID, phone.ErrorCodeInvalidParams, "Nonce must be 32 bytes", nil)
		case errors.Is(err, phone.ErrTPM2Required):
			return phone.EncodeErrorResponse(req.ID, phone.ErrorCodeAttestUnsupported, "TPM2 required but not available", nil)
		default:
			return phone.EncodeErrorResponse(req.ID, phone.ErrorCodeAttestFailed, err.Error(), nil)
		}
	}

	h.logger.Info("returning laptop attestation",
		slog.String("format", result.Format),
		slog.String("security_level", result.SecurityLevel),
		slog.Int("cert_chain_len", len(result.CertificateChain)),
		slog.Bool("boot_verified", result.BootStateVerified),
	)

	return phone.EncodeResponse(req.ID, result)
}
