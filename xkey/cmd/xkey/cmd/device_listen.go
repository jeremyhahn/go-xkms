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
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
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
  xkey device listen --attestation-mode software`,
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

	// Bind flags to viper
	_ = viper.BindPFlag("device.listen.device", deviceListenCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.listen.name", deviceListenCmd.Flags().Lookup("name"))
	_ = viper.BindPFlag("device.listen.timeout", deviceListenCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("device.listen.attestation-mode", deviceListenCmd.Flags().Lookup("attestation-mode"))
	_ = viper.BindPFlag("device.listen.tpm-device", deviceListenCmd.Flags().Lookup("tpm-device"))
}

// runDeviceListen executes the phone listen command.
func runDeviceListen(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	deviceFilter, _ := cmd.Flags().GetString("device")
	deviceName, _ := cmd.Flags().GetString("name")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	attestModeStr, _ := cmd.Flags().GetString("attestation-mode")
	tpmDevice, _ := cmd.Flags().GetString("tpm-device")

	// Parse attestation mode
	attestMode := phone.ParseAttestationMode(attestModeStr)

	// Load phone configuration
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No paired devices. Use 'xkey device pair' first.")
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
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
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceFilter)
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
		return fmt.Errorf("failed to decode phone public key: %w", err)
	}

	// Decode our local static key
	localPrivateKey, err := base64.StdEncoding.DecodeString(targetDevice.LocalNoisePrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode local private key: %w", err)
	}

	// Reconstruct the Noise static key from stored private key
	localStaticKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to reconstruct local key: %w", err)
	}

	// Use hostname as default device name
	if deviceName == "" {
		deviceName = hostname()
	}

	// Initialize TPM2 if mode is not software-only
	var tpmModule tpm2.TrustedPlatformModule
	if attestMode != phone.AttestationModeSoftware {
		tpmModule, err = initTPMForAttestation(tpmDevice, logger)
		if err != nil {
			if attestMode == phone.AttestationModeTPM2 {
				return fmt.Errorf("%w: %v", ErrTPM2InitFailed, err)
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

	// Create the request handler that processes phone requests
	handler, err := newListenRequestHandler(logger, tpmModule, attestMode)
	if err != nil {
		return fmt.Errorf("failed to create request handler: %w", err)
	}

	// Create the BLE peripheral
	peripheral, err := phone.NewBLEPeripheral(&phone.BLEPeripheralConfig{
		LocalStaticKey:       localStaticKey,
		ExpectedRemoteStatic: expectedRemoteStatic,
		DeviceName:           deviceName,
		Logger:               logger,
		RequestHandler:       handler,
	})
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return ErrDeviceBLEUnavailable
		}
		return fmt.Errorf("%w: %v", ErrDeviceListenFailed, err)
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
		peripheral.Stop()
	}()

	// Start the peripheral
	if err := peripheral.Start(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceListenFailed, err)
	}
	defer peripheral.Stop()

	fmt.Printf("Listening for connections from \"%s\"...\n", targetDevice.Name)
	fmt.Printf("Advertising as \"%s\"\n", deviceName)
	if tpmModule != nil {
		fmt.Println("Attestation mode: TPM2 (hardware)")
	} else {
		fmt.Println("Attestation mode: software")
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
func initTPMForAttestation(devicePath string, logger *slog.Logger) (tpm2.TrustedPlatformModule, error) {
	if devicePath == "" {
		devicePath = defaultTPMDevice
	}

	logger.Debug("initializing TPM2 for attestation", slog.String("device", devicePath))

	tpmCfg := &tpm2.Config{
		Device: devicePath,
		Hash:   "SHA-256",
	}

	tpmModule, err := tpm2.NewTPM2(&tpm2.Params{
		Config: tpmCfg,
		Logger: logger,
	})
	if err != nil {
		// Check if it's a "not initialized" error which means TPM is present but not provisioned
		if errors.Is(err, tpm2.ErrNotInitialized) {
			logger.Warn("TPM2 present but not initialized for attestation")
			return nil, err
		}
		return nil, err
	}

	logger.Info("TPM2 initialized for attestation", slog.String("device", devicePath))
	return tpmModule, nil
}

// listenRequestHandler handles incoming requests from the phone.
type listenRequestHandler struct {
	logger   *slog.Logger
	attestor phone.LaptopAttestor
}

// newListenRequestHandler creates a new listen request handler with attestation support.
func newListenRequestHandler(
	logger *slog.Logger,
	tpmModule tpm2.TrustedPlatformModule,
	mode phone.AttestationMode,
) (*listenRequestHandler, error) {
	attestor, err := phone.NewLaptopAttestor(&phone.LaptopAttestorConfig{
		Mode:   mode,
		TPM:    tpmModule,
		Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create laptop attestor: %w", err)
	}

	return &listenRequestHandler{
		logger:   logger,
		attestor: attestor,
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

	// Route the request based on method using map-based dispatch
	handler, ok := h.methodHandlers()[req.Method]
	if !ok {
		h.logger.Warn("unsupported method", slog.String("method", req.Method))
		return phone.EncodeErrorResponse(req.ID, phone.ErrorCodeMethodNotFound, "Method not supported", nil)
	}

	return handler(ctx, req)
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
