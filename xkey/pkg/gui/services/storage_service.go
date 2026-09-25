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

package services

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

const (
	// minPassphraseLength is the minimum allowed passphrase length.
	minPassphraseLength = 8

	// minVolumeSizeGB is the minimum allowed volume size in gigabytes.
	minVolumeSizeGB = 1

	// maxVolumeSizeGB is the maximum allowed volume size in gigabytes.
	maxVolumeSizeGB = 100

	// bytesPerGB converts gigabytes to bytes.
	bytesPerGB = 1024 * 1024 * 1024
)

// wipeStandards maps user-facing standard names to LUKS wipe constants.
var wipeStandards = map[string]luks.WipeStandard{
	"nist": luks.StandardNIST,
	"dod3": luks.StandardDoD3Pass,
	"dod7": luks.StandardDoD7Pass,
}

// StorageStatus describes the current state of the encrypted storage volume.
type StorageStatus struct {
	VolumeExists       bool   `json:"volume_exists"`
	IsLUKS             bool   `json:"is_luks"`
	IsMounted          bool   `json:"is_mounted"`
	IsOpen             bool   `json:"is_open"`
	VolumePath         string `json:"volume_path"`
	MountPoint         string `json:"mount_point"`
	VolumeSizeBytes    int64  `json:"volume_size_bytes,omitempty"`
	ElevationAvailable bool   `json:"elevation_available"`
}

// CreateVolumeParams holds parameters for creating a new encrypted volume.
type CreateVolumeParams struct {
	SizeGB     int    `json:"size_gb"`
	Passphrase string `json:"passphrase"`
}

// StorageService exposes LUKS encrypted volume operations to the frontend.
// It is bound to the Wails runtime so every exported method is callable
// from the Svelte frontend.
type StorageService struct {
	ctx      context.Context
	log      *slog.Logger
	elevator Elevator

	// luksMu guards luksBackend construction and access.
	luksMu sync.Mutex
	// luksBackend is the process-lifetime LUKSStorageBackend used by
	// CreateVolume, UnlockVolume, LockVolume, and RequireUnlocked. Its lock
	// state reflects only what this process itself has done — see
	// RequireUnlocked and Backend.Attach for how a second process's
	// mount (for example an elevated `xkey luks2 unseal` child process) is
	// reconciled.
	luksBackend *xkms.LUKSStorageBackend
}

// NewStorageService creates a new StorageService.
func NewStorageService() *StorageService {
	return &StorageService{
		log: slog.Default().With("component", "storage_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *StorageService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetElevator configures the privilege elevator used for operations
// that require root when the process is not running as root.
func (s *StorageService) SetElevator(e Elevator) {
	s.elevator = e
}

// luksStorageBackend returns the process-lifetime LUKSStorageBackend,
// constructing it against the default xhome-resolved volume on first use.
// The same instance is reused for the life of the service so its lock
// state accumulates across CreateVolume/UnlockVolume/LockVolume/
// RequireUnlocked calls within this process.
func (s *StorageService) luksStorageBackend() (*xkms.LUKSStorageBackend, error) {
	s.luksMu.Lock()
	defer s.luksMu.Unlock()

	if s.luksBackend != nil {
		return s.luksBackend, nil
	}

	vol, err := luks.NewVolume()
	if err != nil {
		return nil, err
	}
	s.luksBackend = xkms.NewLUKSStorageBackend(vol)
	return s.luksBackend, nil
}

// RequireUnlocked fails closed against a locked LUKS volume: it returns
// xkms.ErrLUKSVolumeLocked when a LUKS volume is configured for this xkey
// home but not currently mounted, so that data-directory initialization can
// refuse to open any store rather than silently writing to the plain,
// unencrypted directory beneath an unmounted mount point.
//
// It returns nil when no LUKS volume is configured for this home (Exists is
// false — the no-LUKS data directory is unaffected) and when the volume is
// already usable. "Already usable" includes attaching this process's
// LUKSStorageBackend to a volume mounted by someone else — for example an
// elevated `xkey luks2 unseal` child process this StorageService itself
// spawned when not running as root, or a separate CLI invocation that
// shares the same on-disk container — via Backend.Attach, since in that case
// this process never called Unlock itself.
func (s *StorageService) RequireUnlocked() error {
	vol, err := luks.NewVolume()
	if err != nil {
		// xhome could not be resolved; the data directory open that follows
		// will surface the same failure with more context, so do not block
		// here on a LUKS-specific error the volume can't actually explain.
		return nil
	}
	if !vol.Exists() {
		return nil
	}

	backend, err := s.luksStorageBackend()
	if err != nil {
		return nil
	}
	if backend.IsUnlocked() {
		return nil
	}
	if !vol.IsMounted() {
		return xkms.ErrLUKSVolumeLocked
	}
	return backend.Attach()
}

// GetStatus returns the current state of the encrypted storage volume.
// This method does not require root and is safe to call from any context.
func (s *StorageService) GetStatus() (*StorageStatus, error) {
	elevationAvailable := s.elevator != nil && s.elevator.IsAvailable()

	vol, err := luks.NewVolume()
	if err != nil {
		return &StorageStatus{ElevationAvailable: elevationAvailable}, nil
	}

	status := &StorageStatus{
		VolumePath:         vol.LUKSPath,
		MountPoint:         vol.MountPoint,
		ElevationAvailable: elevationAvailable,
	}

	status.VolumeExists = vol.Exists()
	if status.VolumeExists {
		status.IsLUKS = vol.IsLUKS()
		status.IsMounted = vol.IsMounted()
		status.IsOpen = vol.IsOpen()
		if info, statErr := os.Stat(vol.LUKSPath); statErr == nil {
			status.VolumeSizeBytes = info.Size()
		}
	}

	return status, nil
}

// CreateVolume creates a new LUKS encrypted volume with the given parameters.
// The volume is created and locked; use UnlockVolume to open it, or
// MigrateToEncrypted to import existing data.
func (s *StorageService) CreateVolume(params CreateVolumeParams) error {
	if err := validateVolumeSize(params.SizeGB); err != nil {
		return err
	}
	if err := validatePassphrase(params.Passphrase); err != nil {
		return err
	}

	if geteuid() == 0 {
		backend, err := s.luksStorageBackend()
		if err != nil {
			return err
		}
		sizeBytes := int64(params.SizeGB) * bytesPerGB
		// Initialize creates the volume and auto-unlocks it so it's
		// immediately usable.
		return backend.Initialize(sizeBytes, params.Passphrase)
	}

	// Build: xkey luks2 seal --size <N>G --skip-migrate --unseal --path <path> --mount-point <mount>
	// stdin: passphrase\npassphrase\n
	sizeStr := fmt.Sprintf("%dG", params.SizeGB)
	args := []string{"luks2", "seal", "--size", sizeStr, "--skip-migrate", "--unseal"}
	args = append(args, luksPathArgs()...)
	stdinData := []byte(params.Passphrase + "\n" + params.Passphrase + "\n")
	return s.runElevatedCmd(args, stdinData)
}

// UnlockVolume unlocks and mounts the encrypted volume with the given passphrase.
func (s *StorageService) UnlockVolume(passphrase string) error {
	if err := validatePassphrase(passphrase); err != nil {
		return err
	}

	if geteuid() == 0 {
		backend, err := s.luksStorageBackend()
		if err != nil {
			return err
		}
		return backend.Unlock(passphrase)
	}

	// Build: xkey luks2 unseal --path <path> --mount-point <mount>
	// stdin: passphrase\n
	args := []string{"luks2", "unseal"}
	args = append(args, luksPathArgs()...)
	stdinData := []byte(passphrase + "\n")
	return s.runElevatedCmd(args, stdinData)
}

// LockVolume unmounts and locks the encrypted volume.
func (s *StorageService) LockVolume() error {
	if geteuid() == 0 {
		backend, err := s.luksStorageBackend()
		if err != nil {
			return err
		}
		return backend.Lock()
	}

	// Build: xkey luks2 lock --path <path> --mount-point <mount>
	args := []string{"luks2", "lock"}
	args = append(args, luksPathArgs()...)
	return s.runElevatedCmd(args, nil)
}

// MigrateToEncrypted creates a LUKS volume (if needed) and imports
// existing data from the default data directory into it. The volume is
// temporarily unlocked at a safe mount point (not ~/.xkey) so the
// operation works while the application is running. After import, the
// original plaintext data is cleaned up and the volume is unlocked at
// the real mount point for immediate use.
//
// When backupOriginal is true the original data directory is renamed to
// <dir>-backup before cleanup; otherwise it is removed entirely.
func (s *StorageService) MigrateToEncrypted(sizeGB int, passphrase string, backupOriginal bool) error {
	if err := validateVolumeSize(sizeGB); err != nil {
		return err
	}
	if err := validatePassphrase(passphrase); err != nil {
		return err
	}

	if geteuid() == 0 {
		return s.migrateToEncryptedDirect(sizeGB, passphrase, backupOriginal)
	}

	h, err := xhome.Resolve()
	if err != nil {
		return err
	}
	luksPath, dataDir := h.LUKSPath(), h.MountPoint()

	// If the volume doesn't exist, create it first with --skip-migrate
	vol := luks.NewVolumeWithPaths(luksPath, "")
	if !vol.Exists() {
		sizeStr := fmt.Sprintf("%dG", sizeGB)
		createArgs := []string{"luks2", "seal", "--size", sizeStr, "--skip-migrate"}
		createArgs = append(createArgs, luksPathArgs()...)
		stdinData := []byte(passphrase + "\n" + passphrase + "\n")
		if err := s.runElevatedCmd(createArgs, stdinData); err != nil {
			return err
		}
	}

	// Import data, clean up original, and unlock at the real mount point,
	// all in a single elevated command. This prevents the running GUI from
	// recreating data in the brief window between cleanup and mount.
	// Build: xkey luks2 import-data --path <luksPath> --source <dataDir>
	//        --cleanup [--backup] --unseal --mount-point <dataDir>
	// stdin: passphrase\n
	args := []string{
		"luks2", "import-data",
		"--path", luksPath,
		"--source", dataDir,
		"--cleanup",
		"--unseal",
		"--mount-point", dataDir,
	}
	if backupOriginal {
		args = append(args, "--backup")
	}
	stdinData := []byte(passphrase + "\n")
	return s.runElevatedCmd(args, stdinData)
}

// migrateToEncryptedDirect creates and imports data directly when running as root.
func (s *StorageService) migrateToEncryptedDirect(sizeGB int, passphrase string, backupOriginal bool) error {
	h, err := xhome.Resolve()
	if err != nil {
		return err
	}
	luksPath, dataDir := h.LUKSPath(), h.MountPoint()

	// Create volume if it doesn't exist
	vol := luks.NewVolumeWithPaths(luksPath, "")
	if !vol.Exists() {
		sizeBytes := int64(sizeGB) * bytesPerGB
		defaultVol, newErr := luks.NewVolume()
		if newErr != nil {
			return newErr
		}
		if err := defaultVol.Create(sizeBytes, passphrase); err != nil {
			return err
		}
	}

	// Use a temporary mount point so we don't conflict with the
	// running application's use of ~/.xkey.
	tmpMount, err := os.MkdirTemp("", "xkey-import-")
	if err != nil {
		return err
	}
	defer func() {
		if rmErr := os.RemoveAll(tmpMount); rmErr != nil {
			s.log.Warn("failed to remove temporary import mount point", "dir", tmpMount, "error", rmErr)
		}
	}()

	importVol := luks.NewVolumeWithPaths(luksPath, tmpMount)

	if err := importVol.Unlock(passphrase); err != nil {
		return err
	}

	if err := importVol.CopyDataToVolume(dataDir); err != nil {
		lockErr := importVol.Lock()
		if lockErr != nil {
			s.log.Error("failed to lock volume after copy error",
				"error", lockErr)
		}
		return err
	}

	// Lock the temp-mounted volume before cleaning up the source.
	if err := importVol.Lock(); err != nil {
		return err
	}

	// Clean up original plaintext data now that it is safely inside the
	// LUKS volume. This must happen before the final unlock so the mount
	// point is empty.
	if backupOriginal {
		backupDir := dataDir + "-backup"
		// Remove stale backup from a previous migration.
		if _, statErr := os.Stat(backupDir); statErr == nil {
			if rmErr := os.RemoveAll(backupDir); rmErr != nil {
				s.log.Warn("failed to remove stale backup", "dir", backupDir, "error", rmErr)
			}
		}
		if err := os.Rename(dataDir, backupDir); err != nil {
			s.log.Error("failed to backup original data", "error", err)
			return err
		}
	} else {
		if err := os.RemoveAll(dataDir); err != nil {
			s.log.Error("failed to remove original data", "error", err)
			return err
		}
	}
	// Recreate the empty directory so the LUKS volume can mount to it.
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	luks.ChownToCallingUser(dataDir)

	// Unlock at the real mount point so the volume is immediately usable.
	defaultVol, err := luks.NewVolume()
	if err != nil {
		return err
	}
	return defaultVol.Unlock(passphrase)
}

// WipeVolume securely wipes the encrypted volume using the named standard.
// Supported standards: "nist", "dod3", "dod7".
func (s *StorageService) WipeVolume(standard string) error {
	if geteuid() == 0 {
		std, ok := wipeStandards[standard]
		if !ok {
			return ErrStorageInvalidStandard
		}

		vol, err := luks.NewVolume()
		if err != nil {
			return err
		}

		return luks.Wipe(luks.WipeOptions{
			Path:     vol.LUKSPath,
			Standard: std,
		})
	}

	// Validate the standard before elevating so the user gets an
	// immediate error for invalid input.
	if _, ok := wipeStandards[standard]; !ok {
		return ErrStorageInvalidStandard
	}

	// Build: xkey luks2 wipe --standard <std> --force --path <path> --mount-point <mount>
	args := []string{"luks2", "wipe", "--standard", standard, "--force"}
	args = append(args, luksPathArgs()...)
	return s.runElevatedCmd(args, nil)
}

// luksPathArgs returns CLI args for --path and --mount-point using the
// current user's home directory. This prevents path resolution issues
// when the command is re-invoked via sudo (where $HOME becomes /root).
func luksPathArgs() []string {
	h, err := xhome.Resolve()
	if err != nil {
		return nil
	}
	return []string{"--path", h.LUKSPath(), "--mount-point", h.MountPoint()}
}

// runElevatedCmd executes the xkey CLI with the given arguments and stdin
// via the configured Elevator. Returns ErrStorageRequiresRoot when no
// elevator is available.
func (s *StorageService) runElevatedCmd(args []string, stdinData []byte) error {
	if s.elevator == nil || !s.elevator.IsAvailable() {
		return ErrStorageRequiresRoot
	}

	s.log.Debug("running elevated command", "args", args)
	_, err := s.elevator.Run(args, stdinData)
	if err != nil {
		s.log.Error("elevated command failed", "args", args, "error", err)
	}
	return err
}

// validateVolumeSize checks that the volume size is within acceptable bounds.
func validateVolumeSize(sizeGB int) error {
	if sizeGB < minVolumeSizeGB || sizeGB > maxVolumeSizeGB {
		return ErrStorageInvalidSize
	}
	return nil
}

// validatePassphrase checks that the passphrase meets minimum length requirements.
func validatePassphrase(passphrase string) error {
	if len(passphrase) < minPassphraseLength {
		return ErrStorageWeakPassphrase
	}
	return nil
}
