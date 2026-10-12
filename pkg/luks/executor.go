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

package luks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/loop"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// defaultFilesystem is the filesystem LibExecutor formats new volumes with
// when Filesystem is empty.
const defaultFilesystem = filesystem.Ext4

// filesystemLabel is the label every volume's filesystem is created with.
const filesystemLabel = "xkms"

// loopDevice is the part of a go-luks2 loop.Device LibExecutor uses: its
// node path and an identity-checked detach.
type loopDevice interface {
	Path() string
	Detach(ctx context.Context) (loop.DetachState, error)
}

// The following are go-luks2's kernel-facing primitives. Each is a package
// variable so tests can stand in for the kernel instead of requiring a real
// loop device, dm-crypt mapping or mount. Every LUKS implementation in
// go-xkms drives the kernel through these, and only these — see
// docs/luks/architecture.md.
var (
	setupLoopDevice  = attachLoop
	findLoopDeviceFn = findLoop
	formatLUKS       = formatVolume
	unlockLUKS       = activateVolume
	lockLUKS         = dmcrypt.Deactivate
	lookupMapping    = dmcrypt.Lookup
	makeFilesystem   = filesystem.Make
	mountLUKS        = filesystem.Mount
	unmountLUKS      = filesystem.Unmount
	isMountedFn      = filesystem.IsMounted
	chmodFn          = os.Chmod
)

// attachLoop attaches a loop device to file.
func attachLoop(ctx context.Context, file string) (loopDevice, error) {
	dev, err := loop.Attach(ctx, file)
	if err != nil {
		return nil, err
	}
	return dev, nil
}

// findLoop finds the loop device backing file.
func findLoop(ctx context.Context, file string) (loopDevice, error) {
	dev, err := loop.Find(ctx, file)
	if err != nil {
		return nil, err
	}
	return dev, nil
}

// formatVolume writes a new LUKS2 header to device, protected by pass.
func formatVolume(ctx context.Context, device string, pass *enclave.MemoryEnclave, params luks2.FormatParams) error {
	volume, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	return errors.Join(volume.Format(ctx, pass, params), volume.Close())
}

// activateVolume unlocks the LUKS2 container on device with pass and maps
// it under name. The volume key never leaves go-luks2: it is destroyed as
// soon as the mapping exists, and a mapping whose volume could not be
// released is torn down again rather than reported half-done.
func activateVolume(ctx context.Context, device string, pass *enclave.MemoryEnclave, name string) (*dmcrypt.Mapping, error) {
	volume, err := luks2.Open(ctx, device)
	if err != nil {
		return nil, err
	}
	key, err := volume.Unlock(ctx, pass)
	if err != nil {
		return nil, errors.Join(err, volume.Close())
	}
	mapping, err := dmcrypt.Activate(ctx, volume, key, name)
	key.Destroy()
	if err != nil {
		return nil, errors.Join(err, volume.Close())
	}
	if err := volume.Close(); err != nil {
		return nil, errors.Join(err, dmcrypt.Deactivate(ctx, name))
	}
	return mapping, nil
}

// detachLoop detaches dev. A detach the kernel deferred because something
// still holds the device is a success: it completes when the holder goes.
func detachLoop(ctx context.Context, dev loopDevice) error {
	_, err := dev.Detach(ctx)
	return err
}

// protectPassphrase moves passphrase into locked memory for go-luks2, which
// takes credentials only as enclaves.
func protectPassphrase(passphrase string) (*enclave.MemoryEnclave, error) {
	pass, err := enclave.NewMemoryEnclave([]byte(passphrase))
	if err != nil {
		return nil, &ExecutorError{Operation: "protect_passphrase", Err: err}
	}
	return pass, nil
}

// IsLUKSVolume reports whether the file at path begins with the LUKS2 magic
// bytes ("LUKS" followed by 0xba 0xbe). A file that cannot be opened or is
// shorter than the magic reports false rather than an error: this is a
// best-effort classification, not a header parse.
func IsLUKSVolume(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- caller-supplied container path
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, 6)
	n, err := f.Read(magic)
	if err != nil || n < 6 {
		return false
	}
	want := []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}
	for i := range want {
		if magic[i] != want[i] {
			return false
		}
	}
	return true
}

// IsMounted reports whether mountPoint is currently a mount point. It
// returns an error when the mount state could not be determined; callers
// must not treat that as "not mounted".
func IsMounted(mountPoint string) (bool, error) {
	return isMountedFn(context.Background(), mountPoint)
}

// IsUnlocked reports whether a LUKS device-mapper mapping named mapperName
// currently exists.
func IsUnlocked(mapperName string) bool {
	return mappingExists(context.Background(), mapperName)
}

// mappingExists reports whether device-mapper has a live target named name.
// A lookup that fails for any reason reports false: callers ask in order to
// decide whether to unlock, and an unreadable mapping is not one to use.
func mappingExists(ctx context.Context, name string) bool {
	_, err := lookupMapping(ctx, name)
	return err == nil
}

// LibExecutor is the canonical production Executor, implemented on
// go-luks2. It is the single implementation of LUKS volume lifecycle
// management in go-xkms (go-xkms#917); xkmsd and xkey both reach it through
// this package (xkey via sdk/go/luks).
//
// dm-crypt maps a block device, so a file-backed volume has none until one
// is attached: LibExecutor attaches a loop device to the container file in
// Create and Unlock, and detaches it in Lock. The loop device is not tracked
// in memory between calls — Lock resolves it fresh with go-luks2's loop.Find
// — so a LibExecutor is safe to use from a freshly constructed Manager on
// every call, matching a CLI's one-call-per-process lifecycle as well as a
// daemon's long-lived one.
type LibExecutor struct {
	// Filesystem is the filesystem newly formatted volumes are created
	// with. Empty selects ext4.
	Filesystem string
}

// Ensure LibExecutor implements Executor.
var _ Executor = (*LibExecutor)(nil)

// NewLibExecutor constructs the production Executor with its default
// filesystem (ext4).
func NewLibExecutor() *LibExecutor {
	return &LibExecutor{}
}

func (e *LibExecutor) fsType() filesystem.Type {
	if e.Filesystem == "" {
		return defaultFilesystem
	}
	return filesystem.Type(e.Filesystem)
}

// formatParams translates the volume's KDF settings into go-luks2's. The
// iteration time applies to PBKDF2 only; go-luks2 ignores it for Argon2.
func formatParams(config *VolumeConfig) luks2.FormatParams {
	return luks2.FormatParams{
		KDF: luks2.KDFParams{
			Type:     luks2.KDFType(config.KDF),
			IterTime: time.Duration(config.PBKDFIterTime) * time.Millisecond,
		},
	}
}

// Create formats a new LUKS2 container at config.LUKSPath, unlocks it long
// enough to create a filesystem, then locks and detaches it. The container
// is left locked: callers that want it ready for use call Unlock afterward.
func (e *LibExecutor) Create(ctx context.Context, config *VolumeConfig, sizeBytes int64, passphrase string) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Stat(config.LUKSPath); err == nil {
		return ErrVolumeAlreadyExists
	}

	// The unlock below needs the kernel keyring; refuse before a container
	// file exists rather than after a format that cannot be opened.
	if err := ensureKeyringAvailable(ctx); err != nil {
		return err
	}

	pass, err := protectPassphrase(passphrase)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, destroyPassphrase(pass)) }()

	dir := filepath.Dir(config.LUKSPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &ExecutorError{Operation: "create_dir", Path: dir, Err: err}
	}

	// O_EXCL makes the existence check atomic with creation, closing the
	// race window between the Stat above and this call.
	f, err := os.OpenFile(config.LUKSPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- caller-supplied container path
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrVolumeAlreadyExists
		}
		return &ExecutorError{Operation: "create_file", Path: config.LUKSPath, Err: err}
	}
	if err := f.Truncate(sizeBytes); err != nil {
		cleanup := errors.Join(f.Close(), os.Remove(config.LUKSPath))
		return &ExecutorError{Operation: "truncate", Path: config.LUKSPath, Err: errors.Join(err, cleanup)}
	}
	if err := f.Close(); err != nil {
		return &ExecutorError{Operation: "close_file", Path: config.LUKSPath, Err: errors.Join(err, os.Remove(config.LUKSPath))}
	}

	loopDev, err := setupLoopDevice(ctx, config.LUKSPath)
	if err != nil {
		return &ExecutorError{Operation: "setup_loop", Path: config.LUKSPath, Err: errors.Join(err, os.Remove(config.LUKSPath))}
	}
	device := loopDev.Path()

	// Cleanup runs even when ctx is what failed the step it undoes.
	cleanupCtx := context.WithoutCancel(ctx)

	if err := formatLUKS(ctx, device, pass, formatParams(config)); err != nil {
		cleanup := errors.Join(detachLoop(cleanupCtx, loopDev), os.Remove(config.LUKSPath))
		return &ExecutorError{Operation: "luks_format", Path: device, Err: errors.Join(err, cleanup)}
	}

	mapping, err := unlockLUKS(ctx, device, pass, config.MapperName)
	if err != nil {
		cleanup := errors.Join(detachLoop(cleanupCtx, loopDev), os.Remove(config.LUKSPath))
		return &ExecutorError{Operation: "luks_unlock", Path: device, Err: errors.Join(err, cleanup)}
	}

	if err := makeFilesystem(ctx, mapping.Path(), e.fsType(), filesystem.MakeParams{Label: filesystemLabel}); err != nil {
		cleanup := errors.Join(lockLUKS(cleanupCtx, config.MapperName), detachLoop(cleanupCtx, loopDev), os.Remove(config.LUKSPath))
		return &ExecutorError{Operation: "create_fs", Path: mapping.Path(), Err: errors.Join(err, cleanup)}
	}

	if err := lockLUKS(ctx, config.MapperName); err != nil {
		return &ExecutorError{Operation: "luks_lock", Path: config.MapperName, Err: errors.Join(err, detachLoop(cleanupCtx, loopDev))}
	}

	if err := detachLoop(ctx, loopDev); err != nil {
		return &ExecutorError{Operation: "detach_loop", Path: device, Err: err}
	}

	return nil
}

// destroyPassphrase wipes and releases a passphrase enclave.
func destroyPassphrase(pass *enclave.MemoryEnclave) error {
	if err := pass.Destroy(); err != nil {
		return &ExecutorError{Operation: "destroy_passphrase", Err: err}
	}
	return nil
}

// Unlock attaches a loop device to config.LUKSPath and opens the LUKS
// container, mapping it to config.MapperName.
func (e *LibExecutor) Unlock(ctx context.Context, config *VolumeConfig, passphrase string) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Stat(config.LUKSPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrVolumeNotFound
		}
		return &ExecutorError{Operation: "stat", Path: config.LUKSPath, Err: err}
	}

	// Refuse before a loop device is attached: an unlock that cannot place
	// the volume key in the kernel keyring must not leave one behind.
	if err := ensureKeyringAvailable(ctx); err != nil {
		return err
	}

	pass, err := protectPassphrase(passphrase)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, destroyPassphrase(pass)) }()

	loopDev, err := setupLoopDevice(ctx, config.LUKSPath)
	if err != nil {
		return &ExecutorError{Operation: "setup_loop", Path: config.LUKSPath, Err: err}
	}

	if _, err := unlockLUKS(ctx, loopDev.Path(), pass, config.MapperName); err != nil {
		cleanup := detachLoop(context.WithoutCancel(ctx), loopDev)
		return &ExecutorError{Operation: "luks_unlock", Path: loopDev.Path(), Err: errors.Join(err, cleanup)}
	}

	return nil
}

// Lock closes the LUKS device-mapper mapping and detaches its loop device.
// The loop device is resolved fresh via go-luks2's loop.Find rather than
// cached, so Lock works correctly even when called from a different
// LibExecutor instance (or process) than the one that ran Unlock. A
// container with no loop device attached has nothing to detach.
func (e *LibExecutor) Lock(ctx context.Context, config *VolumeConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := lockLUKS(ctx, config.MapperName); err != nil {
		return &ExecutorError{Operation: "luks_lock", Path: config.MapperName, Err: err}
	}

	loopDev, err := findLoopDeviceFn(ctx, config.LUKSPath)
	if errors.Is(err, loop.ErrNotFound) {
		return nil
	}
	if err != nil {
		return &ExecutorError{Operation: "find_loop", Path: config.LUKSPath, Err: err}
	}
	if err := detachLoop(ctx, loopDev); err != nil {
		return &ExecutorError{Operation: "detach_loop", Path: loopDev.Path(), Err: err}
	}

	return nil
}

// Mount creates the mount point directory if needed and mounts the unlocked
// device-mapper mapping at config.MountPoint.
func (e *LibExecutor) Mount(ctx context.Context, config *VolumeConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(config.MountPoint, 0700); err != nil {
		return &ExecutorError{Operation: "create_mountpoint", Path: config.MountPoint, Err: err}
	}

	mapping, err := lookupMapping(ctx, config.MapperName)
	if err != nil {
		return &ExecutorError{Operation: "lookup_mapping", Path: config.MapperName, Err: err}
	}

	params := filesystem.MountParams{
		Source: mapping.Path(),
		Target: config.MountPoint,
		Type:   e.fsType(),
	}
	if err := mountLUKS(ctx, params); err != nil {
		return &ExecutorError{Operation: "mount", Path: config.MountPoint, Err: err}
	}

	// go-luks2 creates the filesystem with mkfs's default root permissions
	// (0755 for ext4), and mounting it replaces whatever mode MkdirAll gave
	// the mount point directory. Re-assert 0700 here so the unlocked volume
	// is never left world-listable.
	if err := chmodFn(config.MountPoint, 0700); err != nil {
		cleanup := unmountLUKS(context.WithoutCancel(ctx), config.MountPoint, 0)
		return &ExecutorError{Operation: "chmod_mountpoint", Path: config.MountPoint, Err: errors.Join(err, cleanup)}
	}

	return nil
}

// Unmount unmounts config.MountPoint.
func (e *LibExecutor) Unmount(ctx context.Context, config *VolumeConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unmountLUKS(ctx, config.MountPoint, 0); err != nil {
		return &ExecutorError{Operation: "unmount", Path: config.MountPoint, Err: err}
	}
	return nil
}

// IsMounted reports whether config.MountPoint is currently mounted. A mount
// state that cannot be determined reports false rather than propagating an
// error: the Executor interface's IsMounted has no error return, matching
// Manager's atomic state tracking, which is itself a best-effort cache over
// the kernel's ground truth.
func (e *LibExecutor) IsMounted(config *VolumeConfig) bool {
	mounted, err := isMountedFn(context.Background(), config.MountPoint)
	if err != nil {
		return false
	}
	return mounted
}

// IsUnlocked reports whether config.MapperName currently has a device-mapper
// mapping.
func (e *LibExecutor) IsUnlocked(config *VolumeConfig) bool {
	return mappingExists(context.Background(), config.MapperName)
}
