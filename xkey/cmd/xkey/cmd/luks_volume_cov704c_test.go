package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// errC704cHost is the failure the fake LUKS host injects.
var errC704cHost = errors.New("c704c: injected host failure")

// c704cLUKSHost stands in for dm-crypt, the device mapper and the mount
// table behind every volume the luks2 commands open. The container file
// itself stays a real file, so Exists and the commands' renames behave as
// on a host.
type c704cLUKSHost struct {
	mounted map[string]bool // mount point -> mounted
	open    map[string]bool // mapper name -> open
	// fail maps a call ("unlock xkey.luks") to the error it returns; a
	// "#n" suffix fails only the n-th identical call.
	fail  map[string]error
	calls []string
}

// c704cLUKS routes every volume the commands open through a fresh fake host.
func c704cLUKS(t *testing.T) *c704cLUKSHost {
	t.Helper()
	host := &c704cLUKSHost{mounted: map[string]bool{}, open: map[string]bool{}, fail: map[string]error{}}
	saved := openLUKSVolume
	openLUKSVolume = func(vol *luks.Volume) luksVolume { return c704cVolume{host: host, vol: vol} }
	t.Cleanup(func() { openLUKSVolume = saved })
	return host
}

// c704cVolume is one volume on the fake host.
type c704cVolume struct {
	host *c704cLUKSHost
	vol  *luks.Volume
}

// call records op on this volume and returns the failure injected for it.
func (v c704cVolume) call(op string) error {
	name := op + " " + filepath.Base(v.vol.LUKSPath)
	v.host.calls = append(v.host.calls, name)
	n := 0
	for _, c := range v.host.calls {
		if c == name {
			n++
		}
	}
	if err, ok := v.host.fail[fmt.Sprintf("%s#%d", name, n)]; ok {
		return err
	}
	return v.host.fail[name]
}

func (v c704cVolume) GetMountPoint() string { return v.vol.MountPoint }

func (v c704cVolume) Exists() bool {
	_, err := os.Stat(v.vol.LUKSPath)
	return err == nil
}

func (v c704cVolume) IsMounted() (bool, error) {
	if err := v.host.fail["mounted "+filepath.Base(v.vol.LUKSPath)]; err != nil {
		return false, err
	}
	return v.host.mounted[v.vol.MountPoint], nil
}

func (v c704cVolume) IsOpen() bool { return v.host.open[v.vol.MapperName] }

func (v c704cVolume) Create(_ int64, _ string) error {
	if err := v.call("create"); err != nil {
		return err
	}
	return os.WriteFile(v.vol.LUKSPath, []byte("c704c new container"), 0o600)
}

func (v c704cVolume) Unlock(_ string) error {
	if err := v.call("unlock"); err != nil {
		return err
	}
	v.host.mounted[v.vol.MountPoint] = true
	v.host.open[v.vol.MapperName] = true
	return nil
}

func (v c704cVolume) Lock() error {
	if err := v.call("lock"); err != nil {
		return err
	}
	delete(v.host.mounted, v.vol.MountPoint)
	delete(v.host.open, v.vol.MapperName)
	return nil
}

func (v c704cVolume) CopyDataToVolume(_ string) error { return v.call("copy") }

// c704cRequireOp asserts err is the command's typed error for operation op,
// wrapping the injected host failure.
func c704cRequireOp(t *testing.T, err error, op string) {
	t.Helper()
	require.ErrorIs(t, err, errC704cHost)
	var got string
	var sealErr *SealError
	var unsealErr *UnsealError
	var lockErr *LockError
	var importErr *ImportDataError
	var migrateErr *MigrateError
	switch {
	case errors.As(err, &sealErr):
		got = sealErr.Operation
	case errors.As(err, &unsealErr):
		got = unsealErr.Operation
	case errors.As(err, &lockErr):
		got = lockErr.Operation
	case errors.As(err, &importErr):
		got = importErr.Operation
	case errors.As(err, &migrateErr):
		got = migrateErr.Operation
	default:
		t.Fatalf("not a luks2 command error: %v", err)
	}
	assert.Equal(t, op, got)
}

// c704cSeal prepares `luks2 seal --unseal` for a container under root.
func c704cSeal(t *testing.T) (*c704cLUKSHost, string) {
	t.Helper()
	root := asLUKSRoot(t)
	host := c704cLUKS(t)
	sealPath = filepath.Join(root, "xkey.luks")
	sealMountPoint = filepath.Join(root, "mnt")
	sealSize = "64M"
	sealUnseal = true
	pipeStdin(t, "pw\npw\n")
	return host, sealMountPoint
}

func TestC704cSeal_CreatesAndUnlocks(t *testing.T) {
	host, mount := c704cSeal(t)

	out, err := runLUKSCmd(t, runSeal)
	require.NoError(t, err)
	assert.Equal(t, []string{"create xkey.luks", "unlock xkey.luks"}, host.calls)
	assert.True(t, host.mounted[mount])
	assert.FileExists(t, sealPath)
	assert.Contains(t, out, "Mount point: "+mount)
	assert.Contains(t, out, "Volume is unlocked and mounted.")
}

func TestC704cSeal_WithoutUnsealLeavesItLocked(t *testing.T) {
	host, mount := c704cSeal(t)
	sealUnseal = false

	out, err := runLUKSCmd(t, runSeal)
	require.NoError(t, err)
	assert.Equal(t, []string{"create xkey.luks"}, host.calls)
	assert.False(t, host.mounted[mount])
	assert.Contains(t, out, "Use 'xkey luks2 unseal' to unlock the encrypted storage.")
}

func TestC704cSeal_HostFailures(t *testing.T) {
	tests := []struct {
		fail, op string
	}{
		{fail: "create xkey.luks", op: "create_volume"},
		{fail: "mounted xkey.luks", op: "check_mounted"},
		{fail: "unlock xkey.luks", op: "unseal_after_create"},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			host, _ := c704cSeal(t)
			host.fail[tt.fail] = errC704cHost

			out, err := runLUKSCmd(t, runSeal)
			c704cRequireOp(t, err, tt.op)
			assert.NotContains(t, out, "created successfully")
		})
	}
}

// c704cUnseal prepares `luks2 unseal` for an existing container.
func c704cUnseal(t *testing.T) (*c704cLUKSHost, string) {
	t.Helper()
	root := asLUKSRoot(t)
	host := c704cLUKS(t)
	unsealPath = filepath.Join(root, "xkey.luks")
	unsealMountPoint = filepath.Join(root, "mnt")
	writeContainer(t, unsealPath, 16)
	pipeStdin(t, "pw\n")
	return host, unsealMountPoint
}

func TestC704cUnseal_UnlocksAndMounts(t *testing.T) {
	host, mount := c704cUnseal(t)

	out, err := runLUKSCmd(t, runUnseal)
	require.NoError(t, err)
	assert.Equal(t, []string{"unlock xkey.luks"}, host.calls)
	assert.True(t, host.mounted[mount])
	assert.Contains(t, out, "Encrypted storage unlocked and mounted at "+mount)
}

func TestC704cUnseal_HostFailures(t *testing.T) {
	for fail, op := range map[string]string{
		"mounted xkey.luks": "check_mounted",
		"unlock xkey.luks":  "unlock",
	} {
		t.Run(op, func(t *testing.T) {
			host, mount := c704cUnseal(t)
			host.fail[fail] = errC704cHost

			_, err := runLUKSCmd(t, runUnseal)
			c704cRequireOp(t, err, op)
			assert.False(t, host.mounted[mount])
		})
	}
}

// c704cLock prepares `luks2 lock` for a container mounted at mnt.
func c704cLock(t *testing.T) (*c704cLUKSHost, string) {
	t.Helper()
	root := asLUKSRoot(t)
	host := c704cLUKS(t)
	lockPath = filepath.Join(root, "xkey.luks")
	lockMountPoint = filepath.Join(root, "mnt")
	return host, lockMountPoint
}

func TestC704cLock_LocksAMountedOrOpenVolume(t *testing.T) {
	t.Run("mounted", func(t *testing.T) {
		host, mount := c704cLock(t)
		host.mounted[mount] = true

		out, err := runLUKSCmd(t, runLock)
		require.NoError(t, err)
		assert.Equal(t, []string{"lock xkey.luks"}, host.calls)
		assert.False(t, host.mounted[mount])
		assert.Contains(t, out, "Encrypted storage locked successfully.")
	})
	t.Run("open but unmounted", func(t *testing.T) {
		host, _ := c704cLock(t)
		host.open[luks.MapperName] = true

		_, err := runLUKSCmd(t, runLock)
		require.NoError(t, err)
		assert.False(t, host.open[luks.MapperName])
	})
	t.Run("neither", func(t *testing.T) {
		host, _ := c704cLock(t)

		_, err := runLUKSCmd(t, runLock)
		require.ErrorIs(t, err, ErrLockNoVolume)
		assert.Empty(t, host.calls)
	})
}

func TestC704cLock_HostFailures(t *testing.T) {
	for fail, op := range map[string]string{
		"mounted xkey.luks": "check_mounted",
		"lock xkey.luks":    "lock",
	} {
		t.Run(op, func(t *testing.T) {
			host, mount := c704cLock(t)
			host.mounted[mount] = true
			host.fail[fail] = errC704cHost

			out, err := runLUKSCmd(t, runLock)
			c704cRequireOp(t, err, op)
			assert.NotContains(t, out, "locked successfully")
		})
	}
}

// c704cImport prepares `luks2 import-data` from a source holding one file.
func c704cImport(t *testing.T) (*c704cLUKSHost, string) {
	t.Helper()
	root := asLUKSRoot(t)
	isolateImportDataFlags(t)
	host := c704cLUKS(t)
	importDataPath = filepath.Join(root, "xkey.luks")
	importDataSource = filepath.Join(root, "plain")
	importDataMountPoint = filepath.Join(root, "mnt")
	importDataCleanup, importDataBackup, importDataUnseal = false, false, false
	writeContainer(t, importDataPath, 16)
	require.NoError(t, os.MkdirAll(importDataSource, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(importDataSource, "data.db"), []byte("data"), 0o600))
	pipeStdin(t, "pw\n")
	return host, importDataMountPoint
}

func TestC704cImportData_CopiesIntoTheVolume(t *testing.T) {
	host, mount := c704cImport(t)

	out, err := runLUKSCmd(t, runImportData)
	require.NoError(t, err)
	assert.Equal(t, []string{"unlock xkey.luks", "copy xkey.luks", "lock xkey.luks"}, host.calls)
	assert.False(t, host.mounted[mount])
	assert.Contains(t, out, "Data imported successfully!")
	assert.FileExists(t, filepath.Join(importDataSource, "data.db"), "without --cleanup the source is kept")
}

func TestC704cImportData_UnsealMountsAtTheFinalMountPoint(t *testing.T) {
	host, mount := c704cImport(t)
	importDataUnseal = true

	out, err := runLUKSCmd(t, runImportData)
	require.NoError(t, err)
	assert.Equal(t, []string{"unlock xkey.luks", "copy xkey.luks", "lock xkey.luks", "unlock xkey.luks"}, host.calls)
	assert.True(t, host.mounted[mount])
	assert.Contains(t, out, "Data imported and volume unlocked at "+mount)
}

func TestC704cImportData_HostFailures(t *testing.T) {
	tests := []struct {
		fail, op string
		unseal   bool
	}{
		{fail: "unlock xkey.luks", op: "unlock"},
		{fail: "copy xkey.luks", op: "copy_data"},
		{fail: "unlock xkey.luks#2", op: "final_unlock", unseal: true},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			host, _ := c704cImport(t)
			importDataUnseal = tt.unseal
			host.fail[tt.fail] = errC704cHost

			out, err := runLUKSCmd(t, runImportData)
			c704cRequireOp(t, err, tt.op)
			assert.NotContains(t, out, "Data imported")
		})
	}
}

// c704cMigrate prepares `luks2 migrate` of a 1 KiB source container in
// place, and returns the source's original content.
func c704cMigrate(t *testing.T) (*c704cLUKSHost, []byte) {
	t.Helper()
	root := asLUKSRoot(t)
	host := c704cLUKS(t)
	migrateSourcePath = filepath.Join(root, "xkey.luks")
	migratePath, migrateSize = "", ""
	migrateKeepOld, migrateWipe = false, false
	content := writeContainer(t, migrateSourcePath, 1024)
	pipeStdin(t, "pw\n")
	return host, content
}

// c704cMigrateCalls is the dm-crypt sequence of a successful migration.
var c704cMigrateCalls = []string{
	"create xkey.luks",
	"unlock xkey.luks.old", "unlock xkey.luks",
	"copy xkey.luks",
	"lock xkey.luks.old", "lock xkey.luks",
}

func TestC704cMigrate_ReplacesTheContainer(t *testing.T) {
	host, _ := c704cMigrate(t)

	out, err := runLUKSCmd(t, runMigrate)
	require.NoError(t, err)
	assert.Equal(t, c704cMigrateCalls, host.calls)
	assert.Empty(t, host.mounted, "both containers are locked again")

	created, rerr := os.ReadFile(migrateSourcePath)
	require.NoError(t, rerr)
	assert.Equal(t, "c704c new container", string(created))
	assert.NoFileExists(t, migrateSourcePath+".old")
	assert.Contains(t, out, "Removing old container...")
	assert.Contains(t, out, "Migration complete!")
}

func TestC704cMigrate_KeepOldKeepsTheBackup(t *testing.T) {
	_, content := c704cMigrate(t)
	migrateKeepOld = true

	out, err := runLUKSCmd(t, runMigrate)
	require.NoError(t, err)
	backup, rerr := os.ReadFile(migrateSourcePath + ".old")
	require.NoError(t, rerr)
	assert.Equal(t, content, backup)
	assert.Contains(t, out, "(kept as backup)")
}

func TestC704cMigrate_WipeRemovesTheOldContainer(t *testing.T) {
	_, _ = c704cMigrate(t)
	migrateWipe, migrateWipeStandard = true, "nist"

	out, err := runLUKSCmd(t, runMigrate)
	require.NoError(t, err)
	assert.NoFileExists(t, migrateSourcePath+".old")
	assert.Contains(t, out, "Securely wiping old container (nist:")
	assert.Contains(t, out, "securely wiped (nist) and removed")
}

func TestC704cMigrate_LocksAnOpenSourceFirst(t *testing.T) {
	host, _ := c704cMigrate(t)
	host.open[luks.MapperName] = true
	// A source that refuses to lock is reported and the migration goes on.
	host.fail["lock xkey.luks#1"] = errC704cHost

	out, err := runLUKSCmd(t, runMigrate)
	require.NoError(t, err)
	assert.Equal(t, append([]string{"lock xkey.luks"}, c704cMigrateCalls...), host.calls)
	assert.Contains(t, out, "Locking current container...")
	assert.Contains(t, out, "Warning: could not lock container: "+errC704cHost.Error())
}

func TestC704cMigrate_CheckMountedFailureTouchesNothing(t *testing.T) {
	host, content := c704cMigrate(t)
	host.fail["mounted xkey.luks"] = errC704cHost

	_, err := runLUKSCmd(t, runMigrate)
	c704cRequireOp(t, err, "check_mounted")
	assert.Empty(t, host.calls)
	source, rerr := os.ReadFile(migrateSourcePath)
	require.NoError(t, rerr)
	assert.Equal(t, content, source)
}

// TestC704cMigrate_TransferFailuresRestoreTheSource proves every failure
// after the new container exists puts the original container back.
func TestC704cMigrate_TransferFailuresRestoreTheSource(t *testing.T) {
	tests := []struct {
		fail, op string
		cause    error
		calls    []string
	}{
		{
			fail: "unlock xkey.luks.old", op: "unlock_old", cause: ErrMigrateSourceLocked,
			calls: []string{"create xkey.luks", "unlock xkey.luks.old"},
		},
		{
			fail: "unlock xkey.luks", op: "unlock_new",
			calls: []string{"create xkey.luks", "unlock xkey.luks.old", "unlock xkey.luks", "lock xkey.luks.old"},
		},
		{
			fail: "copy xkey.luks", op: "copy_data", cause: ErrMigrateDataCopyFailed,
			calls: []string{"create xkey.luks", "unlock xkey.luks.old", "unlock xkey.luks", "copy xkey.luks", "lock xkey.luks.old", "lock xkey.luks"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			host, content := c704cMigrate(t)
			host.fail[tt.fail] = errC704cHost

			out, err := runLUKSCmd(t, runMigrate)
			c704cRequireOp(t, err, tt.op)
			if tt.cause != nil {
				require.ErrorIs(t, err, tt.cause)
			}
			assert.Equal(t, tt.calls, host.calls)

			source, rerr := os.ReadFile(migrateSourcePath)
			require.NoError(t, rerr)
			assert.Equal(t, content, source, "the original container is restored")
			assert.NoFileExists(t, migrateSourcePath+".old")
			assert.NotContains(t, out, "Migration complete")
		})
	}
}
