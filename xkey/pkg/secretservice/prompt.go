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

package secretservice

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// promptObject implements org.freedesktop.Secret.Prompt. The only prompt
// this daemon issues today is PromptTypeUnlock (see Daemon.Unlock); its
// state lives in the matching *PromptInfo in daemon.prompts.
type promptObject struct {
	daemon *Daemon
	path   dbus.ObjectPath
}

// createPrompt registers a new pending prompt for objects and exports it on
// the bus, returning its object path.
func (d *Daemon) createPrompt(promptType PromptType, objects []dbus.ObjectPath) (dbus.ObjectPath, error) {
	id := strconv.FormatUint(d.promptCount.Add(1), 10)
	path := d.mapper.PromptPath(id)

	info := &PromptInfo{
		Path:      path,
		Type:      promptType,
		Objects:   objects,
		CreatedAt: time.Now(),
		done:      make(chan struct{}),
	}

	d.promptsMu.Lock()
	d.prompts[path] = info
	d.promptsMu.Unlock()

	// conn is nil in tests that exercise prompt bookkeeping without a live
	// bus connection (e.g. unit tests that drive Unlock/resolveUnlockPrompt
	// directly). Production callers always have a connection by the time
	// Unlock can be reached, since Start refuses to mark the daemon running
	// without one.
	if d.conn == nil {
		return path, nil
	}

	obj := &promptObject{daemon: d, path: path}
	if err := d.conn.Export(obj, path, PromptInterface); err != nil {
		d.promptsMu.Lock()
		delete(d.prompts, path)
		d.promptsMu.Unlock()
		return "", &WrappedError{Msg: "failed to export Prompt", Err: err}
	}
	return path, nil
}

// completePrompt resolves info, removes it from the pending-prompt table,
// unexports the object, and emits Completed(dismissed, result) exactly
// once. result is nil for a dismissed/failed prompt.
func (d *Daemon) completePrompt(info *PromptInfo, dismissed bool, result []dbus.ObjectPath) {
	d.promptsMu.Lock()
	delete(d.prompts, info.Path)
	d.promptsMu.Unlock()
	close(info.done)

	if d.conn == nil {
		return
	}

	if result == nil {
		result = []dbus.ObjectPath{}
	}
	if err := d.conn.Emit(info.Path, PromptInterface+".Completed", dismissed, dbus.MakeVariant(result)); err != nil {
		d.logger.Warn("failed to emit Prompt Completed signal",
			slog.String("path", string(info.Path)), slog.String("error", err.Error()))
	}
	_ = d.conn.Export(nil, info.Path, PromptInterface)
}

// Prompt drives the prompted operation to completion and emits Completed.
// Per the freedesktop Secret Service API, Prompt itself returns nothing
// meaningful to a well-behaved caller (which waits on the Completed signal
// instead); a non-nil *dbus.Error here is reserved for a fault this daemon
// could not otherwise report, i.e. a failed SeveritySecurity audit write.
func (p *promptObject) Prompt(windowID string) *dbus.Error {
	d := p.daemon

	d.promptsMu.Lock()
	info, ok := d.prompts[p.path]
	d.promptsMu.Unlock()
	if !ok {
		return dbusNoSuchObjectError(ErrPromptNotFound)
	}
	select {
	case <-info.done:
		return dbus.MakeFailedError(ErrPromptAlreadyResolved)
	default:
	}

	switch info.Type {
	case PromptTypeUnlock:
		return d.resolveUnlockPrompt(info)
	default:
		d.completePrompt(info, true, nil)
		return nil
	}
}

// Dismiss cancels a pending prompt without attempting its operation.
func (p *promptObject) Dismiss() *dbus.Error {
	d := p.daemon

	d.promptsMu.Lock()
	info, ok := d.prompts[p.path]
	d.promptsMu.Unlock()
	if !ok {
		return dbusNoSuchObjectError(ErrPromptNotFound)
	}
	select {
	case <-info.done:
		return dbus.MakeFailedError(ErrPromptAlreadyResolved)
	default:
	}

	auditErr := d.logSecretServiceEvent(audit.OpSecretServiceUnlock, false, ErrPromptDismissed, map[string]any{"path": string(info.Path)})
	d.completePrompt(info, true, nil)
	if auditErr != nil {
		return dbus.MakeFailedError(auditErr)
	}
	return nil
}

// resolveUnlockPrompt collects credentials via the daemon's UnlockFunc and
// attempts to unseal the barrier, completing the prompt with the outcome.
//
// Unlike every other method in this package, a successful unseal that then
// fails to audit is unwound: the barrier is re-sealed rather than left open
// on an action nobody could prove happened. This goes beyond the
// "leave prior side effects in place" convention used elsewhere in the
// package (e.g. Lock, where sealing is already the fail-safe direction)
// because Unlock is the operation go-xkms#723 identified as this package's
// critical security surface: an unaudited unlock is exactly the class of
// bug the issue was filed to close.
func (d *Daemon) resolveUnlockPrompt(info *PromptInfo) *dbus.Error {
	fnPtr := d.unlockFn.Load()
	if fnPtr == nil || *fnPtr == nil {
		auditErr := d.logSecretServiceEvent(audit.OpSecretServiceUnlock, false, ErrCollectionLocked,
			map[string]any{"reason": "no_unlock_func"})
		d.completePrompt(info, true, nil)
		if auditErr != nil {
			return dbus.MakeFailedError(auditErr)
		}
		return nil
	}

	creds, err := (*fnPtr)(d.ctx)
	if err != nil {
		auditErr := d.logSecretServiceEvent(audit.OpSecretServiceUnlock, false, err, nil)
		d.completePrompt(info, true, nil)
		if auditErr != nil {
			return dbus.MakeFailedError(auditErr)
		}
		return nil
	}

	unsealErr := d.barrier.Unseal(d.ctx, creds)
	creds.Secret.Destroy()
	if unsealErr != nil {
		auditErr := d.logSecretServiceEvent(audit.OpSecretServiceUnlock, false, unsealErr, nil)
		d.completePrompt(info, true, nil)
		if auditErr != nil {
			return dbus.MakeFailedError(auditErr)
		}
		return nil
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceUnlock, true, nil,
		map[string]any{"object_count": len(info.Objects)}); auditErr != nil {
		_ = d.barrier.Seal()
		d.completePrompt(info, true, nil)
		return dbus.MakeFailedError(auditErr)
	}

	if expErr := d.exportExistingCollections(); expErr != nil {
		d.logger.Warn("failed to export collections after unlock", slog.String("error", expErr.Error()))
	}
	d.completePrompt(info, false, info.Objects)
	return nil
}
