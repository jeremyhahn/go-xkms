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

import "github.com/godbus/dbus/v5"

// sessionObject implements org.freedesktop.Secret.Session, whose only
// member is Close. The session's cryptographic state lives in daemon.sessions
// (SessionInfo), keyed by this same object path; this type is just the
// exported D-Bus handle onto it.
type sessionObject struct {
	daemon *Daemon
	path   dbus.ObjectPath
}

// exportSession exports the session object at path. Called from OpenSession
// once the SessionInfo has been recorded.
func (d *Daemon) exportSession(path dbus.ObjectPath) error {
	if d.conn == nil {
		return nil
	}
	obj := &sessionObject{daemon: d, path: path}
	if err := d.conn.Export(obj, path, SessionInterface); err != nil {
		return &WrappedError{Msg: "failed to export Session", Err: err}
	}
	return nil
}

// unexportSession removes the session object from the bus.
func (d *Daemon) unexportSession(path dbus.ObjectPath) {
	if d.conn == nil {
		return
	}
	if err := d.conn.Export(nil, path, SessionInterface); err != nil {
		d.logger.Warn("failed to unexport Session interface", "path", string(path), "error", err.Error())
	}
}

// Close closes the session, matching org.freedesktop.Secret.Session.Close.
// This is the spec-correct call site: earlier revisions of this daemon only
// reached the equivalent logic through a non-spec Service.CloseSession
// method, which real Secret Service clients never call.
func (s *sessionObject) Close() *dbus.Error {
	err := s.daemon.CloseSession(s.path)
	if err != nil {
		return err
	}
	s.daemon.unexportSession(s.path)
	return nil
}
