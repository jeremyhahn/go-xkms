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

package notify

import (
	"strings"
	"unicode"
)

// maxDisplayFieldLen bounds how much of a caller-controlled TouchRequest
// field (operation, RP ID, RP name, user name) reaches a notification
// command, dialog, or log line. A WebAuthn caller does not need more than
// this to identify itself, and bounding the length keeps a hostile page
// from padding a dialog or flooding a log.
const maxDisplayFieldLen = 256

// SanitizeTouchRequest returns a copy of req with control characters
// stripped from every field and each field truncated to a bounded length.
// It is presentation hygiene for values a caller-controlled web page
// supplies (RPName and UserName in particular), not an injection defense:
// injection is prevented by never handing these values to a shell, in
// CommandNotifier and in the fido2 sudo notifiers, which substitute into
// fixed argv elements only.
func SanitizeTouchRequest(req *TouchRequest) *TouchRequest {
	return &TouchRequest{
		Operation: sanitizeDisplayField(req.Operation),
		RPID:      sanitizeDisplayField(req.RPID),
		RPName:    sanitizeDisplayField(req.RPName),
		UserName:  sanitizeDisplayField(req.UserName),
	}
}

// sanitizeDisplayField strips control characters (as classified by
// unicode.IsControl, which covers newlines, tabs, and other C0/C1 control
// codes) and truncates to maxDisplayFieldLen runes, appending an ellipsis
// when truncated.
func sanitizeDisplayField(s string) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		if count >= maxDisplayFieldLen {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

// TouchRequestEnv returns req's fields as KEY=VALUE environment entries
// (XKEY_OPERATION, XKEY_RP_ID, XKEY_RP_NAME, XKEY_USER_NAME) suitable for
// appending to an exec.Cmd's Env. This is the safe channel for an operator
// script -- including a shell script invoked as "sh -c ..." -- to read
// request data: unlike argv/text substitution into a script string, an
// environment variable's value can never be reparsed as shell syntax by
// the shell that receives it.
func TouchRequestEnv(req *TouchRequest) []string {
	return []string{
		"XKEY_OPERATION=" + req.Operation,
		"XKEY_RP_ID=" + req.RPID,
		"XKEY_RP_NAME=" + req.RPName,
		"XKEY_USER_NAME=" + req.UserName,
	}
}
