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

package main

import (
	"flag"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// serverFlags holds the command-line overrides of the server section. A flag
// is the top of the precedence order (flags > env > file > defaults), so it
// is applied only when the operator actually set it: the flag's own default
// is never written into the configuration, which is what lets a flag set to
// its zero value ("--host ”", every interface) still win over the file.
type serverFlags struct {
	host *string
}

// registerServerFlags declares the server flags on fs and returns the handles
// apply reads back.
func registerServerFlags(fs *flag.FlagSet) *serverFlags {
	return &serverFlags{
		host: fs.String("host", config.DefaultServerHost,
			"Bind host for every network listener (server.host / XKMS_SERVER_HOST); empty binds all interfaces"),
	}
}

// apply writes the flags the operator set on fs into cfg.
func (f *serverFlags) apply(cfg *config.Config, fs *flag.FlagSet) {
	if flagWasSet(fs, "host") {
		cfg.Server.Host = *f.host
	}
}

// flagWasSet reports whether the named flag appeared on the command line,
// the standard-library equivalent of pflag's Changed().
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
