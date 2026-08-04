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

package qrdb

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ServiceOption configures the QRDB service using the functional options pattern.
type ServiceOption func(*serviceConfig)

// serviceConfig holds the resolved options for constructing a Service.
type serviceConfig struct {
	config  *Config
	client  *qrdbsdk.Client
	kvStore qrdbsdk.KVStore
}

// WithConfig sets the QRDB configuration.
func WithConfig(cfg *Config) ServiceOption {
	return func(sc *serviceConfig) {
		sc.config = cfg
	}
}

// WithQRDBClient sets a pre-configured QRDB SDK client. When provided,
// the service uses this client directly instead of creating a new one
// from the configuration.
func WithQRDBClient(client *qrdbsdk.Client) ServiceOption {
	return func(sc *serviceConfig) {
		sc.client = client
	}
}

// WithKVStore sets the KVStore for embedded mode DAO access. This is
// used to provide direct KVStore access for DAO operations without
// going through the SDK transport layer.
func WithKVStore(store qrdbsdk.KVStore) ServiceOption {
	return func(sc *serviceConfig) {
		sc.kvStore = store
	}
}
