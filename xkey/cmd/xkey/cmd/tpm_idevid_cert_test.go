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

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildCSRSubjectFromOpenSSLDefaults_ValidConfig verifies that a
// well-formed OpenSSL config found via OPENSSL_CONF populates the CSR
// subject from its [req_distinguished_name] defaults with no error.
func TestBuildCSRSubjectFromOpenSSLDefaults_ValidConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "openssl.cnf")
	content := "[req_distinguished_name]\n" +
		"countryName_default = US\n" +
		"stateOrProvinceName_default = California\n" +
		"localityName_default = San Francisco\n" +
		"0.organizationName_default = Example Corp\n" +
		"organizationalUnitName_default = Engineering\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0600))
	t.Setenv("OPENSSL_CONF", cfgPath)

	subject, err := buildCSRSubjectFromOpenSSLDefaults()
	require.NoError(t, err)
	require.NotNil(t, subject)
	assert.Equal(t, "US", subject.Country)
	assert.Equal(t, "California", subject.Province)
	assert.Equal(t, "San Francisco", subject.Locality)
	assert.Equal(t, "Example Corp", subject.Organization)
	assert.Equal(t, "Engineering", subject.OrganizationalUnit)
}

// TestBuildCSRSubjectFromOpenSSLDefaults_UnparseableConfig verifies that a
// config file which exists but cannot be parsed (OPENSSL_CONF pointing at
// a directory forces a read failure) is reported as an error, rather than
// silently tolerated the same way as "no config file found".
func TestBuildCSRSubjectFromOpenSSLDefaults_UnparseableConfig(t *testing.T) {
	t.Setenv("OPENSSL_CONF", t.TempDir())

	subject, err := buildCSRSubjectFromOpenSSLDefaults()
	assert.Error(t, err)
	assert.Nil(t, subject)
}
