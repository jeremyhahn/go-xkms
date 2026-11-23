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

package bootstrap

import (
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
	"gopkg.in/yaml.v3"
)

// zoneRecordsHostname is the name the DANE bootstrap test looks TLSA up for
// (BOOTSTRAP_HOSTNAME in docker-compose.yml) and the leaf's first SAN.
const zoneRecordsHostname = "bootstrap.test"

// TestZoneRecords_VerifyServedChainAndBundle runs the harness's own
// generate-test-certs.sh and generate-zone.sh outside Docker and checks the
// TLSA records CoreDNS would serve against what xkmsd would serve: the TLS
// chain from tls.cert_file (truststrap's transport check, dane.VerifyPeerChain)
// and the /v1/ca/bootstrap bundle (truststrap's bundle check,
// dane.VerifyTLSABundle). xkmsd serves that bundle from tls.ca_file when it is
// set and from its own CA instance otherwise (pkg/server/server.go, the CA
// bundler); the CA instance's key is generated at start and no TLSA record
// can cover it, so TestDANE_Success needs the bundle to come from ca_file.
func TestZoneRecords_VerifyServedChainAndBundle(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	configFile := filepath.Join(dir, "xkmsd.yaml")
	zoneFile := filepath.Join(dir, "bootstrap.test.zone")

	runZoneScript(t, "scripts/generate-test-certs.sh",
		"CERT_DIR="+certDir,
		"CONFIG_FILE="+configFile,
		"TEST_DATA_DIR="+filepath.Join(dir, "data"),
	)
	runZoneScript(t, "setup/generate-zone.sh",
		"TLSA_CERT_FILE="+filepath.Join(certDir, "ca.crt"),
		"TLSA_ZONE_FILE="+zoneFile,
	)

	records := readZoneTLSA(t, zoneFile)
	if len(records) != 4 {
		t.Fatalf("zone has %d TLSA records, want 4 (2 0 1, 2 1 1, 2 0 2, 2 1 2)", len(records))
	}

	var cfg struct {
		TLS struct {
			CertFile string `yaml:"cert_file"`
			CAFile   string `yaml:"ca_file"`
		} `yaml:"tls"`
	}
	raw, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse generated config: %v", err)
	}

	chain := readZonePEMCerts(t, cfg.TLS.CertFile)
	if err := dane.VerifyPeerChain(chain, records, zoneRecordsHostname); err != nil {
		t.Fatalf("served chain %s does not verify against the zone's TLSA records: %v", cfg.TLS.CertFile, err)
	}

	if cfg.TLS.CAFile == "" {
		t.Fatal("generated config has no tls.ca_file, so xkmsd serves /v1/ca/bootstrap " +
			"from its own CA instance, whose key no TLSA record in the zone covers")
	}
	bundle := readZonePEMCerts(t, cfg.TLS.CAFile)
	if err := dane.VerifyTLSABundle(bundle, records); err != nil {
		t.Fatalf("bootstrap bundle %s does not verify against the zone's TLSA records: %v", cfg.TLS.CAFile, err)
	}
	for i, r := range records {
		if err := dane.VerifyTLSA(bundle[0], r); err != nil {
			t.Errorf("TLSA record %d (%d %d %d) does not match the bundle's CA: %v",
				i, r.Usage, r.Selector, r.MatchingType, err)
		}
	}
}

func runZoneScript(t *testing.T, script string, env ...string) {
	t.Helper()
	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", script, err, out)
	}
}

// readZoneTLSA parses the "IN TLSA <usage> <selector> <matching> <hex>" lines
// generate-zone.sh writes.
func readZoneTLSA(t *testing.T, path string) []*dane.TLSARecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open zone: %v", err)
	}
	defer f.Close()

	var records []*dane.TLSARecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 7 || fields[1] != "IN" || fields[2] != "TLSA" {
			continue
		}
		var nums [3]uint8
		for i := range nums {
			n, err := strconv.ParseUint(fields[3+i], 10, 8)
			if err != nil {
				t.Fatalf("TLSA field %q: %v", fields[3+i], err)
			}
			nums[i] = uint8(n)
		}
		data, err := hex.DecodeString(fields[6])
		if err != nil || len(data) == 0 {
			t.Fatalf("TLSA data %q: %v", fields[6], err)
		}
		records = append(records, &dane.TLSARecord{
			Usage: nums[0], Selector: nums[1], MatchingType: nums[2], CertData: data,
		})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan zone: %v", err)
	}
	return records
}

func readZonePEMCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate in %s: %v", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		t.Fatalf("no certificates in %s", path)
	}
	return certs
}
