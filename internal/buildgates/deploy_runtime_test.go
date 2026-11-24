package buildgates

import (
	"regexp"
	"strings"
	"testing"
)

var (
	readmeCreatesUser = regexp.MustCompile(`\b(systemd-sysusers|useradd|adduser)\b`)
	readmeCopiesConf  = regexp.MustCompile(`\b(cp|install)\b.*\bconfigs/xkmsd\.yaml\s+/etc/xkms/xkmsd\.yaml\b`)
	readmeInstallGrp  = regexp.MustCompile(`\binstall\b.*-g\s+xkms\b.*\s/etc/xkms/xkmsd\.yaml\b`)
	readmeChownGrp    = regexp.MustCompile(`\b(chown\s+(-\S+\s+)*\w*:xkms|chgrp\s+(-\S+\s+)*xkms)\s+/etc/xkms/xkmsd\.yaml\b`)
)

// TestDeployReadmeInstallsConfigReadableByXkms: both service definitions run
// xkmsd as xkms, and config.Load reads the file with os.ReadFile, so a
// root:root 0640 /etc/xkms/xkmsd.yaml fails with permission denied. Every
// line installing it must follow the user creation and give it group xkms.
func TestDeployReadmeInstallsConfigReadableByXkms(t *testing.T) {
	lines := strings.Split(docsPathsRead(t, "deploy/README.md"), "\n")
	userLine := -1
	copies := 0
	for i, line := range lines {
		if userLine < 0 && readmeCreatesUser.MatchString(line) {
			userLine = i
		}
		if !readmeCopiesConf.MatchString(line) {
			continue
		}
		copies++
		if userLine < 0 {
			t.Errorf("deploy/README.md:%d installs /etc/xkms/xkmsd.yaml before the xkms user exists: %s", i+1, line)
			continue
		}
		grouped := readmeInstallGrp.MatchString(line)
		for j := i + 1; !grouped && j < len(lines) && j <= i+3; j++ {
			grouped = readmeChownGrp.MatchString(lines[j])
		}
		if !grouped {
			t.Errorf("deploy/README.md:%d installs /etc/xkms/xkmsd.yaml without group xkms (the service user cannot read it): %s", i+1, line)
		}
	}
	if copies == 0 {
		t.Fatal("deploy/README.md never installs configs/xkmsd.yaml to /etc/xkms/xkmsd.yaml")
	}
}

// TestOpenRCServiceRunsFromStateDirectory: configs/xkmsd.yaml uses relative
// xkms-data/ paths, so both service definitions must start in /var/lib/xkms,
// not in / where xkms cannot write.
func TestOpenRCServiceRunsFromStateDirectory(t *testing.T) {
	script := docsPathsRead(t, "deploy/openrc/xkms")
	if !regexp.MustCompile(`(?m)^directory="/var/lib/xkms"$`).MatchString(script) {
		t.Error(`deploy/openrc/xkms does not set directory="/var/lib/xkms" (start-stop-daemon --chdir)`)
	}
	_, startPre, ok := strings.Cut(script, "start_pre() {")
	if !ok {
		t.Fatal("deploy/openrc/xkms has no start_pre")
	}
	startPre, _, _ = strings.Cut(startPre, "\n}\n")
	if !regexp.MustCompile(`(?m)^\s*checkpath --directory --owner xkms:xkms\b.*\s/var/lib/xkms$`).MatchString(startPre) {
		t.Error("deploy/openrc/xkms start_pre does not create /var/lib/xkms owned by xkms:xkms")
	}
	if !regexp.MustCompile(`(?m)^WorkingDirectory=/var/lib/xkms$`).MatchString(docsPathsRead(t, "configs/xkmsd.service")) {
		t.Error("configs/xkmsd.service does not set WorkingDirectory=/var/lib/xkms")
	}
}
