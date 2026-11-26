package fido2hidraw

import (
	"strings"
	"testing"
)

// ueventMatchesUniq reports whether a sysfs uevent file carries HID_UNIQ=uniq,
// ignoring the case of the value.
func ueventMatchesUniq(uevent, uniq string) bool {
	if uniq == "" {
		return false
	}
	for _, line := range strings.Split(uevent, "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "HID_UNIQ=")
		if ok && strings.EqualFold(value, uniq) {
			return true
		}
	}
	return false
}

func TestUeventMatchesUniq(t *testing.T) {
	uevent := "DRIVER=hid-generic\nHID_ID=0003:00001209:0000BEEF\nHID_NAME=xkey\nHID_UNIQ=AbC123\nMODALIAS=hid:b0003\n"
	tests := []struct {
		name string
		uniq string
		want bool
	}{
		{"SameCase", "AbC123", true},
		{"OtherCase", "abc123", true},
		{"Other", "abc124", false},
		{"Empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ueventMatchesUniq(uevent, tt.uniq); got != tt.want {
				t.Fatalf("ueventMatchesUniq(%q) = %v, want %v", tt.uniq, got, tt.want)
			}
		})
	}
}
