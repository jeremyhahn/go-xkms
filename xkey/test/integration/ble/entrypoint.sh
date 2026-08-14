#!/bin/sh
# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-xkms.
#
# go-xkms is dual-licensed:
#
# 1. GNU Affero General Public License v3.0 (AGPL-3.0)
#    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
#
# 2. Commercial License
#    Contact licensing@automatethethings.com for commercial licensing options.
#
# Brings up virtual Bluetooth hardware and runs the BLE integration tests.
#
# Every step fails loudly with the exact reason. A BLE suite that quietly
# degrades to "no controllers, nothing tested" is worse than a red build.
#
# Two facts drive the shape of this script:
#
#   1. AF_BLUETOOTH sockets are rejected outside the initial network
#      namespace (net/bluetooth/af_bluetooth.c), so the container must run
#      with the host network namespace. The emulated controllers therefore
#      live in the host kernel, exactly as the USB gadget suite's dummy_hcd
#      does.
#   2. Because of (1) there can only ever be one bluetoothd per machine: it
#      binds the ATT and SDP L2CAP sockets on BDADDR_ANY. If the host is
#      already running bluetoothd, this script uses it over the host's D-Bus
#      socket instead of starting a second one that could not register any
#      adapter.

set -e

BLE_TEST_TAGS="${BLE_TEST_TAGS:-integration linux ble codec_json}"
BLE_TEST_TIMEOUT="${BLE_TEST_TIMEOUT:-10m}"
BLE_TEST_PACKAGE="${BLE_TEST_PACKAGE:-./test/integration/ble/...}"

# HOST_BUS is the host's D-Bus system socket, mounted read-only by
# docker-compose. It is absent when the host has no D-Bus.
HOST_BUS=/host/run/dbus/system_bus_socket

log() { echo "=== $*"; }

fail() {
	echo "FATAL: $*" >&2
	exit 1
}

wait_for() {
	# wait_for <seconds> <description> <shell test>
	seconds="$1"
	description="$2"
	shift 2
	i=0
	while [ "$i" -lt "$((seconds * 10))" ]; do
		if eval "$@"; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.1
	done
	fail "timed out after ${seconds}s waiting for ${description}"
}

bluez_owned() {
	dbus-send --system --dest=org.freedesktop.DBus --print-reply \
		/org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner string:org.bluez 2>/dev/null |
		grep -q 'boolean true'
}

adapter_registered() {
	dbus-send --system --dest=org.bluez --print-reply "/org/bluez/$1" \
		org.freedesktop.DBus.Properties.Get string:org.bluez.Adapter1 string:Address 2>/dev/null |
		grep -q string
}

log "Virtual BLE Integration Test Setup"

log "Step 1: Load Bluetooth kernel modules"
# hci_vhci provides /dev/vhci, the kernel side of a virtual HCI controller.
# The container must be privileged with /lib/modules mounted; the modules are
# loaded into the HOST kernel.
modprobe bluetooth 2>/dev/null || fail "cannot load the 'bluetooth' module. Run privileged with -v /lib/modules:/lib/modules:ro."
modprobe hci_vhci 2>/dev/null || fail "cannot load the 'hci_vhci' module. It ships with the mainline kernel as drivers/bluetooth/hci_vhci.ko."
[ -c /dev/vhci ] || fail "/dev/vhci is missing. Mount the host /dev into the container (-v /dev:/dev)."

log "Step 2: Select a D-Bus system bus and a bluetoothd"
BLUEZ_MODE=""
if [ -S "$HOST_BUS" ]; then
	DBUS_SYSTEM_BUS_ADDRESS="unix:path=$HOST_BUS"
	export DBUS_SYSTEM_BUS_ADDRESS
	if bluez_owned; then
		BLUEZ_MODE=host
		log "  using the host's bluetoothd over $HOST_BUS"
		log "  (it owns the ATT/SDP L2CAP sockets in the initial network namespace)"
	else
		unset DBUS_SYSTEM_BUS_ADDRESS
	fi
fi

if [ -z "$BLUEZ_MODE" ]; then
	BLUEZ_MODE=container
	log "  no host bluetoothd found, starting a private D-Bus and bluetoothd"
	mkdir -p /run/dbus
	dbus-daemon --system --fork || fail "dbus-daemon failed to start"
	wait_for 10 "the D-Bus system socket" "[ -S /run/dbus/system_bus_socket ]"
fi

log "Step 3: Attach two emulated LE controllers (btvirt)"
btvirt -l2 >/tmp/btvirt.log 2>&1 &
BTVIRT_PID=$!
wait_for 15 "hci0 and hci1 to appear" "[ -d /sys/class/bluetooth/hci0 ] && [ -d /sys/class/bluetooth/hci1 ]"
kill -0 "$BTVIRT_PID" 2>/dev/null || fail "btvirt exited: $(cat /tmp/btvirt.log)"
log "  controllers: $(ls /sys/class/bluetooth/ | tr '\n' ' ')"

if [ "$BLUEZ_MODE" = "container" ]; then
	log "Step 4: Start bluetoothd"
	BLUETOOTHD=/usr/libexec/bluetooth/bluetoothd
	[ -x "$BLUETOOTHD" ] || BLUETOOTHD=/usr/lib/bluetooth/bluetoothd
	[ -x "$BLUETOOTHD" ] || fail "bluetoothd not found"
	"$BLUETOOTHD" --experimental --nodetach >/tmp/bluetoothd.log 2>&1 &
	BLUETOOTHD_PID=$!
	wait_for 20 "org.bluez to own its D-Bus name" "bluez_owned"
	kill -0 "$BLUETOOTHD_PID" 2>/dev/null || fail "bluetoothd exited: $(cat /tmp/bluetoothd.log)"
else
	log "Step 4: Reusing the host's bluetoothd"
fi

log "Step 5: Wait for both controllers to register with bluetoothd"
for hci in hci0 hci1; do
	i=0
	while [ "$i" -lt 200 ]; do
		if adapter_registered "$hci"; then
			break
		fi
		i=$((i + 1))
		sleep 0.1
	done
	adapter_registered "$hci" || fail "bluetoothd never registered /org/bluez/$hci.
If bluetoothd logged 'l2cap_bind: Address already in use' then a second
bluetoothd is running in the host's network namespace and already owns the
ATT/SDP sockets - there can only be one per machine. Either stop the host's
bluetooth.service, or mount its bus into this container with
  -v /run/dbus:/host/run/dbus:ro
so the harness drives the daemon that is already there.
bluetoothd log: $(cat /tmp/bluetoothd.log 2>/dev/null)"
	dbus-send --system --dest=org.bluez --print-reply "/org/bluez/$hci" \
		org.freedesktop.DBus.Properties.Set string:org.bluez.Adapter1 string:Powered variant:boolean:true >/dev/null 2>&1 || true
done
hciconfig -a || true

log "Prerequisites verified (bluez mode: $BLUEZ_MODE)"
log "Running BLE integration tests"
exec go test -tags "$BLE_TEST_TAGS" -v -count=1 -timeout="$BLE_TEST_TIMEOUT" "$BLE_TEST_PACKAGE"
