#!/bin/bash
# build-dummy-hcd.sh — Build and load the dummy_hcd kernel module.
#
# Ubuntu kernels ship with CONFIG_USB_DUMMY_HCD=n, so the module isn't
# available in any package. This script downloads the source from the
# kernel git tree, compiles it against installed headers, and loads it.
#
# Prerequisites:
#   sudo apt install linux-headers-$(uname -r) build-essential curl
#
# Usage:
#   sudo ./build-dummy-hcd.sh         # build + load
#   sudo ./build-dummy-hcd.sh build   # build only
#   sudo ./build-dummy-hcd.sh load    # load previously built module

set -euo pipefail

KVER=$(uname -r)
KVER_SHORT=${KVER%%-*}  # e.g., 6.17.0
KVER_MAJOR=${KVER_SHORT%.*}  # e.g., 6.17
BUILD_DIR="/tmp/dummy-hcd-build"
MODULE_PATH="$BUILD_DIR/dummy_hcd.ko"
KERNEL_GIT_BASE="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain"

check_prerequisites() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: must run as root (sudo)" >&2
        exit 1
    fi

    if [[ ! -d "/usr/src/linux-headers-$KVER" ]]; then
        echo "Error: kernel headers not found. Install with:" >&2
        echo "  sudo apt install linux-headers-$KVER" >&2
        exit 1
    fi

    for cmd in make gcc curl; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "Error: $cmd not found. Install with:" >&2
            echo "  sudo apt install build-essential curl" >&2
            exit 1
        fi
    done
}

download_source() {
    echo "Downloading dummy_hcd.c for kernel v$KVER_SHORT..."
    mkdir -p "$BUILD_DIR"

    # Try tags in order: v6.17.0, v6.17, linux-6.17.y, master
    local url="$KERNEL_GIT_BASE/drivers/usb/gadget/udc/dummy_hcd.c?h=v$KVER_SHORT"
    if ! curl -fsSL "$url" -o "$BUILD_DIR/dummy_hcd.c" 2>/dev/null; then
        url="$KERNEL_GIT_BASE/drivers/usb/gadget/udc/dummy_hcd.c?h=v$KVER_MAJOR"
        echo "Exact tag not found, trying v$KVER_MAJOR..."
        if ! curl -fsSL "$url" -o "$BUILD_DIR/dummy_hcd.c" 2>/dev/null; then
            url="$KERNEL_GIT_BASE/drivers/usb/gadget/udc/dummy_hcd.c?h=linux-$KVER_MAJOR.y"
            echo "Not found, trying stable branch linux-$KVER_MAJOR.y..."
            if ! curl -fsSL "$url" -o "$BUILD_DIR/dummy_hcd.c" 2>/dev/null; then
                url="$KERNEL_GIT_BASE/drivers/usb/gadget/udc/dummy_hcd.c?h=master"
                echo "Stable branch not found, trying master..."
                curl -fsSL "$url" -o "$BUILD_DIR/dummy_hcd.c"
            fi
        fi
    fi

    echo "Source downloaded to $BUILD_DIR/dummy_hcd.c"
}

build_module() {
    echo "Building dummy_hcd.ko for kernel $KVER..."

    cat > "$BUILD_DIR/Makefile" << 'MAKEFILE'
obj-m += dummy_hcd.o
MAKEFILE

    # Detect which compiler the kernel was built with and use it.
    local kernel_cc=""
    if [[ -f "/lib/modules/$KVER/build/include/generated/compiler.h" ]]; then
        kernel_cc=$(grep -oP 'GCC_VERSION "\K[^"]+' "/lib/modules/$KVER/build/include/generated/compiler.h" 2>/dev/null | head -1)
    fi
    if [[ -z "$kernel_cc" ]] && [[ -f "/lib/modules/$KVER/build/include/config/cc/version/text.h" ]]; then
        kernel_cc=$(grep -oP '#define.*"\K[^"]+' "/lib/modules/$KVER/build/include/config/cc/version/text.h" 2>/dev/null | head -1)
    fi

    # Extract major version and try to find matching gcc (e.g., gcc-13).
    local cc_cmd="gcc"
    if [[ -n "$kernel_cc" ]]; then
        local major_ver="${kernel_cc%%.*}"
        if command -v "gcc-$major_ver" &>/dev/null; then
            cc_cmd="gcc-$major_ver"
            echo "Using $cc_cmd to match kernel compiler (gcc $kernel_cc)"
        else
            echo "Warning: kernel was built with gcc $kernel_cc but gcc-$major_ver not found, using default gcc"
        fi
    fi

    make CC="$cc_cmd" -C "/lib/modules/$KVER/build" M="$BUILD_DIR" modules

    if [[ ! -f "$MODULE_PATH" ]]; then
        echo "Error: build failed, $MODULE_PATH not found" >&2
        exit 1
    fi

    echo "Module built: $MODULE_PATH"
}

load_module() {
    if lsmod | grep -q dummy_hcd; then
        echo "dummy_hcd already loaded"
        return
    fi

    if [[ ! -f "$MODULE_PATH" ]]; then
        echo "Error: $MODULE_PATH not found. Run './build-dummy-hcd.sh build' first." >&2
        exit 1
    fi

    echo "Loading dummy_hcd..."
    insmod "$MODULE_PATH" num=1

    # Verify
    if lsmod | grep -q dummy_hcd; then
        echo "dummy_hcd loaded successfully"
        ls /sys/class/udc/
    else
        echo "Error: dummy_hcd failed to load" >&2
        exit 1
    fi
}

ensure_configfs() {
    if [[ ! -d /sys/kernel/config/usb_gadget ]]; then
        echo "Mounting configfs..."
        modprobe configfs 2>/dev/null || true
        mount -t configfs none /sys/kernel/config 2>/dev/null || true
    fi

    if [[ ! -d /sys/kernel/config/usb_gadget ]]; then
        echo "Error: ConfigFS USB gadget directory not available" >&2
        exit 1
    fi
    echo "ConfigFS ready at /sys/kernel/config/usb_gadget"
}

case "${1:-all}" in
    build)
        check_prerequisites
        download_source
        build_module
        ;;
    load)
        check_prerequisites
        ensure_configfs
        load_module
        ;;
    all)
        check_prerequisites
        download_source
        build_module
        ensure_configfs
        load_module
        ;;
    *)
        echo "Usage: $0 [build|load|all]" >&2
        exit 1
        ;;
esac
