# USB — User Guide

> **Status: NORMATIVE** · Feature: `usb` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Carrying xKey on a USB drive

If you want xKey — the binaries and all your encrypted keys and data — on
a single USB drive you can plug into different machines:

```bash
sudo xkey usb create /tmp/xkey.img --size 4G
```

This creates an image file with two parts: a small unencrypted partition
with the xkey program itself (for every CPU type you included, via
`--binary`, plus the current one by default) and a launcher script, and a
larger encrypted partition (LUKS2, the same encryption xKey's optional
full-home encryption uses — see `xkey/docs/luks/`) that holds everything
else. You'll be asked to set a passphrase for the encrypted part; write it
down somewhere safe, because there's no way to recover it if you forget.

Write the image to a real USB drive:

```bash
sudo dd if=/tmp/xkey.img of=/dev/sdX bs=4M status=progress
```

Or skip the intermediate file and write directly to the device (the drive's
full size is used, so `--size` doesn't apply):

```bash
sudo xkey usb create /dev/sdb
```

Then, on the drive, run `xkey.sh` — it figures out which binary matches
the machine you're on and starts xKey with its data pointed at the drive
itself.

To update the binaries later (say, after upgrading xKey) without
recreating the whole drive:

```bash
sudo xkey usb update /tmp/xkey.img --binary ./build/xkey-linux-amd64
```

Check what's on a drive or image without mounting it yourself:

```bash
xkey usb status /tmp/xkey.img
```

## Using xKey as a hardware smartcard

If you want an application that expects a real smartcard reader (OpenSC,
GnuPG, a browser's smartcard login, a VM you're passing a reader into) to
see xKey as one, start the virtual CCID device:

```bash
sudo xkey usb device start
```

Leave it running; it appears to the rest of the system as a smartcard
reader with a card already inserted, presenting whichever PIV or OpenPGP
certificates your xkey backend has. Stop it with `Ctrl+C`, or from another
terminal:

```bash
kill -TERM $(pgrep -f "xkey usb device start")
```

Check whether it's running and see basic device info:

```bash
xkey usb device status
```

If you're on hardware that supports acting as a real USB device (for
example, a Raspberry Pi Zero 2W plugged into another computer's USB port
via its OTG connector), you can present a genuine USB smartcard reader
that any OS recognizes without a custom driver:

```bash
sudo xkey usb device start --transport gadget
```

This needs OTG-capable hardware; on an ordinary laptop or desktop, leave
`--transport` at its default (`uhid`).
