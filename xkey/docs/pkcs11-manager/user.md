# PKCS#11 Module/Token Manager — User Guide

> **Status: NORMATIVE** · Feature: `pkcs11-manager` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

## What this does

When you add a PKCS#11 module (a SoftHSM2 software token, a YubiKey's PIV
applet, or any other PKCS#11 HSM) in the xkey GUI's setup wizard or admin
area, every token currently present in that module shows up right away --
its name, manufacturer, model, and serial number -- so you can see what's
actually plugged in before picking which one to use.

## Adding a module

1. Open **Settings → Backends → PKCS#11** (or the setup wizard's hardware
   step).
2. Enter the path to the PKCS#11 library (for SoftHSM2, this is usually
   `/usr/lib/softhsm/libsofthsm2.so`; xkey also auto-detects common install
   locations).
3. Once the module loads, every slot with a token in it appears in the slot
   list with its label, manufacturer, model, and serial number. A slot with
   no token inserted is not shown.
4. Pick a slot and connect (enter the token's PIN, and its management PIN
   for a YubiKey).

## Keeping the list current

If you insert or remove a token while xkey is running, use **Refresh** on
the module's slot list. The token list updates immediately to match what's
physically present -- a newly inserted token appears, one you removed
disappears.

Initializing a fresh token (via **Initialize Token**, which sets its label
and PINs) updates its entry immediately too: the label and serial number
you just set show up in the slot list without needing a separate refresh.

## Removing a module

Removing a module removes all of its tokens from the list at the same time
-- there is no separate step to clean up individual slot entries.
