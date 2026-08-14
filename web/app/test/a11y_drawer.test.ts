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

// Regression coverage for the drawerA11y action (Modal.svelte's `module`
// export) applied to KeyDetail and CertificatesView's slide-in detail
// panels. Unlike the dialogs fixed via Modal.svelte, these panels are plain
// positioned <div>s (a daisyUI "drawer"), so they get none of a native
// <dialog>'s behaviour for free — drawerA11y supplies the same Escape,
// focus-trap, and focus-restore contract by hand.

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { KeyInfo } from "@go-xkms/sdk";

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    keys: { sign: vi.fn(), verify: vi.fn(), attest: vi.fn(), exportMaterial: vi.fn(), rotate: vi.fn(), delete: vi.fn() },
    backends: { list: vi.fn() },
  }),
  resetSDKClient: () => {},
}));

import KeyDetail from "../src/components/KeyDetail.svelte";

const ecKey: KeyInfo = {
  key_id: "vault-ec",
  key_type: "ecdsa",
  algorithm: "ecdsa-p256",
  backend: "pkcs11",
};

describe("KeyDetail drawer a11y", () => {
  it("exposes dialog semantics with an accessible name", () => {
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    expect(screen.getByRole("dialog", { name: "vault-ec" })).toBeInTheDocument();
  });

  it("moves focus into the panel when it mounts", async () => {
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    await waitFor(() => expect(document.activeElement?.getAttribute("aria-label")).toBe("Close"));
  });

  it("calls onClose when Escape is pressed inside the panel", async () => {
    const onClose = vi.fn();
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose, onChanged: () => {} } });

    await fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });

    expect(onClose).toHaveBeenCalledOnce();
  });

  it("restores focus to the trigger element when the panel is removed", async () => {
    const trigger = document.createElement("button");
    trigger.textContent = "open";
    document.body.appendChild(trigger);
    trigger.focus();

    const { unmount } = render(KeyDetail, {
      props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} },
    });
    await waitFor(() => expect(document.activeElement).not.toBe(trigger));

    unmount();

    expect(document.activeElement).toBe(trigger);
    trigger.remove();
  });
});
