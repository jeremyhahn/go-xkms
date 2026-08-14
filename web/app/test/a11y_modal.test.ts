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

// Regression coverage for the Modal.svelte fix: every view dialog used to be
// a `<dialog class="modal modal-open">` with no `open` attribute, which the
// UA stylesheet rule `dialog:not([open]) { display: none }` renders inert —
// no top layer, no focus trap, no Escape-to-close. Modal.svelte now drives
// the element natively (showModal()/close() where available, the `open`
// property as a jsdom fallback) plus its own Escape/focus handling so the
// behaviour holds even where the native dialog methods are unimplemented
// (jsdom, this test's DOM). TenantsView's "Create tenant" dialog is used as
// a real integration target rather than mounting Modal in isolation.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { TenantInfoResponse, CreateTenantRequest } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<{ tenants: TenantInfoResponse[]; pagination: unknown }>>();
const create = vi.fn<(req: CreateTenantRequest) => Promise<{ tenant: TenantInfoResponse }>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ tenants: { list, create } }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: () => {},
}));

import TenantsView from "../src/views/TenantsView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  list.mockResolvedValue({ tenants: [], pagination: {} });
});

describe("Modal a11y (via TenantsView's create dialog)", () => {
  it("is discoverable as a real dialog once opened — no `hidden: true` needed", async () => {
    render(TenantsView);
    await screen.findByText("No tenants.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));

    // The old markup only satisfied `getByRole("dialog")` with `{ hidden:
    // true }`, since jsdom's UA stylesheet hides `dialog:not([open])`. A
    // real `open` attribute means the plain query now finds it.
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("open");
  });

  it("moves focus onto the first field when it opens", async () => {
    render(TenantsView);
    await screen.findByText("No tenants.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));

    await waitFor(() => expect(document.activeElement).toBe(screen.getByPlaceholderText("Tenant ID")));
  });

  it("closes on Escape and returns focus to the trigger button", async () => {
    render(TenantsView);
    await screen.findByText("No tenants.");

    const trigger = screen.getByRole("button", { name: "+ Create" });
    // jsdom's fireEvent.click does not synthesize the browser's implicit
    // focus-on-click behaviour, so focus it explicitly to set up the
    // realistic precondition for focus restoration below.
    trigger.focus();
    await fireEvent.click(trigger);
    const dialog = screen.getByRole("dialog");

    await fireEvent.keyDown(dialog, { key: "Escape" });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(document.activeElement).toBe(trigger));
  });

  it("does not treat other keys as a close request", async () => {
    render(TenantsView);
    await screen.findByText("No tenants.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    const dialog = screen.getByRole("dialog");

    await fireEvent.keyDown(dialog, { key: "Enter" });

    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("traps Tab at the last focusable element, wrapping back to the first", async () => {
    render(TenantsView);
    await screen.findByText("No tenants.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    const dialog = screen.getByRole("dialog");
    const cancelBtn = screen.getByRole("button", { name: "Cancel" });

    cancelBtn.focus();
    // Cancel is not literally the last focusable (Create is), but disabled
    // buttons are excluded from the trap's candidate list and Create starts
    // enabled once a Tenant ID is present; exercise the boundary directly by
    // focusing the last element in the dialog and asserting a forward Tab
    // wraps to the first rather than escaping the dialog.
    const focusables = dialog.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
    );
    const first = focusables[0]!;
    const last = focusables[focusables.length - 1]!;
    last.focus();

    await fireEvent.keyDown(dialog, { key: "Tab" });

    expect(document.activeElement).toBe(first);
  });
});
