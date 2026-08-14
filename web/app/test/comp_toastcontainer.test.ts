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

import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import ToastContainer from "../src/components/ToastContainer.svelte";
import { toastStore, showToast, dismissToast } from "../src/stores/toast.svelte.ts";

describe("ToastContainer", () => {
  beforeEach(() => {
    for (const t of [...toastStore.toasts]) dismissToast(t.id);
  });

  it("renders a toast for every entry in the store, styled by kind", async () => {
    render(ToastContainer);
    showToast("success", "Key rotated.", 0);
    showToast("error", "Backend unreachable.", 0);

    await waitFor(() => expect(screen.getByText("Key rotated.")).toBeInTheDocument());
    expect(screen.getByText("Backend unreachable.")).toBeInTheDocument();

    const success = screen.getByText("Key rotated.").closest(".alert");
    const error = screen.getByText("Backend unreachable.").closest(".alert");
    expect(success?.className).toContain("alert-success");
    expect(error?.className).toContain("alert-error");
  });

  it("falls back to the info style for an unrecognized kind", async () => {
    render(ToastContainer);
    // @ts-expect-error deliberately exercising the `?? 'alert-info'` fallback
    showToast("bogus", "weird toast", 0);

    await waitFor(() => expect(screen.getByText("weird toast")).toBeInTheDocument());
    expect(screen.getByText("weird toast").closest(".alert")?.className).toContain("alert-info");
  });

  it("removes a toast from the DOM when its dismiss button is clicked", async () => {
    render(ToastContainer);
    showToast("warning", "Dismiss me", 0);
    await waitFor(() => expect(screen.getByText("Dismiss me")).toBeInTheDocument());

    await fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));

    await waitFor(() => expect(screen.queryByText("Dismiss me")).not.toBeInTheDocument());
  });

  it("renders nothing when the store is empty", () => {
    const { container } = render(ToastContainer);
    expect(container.querySelectorAll(".alert").length).toBe(0);
  });
});
