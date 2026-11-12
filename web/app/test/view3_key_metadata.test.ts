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

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const request = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import KeyMetadataView from "../src/views/KeyMetadataView.svelte";

const PATH = "/api/v1/keys/k1/metadata";

function metadata(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    key_id: "k1",
    name: "payments",
    description: "old text",
    algorithm: "ECDSA-P256",
    status: "enabled",
    usage: ["sign", "verify"],
    version: 3,
    exportable: false,
    deletion_protection: true,
    created_at: 1700000000,
    owner: "team-a",
    tags: { team: "a", old: "x" },
    ...over,
  };
}

function field(label: string): string {
  const dt = screen.getByText(label, { selector: "dt" });
  return dt.nextElementSibling?.textContent?.trim() ?? "";
}

async function load(md: Record<string, unknown> = metadata()): Promise<void> {
  request.mockResolvedValueOnce({ metadata: md, timestamp: 1700000100 });
  render(KeyMetadataView);
  await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "k1" } });
  await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: "software" } });
  await fireEvent.click(screen.getByRole("button", { name: "Load" }));
  await screen.findByText("Version", { selector: "dt" });
}

beforeEach(() => {
  vi.clearAllMocks();
  request.mockReset();
  toasts.length = 0;
});

describe("KeyMetadataView", () => {
  it("loads a key's metadata through GET with the backend query", async () => {
    await load();

    expect(request).toHaveBeenCalledWith("GET", PATH, { query: { backend: "software" } });
    expect(screen.getByText("enabled")).toBeInTheDocument();
    expect(field("Algorithm")).toBe("ECDSA-P256");
    expect(field("Version")).toBe("3");
    expect(field("Exportable")).toBe("no");
    expect(field("Deletion protection")).toBe("yes");
    expect(field("Created")).toBe(new Date(1700000000 * 1000).toISOString());
    expect(field("Owner")).toBe("team-a");
    expect(screen.getByDisplayValue("team")).toBeInTheDocument();
    expect(screen.getByDisplayValue("a")).toBeInTheDocument();
    expect(screen.getByDisplayValue("old")).toBeInTheDocument();
    expect(screen.getByDisplayValue("x")).toBeInTheDocument();
  });

  it("renders No tags and never undefined when optional fields are missing", async () => {
    await load({ key_id: "k1", status: "disabled", version: 1, exportable: true, deletion_protection: false });

    expect(screen.getByText("No tags")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("undefined");
  });

  it("saves only the changes through PUT and renders the returned metadata", async () => {
    await load();
    request.mockResolvedValueOnce({
      metadata: metadata({ description: "payments signing", owner: "team-b", tags: { team: "b", env: "prod" } }),
      timestamp: 1700000200,
    });

    await fireEvent.input(screen.getByLabelText("Description"), { target: { value: "payments signing" } });
    await fireEvent.input(screen.getByDisplayValue("a"), { target: { value: "b" } });
    await fireEvent.click(screen.getByRole("button", { name: "Delete tag old" }));
    await fireEvent.click(screen.getByRole("button", { name: "+ Add tag" }));
    await fireEvent.input(screen.getByLabelText("Tag key 3"), { target: { value: "env" } });
    await fireEvent.input(screen.getByLabelText("Tag value 3"), { target: { value: "prod" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(request).toHaveBeenLastCalledWith("PUT", PATH, {
      body: {
        backend: "software",
        key_id: "k1",
        description: "payments signing",
        tags: { env: "prod", team: "b" },
        remove_tags: ["old"],
      },
    });
    await waitFor(() => expect(field("Owner")).toBe("team-b"));
    expect(toasts).toContainEqual({ kind: "success", message: 'Metadata of key "k1" saved.' });
  });

  it("keeps Save disabled while nothing has changed", async () => {
    await load();

    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("keeps Load disabled until key ID and backend are set", async () => {
    render(KeyMetadataView);
    const btn = screen.getByRole("button", { name: "Load" });
    expect(btn).toBeDisabled();
    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "k1" } });
    expect(btn).toBeDisabled();
    await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: "software" } });
    expect(btn).toBeEnabled();
  });

  it("rejects an empty tag key inline and sends no PUT", async () => {
    await load();

    await fireEvent.click(screen.getByRole("button", { name: "+ Add tag" }));
    await fireEvent.input(screen.getByLabelText("Tag value 3"), { target: { value: "x2" } });

    expect(screen.getByText("Tag keys must not be empty.")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("rejects a duplicate tag key inline and sends no PUT", async () => {
    await load();

    await fireEvent.click(screen.getByRole("button", { name: "+ Add tag" }));
    await fireEvent.input(screen.getByLabelText("Tag key 3"), { target: { value: "team" } });

    expect(screen.getByText("Duplicate tag key: team")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("shows a rejected GET in an error alert", async () => {
    request.mockRejectedValueOnce(new Error("key not found"));
    render(KeyMetadataView);
    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "k1" } });
    await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: "software" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    expect(await screen.findByText("key not found")).toBeInTheDocument();
  });

  it("shows a rejected PUT in an error alert", async () => {
    await load();
    request.mockRejectedValueOnce(new Error("permission denied"));

    await fireEvent.input(screen.getByLabelText("Name"), { target: { value: "renamed" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
  });
});
