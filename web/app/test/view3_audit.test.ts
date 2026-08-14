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
import { render, screen, waitFor, within } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import type { AuditEvent, AuditFilter, AuditPage } from "@go-xkms/sdk";

const query = vi.fn<(filter?: AuditFilter) => Promise<AuditPage>>();

const toasts: { kind: string; message: string }[] = [];

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ audit: { query } }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import AuditView from "../src/views/AuditView.svelte";

function event(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    timestamp: "2026-03-04T05:06:07Z",
    actor: "alice",
    resource: "keys",
    action: "sign",
    outcome: "allow",
    ...over,
  } as AuditEvent;
}

function page(over: Partial<AuditPage> = {}): AuditPage {
  return { events: [event()], total: 1, ...over } as AuditPage;
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  query.mockResolvedValue(page());
});

describe("AuditView listing", () => {
  it("renders the events returned for the initial unfiltered query", async () => {
    query.mockResolvedValue(
      page({
        events: [
          event(),
          event({ actor: "bob", resource: "barrier", action: "unseal", outcome: "deny" }),
        ],
        total: 2,
      }),
    );

    render(AuditView);

    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());
    expect(screen.getByText("bob")).toBeInTheDocument();
    expect(screen.getByText("unseal")).toBeInTheDocument();
    // "allow"/"deny" also appear as options in the Outcome filter, so scope
    // the outcome assertions to the results table.
    const table = document.querySelector("table") as HTMLElement;
    expect(within(table).getByText("allow")).toBeInTheDocument();
    expect(within(table).getByText("deny")).toBeInTheDocument();
  });

  it("sends no filter fields on the initial load", async () => {
    render(AuditView);

    await waitFor(() => expect(query).toHaveBeenCalled());
    // Every unset field must be undefined rather than an empty string: the
    // server treats "" and absent the same, but sending blanks makes the
    // request self-describing garbage and hides real bugs.
    expect(query).toHaveBeenCalledWith({
      actor: undefined,
      resource: undefined,
      action: undefined,
      outcome: undefined,
      from: undefined,
      to: undefined,
      limit: 100,
      cursor: undefined,
    });
  });

  it("shows an empty message when nothing matches", async () => {
    query.mockResolvedValue(page({ events: [], total: 0 }));

    render(AuditView);

    expect(await screen.findByText("No audit events match these filters.")).toBeInTheDocument();
  });

  it("surfaces a query failure instead of an empty table", async () => {
    query.mockRejectedValue(new Error("audit chain unreadable"));

    render(AuditView);

    expect(await screen.findByText("audit chain unreadable")).toBeInTheDocument();
    expect(screen.queryByText("No audit events match these filters.")).toBeNull();
  });
});

describe("AuditView filtering", () => {
  it("passes the entered filters through and resets paging", async () => {
    render(AuditView);
    await waitFor(() => expect(query).toHaveBeenCalledTimes(1));

    await userEvent.type(screen.getByLabelText("Actor"), "alice");
    await userEvent.type(screen.getByLabelText("Resource"), "keys");
    await userEvent.type(screen.getByLabelText("Action"), "sign");
    await userEvent.selectOptions(screen.getByLabelText("Outcome"), "deny");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() => expect(query).toHaveBeenCalledTimes(2));
    expect(query).toHaveBeenLastCalledWith(
      expect.objectContaining({
        actor: "alice",
        resource: "keys",
        action: "sign",
        outcome: "deny",
        cursor: undefined,
      }),
    );
  });

  it("converts the datetime-local bounds to RFC3339", async () => {
    render(AuditView);
    await waitFor(() => expect(query).toHaveBeenCalledTimes(1));

    await userEvent.type(screen.getByLabelText("From"), "2026-01-01T00:00");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() => expect(query).toHaveBeenCalledTimes(2));
    const sent = query.mock.calls[1]?.[0];
    // The endpoint parses RFC3339 strictly; a raw datetime-local value is a
    // 400 from the server.
    expect(sent?.from).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    expect(new Date(sent?.from ?? "").getTime()).not.toBeNaN();
  });

  it("clears every filter and requeries", async () => {
    render(AuditView);
    await waitFor(() => expect(query).toHaveBeenCalledTimes(1));

    await userEvent.type(screen.getByLabelText("Actor"), "alice");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(query).toHaveBeenCalledTimes(2));

    await userEvent.click(screen.getByRole("button", { name: "Clear" }));

    await waitFor(() => expect(query).toHaveBeenCalledTimes(3));
    expect(query).toHaveBeenLastCalledWith(expect.objectContaining({ actor: undefined }));
    expect(screen.getByLabelText("Actor")).toHaveValue("");
  });
});

describe("AuditView cursor paging", () => {
  it("follows the opaque cursor forward and back", async () => {
    query.mockResolvedValueOnce(page({ next: "cursor-2", total: 2 }));

    render(AuditView);
    await waitFor(() => expect(query).toHaveBeenCalledTimes(1));

    const next = screen.getByRole("button", { name: "Next" });
    expect(next).toBeEnabled();
    // Previous is meaningless on the first page.
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    query.mockResolvedValueOnce(page({ events: [event({ actor: "carol" })], total: 2 }));
    await userEvent.click(next);

    await waitFor(() => expect(query).toHaveBeenCalledTimes(2));
    // The server's `next` must be echoed back as `cursor` — paging by offset
    // would skip or repeat records on an append-only chain.
    expect(query).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: "cursor-2" }));
    await waitFor(() => expect(screen.getByText("carol")).toBeInTheDocument());

    query.mockResolvedValueOnce(page({ next: "cursor-2", total: 2 }));
    await userEvent.click(screen.getByRole("button", { name: "Previous" }));

    await waitFor(() => expect(query).toHaveBeenCalledTimes(3));
    expect(query).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: undefined }));
  });

  it("disables Next on the last page", async () => {
    query.mockResolvedValue(page({ next: "" }));

    render(AuditView);

    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });
});

describe("AuditView event detail", () => {
  it("shows the chain link and attributes for the selected event", async () => {
    query.mockResolvedValue(
      page({
        events: [
          event({
            role: "admin",
            tenant_id: "t1",
            client_ip: "10.0.0.9",
            request_id: "req-1",
            prev_hash: "abc123def456",
            attributes: { key_id: "k1", count: 3 },
          }),
        ],
      }),
    );

    render(AuditView);
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Details" }));

    // prev_hash is the tamper-evidence link; an operator verifying the chain
    // needs it visible, so its absence would be a real regression.
    expect(await screen.findByText("abc123def456")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.9")).toBeInTheDocument();
    expect(screen.getByText("req-1")).toBeInTheDocument();
    expect(screen.getByText(/"key_id": "k1"/)).toBeInTheDocument();
  });

  it("renders an em dash for the optional fields an event omits", async () => {
    render(AuditView);
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Details" }));

    await screen.findByText("Audit event");
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("closes the detail dialog", async () => {
    render(AuditView);
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Details" }));
    await screen.findByText("Audit event");

    await userEvent.click(screen.getByRole("button", { name: "Close", hidden: true }));

    await waitFor(() => expect(screen.queryByText("Audit event")).toBeNull());
  });
});
