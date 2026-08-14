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

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/svelte";
import DataTable from "../src/components/DataTable.svelte";

const columns = [
  { key: "id", label: "ID" },
  { key: "backend", label: "Backend" },
];

const rows = [
  { id: "key-1", backend: "software" },
  { id: "key-2", backend: "tpm2" },
];

describe("DataTable", () => {
  it("renders a header cell per column and a row per record", () => {
    render(DataTable, { props: { columns, rows } });

    expect(screen.getByRole("columnheader", { name: "ID" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Backend" })).toBeInTheDocument();
    expect(screen.getByText("key-1")).toBeInTheDocument();
    expect(screen.getByText("software")).toBeInTheDocument();
    expect(screen.getByText("key-2")).toBeInTheDocument();
    expect(screen.getByText("tpm2")).toBeInTheDocument();
  });

  it("renders the empty message and no table when rows is empty", () => {
    render(DataTable, { props: { columns, rows: [], emptyMessage: "No keys found." } });

    expect(screen.getByText("No keys found.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("falls back to the default empty message when none is supplied", () => {
    render(DataTable, { props: { columns, rows: [] } });
    expect(screen.getByText("No records.")).toBeInTheDocument();
  });

  it("renders an empty cell rather than the literal string 'null' or 'undefined'", () => {
    render(DataTable, { props: { columns, rows: [{ id: "key-3", backend: null }] } });
    // The backend cell must be blank, not the text "null".
    expect(screen.queryByText("null")).not.toBeInTheDocument();
    const row = screen.getByText("key-3").closest("tr");
    expect(row).not.toBeNull();
    const cells = row!.querySelectorAll("td");
    expect(cells[1]!.textContent).toBe("");
  });

  it("fires onRowClick with the clicked row's data", async () => {
    const onRowClick = vi.fn();
    render(DataTable, { props: { columns, rows, onRowClick } });

    await fireEvent.click(screen.getByText("key-2"));

    expect(onRowClick).toHaveBeenCalledOnce();
    expect(onRowClick).toHaveBeenCalledWith(rows[1]);
  });

  it("does not throw when a row is clicked and no onRowClick handler is given", async () => {
    render(DataTable, { props: { columns, rows } });
    // Absence of a crash is the assertion; also confirm no pointer-cursor class
    // was applied since there is nothing to click through to.
    const row = screen.getByText("key-1").closest("tr");
    expect(row?.className).not.toContain("cursor-pointer");
    await expect(fireEvent.click(screen.getByText("key-1"))).resolves.toBeTruthy();
  });
});
