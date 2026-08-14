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

// Regression coverage for the DataTable.svelte a11y fixes: a clickable row
// used to be mouse-only (an onclick handler on a plain, non-focusable <tr>),
// column headers had no `scope`, and the table had no accessible name of its
// own beyond whatever page heading happened to precede it.

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

describe("DataTable a11y", () => {
  it("marks every column header with scope=col", () => {
    render(DataTable, { props: { columns, rows } });

    for (const header of screen.getAllByRole("columnheader")) {
      expect(header).toHaveAttribute("scope", "col");
    }
  });

  it("exposes an accessible name via a visually-hidden caption when provided", () => {
    render(DataTable, { props: { columns, rows, caption: "Cryptographic keys" } });

    expect(screen.getByRole("table", { name: "Cryptographic keys" })).toBeInTheDocument();
  });

  it("makes a clickable row keyboard-focusable", () => {
    render(DataTable, { props: { columns, rows, onRowClick: () => {} } });

    const row = screen.getByText("key-1").closest("tr")!;
    expect(row).toHaveAttribute("tabindex", "0");
  });

  it("does not make a non-clickable row focusable", () => {
    render(DataTable, { props: { columns, rows } });

    const row = screen.getByText("key-1").closest("tr")!;
    expect(row).not.toHaveAttribute("tabindex");
  });

  it("activates the row with Enter", async () => {
    const onRowClick = vi.fn();
    render(DataTable, { props: { columns, rows, onRowClick } });

    const row = screen.getByText("key-2").closest("tr")!;
    row.focus();
    await fireEvent.keyDown(row, { key: "Enter" });

    expect(onRowClick).toHaveBeenCalledOnce();
    expect(onRowClick).toHaveBeenCalledWith(rows[1]);
  });

  it("activates the row with Space", async () => {
    const onRowClick = vi.fn();
    render(DataTable, { props: { columns, rows, onRowClick } });

    const row = screen.getByText("key-1").closest("tr")!;
    row.focus();
    await fireEvent.keyDown(row, { key: " " });

    expect(onRowClick).toHaveBeenCalledOnce();
    expect(onRowClick).toHaveBeenCalledWith(rows[0]);
  });

  it("ignores unrelated keys", async () => {
    const onRowClick = vi.fn();
    render(DataTable, { props: { columns, rows, onRowClick } });

    const row = screen.getByText("key-1").closest("tr")!;
    row.focus();
    await fireEvent.keyDown(row, { key: "Tab" });

    expect(onRowClick).not.toHaveBeenCalled();
  });
});
