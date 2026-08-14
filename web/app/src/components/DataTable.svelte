<script lang="ts">
  interface Column {
    key: string;
    label: string;
  }
  interface Props {
    columns: Column[];
    rows: Array<Record<string, unknown>>;
    emptyMessage?: string;
    onRowClick?: (row: Record<string, unknown>) => void;
    /**
     * Accessible name for the table, rendered as a visually-hidden
     * `<caption>`. The visible page heading identifies the table for
     * sighted users, but a caption is what gives screen-reader users the
     * same context when they land inside the table directly.
     */
    caption?: string;
  }
  let { columns, rows, emptyMessage = "No records.", onRowClick, caption }: Props = $props();

  function cell(row: Record<string, unknown>, key: string): string {
    const v = row[key];
    if (v === null || v === undefined) return "";
    return String(v);
  }

  // A row that acts as a link/button must be operable from the keyboard too,
  // not just clickable — Enter and Space both activate it, matching native
  // button semantics, while the row keeps its native `row` role so table
  // navigation commands in assistive tech still work.
  function onRowKeydown(e: KeyboardEvent, row: Record<string, unknown>): void {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    onRowClick?.(row);
  }
</script>

{#if rows.length === 0}
  <div class="text-sm text-base-content/60 py-6 text-center">{emptyMessage}</div>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      {#if caption}<caption class="sr-only">{caption}</caption>{/if}
      <thead>
        <tr>
          {#each columns as col (col.key)}
            <th scope="col">{col.label}</th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each rows as row, i (i)}
          <tr
            class={onRowClick ? "hover cursor-pointer" : ""}
            tabindex={onRowClick ? 0 : undefined}
            onclick={() => onRowClick?.(row)}
            onkeydown={onRowClick ? (e: KeyboardEvent) => onRowKeydown(e, row) : undefined}
          >
            {#each columns as col (col.key)}
              <td>{cell(row, col.key)}</td>
            {/each}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
