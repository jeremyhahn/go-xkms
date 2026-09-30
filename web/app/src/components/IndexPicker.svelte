<script lang="ts">
  // IndexPicker is a grid of checkboxes over a set of small indices: the PCR
  // selection of a pcr condition, the localities of a locality condition.
  interface Props {
    legend: string;
    /** Prefix of each checkbox's accessible name, e.g. "PCR" gives "PCR 7". */
    label: string;
    indices: number[];
    selected: number[];
    columns?: number;
    onToggle: (index: number) => void;
  }
  let { legend, label, indices, selected, columns = 6, onToggle }: Props = $props();
</script>

<fieldset>
  <legend class="label-text mb-1">{legend}</legend>
  <div class="grid gap-1" style="grid-template-columns: repeat({columns}, minmax(0, 1fr))">
    {#each indices as i (i)}
      <label class="label cursor-pointer justify-start gap-1 p-1">
        <input
          type="checkbox"
          class="checkbox checkbox-sm"
          aria-label={`${label} ${i}`}
          checked={selected.includes(i)}
          onchange={() => onToggle(i)}
        />
        <span class="label-text text-xs">{i}</span>
      </label>
    {/each}
  </div>
</fieldset>
