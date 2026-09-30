<script lang="ts">
  /**
   * IndexPicker is a grid of checkboxes over a set of small indices: the PCR
   * selection of a pcr condition, the localities of a locality condition.
   * Each checkbox is named "<label> <index>".
   */
  import { createEventDispatcher } from 'svelte';

  export let legend: string;
  export let label: string;
  export let indices: number[];
  export let selected: number[];
  export let columns = 8;

  const dispatch = createEventDispatcher<{ toggle: number }>();
</script>

<fieldset class="index-picker" style="grid-template-columns: repeat({columns}, 1fr)">
  <legend class="text-label-medium">{legend}</legend>
  {#each indices as index}
    <label class="index-choice text-body-small">
      <input
        type="checkbox"
        checked={selected.includes(index)}
        on:change={() => dispatch('toggle', index)}
        aria-label="{label} {index}"
      />
      {index}
    </label>
  {/each}
</fieldset>

<style>
  .index-picker {
    display: grid;
    gap: 4px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    padding: 8px;
  }

  .index-choice {
    display: flex;
    align-items: center;
    gap: 4px;
  }
</style>
