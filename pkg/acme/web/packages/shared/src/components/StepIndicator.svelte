<!--
  Copyright (C) 2024 Trusted CA Authors.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0, or alternatively, under the terms of the
  GNU Affero General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any
  later version. A commercial license is available from the authors.
-->
<script lang="ts">
  /** Props for the step progress indicator. */
  interface Props {
    /** Human-readable labels for each step. */
    steps: readonly string[];
    /** Zero-based index of the currently active step. */
    currentIndex: number;
  }

  let { steps, currentIndex }: Props = $props();
</script>

<ul class="steps w-full mb-6">
  {#each steps as label, i}
    <li class="step" class:step-primary={i <= currentIndex}>
      {label}
    </li>
  {/each}
</ul>
