<!--
  Copyright (C) 2024 Trusted CA Authors.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0, or alternatively, under the terms of the
  GNU Affero General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any
  later version. A commercial license is available from the authors.
-->
<script lang="ts">
  import { setupWizardStore } from '@trustedca/shared/stores/setup-wizard.svelte';

  let { onDone }: { onDone: () => void } = $props();

  // Share-free contract: shares are sealed to enrolled Security Officers and
  // never reach the browser; only the generated share count is reported.
  const hasShamirShares = $derived(setupWizardStore.shamirShareCount > 0);
</script>

<div class="flex flex-col items-center gap-6">
  <!-- Success icon -->
  <svg
    xmlns="http://www.w3.org/2000/svg"
    class="h-16 w-16 text-success"
    fill="none"
    viewBox="0 0 24 24"
    stroke="currentColor"
  >
    <path
      stroke-linecap="round"
      stroke-linejoin="round"
      stroke-width="2"
      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
    />
  </svg>

  <div class="text-center">
    <h2 class="text-2xl font-bold">Setup Complete</h2>
    <p class="text-base-content/70 mt-2">
      Your Trusted CA has been successfully initialized and is ready for use.
    </p>
  </div>

  <!-- Shamir share distribution notice -->
  {#if hasShamirShares}
    <div class="w-full max-w-2xl space-y-4">
      <div role="alert" class="alert alert-info">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-5 w-5 shrink-0"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <div class="text-sm">
          <p class="font-semibold">
            {setupWizardStore.shamirShareCount} Shamir key shares generated and sealed
            to enrolled Security Officers.
          </p>
          <p class="mt-1">
            Shares are never displayed or transmitted. Each Security Officer
            claims their share with their enrolled credential. At least
            {setupWizardStore.shamirThreshold} officers are required to unseal
            the CA.
          </p>
        </div>
      </div>
    </div>
  {/if}

  <button class="btn btn-primary btn-lg" onclick={onDone}>
    Continue to Dashboard
  </button>
</div>
