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

  let { onNext, onBack }: { onNext: () => void; onBack: () => void } =
    $props();

  const strategyLabels: Readonly<Record<string, string>> = {
    none: 'None (Unencrypted)',
    software: 'Passphrase',
    shamir: 'Shamir Secret Sharing',
  } as const;
</script>

<div class="flex flex-col items-center gap-6">
  <div class="text-center">
    <h2 class="text-2xl font-bold">Review Configuration</h2>
    <p class="text-base-content/70 mt-2">
      Verify all settings before initializing the Certificate Authority.
    </p>
  </div>

  <div class="w-full max-w-2xl space-y-4">
    <!-- Barrier -->
    <div class="bg-base-200 rounded-lg p-4">
      <h3 class="mb-3 text-sm font-semibold uppercase tracking-wide text-primary">
        Encryption Barrier
      </h3>
      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-base-content/70">Strategy</span>
          <span class="badge badge-sm badge-success">
            {strategyLabels[setupWizardStore.barrierStrategy] ??
              setupWizardStore.barrierStrategy}
          </span>
        </div>
        {#if setupWizardStore.barrierStrategy === 'shamir'}
          <div class="flex items-center justify-between">
            <span class="text-base-content/70">Shamir Scheme</span>
            <span class="font-medium">
              {setupWizardStore.shamirThreshold}-of-{setupWizardStore.shamirTotal}
            </span>
          </div>
        {/if}
      </div>
    </div>

    <!-- Certificate Authority -->
    <div class="bg-base-200 rounded-lg p-4">
      <h3 class="mb-3 text-sm font-semibold uppercase tracking-wide text-primary">
        Certificate Authority
      </h3>
      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-base-content/70">Root CA</span>
          <span class="font-mono text-sm">{setupWizardStore.rootCAName}</span>
        </div>
        <div class="flex items-center justify-between">
          <span class="text-base-content/70">Intermediate CA</span>
          <span class="font-mono text-sm"
            >{setupWizardStore.intermediateCAName}</span
          >
        </div>
        <div class="flex items-center justify-between">
          <span class="text-base-content/70">Key Algorithm</span>
          <span class="font-medium">{setupWizardStore.keyAlgorithm}</span>
        </div>
        <div class="flex items-center justify-between">
          <span class="text-base-content/70">Validity</span>
          <span class="font-medium">{setupWizardStore.validityYears} years</span>
        </div>
      </div>
    </div>

    <!-- CA Subject -->
    {#if setupWizardStore.organization || setupWizardStore.organizationalUnit || setupWizardStore.country || setupWizardStore.state || setupWizardStore.locality}
      <div class="bg-base-200 rounded-lg p-4">
        <h3 class="mb-3 text-sm font-semibold uppercase tracking-wide text-primary">
          CA Subject
        </h3>
        <div class="space-y-2">
          {#if setupWizardStore.organization}
            <div class="flex items-center justify-between">
              <span class="text-base-content/70">Organization</span>
              <span class="font-mono text-sm">{setupWizardStore.organization}</span>
            </div>
          {/if}
          {#if setupWizardStore.organizationalUnit}
            <div class="flex items-center justify-between">
              <span class="text-base-content/70">Organizational Unit</span>
              <span class="font-mono text-sm">{setupWizardStore.organizationalUnit}</span>
            </div>
          {/if}
          {#if setupWizardStore.country}
            <div class="flex items-center justify-between">
              <span class="text-base-content/70">Country</span>
              <span class="font-mono text-sm">{setupWizardStore.country}</span>
            </div>
          {/if}
          {#if setupWizardStore.state}
            <div class="flex items-center justify-between">
              <span class="text-base-content/70">State / Province</span>
              <span class="font-mono text-sm">{setupWizardStore.state}</span>
            </div>
          {/if}
          {#if setupWizardStore.locality}
            <div class="flex items-center justify-between">
              <span class="text-base-content/70">Locality / City</span>
              <span class="font-mono text-sm">{setupWizardStore.locality}</span>
            </div>
          {/if}
        </div>
      </div>
    {/if}

    {#if setupWizardStore.barrierStrategy === 'shamir'}
      <div role="alert" class="alert alert-warning">
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
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
          />
        </svg>
        <span class="text-sm">
          After initialization, {setupWizardStore.shamirTotal} Shamir shares will
          be displayed. You must save all shares — they cannot be recovered later.
        </span>
      </div>
    {/if}
  </div>

  <div class="flex w-full max-w-2xl justify-between">
    <button class="btn btn-ghost" onclick={onBack}>Back</button>
    <button class="btn btn-primary" onclick={onNext}>Initialize</button>
  </div>
</div>
