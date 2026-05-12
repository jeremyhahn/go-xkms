<!--
  Copyright (C) 2024 Trusted CA Authors.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0, or alternatively, under the terms of the
  GNU Affero General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any
  later version. A commercial license is available from the authors.
-->
<script lang="ts">
  import {
    setupWizardStore,
    nextStep,
  } from '@trustedca/shared/stores/setup-wizard.svelte';
  import type { BarrierStrategy } from '@trustedca/shared/stores/setup-wizard.svelte';

  let { onNext, onCancel }: { onNext: () => void; onCancel: () => void } =
    $props();

  let strategy: BarrierStrategy = $state(setupWizardStore.barrierStrategy);
  let secret: string = $state(setupWizardStore.barrierSecret);
  let secretConfirm: string = $state(setupWizardStore.barrierSecretConfirm);
  let shamirThreshold: number = $state(setupWizardStore.shamirThreshold);
  let shamirTotal: number = $state(setupWizardStore.shamirTotal);

  const strategies: readonly {
    id: BarrierStrategy;
    label: string;
    description: string;
  }[] = [
    {
      id: 'none',
      label: 'None',
      description:
        'No encryption barrier. Data is stored unencrypted. Not recommended for production use.',
    },
    {
      id: 'software',
      label: 'Passphrase',
      description:
        'Protect the barrier with a single passphrase. Simple and suitable for single-operator deployments.',
    },
    {
      id: 'shamir',
      label: 'Shamir Secret Sharing',
      description:
        'Split the barrier key into N shares. Any M shares are required to unseal. Ideal for high-security, multi-operator environments.',
    },
  ] as const;

  /** Validation for Shamir: threshold must be <= total and both must be > 0. */
  let shamirError = $derived<string | null>(
    strategy !== 'shamir'
      ? null
      : shamirThreshold <= 0 || shamirTotal <= 0
        ? 'Both values must be greater than zero.'
        : shamirThreshold > shamirTotal
          ? 'Threshold cannot exceed total shares.'
          : null,
  );

  /** Validation for passphrase: non-empty and confirmed. */
  let passphraseError = $derived<string | null>(
    strategy !== 'software'
      ? null
      : secret.length === 0
        ? 'Passphrase is required.'
        : secret !== secretConfirm
          ? 'Passphrases do not match.'
          : null,
  );

  let isValid = $derived(shamirError === null && passphraseError === null);

  function handleNext(): void {
    if (!isValid) return;
    setupWizardStore.barrierStrategy = strategy;
    setupWizardStore.barrierSecret = secret;
    setupWizardStore.barrierSecretConfirm = secretConfirm;
    setupWizardStore.shamirThreshold = shamirThreshold;
    setupWizardStore.shamirTotal = shamirTotal;
    onNext();
  }
</script>

<div class="flex flex-col items-center gap-6">
  <div class="text-center">
    <h2 class="text-2xl font-bold">Configure Encryption Barrier</h2>
    <p class="text-base-content/70 mt-2">
      The barrier protects all CA keys and sensitive data at rest.
    </p>
  </div>

  <div class="w-full max-w-2xl space-y-6">
    <!-- Strategy selector cards -->
    <div class="grid grid-cols-3 gap-4">
      {#each strategies as s (s.id)}
        <button
          type="button"
          class="card cursor-pointer border-2 p-4 text-left transition-colors
            {strategy === s.id
              ? s.id === 'none'
                ? 'border-warning bg-warning/5'
                : 'border-primary bg-primary/5'
              : 'border-base-300 hover:border-primary/50'}"
          onclick={() => (strategy = s.id)}
        >
          <div class="flex items-start gap-3">
            <input
              type="radio"
              name="barrier-strategy"
              class="radio radio-primary mt-1"
              value={s.id}
              checked={strategy === s.id}
              onchange={() => (strategy = s.id)}
            />
            <div>
              <span class="font-semibold">{s.label}</span>
              <p class="text-base-content/60 mt-1 text-sm">
                {s.description}
              </p>
            </div>
          </div>
        </button>
      {/each}
    </div>

    <!-- None warning -->
    {#if strategy === 'none'}
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
          <strong>Warning:</strong> All CA keys and sensitive data will be stored
          unencrypted on disk. This is not recommended for production deployments.
        </span>
      </div>
    {/if}

    <!-- Passphrase fields -->
    {#if strategy === 'software'}
      <div class="bg-base-200 rounded-lg p-6 space-y-4">
        <h3 class="font-semibold">Barrier Passphrase</h3>

        <div class="form-control">
          <label class="label" for="barrier-secret">
            <span class="label-text">Passphrase</span>
          </label>
          <input
            id="barrier-secret"
            type="password"
            class="input input-bordered w-full"
            placeholder="Enter a strong passphrase"
            bind:value={secret}
          />
        </div>

        <div class="form-control">
          <label class="label" for="barrier-secret-confirm">
            <span class="label-text">Confirm Passphrase</span>
          </label>
          <input
            id="barrier-secret-confirm"
            type="password"
            class="input input-bordered w-full"
            placeholder="Re-enter passphrase"
            bind:value={secretConfirm}
          />
        </div>

        {#if passphraseError !== null && (secret.length > 0 || secretConfirm.length > 0)}
          <div role="alert" class="alert alert-error">
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
                d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <span class="text-sm">{passphraseError}</span>
          </div>
        {/if}
      </div>
    {/if}

    <!-- Shamir configuration -->
    {#if strategy === 'shamir'}
      <div class="bg-base-200 rounded-lg p-6">
        <h3 class="mb-4 font-semibold">Shamir Secret Sharing</h3>

        <div role="alert" class="alert alert-info mb-4">
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
          <span class="text-sm">
            The barrier key is split into <strong>N</strong> shares. Any
            <strong>M</strong> of those shares can reconstruct the key and unseal
            the CA. Distribute shares to different operators for security.
          </span>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div class="form-control">
            <label class="label" for="shamir-threshold">
              <span class="label-text">Threshold (M)</span>
            </label>
            <input
              id="shamir-threshold"
              type="number"
              class="input input-bordered w-full"
              min="1"
              max="20"
              bind:value={shamirThreshold}
            />
            <label class="label" for="shamir-threshold">
              <span class="label-text-alt text-base-content/60">
                Minimum shares to unseal
              </span>
            </label>
          </div>
          <div class="form-control">
            <label class="label" for="shamir-total">
              <span class="label-text">Total Shares (N)</span>
            </label>
            <input
              id="shamir-total"
              type="number"
              class="input input-bordered w-full"
              min="1"
              max="20"
              bind:value={shamirTotal}
            />
            <label class="label" for="shamir-total">
              <span class="label-text-alt text-base-content/60">
                Total shares generated
              </span>
            </label>
          </div>
        </div>

        {#if shamirError !== null}
          <div role="alert" class="alert alert-error mt-4">
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
                d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <span class="text-sm">{shamirError}</span>
          </div>
        {/if}

        {#if shamirError === null && shamirTotal > 0}
          <p class="text-base-content/50 mt-4 text-sm">
            Configuration: {shamirThreshold}-of-{shamirTotal} scheme. The system
            tolerates the loss of {shamirTotal - shamirThreshold} share{shamirTotal -
              shamirThreshold !==
            1
              ? 's'
              : ''}.
          </p>
        {/if}
      </div>
    {/if}
  </div>

  <div class="flex w-full max-w-2xl justify-between">
    <button class="btn btn-ghost" onclick={onCancel}>Cancel</button>
    <button
      class="btn btn-primary"
      disabled={!isValid}
      onclick={handleNext}
    >
      Next
    </button>
  </div>
</div>
