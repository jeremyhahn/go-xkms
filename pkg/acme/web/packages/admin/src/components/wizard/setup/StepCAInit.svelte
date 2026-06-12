<!--
  Copyright (C) 2024 Trusted CA Authors.

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0, or alternatively, under the terms of the
  GNU Affero General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any
  later version. A commercial license is available from the authors.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { setupWizardStore } from '@trustedca/shared/stores/setup-wizard.svelte';
  import { setupApi } from '@trustedca/shared/api/setup';

  let { onNext, onBack }: { onNext: () => void; onBack: () => void } =
    $props();

  let rootCAName: string = $state(setupWizardStore.rootCAName);
  let intermediateCAName: string = $state(setupWizardStore.intermediateCAName);
  let keyAlgorithm: string = $state(setupWizardStore.keyAlgorithm);
  let validityYears: number = $state(setupWizardStore.validityYears);
  let organization: string = $state(setupWizardStore.organization);
  let organizationalUnit: string = $state(setupWizardStore.organizationalUnit);
  let country: string = $state(setupWizardStore.country);
  let stateProvince: string = $state(setupWizardStore.state);
  let locality: string = $state(setupWizardStore.locality);

  const fallbackAlgorithms: readonly { value: string; label: string }[] = [
    { value: 'ECDSA', label: 'ECDSA P-256 (recommended)' },
    { value: 'ECDSA-P384', label: 'ECDSA P-384' },
    { value: 'RSA-2048', label: 'RSA 2048-bit' },
    { value: 'RSA-4096', label: 'RSA 4096-bit' },
    { value: 'Ed25519', label: 'Ed25519' },
  ] as const;

  let keyAlgorithms: { value: string; label: string }[] = $state(
    fallbackAlgorithms.map((a) => ({ value: a.value, label: a.label })),
  );

  let rootNameError = $derived<string | null>(
    rootCAName.trim().length === 0 ? 'Root CA name is required.' : null,
  );

  let intermediateNameError = $derived<string | null>(
    intermediateCAName.trim().length === 0
      ? 'Intermediate CA name is required.'
      : null,
  );

  let validityError = $derived<string | null>(
    validityYears <= 0
      ? 'Validity must be greater than zero.'
      : validityYears > 100
        ? 'Validity cannot exceed 100 years.'
        : null,
  );

  let isValid = $derived(
    rootNameError === null &&
      intermediateNameError === null &&
      validityError === null,
  );

  function handleNext(): void {
    if (!isValid) return;
    setupWizardStore.rootCAName = rootCAName.trim();
    setupWizardStore.intermediateCAName = intermediateCAName.trim();
    setupWizardStore.keyAlgorithm = keyAlgorithm;
    setupWizardStore.validityYears = validityYears;
    setupWizardStore.organization = organization.trim();
    setupWizardStore.organizationalUnit = organizationalUnit.trim();
    setupWizardStore.country = country.trim();
    setupWizardStore.state = stateProvince.trim();
    setupWizardStore.locality = locality.trim();
    onNext();
  }

  onMount(() => {
    async function loadData(): Promise<void> {
      // Load available algorithms from the server.
      try {
        const algos = await setupApi.getAlgorithms();
        if (Array.isArray(algos.signing) && algos.signing.length > 0) {
          keyAlgorithms = algos.signing.map(
            (a: { algorithm: string; curve?: string; key_size?: number }) => {
              let label = a.algorithm;
              if (a.curve) {
                label = `${a.algorithm} ${a.curve}`;
              } else if (a.key_size) {
                label = `${a.algorithm} ${a.key_size}-bit`;
              }
              return { value: a.algorithm + (a.curve ? `-${a.curve}` : a.key_size ? `-${a.key_size}` : ''), label };
            },
          );
          if (keyAlgorithms.length > 0 && keyAlgorithms[0] !== undefined) {
            keyAlgorithm = keyAlgorithms[0].value;
          }
        }
      } catch {
        // Fall back to static list already set in initial state.
      }

      // Pre-populate subject fields from server defaults.
      try {
        const defaults = await setupApi.getDefaults();
        if (defaults.organization && !organization) {
          organization = defaults.organization;
        }
        if (defaults.organizational_unit && !organizationalUnit) {
          organizationalUnit = defaults.organizational_unit;
        }
        if (defaults.country && !country) {
          country = defaults.country;
        }
        if (defaults.state && !stateProvince) {
          stateProvince = defaults.state;
        }
        if (defaults.locality && !locality) {
          locality = defaults.locality;
        }
      } catch {
        // Defaults endpoint is optional; proceed without pre-population.
      }
    }
    loadData();
  });
</script>

<div class="flex flex-col items-center gap-6">
  <div class="text-center">
    <h2 class="text-2xl font-bold">Initialize Certificate Authority</h2>
    <p class="text-base-content/70 mt-2">
      Configure the root and intermediate CA hierarchy for certificate issuance.
    </p>
  </div>

  <div class="w-full max-w-2xl space-y-4">
    <!-- Root CA -->
    <div class="form-control">
      <label class="label" for="root-ca-name">
        <span class="label-text font-medium">Root CA Common Name</span>
      </label>
      <input
        id="root-ca-name"
        type="text"
        class="input input-bordered w-full"
        placeholder="e.g. My Organisation Root CA"
        bind:value={rootCAName}
      />
      {#if rootNameError !== null && rootCAName.length > 0}
        <label class="label" for="root-ca-name">
          <span class="label-text-alt text-error">{rootNameError}</span>
        </label>
      {/if}
    </div>

    <!-- Intermediate CA -->
    <div class="form-control">
      <label class="label" for="intermediate-ca-name">
        <span class="label-text font-medium">Intermediate CA Common Name</span>
      </label>
      <input
        id="intermediate-ca-name"
        type="text"
        class="input input-bordered w-full"
        placeholder="e.g. My Organisation Intermediate CA"
        bind:value={intermediateCAName}
      />
      {#if intermediateNameError !== null && intermediateCAName.length > 0}
        <label class="label" for="intermediate-ca-name">
          <span class="label-text-alt text-error"
            >{intermediateNameError}</span
          >
        </label>
      {/if}
    </div>

    <!-- Key Algorithm -->
    <div class="form-control">
      <label class="label" for="key-algorithm">
        <span class="label-text font-medium">Key Algorithm</span>
      </label>
      <select
        id="key-algorithm"
        class="select select-bordered w-full"
        bind:value={keyAlgorithm}
      >
        {#each keyAlgorithms as alg (alg.value)}
          <option value={alg.value}>{alg.label}</option>
        {/each}
      </select>
      <label class="label" for="key-algorithm">
        <span class="label-text-alt text-base-content/60">
          Applied to both root and intermediate CA key pairs.
        </span>
      </label>
    </div>

    <!-- Validity -->
    <div class="form-control">
      <label class="label" for="validity-years">
        <span class="label-text font-medium">CA Certificate Validity (years)</span>
      </label>
      <input
        id="validity-years"
        type="number"
        class="input input-bordered w-full"
        min="1"
        max="100"
        bind:value={validityYears}
      />
      {#if validityError !== null}
        <label class="label" for="validity-years">
          <span class="label-text-alt text-error">{validityError}</span>
        </label>
      {/if}
    </div>

    <!-- Subject fields -->
    <div class="divider text-sm">CA Subject (Optional)</div>

    <div class="form-control">
      <label class="label" for="organization">
        <span class="label-text font-medium">Organization</span>
      </label>
      <input
        id="organization"
        type="text"
        class="input input-bordered w-full"
        placeholder="e.g., ACME Corporation"
        bind:value={organization}
      />
    </div>

    <div class="form-control">
      <label class="label" for="organizational-unit">
        <span class="label-text font-medium">Organizational Unit</span>
      </label>
      <input
        id="organizational-unit"
        type="text"
        class="input input-bordered w-full"
        placeholder="e.g., IT Security"
        bind:value={organizationalUnit}
      />
    </div>

    <div class="grid grid-cols-2 gap-4">
      <div class="form-control">
        <label class="label" for="country">
          <span class="label-text font-medium">Country</span>
        </label>
        <input
          id="country"
          type="text"
          class="input input-bordered w-full"
          placeholder="e.g., US"
          maxlength={2}
          bind:value={country}
        />
      </div>

      <div class="form-control">
        <label class="label" for="state">
          <span class="label-text font-medium">State / Province</span>
        </label>
        <input
          id="state"
          type="text"
          class="input input-bordered w-full"
          placeholder="e.g., California"
          bind:value={stateProvince}
        />
      </div>
    </div>

    <div class="form-control">
      <label class="label" for="locality">
        <span class="label-text font-medium">Locality / City</span>
      </label>
      <input
        id="locality"
        type="text"
        class="input input-bordered w-full"
        placeholder="e.g., San Francisco"
        bind:value={locality}
      />
    </div>
  </div>

  <div class="flex w-full max-w-2xl justify-between">
    <button class="btn btn-ghost" onclick={onBack}>Back</button>
    <button
      class="btn btn-primary"
      disabled={!isValid}
      onclick={handleNext}
    >
      Next
    </button>
  </div>
</div>
