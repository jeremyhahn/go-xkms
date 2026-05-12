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

  let username: string = $state(setupWizardStore.adminUsername);
  let password: string = $state(setupWizardStore.adminPassword);
  let passwordConfirm: string = $state(setupWizardStore.adminPasswordConfirm);

  let usernameError = $derived<string | null>(
    username.trim().length === 0
      ? 'Username is required.'
      : username.trim().length < 3
        ? 'Username must be at least 3 characters.'
        : null,
  );

  let passwordError = $derived<string | null>(
    password.length === 0
      ? 'Password is required.'
      : password.length < 8
        ? 'Password must be at least 8 characters.'
        : null,
  );

  let confirmError = $derived<string | null>(
    passwordConfirm.length > 0 && password !== passwordConfirm
      ? 'Passwords do not match.'
      : null,
  );

  let isValid = $derived(
    usernameError === null &&
      passwordError === null &&
      confirmError === null &&
      passwordConfirm.length > 0,
  );

  function handleNext(): void {
    if (!isValid) return;
    setupWizardStore.adminUsername = username.trim();
    setupWizardStore.adminPassword = password;
    setupWizardStore.adminPasswordConfirm = passwordConfirm;
    onNext();
  }
</script>

<div class="flex flex-col items-center gap-6">
  <div class="text-center">
    <h2 class="text-2xl font-bold">Create Administrator Account</h2>
    <p class="text-base-content/70 mt-2">
      This account will have full administrative access to the CA.
    </p>
  </div>

  <div class="w-full max-w-2xl space-y-4">
    <!-- Username -->
    <div class="form-control">
      <label class="label" for="admin-username">
        <span class="label-text font-medium">Username</span>
      </label>
      <input
        id="admin-username"
        type="text"
        class="input input-bordered w-full"
        placeholder="admin"
        autocomplete="username"
        bind:value={username}
      />
      {#if usernameError !== null && username.length > 0}
        <label class="label" for="admin-username">
          <span class="label-text-alt text-error">{usernameError}</span>
        </label>
      {/if}
    </div>

    <!-- Password -->
    <div class="form-control">
      <label class="label" for="admin-password">
        <span class="label-text font-medium">Password</span>
      </label>
      <input
        id="admin-password"
        type="password"
        class="input input-bordered w-full"
        placeholder="Enter a strong password"
        autocomplete="new-password"
        bind:value={password}
      />
      {#if passwordError !== null && password.length > 0}
        <label class="label" for="admin-password">
          <span class="label-text-alt text-error">{passwordError}</span>
        </label>
      {/if}
    </div>

    <!-- Confirm Password -->
    <div class="form-control">
      <label class="label" for="admin-password-confirm">
        <span class="label-text font-medium">Confirm Password</span>
      </label>
      <input
        id="admin-password-confirm"
        type="password"
        class="input input-bordered w-full"
        placeholder="Re-enter password"
        autocomplete="new-password"
        bind:value={passwordConfirm}
      />
      {#if confirmError !== null}
        <label class="label" for="admin-password-confirm">
          <span class="label-text-alt text-error">{confirmError}</span>
        </label>
      {/if}
    </div>

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
      <span class="text-sm">
        Store these credentials securely. The password cannot be recovered
        without administrator access to the server.
      </span>
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
