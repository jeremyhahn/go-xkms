<script lang="ts">
  /**
   * TPMPolicyPanel manages named TPM policies through TPMPolicyService: an OR
   * of branches, each an AND of pcr (values captured live from the TPM),
   * password and locality conditions, approved by the scope's TPM-resident
   * authority, which keys and sealed objects reference by name.
   * The operations run on the connected server when there is one, and
   * otherwise on xKey's own TPM. The built-in "platform" policy is listed
   * first and cannot be changed.
   */
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Input from '$lib/components/Input.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Toggle from '$lib/components/Toggle.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import IndexPicker from '$lib/components/IndexPicker.svelte';
  import { mdiTune, mdiPlus, mdiRefresh, mdiDelete, mdiShieldKey } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackendWithError, callBackendVoidWithError } from '$lib/api/backend';
  import type {
    TPMPolicyInfo, TPMPolicyStatus, TPMPolicyVerification, TPMAuthorityInfo,
  } from '$lib/api/backend';
  import {
    BANKS, LOCALITIES, PCR_INDICES, describeBranch, draftError, draftToBranch, newBranchDraft,
    pcrBranch, policySummary, toggleIndex,
  } from '$lib/utils/tpmPolicy';
  import type { BranchDraft } from '$lib/utils/tpmPolicy';

  let status: TPMPolicyStatus | null = null;
  let policies: TPMPolicyInfo[] = [];
  let loading = true;
  let loadError = '';
  let busy = '';

  // Create dialog: simple mode builds one pcr branch from createBank and
  // createPCRs; advanced mode sends every draft in createBranches.
  let showCreate = false;
  let createName = '';
  let createDescription = '';
  let createAdvanced = false;
  let createBank = 'sha256';
  let createPCRs: number[] = [];
  let createBranches: BranchDraft[] = [newBranchDraft()];
  let createOwnerAuth = '';
  let createError = '';

  // Description dialog
  let showDescribe = false;
  let describeName = '';
  let describeText = '';
  let describeError = '';

  // Verify result
  let verification: TPMPolicyVerification | null = null;

  // Details (the captured PCR values, like `xkey tpm policy get`)
  let details: TPMPolicyInfo | null = null;

  // Objects dialog
  let objectsPolicy = '';
  let objects: string[] = [];
  let showObjects = false;

  // Delete dialog
  let deleteName = '';
  let deleteOwnerAuth = '';
  let deleteError = '';
  let showDelete = false;

  // Auto-unseal dialog (local mode: the barrier password is sealed under the policy)
  let autoUnsealName = '';
  let autoUnsealPassword = '';
  let autoUnsealError = '';
  let showAutoUnseal = false;

  // Rotate dialog
  let showRotate = false;

  $: isLocal = status?.mode === 'local';

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    const statusResult = await callBackendWithError<TPMPolicyStatus>('TPMPolicyService', 'GetStatus');
    status = statusResult.result;
    if (!status?.available) {
      policies = [];
      loadError = 'No TPM policy service: xKey has no TPM, and no server is connected.';
      loading = false;
      return;
    }
    const listResult = await callBackendWithError<TPMPolicyInfo[]>('TPMPolicyService', 'ListPolicies');
    if (listResult.error) {
      loadError = listResult.error;
    }
    policies = listResult.result ?? [];
    loading = false;
  }

  function openCreate(): void {
    createName = '';
    createDescription = '';
    createAdvanced = false;
    createBank = 'sha256';
    createPCRs = [];
    createBranches = [newBranchDraft()];
    createOwnerAuth = '';
    createError = '';
    showCreate = true;
  }

  /** updateBranch replaces the draft at index i with change applied. */
  function updateBranch(i: number, change: Partial<BranchDraft>): void {
    createBranches = createBranches.map((b, j) => (j === i ? { ...b, ...change } : b));
  }

  /** createValidation returns why the create dialog cannot be sent, or ''. */
  function createValidation(): string {
    if (!createName.trim()) {
      return 'A policy name is required.';
    }
    if (!createAdvanced) {
      return createPCRs.length === 0 ? 'Select at least one PCR.' : '';
    }
    const invalid = createBranches.findIndex((b) => draftError(b) !== '');
    return invalid < 0 ? '' : `Branch ${invalid + 1}: ${draftError(createBranches[invalid])}`;
  }

  async function submitCreate(): Promise<void> {
    createError = createValidation();
    if (createError) {
      return;
    }
    const branches = createAdvanced ? createBranches.map(draftToBranch) : [pcrBranch(createBank, createPCRs)];
    busy = 'create';
    const { error } = await callBackendWithError<TPMPolicyInfo>(
      'TPMPolicyService', 'CreatePolicy', createName.trim(), createDescription, branches, false, createOwnerAuth,
    );
    busy = '';
    if (error) {
      createError = error;
      return;
    }
    showCreate = false;
    addNotification('success', `Policy "${createName.trim()}" created from the live PCR values`);
    await load();
  }

  async function changePolicy(method: 'UpdatePolicy' | 'RevokePolicy', name: string): Promise<void> {
    busy = `${method}:${name}`;
    const { error } = await callBackendWithError<TPMPolicyInfo>('TPMPolicyService', method, name);
    busy = '';
    if (error) {
      addNotification('error', error);
      return;
    }
    addNotification('success', method === 'UpdatePolicy'
      ? `Policy "${name}" re-captured and re-approved`
      : `Policy "${name}" revoked`);
    await load();
  }

  async function verify(name: string): Promise<void> {
    busy = `verify:${name}`;
    const { result, error } = await callBackendWithError<TPMPolicyVerification>('TPMPolicyService', 'VerifyPolicy', name);
    busy = '';
    if (error || !result) {
      addNotification('error', error || `Failed to verify "${name}"`);
      return;
    }
    verification = result;
  }

  async function openDetails(name: string): Promise<void> {
    const { result, error } = await callBackendWithError<TPMPolicyInfo>('TPMPolicyService', 'GetPolicy', name);
    if (error || !result) {
      addNotification('error', error || `Failed to load "${name}"`);
      return;
    }
    details = result;
  }

  function sortedValues(values: Record<string, string> | undefined): Array<[string, string]> {
    return Object.entries(values ?? {}).sort((a, b) => Number(a[0]) - Number(b[0]));
  }

  function openDescribe(policy: TPMPolicyInfo): void {
    describeName = policy.name;
    describeText = policy.description ?? '';
    describeError = '';
    showDescribe = true;
  }

  async function submitDescribe(): Promise<void> {
    busy = 'describe';
    const { error } = await callBackendWithError<TPMPolicyInfo>(
      'TPMPolicyService', 'SetDescription', describeName, describeText,
    );
    busy = '';
    if (error) {
      describeError = error;
      return;
    }
    showDescribe = false;
    addNotification('success', `Description of "${describeName}" saved`);
    await load();
  }

  async function openObjects(name: string): Promise<void> {
    const { result, error } = await callBackendWithError<string[]>('TPMPolicyService', 'PolicyObjects', name);
    if (error) {
      addNotification('error', error);
      return;
    }
    objectsPolicy = name;
    objects = result ?? [];
    showObjects = true;
  }

  function openDelete(name: string): void {
    deleteName = name;
    deleteOwnerAuth = '';
    deleteError = '';
    showDelete = true;
  }

  async function submitDelete(): Promise<void> {
    busy = 'delete';
    const { ok, error } = await callBackendVoidWithError('TPMPolicyService', 'DeletePolicy', deleteName, deleteOwnerAuth);
    busy = '';
    if (!ok) {
      deleteError = error || 'Failed to delete the policy.';
      return;
    }
    showDelete = false;
    addNotification('success', `Policy "${deleteName}" deleted`);
    await load();
  }

  async function toggleAutoUnseal(policy: TPMPolicyInfo, on: boolean): Promise<void> {
    if (on && isLocal) {
      autoUnsealName = policy.name;
      autoUnsealPassword = '';
      autoUnsealError = '';
      showAutoUnseal = true;
      await load();
      return;
    }
    busy = `auto:${policy.name}`;
    const { ok, error } = isLocal
      ? await callBackendVoidWithError('BarrierAutoUnsealService', 'DisableAutoUnseal')
      : await callBackendVoidWithError('TPMPolicyService', 'SetAutoUnseal', policy.name, on);
    busy = '';
    if (!ok) {
      addNotification('error', error || 'Failed to change auto-unseal');
    }
    await load();
  }

  async function submitAutoUnseal(): Promise<void> {
    if (!autoUnsealPassword) {
      autoUnsealError = 'The barrier password is required.';
      return;
    }
    busy = 'auto-unseal';
    const { ok, error } = await callBackendVoidWithError(
      'BarrierAutoUnsealService', 'EnableAutoUnseal', autoUnsealName, autoUnsealPassword,
    );
    busy = '';
    autoUnsealPassword = '';
    if (!ok) {
      autoUnsealError = error || 'Failed to enable auto-unseal.';
      return;
    }
    showAutoUnseal = false;
    addNotification('success', `Barrier auto-unseal now uses "${autoUnsealName}"`);
    await load();
  }

  async function submitRotate(): Promise<void> {
    busy = 'rotate';
    const { result, error } = await callBackendWithError<TPMAuthorityInfo>('TPMPolicyService', 'RotateAuthority');
    busy = '';
    showRotate = false;
    if (error || !result) {
      addNotification('error', error || 'Failed to rotate the policy authority');
      return;
    }
    addNotification('success', `Policy authority rotated to generation ${result.generation}`);
    await load();
  }

  onMount(load);
</script>

<Card variant="elevated">
  <div class="section" data-testid="tpm-policy-panel">
    <div class="section-heading-row">
      <h2 class="text-title-medium section-heading">
        <Icon path={mdiTune} size={20} />
        TPM Policies
      </h2>
      <div class="heading-actions">
        {#if status?.available}
          <span class="text-body-small mode-label" data-testid="policy-mode">
            {isLocal ? 'Local TPM (system scope)' : 'Connected server'}
          </span>
        {/if}
        <Button variant="text" icon={mdiRefresh} on:click={load}>Refresh</Button>
        <Button variant="outline" icon={mdiShieldKey} disabled={!status?.available} on:click={() => (showRotate = true)}>
          Rotate Authority
        </Button>
        <Button variant="primary" icon={mdiPlus} disabled={!status?.available} on:click={openCreate}>
          Create Policy
        </Button>
      </div>
    </div>

    <p class="text-body-small description">
      A named policy is one or more branches, each requiring all of its conditions: the live values of
      selected PCRs, the object's password, or the TPM locality. It is approved by a TPM-resident authority,
      and keys and sealed data bound to it open only while a branch holds. After an intended change (a
      firmware update), <em>Update</em> re-captures and re-approves it without re-keying anything.
    </p>

    {#if loading}
      <div class="loading-row"><LoadingSpinner size={28} /></div>
    {:else if loadError}
      <p class="text-body-medium error-text" role="alert">{loadError}</p>
    {:else}
      <table class="policy-table" aria-label="TPM policies">
        <thead>
          <tr>
            <th class="text-label-small" scope="col">Name</th>
            <th class="text-label-small" scope="col">Description</th>
            <th class="text-label-small" scope="col">Conditions</th>
            <th class="text-label-small" scope="col">Approval</th>
            <th class="text-label-small" scope="col">Auto-unseal</th>
            <th class="text-label-small" scope="col">Objects</th>
            <th class="text-label-small" scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each policies as policy (policy.name)}
            <tr data-testid="policy-row-{policy.name}">
              <td class="text-body-medium">
                {#if policy.builtin}
                  {policy.name}
                  <span class="builtin-tag text-label-small">built-in</span>
                {:else}
                  <button class="count-link text-body-medium" on:click={() => openDetails(policy.name)}
                    aria-label="Details of {policy.name}">{policy.name}</button>
                {/if}
              </td>
              <td class="text-body-small">{policy.description ?? ''}</td>
              <td class="text-body-small font-mono">{policySummary(policy)}</td>
              <td>
                <StatusBadge status={policy.approved ? 'verified' : 'warning'} label={policy.approved ? 'Approved' : 'Revoked'} />
              </td>
              <td>
                {#if !policy.builtin}
                  <Toggle
                    checked={policy.auto_unseal}
                    disabled={busy !== ''}
                    aria-label="Auto-unseal {policy.name}"
                    onChange={(on) => toggleAutoUnseal(policy, on)}
                  />
                {/if}
              </td>
              <td>
                <button class="count-link text-body-medium" on:click={() => openObjects(policy.name)}
                  aria-label="Objects bound to {policy.name}">
                  {policy.object_count}
                </button>
              </td>
              <td class="row-actions">
                {#if !policy.builtin}
                  <Button size="sm" variant="text" on:click={() => openDescribe(policy)}>Describe</Button>
                  <Button size="sm" variant="text" loading={busy === `verify:${policy.name}`} on:click={() => verify(policy.name)}>Verify</Button>
                  <Button size="sm" variant="text" loading={busy === `UpdatePolicy:${policy.name}`} on:click={() => changePolicy('UpdatePolicy', policy.name)}>Update</Button>
                  <Button size="sm" variant="text" loading={busy === `RevokePolicy:${policy.name}`} disabled={!policy.approved} on:click={() => changePolicy('RevokePolicy', policy.name)}>Revoke</Button>
                  <Button size="sm" variant="text" icon={mdiDelete} on:click={() => openDelete(policy.name)}>Delete</Button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</Card>

<Modal bind:open={showCreate} title="Create TPM Policy" maxWidth="600px">
  <div class="form">
    <Input id="policy-name" label="Name" bind:value={createName} placeholder="boot" />
    <Input id="policy-description" label="Description" bind:value={createDescription} placeholder="firmware and Secure Boot" />
    <div class="mode-tabs" role="tablist">
      <button role="tab" class="mode-tab text-label-large" class:active={!createAdvanced} aria-selected={!createAdvanced}
        on:click={() => (createAdvanced = false)}>Simple</button>
      <button role="tab" class="mode-tab text-label-large" class:active={createAdvanced} aria-selected={createAdvanced}
        on:click={() => (createAdvanced = true)}>Advanced</button>
    </div>
    {#if !createAdvanced}
      <div class="form-field">
        <label class="text-label-medium" for="policy-bank">PCR bank</label>
        <select id="policy-bank" class="form-select" bind:value={createBank}>
          {#each BANKS as bank}
            <option value={bank}>{bank}</option>
          {/each}
        </select>
      </div>
      <IndexPicker legend="PCRs (values are read from the TPM)" label="PCR" indices={PCR_INDICES} selected={createPCRs}
        on:toggle={(e) => (createPCRs = toggleIndex(createPCRs, e.detail))} />
    {:else}
      <p class="text-body-small description">
        An object opens when any branch holds; a branch holds when all of its conditions do.
      </p>
      {#each createBranches as branch, i}
        <fieldset class="branch" data-testid="branch-{i + 1}">
          <legend class="text-label-large">Branch {i + 1}</legend>
          <label class="condition text-body-medium">
            <input type="checkbox" checked={branch.pcr} aria-label="Branch {i + 1} PCR condition"
              on:change={() => updateBranch(i, { pcr: !branch.pcr })} />
            PCR values
          </label>
          {#if branch.pcr}
            <select class="form-select" aria-label="Branch {i + 1} bank" value={branch.bank}
              on:change={(e) => updateBranch(i, { bank: e.currentTarget.value })}>
              {#each BANKS as bank}
                <option value={bank}>{bank}</option>
              {/each}
            </select>
            <IndexPicker legend="PCRs" label="Branch {i + 1} PCR" indices={PCR_INDICES} selected={branch.pcrs}
              on:toggle={(e) => updateBranch(i, { pcrs: toggleIndex(branch.pcrs, e.detail) })} />
          {/if}
          <label class="condition text-body-medium">
            <input type="checkbox" checked={branch.authValue} aria-label="Branch {i + 1} password condition"
              on:change={() => updateBranch(i, { authValue: !branch.authValue })} />
            Object password
          </label>
          <label class="condition text-body-medium">
            <input type="checkbox" checked={branch.locality} aria-label="Branch {i + 1} locality condition"
              on:change={() => updateBranch(i, { locality: !branch.locality })} />
            TPM locality
          </label>
          {#if branch.locality}
            <IndexPicker legend="Localities" label="Branch {i + 1} locality" indices={LOCALITIES} columns={5}
              selected={branch.localities}
              on:toggle={(e) => updateBranch(i, { localities: toggleIndex(branch.localities, e.detail) })} />
          {/if}
          {#if createBranches.length > 1}
            <Button size="sm" variant="text" icon={mdiDelete}
              on:click={() => (createBranches = createBranches.filter((_, j) => j !== i))}>Remove branch {i + 1}</Button>
          {/if}
        </fieldset>
      {/each}
      <Button size="sm" variant="outline" icon={mdiPlus} on:click={() => (createBranches = [...createBranches, newBranchDraft()])}>
        Add branch
      </Button>
    {/if}
    <Input id="policy-owner-auth" type="password" label="TPM owner password (if set)" bind:value={createOwnerAuth} />
    {#if createError}<p class="text-body-small error-text" role="alert">{createError}</p>{/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showCreate = false)}>Cancel</Button>
    <Button variant="primary" loading={busy === 'create'} on:click={submitCreate}>Create</Button>
  </svelte:fragment>
</Modal>

<Modal bind:open={showDescribe} title="Describe {describeName}" maxWidth="480px">
  <div class="form">
    <Input id="policy-describe" label="Description" bind:value={describeText} placeholder="firmware and Secure Boot" />
    {#if describeError}<p class="text-body-small error-text" role="alert">{describeError}</p>{/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showDescribe = false)}>Cancel</Button>
    <Button variant="primary" loading={busy === 'describe'} on:click={submitDescribe}>Save</Button>
  </svelte:fragment>
</Modal>

<Modal open={verification !== null} title="Verify {verification?.name ?? ''}" maxWidth="480px">
  {#if verification}
    <div class="form" data-testid="verify-result">
      <p class="text-body-medium">
        {verification.match
          ? 'The live PCRs match the captured values.'
          : 'The live PCRs differ from the captured values.'}
      </p>
      <ul class="object-list">
        {#each verification.branches as branch, i}
          <li class="text-body-small">
            Branch {i + 1}: {branch.match ? 'PCRs match' : `PCRs changed: ${(branch.mismatched ?? []).join(', ')}`};
            {branch.approved ? 'approval current' : 'approval not current (revoked or out of date)'}
          </li>
        {/each}
      </ul>
      <p class="text-body-small description">This check is advisory: the TPM enforces the policy whenever a bound object is used.</p>
    </div>
  {/if}
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (verification = null)}>Close</Button>
  </svelte:fragment>
</Modal>

<Modal open={details !== null} title="Policy {details?.name ?? ''}" maxWidth="600px">
  {#if details}
    <div class="form" data-testid="policy-details">
      {#if details.description}<p class="text-body-medium">{details.description}</p>{/if}
      <p class="text-body-medium">
        NV index 0x{(details.index ?? 0).toString(16).padStart(8, '0')}
        · {details.approved ? `approved at epoch ${details.epoch ?? 0} (authority generation ${details.authority_generation ?? 0})` : 'revoked'}
      </p>
      {#each details.branches ?? [] as branch, i}
        <p class="text-label-large">Branch {i + 1}: {describeBranch(branch)}</p>
        {#each branch.conditions.filter((c) => c.type === 'pcr') as condition}
          <table class="policy-table" aria-label="Captured PCR values of branch {i + 1}">
            <thead><tr><th class="text-label-small" scope="col">PCR</th><th class="text-label-small" scope="col">Captured value</th></tr></thead>
            <tbody>
              {#each sortedValues(condition.pcr_values) as [pcr, value] (pcr)}
                <tr><td class="text-body-small">{pcr}</td><td class="text-body-small font-mono value-cell">{value}</td></tr>
              {/each}
            </tbody>
          </table>
        {/each}
      {/each}
    </div>
  {/if}
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (details = null)}>Close</Button>
  </svelte:fragment>
</Modal>

<Modal bind:open={showObjects} title="Objects bound to {objectsPolicy}" maxWidth="440px">
  {#if objects.length === 0}
    <p class="text-body-medium">No keys or sealed objects are bound to this policy.</p>
  {:else}
    <ul class="object-list" data-testid="policy-objects">
      {#each objects as id}
        <li class="text-body-small font-mono">{id}</li>
      {/each}
    </ul>
  {/if}
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showObjects = false)}>Close</Button>
  </svelte:fragment>
</Modal>

<Modal bind:open={showDelete} title="Delete {deleteName}" maxWidth="480px">
  <div class="form">
    <p class="text-body-medium">
      Deleting a policy removes its NV index. It is refused while keys or sealed objects are bound to it.
    </p>
    <Input id="delete-owner-auth" type="password" label="TPM owner password (if set)" bind:value={deleteOwnerAuth} />
    {#if deleteError}<p class="text-body-small error-text" role="alert">{deleteError}</p>{/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showDelete = false)}>Cancel</Button>
    <Button variant="danger" loading={busy === 'delete'} on:click={submitDelete}>Delete</Button>
  </svelte:fragment>
</Modal>

<Modal bind:open={showAutoUnseal} title="Auto-unseal with {autoUnsealName}" maxWidth="480px">
  <div class="form">
    <p class="text-body-medium">
      The barrier password is sealed in the TPM under "{autoUnsealName}". At startup the TPM releases it only
      while the PCRs hold the values this policy approves; otherwise you unlock by hand.
    </p>
    <Input id="auto-unseal-password" type="password" label="Barrier password" bind:value={autoUnsealPassword} />
    {#if autoUnsealError}<p class="text-body-small error-text" role="alert">{autoUnsealError}</p>{/if}
  </div>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showAutoUnseal = false)}>Cancel</Button>
    <Button variant="primary" loading={busy === 'auto-unseal'} on:click={submitAutoUnseal}>Enable</Button>
  </svelte:fragment>
</Modal>

<Modal bind:open={showRotate} title="Rotate Policy Authority" maxWidth="440px">
  <p class="text-body-medium">
    A new TPM-resident authority re-approves every policy, and the old one stops authorizing anything.
    No key or sealed object is re-keyed.
  </p>
  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (showRotate = false)}>Cancel</Button>
    <Button variant="primary" loading={busy === 'rotate'} on:click={submitRotate}>Rotate</Button>
  </svelte:fragment>
</Modal>

<style>
  .section {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .section-heading-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }

  .section-heading {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
  }

  .heading-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .mode-label,
  .description {
    color: var(--color-on-surface-variant);
  }

  .loading-row {
    display: flex;
    justify-content: center;
    padding: 24px;
  }

  .error-text {
    color: var(--color-error);
  }

  .policy-table {
    width: 100%;
    border-collapse: collapse;
  }

  .policy-table th,
  .policy-table td {
    text-align: left;
    padding: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .builtin-tag {
    margin-left: 6px;
    padding: 2px 6px;
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-high);
  }

  .count-link {
    background: none;
    border: none;
    color: var(--color-primary);
    cursor: pointer;
    padding: 0;
  }

  .row-actions {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form-select {
    padding: 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-outline);
    background-color: var(--color-surface);
    color: var(--color-on-surface);
  }

  .mode-tabs {
    display: flex;
    gap: 4px;
  }

  .mode-tab {
    padding: 6px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: none;
    color: var(--color-on-surface);
    cursor: pointer;
  }

  .mode-tab.active {
    background-color: var(--color-secondary-container);
    color: var(--color-on-secondary-container);
  }

  .branch {
    display: flex;
    flex-direction: column;
    gap: 8px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    padding: 8px;
  }

  .condition {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .value-cell {
    word-break: break-all;
  }

  .object-list {
    margin: 0;
    padding-left: 16px;
  }
</style>
