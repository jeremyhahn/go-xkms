<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import { mdiClose, mdiAccountPlus } from '@mdi/js';
  import type { TeamInfo, CreateTeamParams } from '$lib/api/backend';

  export let open: boolean = false;
  export let mode: 'create' | 'edit' = 'create';
  export let team: TeamInfo | null = null;

  const dispatch = createEventDispatcher<{
    save: { name: string; members: string[] };
  }>();

  let teamName = '';
  let members: string[] = [];
  let newMemberInput = '';
  let nameError = '';

  // Re-initialise form fields whenever the dialog opens or the team prop changes.
  $: if (open) {
    if (mode === 'edit' && team) {
      teamName = team.name;
      members = [...(team.members ?? [])];
    } else {
      teamName = '';
      members = [];
    }
    newMemberInput = '';
    nameError = '';
  }

  function validateName(): boolean {
    if (!teamName.trim()) {
      nameError = 'Team name is required';
      return false;
    }
    nameError = '';
    return true;
  }

  function handleAddMember(): void {
    const id = newMemberInput.trim();
    if (!id) return;
    if (members.includes(id)) {
      newMemberInput = '';
      return;
    }
    members = [...members, id];
    newMemberInput = '';
  }

  function handleRemoveMember(userID: string): void {
    members = members.filter(m => m !== userID);
  }

  function handleAddMemberKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddMember();
    }
  }

  function handleSubmit(): void {
    if (!validateName()) return;
    dispatch('save', { name: teamName.trim(), members });
  }

  function handleClose(): void {
    open = false;
  }
</script>

<Modal
  bind:open
  title={mode === 'create' ? 'New Team' : 'Manage Team'}
  maxWidth="480px"
  persistent={false}
>
  <div class="team-form">
    <div class="form-field">
      <label class="form-label" for="team-name-input">Team Name</label>
      <input
        id="team-name-input"
        type="text"
        class="form-input"
        class:form-input--error={!!nameError}
        bind:value={teamName}
        placeholder="e.g. Engineering"
        on:input={() => { if (nameError) validateName(); }}
      />
      {#if nameError}
        <span class="form-error">{nameError}</span>
      {/if}
    </div>

    <div class="form-field">
      <span class="form-label">Members</span>

      {#if members.length > 0}
        <ul class="member-list" aria-label="Team members">
          {#each members as userID (userID)}
            <li class="member-item">
              <span class="member-id">{userID}</span>
              <button
                class="member-remove"
                type="button"
                aria-label="Remove {userID}"
                on:click={() => handleRemoveMember(userID)}
              >
                <Icon path={mdiClose} size={16} />
              </button>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="no-members">No members yet.</p>
      {/if}

      <div class="add-member-row">
        <input
          type="text"
          class="form-input add-member-input"
          bind:value={newMemberInput}
          placeholder="User ID or username"
          on:keydown={handleAddMemberKeydown}
        />
        <button
          class="add-member-btn"
          type="button"
          aria-label="Add member"
          disabled={!newMemberInput.trim()}
          on:click={handleAddMember}
        >
          <Icon path={mdiAccountPlus} size={18} />
          <span>Add</span>
        </button>
      </div>
    </div>
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleClose}>Cancel</Button>
    <Button variant="primary" on:click={handleSubmit} disabled={!teamName.trim()}>
      {mode === 'create' ? 'Create' : 'Save'}
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .team-form {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-label {
    font-size: 13px;
    font-weight: 500;
    color: var(--color-on-surface-variant);
  }

  .form-input {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    transition: border-color var(--transition-fast);
    width: 100%;
    box-sizing: border-box;
  }

  .form-input:focus {
    border-color: var(--color-primary);
  }

  .form-input--error {
    border-color: var(--color-error);
  }

  .form-error {
    font-size: 12px;
    color: var(--color-error);
  }

  /* Member list */
  .member-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
    max-height: 160px;
    overflow-y: auto;
  }

  .member-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
    background: var(--color-surface-container);
    font-size: 13px;
    color: var(--color-on-surface);
    gap: 8px;
  }

  .member-id {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
    font-family: var(--font-mono, monospace);
  }

  .member-remove {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    flex-shrink: 0;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .member-remove:hover {
    background: var(--color-error-container);
    color: var(--color-error);
  }

  .no-members {
    font-size: 13px;
    color: var(--color-on-surface-variant);
    opacity: 0.7;
    margin: 0;
    padding: 4px 0;
  }

  /* Add member row */
  .add-member-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .add-member-input {
    flex: 1;
  }

  .add-member-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0 14px;
    height: 40px;
    border: 1px solid var(--color-outline);
    border-radius: var(--radius-xl);
    background: transparent;
    color: var(--color-primary);
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
    transition: background-color var(--transition-fast);
  }

  .add-member-btn:hover:not(:disabled) {
    background: var(--color-primary-95, var(--color-surface-container));
  }

  .add-member-btn:disabled {
    opacity: 0.38;
    cursor: not-allowed;
  }
</style>
