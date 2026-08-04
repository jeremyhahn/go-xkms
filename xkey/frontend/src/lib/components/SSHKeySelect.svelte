<script lang="ts">
  import { isWailsAvailable, callBackend, SSHLocalService } from '$lib/api/backend';
  import type { SSHKeyInfo, SSHLocalKeyInfo } from '$lib/api/backend';

  /** Input id for the dialog's <label for=...>. */
  export let id: string = 'ssh-key-select';
  /** Selected xkey-managed key name ('' when none / local). */
  export let keyName: string = '';
  /** '' = xkey-managed key; 'local' = operator's agent/~/.ssh key. */
  export let keySource: '' | 'local' = '';
  /** Local key pin: identity file path or "agent:<fp>" ('' when managed). */
  export let localIdentity: string = '';

  interface KeyOption {
    /** Stable option identity for keyed each-blocks and selection. */
    id: string;
    group: 'none' | 'xkey' | 'local';
    label: string;
    detail: string;
    /** Concatenated lowercase haystack for type-to-search filtering. */
    search: string;
    keyName: string;
    keySource: '' | 'local';
    localIdentity: string;
  }

  const noneOption: KeyOption = {
    id: 'none',
    group: 'none',
    label: 'No key',
    detail: 'agent / password auth',
    search: 'no key none password agent',
    keyName: '',
    keySource: '',
    localIdentity: '',
  };

  let options: KeyOption[] = [noneOption];
  let loaded = false;
  let open = false;
  let query = '';
  let highlighted = 0;
  let inputEl: HTMLInputElement;

  $: filtered = filterOptions(options, query);
  $: if (highlighted >= filtered.length) highlighted = Math.max(0, filtered.length - 1);

  function filterOptions(all: KeyOption[], q: string): KeyOption[] {
    const needle = q.trim().toLowerCase();
    if (!needle) return all;
    return all.filter((o) => o.search.includes(needle));
  }

  function xkeyOption(k: SSHKeyInfo): KeyOption {
    const backend = k.backend || 'software';
    return {
      id: `xkey:${k.name}`,
      group: 'xkey',
      label: k.name,
      detail: `${k.algorithm} · ${backend}`,
      search: `${k.name} ${k.algorithm} ${backend} ${k.comment} ${k.fingerprint}`.toLowerCase(),
      keyName: k.name,
      keySource: '',
      localIdentity: '',
    };
  }

  function localOption(k: SSHLocalKeyInfo): KeyOption {
    const identity = k.path || `agent:${k.fingerprint}`;
    const name = k.path ? (k.path.split('/').pop() ?? k.path) : k.fingerprint;
    const where = k.source === 'agent' ? 'ssh-agent' : 'file';
    return {
      id: `local:${identity}`,
      group: 'local',
      label: k.comment || name,
      detail: `${k.key_type} · ${where}${k.path ? ` · ${k.path}` : ''}`,
      search: `${k.comment} ${k.path} ${k.key_type} ${k.fingerprint} ${where} local`.toLowerCase(),
      keyName: '',
      keySource: 'local',
      localIdentity: identity,
    };
  }

  async function loadOptions(): Promise<void> {
    if (loaded) return;
    loaded = true;
    if (!isWailsAvailable()) return;
    const [managed, local] = await Promise.all([
      callBackend<SSHKeyInfo[]>('SSHService', 'ListKeys'),
      SSHLocalService.listLocalKeys(),
    ]);
    options = [
      noneOption,
      ...(managed ?? []).map(xkeyOption),
      ...(local ?? []).map(localOption),
    ];
  }

  /** The option matching the current bound selection, if it is in the list. */
  $: selected =
    options.find((o) =>
      keySource === 'local' ? o.keySource === 'local' && o.localIdentity === localIdentity : o.keySource === '' && o.keyName === keyName
    ) ?? null;

  /** Label shown in the closed input — derived from bound values even before
   *  the lists load (e.g. an edited profile referencing a key). */
  $: displayLabel = selected
    ? selected.label
    : keySource === 'local' && localIdentity
      ? (localIdentity.startsWith('agent:') ? localIdentity.slice('agent:'.length) : (localIdentity.split('/').pop() ?? localIdentity))
      : keyName || noneOption.label;

  function openDropdown(): void {
    void loadOptions();
    query = '';
    highlighted = 0;
    open = true;
  }

  function select(option: KeyOption): void {
    keyName = option.keyName;
    keySource = option.keySource;
    localIdentity = option.localIdentity;
    open = false;
    query = '';
    inputEl?.blur();
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (!open && (e.key === 'ArrowDown' || e.key === 'Enter')) {
      e.preventDefault();
      openDropdown();
      return;
    }
    if (!open) return;
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        highlighted = Math.min(highlighted + 1, filtered.length - 1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        highlighted = Math.max(highlighted - 1, 0);
        break;
      case 'Enter':
        e.preventDefault();
        if (filtered[highlighted]) select(filtered[highlighted]);
        break;
      case 'Escape':
        e.preventDefault();
        open = false;
        query = '';
        inputEl?.blur();
        break;
    }
  }

  function handleInput(e: Event): void {
    const target = e.currentTarget as HTMLInputElement;
    query = target.value;
    if (!open) openDropdown();
    highlighted = 0;
  }

  function handleFocus(): void {
    openDropdown();
  }

  function handleBlur(e: FocusEvent): void {
    // Keep the dropdown open when focus moves into it (option mousedown).
    const next = e.relatedTarget as HTMLElement | null;
    if (next?.closest?.(`[data-owner="${id}"]`)) return;
    open = false;
    query = '';
  }

  function groupTitle(group: KeyOption['group']): string {
    return group === 'xkey' ? 'xKey keys' : 'Local keys';
  }

  /** Groups preserved in filtered order, with headers between group changes. */
  $: rows = filtered.map((o, i) => ({
    option: o,
    index: i,
    header: o.group !== 'none' && (i === 0 || filtered[i - 1].group !== o.group) ? groupTitle(o.group) : null,
  }));
</script>

<div class="key-select" data-testid="ssh-key-select">
  <input
    {id}
    bind:this={inputEl}
    class="text-input key-select-input"
    type="text"
    role="combobox"
    aria-expanded={open}
    aria-controls="{id}-listbox"
    aria-autocomplete="list"
    autocomplete="off"
    placeholder="Search keys…"
    data-testid="ssh-key-select-input"
    value={open ? query : displayLabel}
    on:focus={handleFocus}
    on:blur={handleBlur}
    on:keydown={handleKeydown}
    on:input={handleInput}
  />
  <span class="key-select-caret" aria-hidden="true">▾</span>

  {#if open}
    <ul class="key-select-list" id="{id}-listbox" role="listbox" data-owner={id} data-testid="ssh-key-select-list">
      {#if filtered.length === 0}
        <li class="key-select-empty text-body-medium" data-testid="ssh-key-select-empty">No keys match “{query}”</li>
      {/if}
      {#each rows as row (row.option.id)}
        {#if row.header}
          <li class="key-select-group text-label-small" role="presentation">{row.header}</li>
        {/if}
        <li
          class="key-select-option"
          class:key-select-option--highlighted={row.index === highlighted}
          class:key-select-option--selected={selected?.id === row.option.id}
          role="option"
          aria-selected={selected?.id === row.option.id}
          tabindex="-1"
          data-testid="ssh-key-option-{row.option.id}"
          on:mousedown|preventDefault={() => select(row.option)}
          on:mouseenter={() => (highlighted = row.index)}
        >
          <span class="key-select-option-label">{row.option.label}</span>
          <span class="key-select-option-detail">{row.option.detail}</span>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .key-select {
    position: relative;
    width: 100%;
  }

  .text-input {
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    width: 100%;
    box-sizing: border-box;
  }

  .text-input:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .key-select-input {
    padding-right: 28px;
    cursor: pointer;
  }

  .key-select-input:focus {
    cursor: text;
  }

  .key-select-caret {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    pointer-events: none;
    color: var(--color-on-surface-variant);
    font-size: 12px;
  }

  .key-select-list {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    right: 0;
    z-index: 30;
    max-height: 260px;
    overflow-y: auto;
    margin: 0;
    padding: 4px;
    list-style: none;
    background-color: var(--color-surface-container-high);
    border: 1px solid var(--color-outline);
    border-radius: var(--radius-sm);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.25);
  }

  .key-select-group {
    padding: 6px 10px 2px;
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .key-select-option {
    display: flex;
    flex-direction: column;
    gap: 1px;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
    cursor: pointer;
  }

  .key-select-option--highlighted {
    background-color: var(--color-surface-container-highest);
  }

  .key-select-option--selected .key-select-option-label {
    color: var(--color-primary);
  }

  .key-select-option-label {
    font-size: 14px;
    color: var(--color-on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .key-select-option-detail {
    font-size: 12px;
    color: var(--color-on-surface-variant);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .key-select-empty {
    padding: 10px;
    color: var(--color-on-surface-variant);
  }
</style>
