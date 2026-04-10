<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { slide } from 'svelte/transition';
  import Icon from './Icon.svelte';
  import {
    mdiFolder,
    mdiFolderOpen,
    mdiChevronRight,
    mdiDotsVertical,
  } from '$lib/utils/icons';

  interface FolderNode {
    name: string;
    path: string;
    children: FolderNode[];
  }

  export let node: FolderNode;
  export let depth: number = 0;
  export let selectedFolder: string | null = null;
  export let expandedPaths: Set<string>;
  export let getSubtreeCount: (path: string) => number;

  const dispatch = createEventDispatcher<{
    select: string;
    toggleExpand: string;
    openContextMenu: { event: MouseEvent; path: string };
  }>();

  $: hasChildren = node.children.length > 0;
  $: isExpanded = expandedPaths.has(node.path);
  $: count = getSubtreeCount(node.path);
  $: isSelected = selectedFolder === node.path;

  function handleClick(): void {
    dispatch('select', node.path);
  }

  function handleToggleExpand(e: MouseEvent): void {
    e.stopPropagation();
    dispatch('toggleExpand', node.path);
  }

  function handleContextMenu(e: MouseEvent): void {
    e.preventDefault();
    dispatch('openContextMenu', { event: e, path: node.path });
  }

  function handleKeyDown(e: KeyboardEvent): void {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      dispatch('select', node.path);
    }
  }

  function handleExpandKeyDown(e: KeyboardEvent): void {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      e.stopPropagation();
      dispatch('toggleExpand', node.path);
    }
  }

  // Forward events from children
  function forwardSelect(e: CustomEvent<string>): void {
    dispatch('select', e.detail);
  }

  function forwardToggleExpand(e: CustomEvent<string>): void {
    dispatch('toggleExpand', e.detail);
  }

  function forwardOpenContextMenu(e: CustomEvent<{ event: MouseEvent; path: string }>): void {
    dispatch('openContextMenu', e.detail);
  }
</script>

<div class="tree-branch">
  <div
    class="tree-item"
    class:selected={isSelected}
    on:click={handleClick}
    on:contextmenu={handleContextMenu}
    on:keydown={handleKeyDown}
    role="treeitem"
    tabindex="0"
    aria-expanded={hasChildren ? isExpanded : undefined}
    aria-selected={isSelected}
  >
    <span class="indent-guide" style="width: {depth * 16 + 4}px;"></span>
    {#if hasChildren}
      <button
        class="chevron-btn"
        class:expanded={isExpanded}
        on:click={handleToggleExpand}
        on:keydown|stopPropagation={handleExpandKeyDown}
        aria-label={isExpanded ? 'Collapse' : 'Expand'}
        tabindex="-1"
      >
        <Icon path={mdiChevronRight} size={16} />
      </button>
    {:else}
      <span class="chevron-spacer"></span>
    {/if}
    <span class="item-icon">
      <Icon path={isExpanded && hasChildren ? mdiFolderOpen : mdiFolder} size={18} />
    </span>
    <span class="item-label">{node.name}</span>
    {#if count > 0}
      <span class="item-count">{count}</span>
    {/if}
    <button
      class="menu-btn"
      on:click|stopPropagation={handleContextMenu}
      aria-label="Folder options for {node.name}"
      tabindex="-1"
    >
      <Icon path={mdiDotsVertical} size={16} />
    </button>
  </div>

  {#if hasChildren && isExpanded}
    <div class="tree-children" role="group" transition:slide={{ duration: 150 }}>
      {#each node.children as child (child.path)}
        <svelte:self
          node={child}
          depth={depth + 1}
          {selectedFolder}
          {expandedPaths}
          {getSubtreeCount}
          on:select={forwardSelect}
          on:toggleExpand={forwardToggleExpand}
          on:openContextMenu={forwardOpenContextMenu}
        />
      {/each}
    </div>
  {/if}
</div>

<style>
  /* ---- Tree item (row) ---- */
  .tree-item {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 6px 8px 6px 0;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1;
    width: 100%;
    text-align: left;
    border-radius: var(--radius-sm);
    margin: 0 4px;
    box-sizing: border-box;
    transition: background-color 120ms ease, color 120ms ease;
    position: relative;
    min-height: 32px;
  }

  .tree-item:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .tree-item.selected {
    background-color: var(--color-primary-container, var(--color-surface-variant));
    color: var(--color-on-primary-container, var(--color-primary));
    font-weight: 500;
  }

  .tree-item:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: -2px;
  }

  /* ---- Indentation guide ---- */
  .indent-guide {
    flex-shrink: 0;
    display: inline-block;
  }

  /* ---- Chevron expand/collapse button ---- */
  .chevron-btn {
    width: 18px;
    height: 18px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    padding: 0;
    transition: transform 150ms ease, background-color 120ms ease;
    transform: rotate(0deg);
  }

  .chevron-btn.expanded {
    transform: rotate(90deg);
  }

  .chevron-btn:hover {
    background-color: var(--color-surface-variant);
  }

  .chevron-spacer {
    width: 18px;
    flex-shrink: 0;
    display: inline-block;
  }

  /* ---- Folder icon ---- */
  .item-icon {
    display: flex;
    flex-shrink: 0;
    color: var(--color-on-surface-variant);
  }

  .selected .item-icon {
    color: var(--color-on-primary-container, var(--color-primary));
  }

  /* ---- Label ---- */
  .item-label {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  /* ---- Count badge ---- */
  .item-count {
    font-size: 11px;
    font-weight: 500;
    padding: 0 5px;
    min-width: 18px;
    height: 18px;
    line-height: 18px;
    text-align: center;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    flex-shrink: 0;
  }

  .selected .item-count {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
  }

  /* ---- Three-dot menu button ---- */
  .menu-btn {
    width: 22px;
    height: 22px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    opacity: 0;
    transition: opacity 120ms ease, background-color 120ms ease;
    padding: 0;
    margin-left: 2px;
  }

  .tree-item:hover .menu-btn {
    opacity: 1;
  }

  .menu-btn:hover {
    background-color: var(--color-surface-variant);
  }

  /* ---- Tree nesting / children ---- */
  .tree-branch {
    position: relative;
  }

  .tree-children {
    overflow: hidden;
  }
</style>
