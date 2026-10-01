/**
 * clickOutside is a Svelte action that dispatches a custom "clickoutside" event
 * when a pointer-down event occurs outside the element the action is attached to.
 *
 * Usage:
 *   <div use:clickOutside on:clickoutside={() => open = false}>...</div>
 *
 * The return type declares the event to Svelte's type checker, so
 * on:clickoutside type-checks on the element the action is used on.
 */
import type { ActionReturn } from 'svelte/action';

/** The events the clickOutside action adds to its element. */
export interface ClickOutsideAttributes {
  'on:clickoutside'?: (event: CustomEvent<void>) => void;
}

export function clickOutside(node: HTMLElement): ActionReturn<undefined, ClickOutsideAttributes> {
  function handlePointerDown(event: PointerEvent): void {
    if (!node.contains(event.target as Node)) {
      node.dispatchEvent(new CustomEvent('clickoutside'));
    }
  }

  document.addEventListener('pointerdown', handlePointerDown, true);

  return {
    destroy(): void {
      document.removeEventListener('pointerdown', handlePointerDown, true);
    },
  };
}
