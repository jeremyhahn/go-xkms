/**
 * clickOutside is a Svelte action that dispatches a custom "clickoutside" event
 * when a pointer-down event occurs outside the element the action is attached to.
 *
 * Usage:
 *   <div use:clickOutside on:clickoutside={() => open = false}>...</div>
 */
export function clickOutside(node: HTMLElement): { destroy(): void } {
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
