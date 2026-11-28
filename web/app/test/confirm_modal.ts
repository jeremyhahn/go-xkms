import { fireEvent, screen, within } from "@testing-library/svelte";
import { vi } from "vitest";

// Destructive actions confirm through components/Modal.svelte, never
// window.confirm (Codex finding 14 on row 2082). spyWindowConfirm answers
// "yes" so a view that still calls window.confirm acts at once and fails the
// "nothing before the confirm" assertion instead of hanging.
export function spyWindowConfirm() {
  return vi.spyOn(window, "confirm").mockReturnValue(true);
}

/** confirmDialog returns the open confirm dialog. */
export async function confirmDialog(): Promise<HTMLElement> {
  return screen.findByRole("dialog");
}

/** answerConfirm clicks the named button inside the open confirm dialog. */
export async function answerConfirm(name: string): Promise<void> {
  const dialog = await confirmDialog();
  await fireEvent.click(within(dialog).getByRole("button", { name }));
}
