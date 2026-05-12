/** A single action item in the ActionMenu overflow list. */
export interface ActionItem {
  /** Render a horizontal divider instead of an item when true. */
  divider?: true;
  label?: string;
  icon?: string;
  onClick?: () => void;
  /** Renders the item in error/danger colour. */
  destructive?: boolean;
  /** Forwarded as data-testid on the menu item button. */
  testid?: string;
}

/** The primary action rendered as a solid Button beside the kebab trigger. */
export interface PrimaryAction {
  label: string;
  icon?: string;
  onClick: () => void;
  variant?: 'primary' | 'secondary' | 'tertiary' | 'outline';
  loading?: boolean;
  testid?: string;
}
