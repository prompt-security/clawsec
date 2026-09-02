import type { AdvisoryPlatformFilter } from '../types';

export type FilterTabOption<T extends string> = {
  value: T;
  label: string;
};

/**
 * Every filter tab selects the same way: acid green on ink. Severity and
 * platform colour coding belongs to the advisory cards, where each hue sits on
 * a dark surface and stays legible — on a white page those same tints wash out.
 */
const TAB_ACTIVE = 'bg-clawd-800 text-clawd-green border-2 border-clawd-green';
const TAB_INACTIVE =
  'bg-white text-gray-600 border-2 border-clawd-700/60 hover:border-clawd-600 hover:text-clawd-600';

export const PLATFORM_TABS = [
  { value: 'all', label: 'All Platforms' },
  { value: 'openclaw', label: 'OpenClaw' },
  { value: 'nanoclaw', label: 'NanoClaw' },
  { value: 'hermes', label: 'Hermes' },
  { value: 'picoclaw', label: 'Picoclaw' },
  { value: 'other', label: 'Other' },
] as const satisfies ReadonlyArray<FilterTabOption<AdvisoryPlatformFilter>>;

export const FilterTabs = <T extends string>({
  tabs,
  selected,
  onSelect,
  ariaLabel,
  className = 'mb-8',
}: {
  tabs: ReadonlyArray<FilterTabOption<T>>;
  selected: T;
  onSelect: (value: T) => void;
  ariaLabel: string;
  className?: string;
}) => (
  <div role="group" aria-label={ariaLabel} className={`flex flex-wrap justify-center gap-3 ${className}`}>
    {tabs.map(({ value, label }) => (
      <button
        key={value}
        type="button"
        aria-pressed={selected === value}
        onClick={() => onSelect(value)}
        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors ${
          selected === value ? TAB_ACTIVE : TAB_INACTIVE
        }`}
      >
        {label}
      </button>
    ))}
  </div>
);
