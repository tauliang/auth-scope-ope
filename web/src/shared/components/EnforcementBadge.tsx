import type { ReceiptEnforcementSummary } from '../api/generated';

// The only honest enforcement levels. These labels are rendered exactly
// as received in authenticated evidence; OPE never invents, upgrades,
// or softens them.
const HONEST_LEVELS = new Set(['observed', 'checked', 'enforced']);

// EnforcementBadge renders one enforcement level label from
// authenticated evidence. A level outside the honest set renders
// nothing: inventing an enforcement claim would be dishonest, and a
// missing label is safer than a wrong one.
export function EnforcementBadge({
  level,
  scope,
}: {
  level: string;
  scope?: string;
}) {
  if (!HONEST_LEVELS.has(level)) {
    return null;
  }
  return (
    <span className="enforcement-badge" data-level={level} title={scope ? `Scope: ${scope}` : undefined}>
      {level}
    </span>
  );
}

// EnforcementList renders the historical enforcement summary carried by
// a verified receipt. Entries whose level is not one of the honest
// three are skipped rather than relabeled.
export function EnforcementList({ entries }: { entries: ReceiptEnforcementSummary[] }) {
  const honest = entries.filter((entry) => HONEST_LEVELS.has(entry.level));
  if (honest.length === 0) {
    return <p>No enforcement evidence recorded.</p>;
  }
  return (
    <ul aria-label="Historical enforcement">
      {honest.map((entry, index) => (
        <li key={index}>
          {entry.scope}: <EnforcementBadge level={entry.level} scope={entry.scope} />
        </li>
      ))}
    </ul>
  );
}

export default EnforcementBadge;
