import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { EnforcementBadge, EnforcementList } from './EnforcementBadge';

describe('EnforcementBadge', () => {
  it.each(['observed', 'checked', 'enforced'])('renders the honest level %s', (level) => {
    const { container } = render(<EnforcementBadge level={level} scope="git-actions" />);
    expect(container.textContent).toBe(level);
  });

  it.each(['blocked', 'pending', 'trusted', 'unknown', ''])(
    'renders nothing for a dishonest or unknown level %s',
    (level) => {
      const { container } = render(<EnforcementBadge level={level} scope="git-actions" />);
      expect(container).toBeEmptyDOMElement();
    },
  );

  it('never upgrades a level', () => {
    render(<EnforcementBadge level="observed" />);
    expect(screen.getByText('observed')).toBeDefined();
    expect(screen.queryByText('enforced')).toBeNull();
  });
});

describe('EnforcementList', () => {
  it('skips entries whose level is not honest instead of relabeling them', () => {
    render(
      <EnforcementList
        entries={[
          { scope: 'git-actions', level: 'enforced' },
          { scope: 'cli', level: 'magical' },
        ]}
      />,
    );
    expect(screen.getByText('enforced')).toBeDefined();
    expect(screen.queryByText('magical')).toBeNull();
  });

  it('renders a plain note when no honest entries exist', () => {
    render(<EnforcementList entries={[{ scope: 'cli', level: 'magical' }]} />);
    expect(screen.getByText('No enforcement evidence recorded.')).toBeDefined();
  });
});
