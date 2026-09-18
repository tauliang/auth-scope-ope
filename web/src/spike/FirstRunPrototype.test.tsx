import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import FirstRunPrototype, { PROTOTYPE_STEPS } from './FirstRunPrototype';

describe('FirstRunPrototype', () => {
  it('walks the full click-through to a simulated confirmed RunID', async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    render(<FirstRunPrototype onDone={onDone} />);

    for (let i = 0; i < PROTOTYPE_STEPS.length; i++) {
      expect(screen.getByLabelText('progress')).toHaveTextContent(
        `Step ${i + 1} of ${PROTOTYPE_STEPS.length}`,
      );
      await user.click(screen.getByRole('button', { name: i === PROTOTYPE_STEPS.length - 1 ? 'Finish' : 'Continue' }));
    }

    expect(onDone).toHaveBeenCalledWith(PROTOTYPE_STEPS.length);
    expect(screen.getByText(/Simulated confirmed RunID/)).toBeInTheDocument();
  });

  it('covers every planned step exactly once', () => {
    expect(PROTOTYPE_STEPS).toHaveLength(10);
    expect(new Set(PROTOTYPE_STEPS).size).toBe(PROTOTYPE_STEPS.length);
  });
});
