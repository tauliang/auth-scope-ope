import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ProblemPanel, problemPanelForError } from './ProblemPanel';
import { ApiError } from '../api/client';

describe('ProblemPanel', () => {
  it('renders the blocked condition and recovery action', () => {
    render(
      <ProblemPanel
        title="A conflicting record already exists."
        detail="The request was already recorded."
      />,
    );
    expect(screen.getByText('A conflicting record already exists.')).toBeDefined();
    expect(screen.getByText('The request was already recorded.')).toBeDefined();
  });

  it('renders without detail and wires the action buttons', () => {
    let retried = 0;
    let dismissed = 0;
    render(
      <ProblemPanel
        title="Something failed."
        onRetry={() => {
          retried++;
        }}
        onDismiss={() => {
          dismissed++;
        }}
      />,
    );
    screen.getByText('Try again').click();
    screen.getByText('Dismiss').click();
    expect(retried).toBe(1);
    expect(dismissed).toBe(1);
  });
});

describe('problemPanelForError', () => {
  it.each([
    [400, 'Check the entered values', true],
    [401, 'Unlock again with your passkey', false],
    [403, 'Review what the pass allows', false],
    [404, 'Go back and pick the item again', false],
    [409, 'Do not send the request again', false],
    [412, 'Refresh the issue or proposal', false],
    [422, 'Start the decision over', false],
    [429, 'Wait a minute', true],
    [503, 'Wait a moment', true],
  ])(
    'maps status %d to a safe recovery action',
    (status, action, retryable) => {
      const panel = problemPanelForError(new ApiError(status, 'failed', 'Request failed.'));
      expect(panel.title).toBe('Request failed.');
      expect(panel.detail).toContain(action);
      expect(panel.retryable).toBe(retryable);
    },
  );

  it('falls back to a generic title and no guidance for unknown statuses', () => {
    const panel = problemPanelForError(new ApiError(418, '', ''));
    expect(panel.title).toBe('The request failed (418).');
    expect(panel.detail).toBeUndefined();
    expect(panel.retryable).toBe(false);
  });

  it('never marks an ambiguous mutation as retryable', () => {
    for (const status of [403, 404, 409, 412, 422]) {
      const panel = problemPanelForError(new ApiError(status, 'failed', 'Request failed.'));
      expect(panel.retryable).toBe(false);
    }
  });

  it('never suggests credentials, bypasses, or duplicate mutations', () => {
    const bodies = [400, 401, 403, 404, 409, 412, 422, 503]
      .map((status) => {
        const panel = problemPanelForError(new ApiError(status, 'failed', 'Request failed.'));
        return `${panel.title} ${panel.detail ?? ''}`;
      })
      .join(' ')
      .toLowerCase();
    for (const forbidden of [
      'personal access token',
      'token',
      'bypass',
      'disable the check',
      'launch the agent',
    ]) {
      expect(bodies).not.toContain(forbidden);
    }
  });

  it('handles non-API failures with a conservative default', () => {
    const panel = problemPanelForError(new Error('boom'));
    expect(panel.title).toBe('The request could not be completed.');
    expect(panel.retryable).toBe(true);
  });
});
