import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ApiError,
  createMissionPassDraft,
  fetchMissionPass,
  newIdempotencyKey,
  reviseMissionPassDraft,
} from '../../shared/api/client';
import type { MissionPassReview as MissionPassReviewPayload } from '../../shared/api/generated';
import { ApprovalCard } from './ApprovalCard';

// Fixed template values for presentation. Source of truth is
// internal/missionpass/template.go; these never vary per draft, so the
// review renders them directly instead of asking AuthScope again.
const TEMPLATE = {
  can: [
    'Work on the generated mission branch',
    "Run the repository's configured tests",
    'Open one pull request',
  ],
  willAsk: ['Any operation outside the approved grant needs a one-time founder-approved expansion'],
  cannot: [
    'Touch the default branch',
    'Modify protected paths or workflows',
    'Deploy or change release targets',
    'Read secrets',
    'Administer the repository',
  ],
  protectedPaths: [
    '.github/workflows/',
    '.github/actions/',
    'Dockerfile',
    'docker-compose.yml',
    '.env',
    'secrets/',
  ],
  enforcementLabels: [
    'GitHub actions are brokered and enforced by AuthScope',
    'Agent runtime actions are compiled and enforced by AuthScope',
  ],
  maxTtlHours: 2,
  maxBudgetMicros: 20_000_000,
  maxPendingExpansions: 1,
} as const;

const DEFAULT_BUDGET_MICROS = 10_000_000;
const DEFAULT_TTL_MS = 60 * 60 * 1000;

function microsToDollars(micros: number): string {
  return (micros / 1_000_000).toFixed(2);
}

function dollarsToMicros(dollars: string): number | null {
  const parsed = Number.parseFloat(dollars);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.round(parsed * 1_000_000);
}

// toInputValue renders an RFC 3339 timestamp as a datetime-local value in
// UTC; fromInputValue interprets the field back as UTC.
function toInputValue(iso: string): string {
  return new Date(iso).toISOString().slice(0, 16);
}

function fromInputValue(value: string): string | null {
  const parsed = new Date(`${value}:00Z`);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.title || `Request failed (${err.status}).`;
  return 'The request could not be completed.';
}

type ReviseState =
  | { kind: 'idle' }
  | { kind: 'revising' }
  | { kind: 'error'; message: string };

// MissionPassReview renders exactly one shaped mission proposal for
// founder review. Objective, acceptance criteria, digests, kit identity,
// and enforcement are read-only; only expiry and the aggregate budget
// are editable, and only as narrowing edits. Changing either value marks
// the visible review stale until the revision returns.
export function MissionPassReview({
  review,
  onRevised,
}: {
  review: MissionPassReviewPayload;
  onRevised: (next: MissionPassReviewPayload) => void;
}) {
  const [expiryInput, setExpiryInput] = useState(() => toInputValue(review.limits.expires_at));
  const [budgetInput, setBudgetInput] = useState(() => microsToDollars(review.limits.max_aggregate_cost_micros));
  const [reviseState, setReviseState] = useState<ReviseState>({ kind: 'idle' });
  const [refreshing, setRefreshing] = useState(false);

  // A fresh revision resets the editable fields to the new limits.
  useEffect(() => {
    setExpiryInput(toInputValue(review.limits.expires_at));
    setBudgetInput(microsToDollars(review.limits.max_aggregate_cost_micros));
    setReviseState({ kind: 'idle' });
  }, [review.pass_id, review.draft_version]);

  const currentExpiry = review.limits.expires_at;
  const currentBudget = review.limits.max_aggregate_cost_micros;
  const stale =
    expiryInput !== toInputValue(currentExpiry) ||
    dollarsToMicros(budgetInput) !== currentBudget;

  function validate(): string | null {
    // Each editable limit may only narrow; leaving a field unchanged is
    // always fine.
    if (expiryInput !== toInputValue(currentExpiry)) {
      const expiryIso = fromInputValue(expiryInput);
      if (!expiryIso) return 'Enter a valid expiry date and time.';
      const expiryMs = Date.parse(expiryIso);
      if (expiryMs <= Date.now()) return 'Expiry must be in the future.';
      if (expiryMs > Date.now() + TEMPLATE.maxTtlHours * 3_600_000)
        return `Expiry cannot exceed the ${TEMPLATE.maxTtlHours}-hour template maximum.`;
      if (expiryMs >= Date.parse(currentExpiry))
        return 'Expiry can only move earlier, not later.';
    }
    if (budgetInput !== microsToDollars(currentBudget)) {
      const budgetMicros = dollarsToMicros(budgetInput);
      if (budgetMicros === null) return 'Enter a valid budget in dollars.';
      if (budgetMicros > TEMPLATE.maxBudgetMicros)
        return `Budget cannot exceed the $${microsToDollars(TEMPLATE.maxBudgetMicros)} template maximum.`;
      if (budgetMicros >= currentBudget) return 'Budget can only move lower, not higher.';
    }
    return null;
  }

  async function revise() {
    const problem = validate();
    if (problem || !stale) {
      setReviseState({ kind: 'error', message: problem ?? 'Change a limit to revise.' });
      return;
    }
    setReviseState({ kind: 'revising' });
    try {
      const next = await reviseMissionPassDraft(review.pass_id, {
        expected_store_revision: review.store_revision,
        expected_draft_version: review.draft_version,
        expires_at: fromInputValue(expiryInput) as string,
        max_aggregate_cost_micros: dollarsToMicros(budgetInput) as number,
      });
      onRevised(next);
    } catch (err) {
      const recoverable = err instanceof ApiError && (err.status === 409 || err.status >= 500);
      setReviseState({
        kind: 'error',
        message: recoverable
          ? `${errorMessage(err)} Refresh the review and try again.`
          : errorMessage(err),
      });
    }
  }

  async function refresh() {
    setRefreshing(true);
    try {
      onRevised(await fetchMissionPass(review.pass_id));
    } catch (err) {
      setReviseState({ kind: 'error', message: errorMessage(err) });
    } finally {
      setRefreshing(false);
    }
  }

  const validationError = stale ? validate() : null;

  return (
    <article aria-label="Mission proposal review">
      <h3>Proposal review</h3>
      {review.reconciliation === 'pending' && (
        <p role="alert">
          The upstream outcome is still uncertain for this draft. The values below are the last
          known state. <button type="button" onClick={refresh} disabled={refreshing}>
            {refreshing ? 'Checking…' : 'Check again'}
          </button>
        </p>
      )}
      {stale && (
        <p role="alert">
          The limits changed. This review no longer matches the draft; revise to apply the new
          limits.
        </p>
      )}

      <h4>Objective</h4>
      <p>{review.objective}</p>
      {review.acceptance_criteria.length > 0 && (
        <>
          <h4>Acceptance evidence</h4>
          <ul>
            {review.acceptance_criteria.map((criterion, index) => (
              <li key={index}>{criterion}</li>
            ))}
          </ul>
        </>
      )}

      <h4>What the mission may do</h4>
      <dl>
        <dt>Can</dt>
        <dd>
          <ul>
            {TEMPLATE.can.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </dd>
        <dt>Will ask</dt>
        <dd>
          <ul>
            {TEMPLATE.willAsk.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </dd>
        <dt>Cannot</dt>
        <dd>
          <ul>
            {TEMPLATE.cannot.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </dd>
      </dl>

      <dl>
        <dt>Repository</dt>
        <dd>{review.repository_name}</dd>
        <dt>Issue</dt>
        <dd>#{review.issue_number}</dd>
        <dt>Base commit</dt>
        <dd>
          <code>{review.base_sha}</code>
        </dd>
        <dt>Mission branch</dt>
        <dd>
          <code>{review.mission_branch}</code>
        </dd>
        <dt>Agent kit</dt>
        <dd>
          {review.agent_kit_id} {review.agent_kit_version} (fixed)
        </dd>
        <dt>Proposal digest</dt>
        <dd>
          <code style={{ overflowWrap: 'anywhere' }}>{review.proposal_digest}</code>
        </dd>
      </dl>

      <h4>Enforcement</h4>
      <ul>
        {TEMPLATE.enforcementLabels.map((label) => (
          <li key={label}>{label}</li>
        ))}
      </ul>

      <h4>Limits</h4>
      <p>
        Only these two values can change, and only to narrower values. Anything else about the
        proposal is immutable.
      </p>
      <label>
        Expiry (UTC)
        <input
          type="datetime-local"
          value={expiryInput}
          onChange={(e) => setExpiryInput(e.target.value)}
          aria-label="Expiry (UTC)"
        />
      </label>
      <label>
        Aggregate budget (USD)
        <input
          type="text"
          inputMode="decimal"
          value={budgetInput}
          onChange={(e) => setBudgetInput(e.target.value)}
          aria-label="Aggregate budget (USD)"
        />
      </label>
      {validationError && <p role="alert">{validationError}</p>}
      {reviseState.kind === 'error' && <p role="alert">{reviseState.message}</p>}
      <button
        type="button"
        onClick={revise}
        disabled={!stale || reviseState.kind === 'revising' || validationError !== null}
      >
        {reviseState.kind === 'revising' ? 'Revising…' : 'Revise draft'}
      </button>

      <details>
        <summary>Technical details</summary>
        <dl>
          <dt>Invocation digest</dt>
          <dd>
            <code style={{ overflowWrap: 'anywhere' }}>{review.invocation_digest}</code>
          </dd>
          <dt>Runner arguments (in order)</dt>
          <dd>
            <ol>
              {review.runner_arguments.map((arg, index) => (
                <li key={index}>
                  <code>{arg}</code>
                </li>
              ))}
            </ol>
          </dd>
          <dt>Protected paths</dt>
          <dd>
            <ul>
              {TEMPLATE.protectedPaths.map((path) => (
                <li key={path}>
                  <code>{path}</code>
                </li>
              ))}
            </ul>
          </dd>
          <dt>Fixed technical ceilings</dt>
          <dd>
            <ul>
              <li>Expiry at most {TEMPLATE.maxTtlHours} hours from creation</li>
              <li>Aggregate budget at most ${microsToDollars(TEMPLATE.maxBudgetMicros)}</li>
              <li>At most {TEMPLATE.maxPendingExpansions} pending expansion at a time</li>
            </ul>
          </dd>
          <dt>Source revision</dt>
          <dd>
            <code>{review.source_revision}</code>
          </dd>
          <dt>Draft version</dt>
          <dd>{review.draft_version}</dd>
        </dl>
      </details>
      <ApprovalCard review={review} onChanged={onRevised} />
    </article>
  );
}

type AuthorizeState =
  | { kind: 'creating' }
  | { kind: 'review'; review: MissionPassReviewPayload }
  | { kind: 'error'; message: string; recoverable: boolean };

// MissionPassAuthorize creates exactly one mission-pass draft for the
// authorized issue and hands it to the review. A 202 answer means the
// upstream outcome stayed ambiguous: the pending draft is shown with a
// way to check again, and retrying the creation reuses the same
// idempotency key so it resolves to the same pass.
export function MissionPassAuthorize({
  connectionId,
  issueNumber,
  onBack,
}: {
  connectionId: string;
  issueNumber: number;
  onBack: () => void;
}) {
  const [state, setState] = useState<AuthorizeState>({ kind: 'creating' });
  const idempotencyKey = useRef<string | null>(null);

  // create opens the draft. Retrying reuses the same idempotency key so
  // the retry resolves to the same pass instead of opening a duplicate
  // draft.
  const create = useCallback(async () => {
    setState({ kind: 'creating' });
    if (idempotencyKey.current === null) idempotencyKey.current = newIdempotencyKey();
    try {
      const review = await createMissionPassDraft(
        {
          connection_id: connectionId,
          issue_number: issueNumber,
          expires_at: new Date(Date.now() + DEFAULT_TTL_MS).toISOString(),
          max_aggregate_cost_micros: DEFAULT_BUDGET_MICROS,
        },
        idempotencyKey.current,
      );
      setState({ kind: 'review', review });
    } catch (err: unknown) {
      const recoverable = err instanceof ApiError && (err.status === 409 || err.status >= 500);
      setState({ kind: 'error', message: errorMessage(err), recoverable });
    }
  }, [connectionId, issueNumber]);

  useEffect(() => {
    void create();
  }, [create]);

  return (
    <section aria-label="Authorize">
      <h2>Authorize</h2>
      {state.kind === 'creating' && <p>Creating the exact AuthScope proposal…</p>}
      {state.kind === 'error' && (
        <div>
          <p role="alert">{state.message}</p>
          {state.recoverable && (
            <button type="button" onClick={() => void create()}>
              Try again
            </button>
          )}{' '}
          <button type="button" onClick={onBack}>
            Pick another issue
          </button>
        </div>
      )}
      {state.kind === 'review' && (
        <>
          <MissionPassReview
            review={state.review}
            onRevised={(review) => setState({ kind: 'review', review })}
          />
          <button type="button" onClick={onBack}>
            Pick another issue
          </button>
        </>
      )}
    </section>
  );
}

export default MissionPassReview;
