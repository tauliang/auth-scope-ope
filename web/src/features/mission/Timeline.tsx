import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, fetchTimeline } from '../../shared/api/client';
import type { TimelineEvent, TimelineResponse } from '../../shared/api/generated';

// trustedRepositoryName validates the verified repository binding
// before it is used in a link. Only owner/repo shapes are linkable;
// anything else renders as plain text.
function trustedRepositoryName(name: string | undefined): string | null {
  if (!name) return null;
  return /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(name) ? name : null;
}

// eventLinks renders trusted branch and PR links for an event. The
// repository comes only from the verified repository binding, and the
// PR identifier only from the projected numeric event field.
function eventLinks(event: TimelineEvent, repository: string | null): React.ReactNode {
  if (!repository) return null;
  const links: React.ReactNode[] = [];
  if (event.pull_request_number && event.pull_request_number > 0) {
    const href = `https://github.com/${repository}/pull/${event.pull_request_number}`;
    links.push(
      <a key="pr" href={href} target="_blank" rel="noreferrer">
        PR #{event.pull_request_number}
      </a>,
    );
  }
  if (event.branch) {
    const href = `https://github.com/${repository}/tree/${encodeURIComponent(event.branch)}`;
    links.push(
      <a key="branch" href={href} target="_blank" rel="noreferrer">
        {event.branch}
      </a>,
    );
  }
  if (links.length === 0) return null;
  return (
    <span>
      {' '}
      {links.reduce<React.ReactNode[]>((acc, link, i) => (i === 0 ? [link] : [...acc, ' · ', link]), [])}
    </span>
  );
}

// humanEventLabel renders one safely projected event in plain language.
// Only allowlisted event types ever reach this list.
function humanEventLabel(event: TimelineEvent): string {
  switch (event.type) {
    case 'mission_started':
      return 'Mission started';
    case 'action_checked':
      return `Check ${event.check_kind ?? 'unknown'} ${event.check_outcome ?? 'unknown'}`;
    case 'expansion_requested':
      return `Expansion requested${event.reason_code ? `: ${event.reason_code}` : ''}`;
    case 'pull_request_created':
      return 'Pull request opened';
    case 'run_succeeded':
      return 'Run succeeded';
    case 'run_failed':
      return 'Run failed';
    case 'mission_expired':
      return 'Mission expired';
    case 'mission_revoked':
      return 'Mission revoked';
    case 'receipt_ready':
      return 'Receipt ready';
    default:
      return event.type;
  }
}

type TimelineState =
  | { kind: 'loading' }
  | { kind: 'ready'; timeline: TimelineResponse }
  | { kind: 'error'; message: string };

function timelineErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 404) return 'This mission pass was not found.';
    return err.title || `The timeline failed to load (${err.status}).`;
  }
  return 'The timeline could not be loaded.';
}

// Timeline renders the safe projected event timeline of a mission pass.
// It polls while reconciliation is pending so an ambiguous revocation
// settles visibly, and it pages through older events by cursor.
// pollIntervalMs is injectable for tests; it defaults to 4 seconds.
export function Timeline({ passId, pollIntervalMs = 4000 }: { passId: string; pollIntervalMs?: number }) {
  const [state, setState] = useState<TimelineState>({ kind: 'loading' });
  const [loadingMore, setLoadingMore] = useState(false);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(
    async (after?: string) => {
      const page = await fetchTimeline(passId, after, 100);
      return page;
    },
    [passId],
  );

  useEffect(() => {
    let cancelled = false;
    setState({ kind: 'loading' });
    load()
      .then((timeline) => {
        if (!cancelled) setState({ kind: 'ready', timeline });
      })
      .catch((err: unknown) => {
        if (!cancelled) setState({ kind: 'error', message: timelineErrorMessage(err) });
      });
    return () => {
      cancelled = true;
    };
  }, [load]);

  // While reconciliation is pending, refresh every few seconds so the
  // settled outcome appears without a manual reload. A failed poll
  // keeps the last good page and retries on the next tick.
  useEffect(() => {
    if (state.kind !== 'ready' || state.timeline.reconciliation !== 'pending') {
      return;
    }
    let cancelled = false;
    const tick = () => {
      pollTimer.current = setTimeout(() => {
        load()
          .then((timeline) => {
            if (!cancelled) {
              setState({ kind: 'ready', timeline });
            }
          })
          .catch(() => {
            if (!cancelled) {
              tick();
            }
          });
      }, pollIntervalMs);
    };
    tick();
    return () => {
      cancelled = true;
      if (pollTimer.current) clearTimeout(pollTimer.current);
    };
  }, [state, load, pollIntervalMs]);

  const loadMore = useCallback(async () => {
    if (state.kind !== 'ready' || loadingMore) return;
    const cursor = state.timeline.cursor;
    if (!cursor) return;
    setLoadingMore(true);
    try {
      const page = await load(cursor);
      setState({
        kind: 'ready',
        timeline: {
          ...page,
          events: [...state.timeline.events, ...page.events],
        },
      });
    } catch (err: unknown) {
      setState({ kind: 'error', message: timelineErrorMessage(err) });
    } finally {
      setLoadingMore(false);
    }
  }, [state, load, loadingMore]);

  if (state.kind === 'loading') {
    return (
      <section aria-label="mission timeline">
        <h2>Timeline</h2>
        <p>Loading the mission timeline…</p>
      </section>
    );
  }
  if (state.kind === 'error') {
    return (
      <section aria-label="mission timeline">
        <h2>Timeline</h2>
        <p role="alert">{state.message}</p>
      </section>
    );
  }

  const { timeline } = state;
  const repository = trustedRepositoryName(timeline.repository_name);
  return (
    <section aria-label="mission timeline">
      <h2>Timeline</h2>
      <p>
        State: {timeline.state} · Reconciliation: {timeline.reconciliation}
      </p>
      {!timeline.compatible && (
        <p role="alert">
          The event projection is incompatible and paused
          {timeline.incompatibility_reason ? `: ${timeline.incompatibility_reason}` : ''}.
        </p>
      )}
      {timeline.stale && <p role="alert">The timeline is stale; the next refresh will catch up.</p>}
      {timeline.containment && (
        <p role="alert">Containment: {timeline.containment}. This mission is revoked.</p>
      )}
      {timeline.events.length === 0 ? (
        <p>No events yet.</p>
      ) : (
        <ol>
          {timeline.events.map((event) => (
            <li key={event.event_id}>
              <span>{humanEventLabel(event)}</span>
              {eventLinks(event, repository)}{' '}
              <time dateTime={event.occurred_at}>
                {new Date(event.occurred_at).toLocaleString()}
              </time>
            </li>
          ))}
        </ol>
      )}
      {timeline.cursor && (
        <button type="button" onClick={loadMore} disabled={loadingMore}>
          {loadingMore ? 'Loading…' : 'Load more'}
        </button>
      )}
    </section>
  );
}
