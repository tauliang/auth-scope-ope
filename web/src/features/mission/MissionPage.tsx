import { useCallback, useEffect, useState } from 'react';
import { Timeline } from './Timeline';
import { ReceiptView } from './ReceiptView';
import { RevokeButton } from './RevokeButton';
import { ExpansionCard } from './ExpansionCard';
import { fetchMissionPass, listPendingExpansions } from '../../shared/api/client';
import type {
  MissionPassReview as MissionPassPayload,
  PendingExpansion,
} from '../../shared/api/generated';
import { ProblemPanel, problemPanelForError } from '../../shared/components/ProblemPanel';

// missionPathPrefix is the transient browser route for a mission pass.
// The pass id follows the prefix. A ?cli_revocation= query parameter
// carries the CLI revocation request id for the founder's decision.
export const missionPathPrefix = '/mission/';

// missionPassIdFromPath extracts the pass id from the mission route, or
// null when the pathname is not a mission route.
export function missionPassIdFromPath(pathname: string): string | null {
  if (!pathname.startsWith(missionPathPrefix)) {
    return null;
  }
  const id = pathname.slice(missionPathPrefix.length).split('/')[0];
  return id === '' ? null : id;
}

// missionPassIdFromLocation resolves the pass id from the path first and
// then from the ?pass= query parameter, so deep links restore server
// state either way.
export function missionPassIdFromLocation(pathname: string, search: string): string | null {
  const fromPath = missionPassIdFromPath(pathname);
  if (fromPath) return fromPath;
  const id = new URLSearchParams(search).get('pass');
  return id === '' ? null : id;
}

// cliRevocationIdFromSearch extracts the CLI revocation request id from
// the query string, or null when absent.
export function cliRevocationIdFromSearch(search: string): string | null {
  const params = new URLSearchParams(search);
  const id = params.get('cli_revocation');
  return id === '' ? null : id;
}

// PassStateSection renders the pass lifecycle state and remaining
// limits from the authenticated pass record. When reconciliation is
// pending the projection is marked stale until the worker settles it.
function PassStateSection({ passId }: { passId: string }) {
  const [pass, setPass] = useState<MissionPassPayload | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let cancelled = false;
    fetchMissionPass(passId).then(
      (next) => {
        if (!cancelled) setPass(next);
      },
      (err: unknown) => {
        if (!cancelled) setError(err);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [passId]);

  if (error) {
    const panel = problemPanelForError(error);
    return (
      <section aria-label="mission state">
        <h2>Mission state</h2>
        <ProblemPanel title={panel.title} detail={panel.detail} />
      </section>
    );
  }

  if (!pass) {
    return (
      <section aria-label="mission state">
        <h2>Mission state</h2>
        <p role="status">Loading mission state…</p>
      </section>
    );
  }

  return (
    <section aria-label="mission state">
      <h2>Mission state</h2>
      <dl>
        <dt>State</dt>
        <dd>{pass.state}</dd>
        <dt>Mission branch</dt>
        <dd>{pass.mission_branch ? <code>{pass.mission_branch}</code> : 'not assigned yet'}</dd>
        <dt>Cost ceiling</dt>
        <dd>${(pass.limits.max_aggregate_cost_micros / 1_000_000).toFixed(2)}</dd>
        <dt>Expires at</dt>
        <dd>{pass.limits.expires_at}</dd>
        {pass.reconciliation === 'pending' && (
          <>
            <dt>Projection</dt>
            <dd role="status">
              Stale: the last operation is still reconciling. This view refreshes when the worker
              settles it.
            </dd>
          </>
        )}
      </dl>
    </section>
  );
}

// MissionPage renders one mission pass: its state and remaining limits,
// the safe projected timeline, pending expansion decision cards, the
// founder's revoke control, and the verified receipt with the automatic
// GitHub check status. When the CLI opened the result-only revocation
// handoff (?cli_revocation=), the page shows the requested revocation
// banner and the founder completes the normal revoke decision below;
// the result is handed back to the waiting CLI; the result code is never
// shown here.
export function MissionPage({ passId, cliRevocationId }: { passId: string; cliRevocationId: string | null }) {
  const [timelineKey, setTimelineKey] = useState(0);
  const refresh = useCallback(() => setTimelineKey((n) => n + 1), []);
  const [expansions, setExpansions] = useState<PendingExpansion[] | null>(null);

  const loadExpansions = useCallback(() => {
    listPendingExpansions(passId).then(setExpansions, () => setExpansions([]));
  }, [passId]);

  useEffect(() => {
    loadExpansions();
  }, [loadExpansions]);

  const onExpansionDecided = useCallback(
    () => {
      // The decision settled upstream; refresh the cards and timeline.
      loadExpansions();
      refresh();
    },
    [loadExpansions, refresh],
  );

  return (
    <main>
      <h1>AuthScope OPE</h1>
      {cliRevocationId && (
        <p role="status">
          The CLI requested this revocation. Complete it below to hand the result back to the
          waiting CLI; the result code is never shown here.
        </p>
      )}
      <PassStateSection passId={passId} />
      <section aria-label="mission pass">
        <h2>Mission pass</h2>
        <p><code>{passId}</code></p>
        <RevokeButton passId={passId} onRevoked={refresh} cliRevocationId={cliRevocationId ?? undefined} />
      </section>
      {expansions !== null && expansions.length > 0 && (
        <section aria-label="pending expansions">
          <h2>Pending expansions</h2>
          {expansions.map((expansion) => (
            <ExpansionCard
              key={expansion.expansion_id}
              passId={passId}
              expansion={expansion}
              onDecided={onExpansionDecided}
            />
          ))}
        </section>
      )}
      <Timeline key={timelineKey} passId={passId} />
      <ReceiptView passId={passId} />
    </main>
  );
}

export default MissionPage;
