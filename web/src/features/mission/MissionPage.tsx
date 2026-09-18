import { useCallback, useEffect, useState } from 'react';
import { Timeline } from './Timeline';
import { RevokeButton } from './RevokeButton';
import { ExpansionCard } from './ExpansionCard';
import { listPendingExpansions } from '../../shared/api/client';
import type {
  PendingExpansion,
} from '../../shared/api/generated';

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

// cliRevocationIdFromSearch extracts the CLI revocation request id from
// the query string, or null when absent.
export function cliRevocationIdFromSearch(search: string): string | null {
  const params = new URLSearchParams(search);
  const id = params.get('cli_revocation');
  return id === '' ? null : id;
}

// MissionPage renders one mission pass: its safe projected timeline and
// the founder's revoke control. When the CLI opened the result-only
// revocation handoff (?cli_revocation=), the page shows the requested
// revocation banner and the founder completes the normal revoke
// decision below; the result is handed back to the waiting CLI.
// Pending expansion deltas render as decision cards above the timeline.
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
    </main>
  );
}

export default MissionPage;
