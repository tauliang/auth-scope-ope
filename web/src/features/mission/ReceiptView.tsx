import { useCallback, useEffect, useState } from 'react';
import { ApiError, fetchMissionReceipt } from '../../shared/api/client';
import type { ReceiptStatus, ReceiptView as ReceiptViewData } from '../../shared/api/generated';

// reasonLabel renders the fixed unverifiable reason codes in plain
// language. The codes are fixed by the server; anything else renders
// as-is.
function reasonLabel(code: string | undefined): string {
  switch (code) {
    case 'bad_signature':
      return 'the signature did not verify';
    case 'bad_key':
      return 'the signing key was unknown or invalid when the receipt was signed';
    case 'bad_payload':
      return 'the receipt payload was malformed';
    case 'bad_binding':
      return 'the receipt did not match this pass';
    default:
      return code || 'the receipt could not be verified';
  }
}

type ReceiptViewState =
  | { kind: 'loading' }
  | { kind: 'ready'; status: ReceiptStatus }
  | { kind: 'error'; message: string };

function receiptErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 404) return 'This mission pass was not found.';
    return err.title || `The receipt failed to load (${err.status}).`;
  }
  return 'The receipt could not be loaded.';
}

// shouldPoll keeps refreshing while the receipt is unverified or the
// check publication has not settled, so the verified outcome and the
// published check appear without a manual reload.
function shouldPoll(status: ReceiptStatus): boolean {
  if (status.verification === 'pending' || status.verification === 'unverifiable') return true;
  const state = status.publication?.state;
  return state === undefined || state === 'in_flight';
}

function VerifiedDetails({ view }: { view: ReceiptViewData }) {
  const digestPrefix = view.receipt_digest.length > 12 ? view.receipt_digest.slice(0, 12) : view.receipt_digest;
  return (
    <dl>
      <dt>Outcome</dt>
      <dd>{view.outcome}</dd>
      <dt>Receipt digest</dt>
      <dd><code>sha256:{digestPrefix}</code></dd>
      {view.settlement_digest && (
        <>
          <dt>Settlement digest</dt>
          <dd><code>{view.settlement_digest}</code></dd>
        </>
      )}
      <dt>Signing key</dt>
      <dd><code>{view.key_id}</code></dd>
      {view.mission_versions && view.mission_versions.length > 0 && (
        <>
          <dt>Mission versions</dt>
          <dd>{view.mission_versions.join(', ')}</dd>
        </>
      )}
      {view.checks && view.checks.length > 0 && (
        <>
          <dt>Checks</dt>
          <dd>
            <ul>
              {view.checks.map((check, i) => (
                <li key={i}>{check.kind}: {check.outcome}</li>
              ))}
            </ul>
          </dd>
        </>
      )}
      {view.historical_enforcement && view.historical_enforcement.length > 0 && (
        <>
          <dt>Historical enforcement</dt>
          <dd>
            <ul>
              {view.historical_enforcement.map((entry, i) => (
                <li key={i}>{entry.scope}: {entry.level}</li>
              ))}
            </ul>
          </dd>
        </>
      )}
    </dl>
  );
}

// ReceiptView renders the private verified receipt view of a mission
// pass. Pending, verified-success, verified-failure, disputed,
// publication-pending, and unverifiable states each render distinctly.
// An unverifiable receipt blocks completion language: the pass stays
// in outcome_pending until a receipt verifies locally. There is no
// manual publish button and no public share route; the worker
// publishes the privacy-safe GitHub check automatically.
// pollIntervalMs is injectable for tests; it defaults to 4 seconds.
export function ReceiptView({ passId, pollIntervalMs = 4000 }: { passId: string; pollIntervalMs?: number }) {
  const [state, setState] = useState<ReceiptViewState>({ kind: 'loading' });

  const load = useCallback(async () => {
    return fetchMissionReceipt(passId);
  }, [passId]);

  useEffect(() => {
    let cancelled = false;
    setState({ kind: 'loading' });
    load()
      .then((status) => {
        if (!cancelled) setState({ kind: 'ready', status });
      })
      .catch((err: unknown) => {
        if (!cancelled) setState({ kind: 'error', message: receiptErrorMessage(err) });
      });
    return () => {
      cancelled = true;
    };
  }, [load]);

  // While the receipt is unverified or the check publication is still
  // in flight, refresh on a timer. A failed poll keeps the last good
  // view and retries on the next tick.
  useEffect(() => {
    if (state.kind !== 'ready' || !shouldPoll(state.status)) {
      return;
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      timer = setTimeout(() => {
        load()
          .then((status) => {
            if (!cancelled) {
              setState({ kind: 'ready', status });
              if (shouldPoll(status)) tick();
            }
          })
          .catch(() => {
            if (!cancelled) tick();
          });
      }, pollIntervalMs);
    };
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [state, load, pollIntervalMs]);

  if (state.kind === 'loading') {
    return (
      <section aria-label="receipt">
        <h2>Receipt</h2>
        <p role="status">Loading receipt…</p>
      </section>
    );
  }

  if (state.kind === 'error') {
    return (
      <section aria-label="receipt">
        <h2>Receipt</h2>
        <p role="alert">{state.message}</p>
      </section>
    );
  }

  const { status } = state;

  if (status.verification === 'pending') {
    return (
      <section aria-label="receipt">
        <h2>Receipt</h2>
        <p role="status">Receipt pending. The signed execution receipt has not been verified yet.</p>
      </section>
    );
  }

  if (status.verification === 'unverifiable') {
    return (
      <section aria-label="receipt">
        <h2>Receipt</h2>
        <p role="alert">Receipt unverifiable: {reasonLabel(status.reason_code)}.</p>
        <p>The pass stays pending until a receipt verifies locally.</p>
      </section>
    );
  }

  const view = status.view;
  if (!view) {
    return (
      <section aria-label="receipt">
        <h2>Receipt</h2>
        <p role="status">Receipt pending. The signed execution receipt has not been verified yet.</p>
      </section>
    );
  }

  const publicationState = status.publication?.state;
  return (
    <section aria-label="receipt">
      <h2>Receipt</h2>
      <p role="status">
        {view.outcome === 'success' ? 'Verified receipt: run succeeded.' : 'Verified receipt: run failed.'}
      </p>
      <VerifiedDetails view={view} />
      {publicationState === 'settled' && <p>GitHub check published.</p>}
      {publicationState === 'in_flight' && <p role="status">Check publication pending.</p>}
      {publicationState === 'disputed' && <p role="alert">Check publication disputed.</p>}
      {publicationState === undefined && <p role="status">Check publication pending.</p>}
    </section>
  );
}

export default ReceiptView;
