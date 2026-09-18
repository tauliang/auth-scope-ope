import { useCallback, useEffect, useState } from 'react';
import IssuePicker from './IssuePicker';
import { MissionPassAuthorize } from './MissionPassReview';
import { CLIAuthorization, cliAuthorizationIdFromPath } from './CLIAuthorization';
import { readStoredConnection } from '../connect/GitHubConnection';
import type { GitHubConnection, GitHubIssueSnapshot } from '../../shared/api/generated';
import { ProblemPanel, problemPanelForError } from '../../shared/components/ProblemPanel';

// AuthorizePage is the Authorize screen: issue preview, the compact
// AuthScope proposal with its two editable limits, exact-digest
// approval, and the CLI browser handoff. It owns the transient CLI
// authorization path (/authorize/cli/<id>): the CLI prints that URL and
// the founder approves the exact launch request in the browser.
// Deep links restore server state: ?issue=<number> re-opens the picker
// with the issue pre-selected when a repository is connected.
export function AuthorizePage() {
  const [connection, setConnection] = useState<GitHubConnection | null>(null);
  const [snapshot, setSnapshot] = useState<GitHubIssueSnapshot | null>(null);
  const [approvedPassId, setApprovedPassId] = useState<string | null>(null);

  useEffect(() => {
    setConnection(readStoredConnection());
  }, []);

  const cliAuthorizationId =
    typeof window !== 'undefined' ? cliAuthorizationIdFromPath(window.location.pathname) : null;

  const handleAuthorize = useCallback((next: GitHubIssueSnapshot) => {
    setApprovedPassId(null);
    setSnapshot(next);
  }, []);

  const handleBack = useCallback(() => {
    setApprovedPassId(null);
    setSnapshot(null);
  }, []);

  const handleApproved = useCallback((passId: string) => {
    setApprovedPassId(passId);
  }, []);

  if (cliAuthorizationId) {
    return <CLIAuthorization authorizationId={cliAuthorizationId} />;
  }

  return (
    <main>
      <h1>AuthScope OPE</h1>
      <section aria-label="authorize">
        <h2>Authorize</h2>
        {!connection && (
          <p>
            No repository is connected yet. <a href="/">Connect a repository first</a>.
          </p>
        )}
        {connection && !snapshot && (
          <IssuePicker connection={connection} onAuthorize={handleAuthorize} />
        )}
        {connection && snapshot && (
          <>
            <MissionPassAuthorize
              connectionId={connection.connection_id}
              issueNumber={snapshot.issue_number}
              onBack={handleBack}
              onApproved={handleApproved}
            />
            {approvedPassId && (
              <section aria-label="next step">
                <h2>Next step</h2>
                <p>
                  <a href={`/mission?pass=${encodeURIComponent(approvedPassId)}`}>
                    Open the mission pass
                  </a>
                </p>
              </section>
            )}
          </>
        )}
      </section>
    </main>
  );
}

// AuthorizeErrorPage renders a typed failure with its blocked condition
// and safe recovery action.
export function AuthorizeErrorPage({ error }: { error: unknown }) {
  const panel = problemPanelForError(error);
  return (
    <main>
      <h1>AuthScope OPE</h1>
      <ProblemPanel title={panel.title} detail={panel.detail} />
    </main>
  );
}

export default AuthorizePage;
