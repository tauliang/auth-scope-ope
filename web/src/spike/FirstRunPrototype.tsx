import { useState } from 'react';

// Step ids of the contract-faithful first-run click-through. The prototype
// uses fixtures generated from the immutable upstream operation schemas; no
// step talks to a real service.
export const PROTOTYPE_STEPS = [
  'bootstrap',
  'recovery-enrollment',
  'workspace',
  'github-handoff',
  'issue-selection',
  'proposal-review',
  'pass-approval',
  'cli-authorization',
  'token-exchange',
  'run-confirmed',
] as const;

export type PrototypeStep = (typeof PROTOTYPE_STEPS)[number];

const STEP_COPY: Record<PrototypeStep, { title: string; body: string }> = {
  bootstrap: {
    title: 'Welcome',
    body: 'This instance is not enrolled yet. Enrollment binds one founder passkey to one immutable workspace.',
  },
  'recovery-enrollment': {
    title: 'Recovery method',
    body: 'Register a recovery method (printed one-time code). It is the only way back in if the passkey is lost.',
  },
  workspace: {
    title: 'Workspace',
    body: 'Instance bound to workspace "personal" on host ope.example. This binding can never change.',
  },
  'github-handoff': {
    title: 'Connect GitHub',
    body: 'Install the AuthScope GitHub App. The handoff is hosted by AuthScope; OPE never sees a GitHub credential.',
  },
  'issue-selection': {
    title: 'Pick an issue',
    body: 'Repository acme/website, issue #42 "Fix the signup form validation". One issue becomes one Mission Pass.',
  },
  'proposal-review': {
    title: 'Review the proposal',
    body: 'Mission "Fix the signup form validation" with two editable limits: file scope and a 30 minute runtime cap.',
  },
  'pass-approval': {
    title: 'Approve with passkey',
    body: 'Approving signs an exact decision attestation with the workspace workload identity. Nothing else is signed.',
  },
  'cli-authorization': {
    title: 'Authorize the CLI',
    body: 'A one-use browser handoff authorizes the CLI with PKCE. No refresh credential is stored.',
  },
  'token-exchange': {
    title: 'Exchange',
    body: 'The one-use code is exchanged once. The governed run is prepared through an anonymous descriptor.',
  },
  'run-confirmed': {
    title: 'Run confirmed',
    body: 'Simulated confirmed RunID run-7f3a2c. The mission is now governed by the AuthScope authority.',
  },
};

// FirstRunPrototype is the Task 1 usability-spike click-through. It ends at
// a simulated confirmed RunID and records no real data.
export default function FirstRunPrototype({ onDone }: { onDone?: (steps: number) => void }) {
  const [index, setIndex] = useState(0);
  const step = PROTOTYPE_STEPS[index];
  const last = index === PROTOTYPE_STEPS.length - 1;

  function advance() {
    if (last) {
      onDone?.(PROTOTYPE_STEPS.length);
      return;
    }
    setIndex(index + 1);
  }

  return (
    <main aria-label="first-run prototype">
      <h1>{STEP_COPY[step].title}</h1>
      <p>{STEP_COPY[step].body}</p>
      <p aria-label="progress">
        Step {index + 1} of {PROTOTYPE_STEPS.length}
      </p>
      <button type="button" onClick={advance}>
        {last ? 'Finish' : 'Continue'}
      </button>
    </main>
  );
}
