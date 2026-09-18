import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const root = document.getElementById('root');
if (!root) throw new Error('missing #root element');

// Minimal connect screen: first paint before React boots, replaced by the
// App once the bootstrap state loads. Kept static on purpose; all
// enrollment and session state lives in React.
root.innerHTML =
  '<main><h1>AuthScope OPE</h1><p>Connecting to the local service…</p></main>';

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
