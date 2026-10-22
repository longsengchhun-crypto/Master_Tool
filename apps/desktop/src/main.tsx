import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import '@fontsource-variable/bricolage-grotesque';
import './index.css';

async function start() {
  // Development preview with invented data: only under `vite` and only when explicitly requested (?mock=…).
  if (import.meta.env.DEV && new URLSearchParams(location.search).has('mock')) {
    const { installMock } = await import('./dev/mock');
    installMock();
  }
  ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}

void start();
