import { useState } from 'react';
import { openUrl } from '@tauri-apps/plugin-opener';
import { ArrowRight, Check, FileSearch, MessageCircle, Paperclip } from 'lucide-react';
import type { TelegramStatus } from '../lib/types';
import { Button, Card, Notice } from '../components/ui';

/** Opens a Telegram link in the person's browser or Telegram app. Falls back to a new tab where the plugin is absent (dev preview). */
export async function openLink(url: string) {
  try {
    await openUrl(url);
  } catch {
    window.open(url, '_blank', 'noopener,noreferrer');
  }
}

/** `ABCD-EFGH`, whatever the person typed or pasted. */
export function formatCode(raw: string): string {
  const c = raw.replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 8);
  return c.length > 4 ? `${c.slice(0, 4)}-${c.slice(4)}` : c;
}

function Step({ n, done, active, title, children }: { n: number; done?: boolean; active?: boolean; title: string; children?: React.ReactNode }) {
  return (
    <li className="flex gap-4">
      <div className="flex flex-col items-center">
        <span className={`grid size-7 shrink-0 place-items-center rounded-full border text-xs font-semibold ${done ? 'border-ok bg-okbg text-ok' : active ? 'border-accent bg-accent text-accentink' : 'border-strong text-muted'}`}>
          {done ? <Check className="size-3.5" aria-label="Done" /> : n}
        </span>
        <span className="mt-1 w-px flex-1 bg-line" aria-hidden />
      </div>
      <div className="min-w-0 flex-1 pb-6">
        <h3 className={`text-sm font-semibold ${active || done ? 'text-ink' : 'text-muted'}`}>{title}</h3>
        {children && <div className="mt-1 text-sm text-muted">{children}</div>}
      </div>
    </li>
  );
}

/** Where a result goes, in three plain boxes. */
function Flow() {
  const box = 'flex items-center gap-2.5 rounded-lg border border-line bg-surface2 px-3.5 py-2.5 text-sm text-ink';
  return (
    <div className="flex flex-wrap items-center gap-2" role="img" aria-label="A file arrives, SENTRIX checks it, and the result comes to your private chat with the bot">
      <span className={box}><Paperclip className="size-4 text-muted" aria-hidden /> A file reaches you</span>
      <ArrowRight className="size-4 text-faint" aria-hidden />
      <span className={box}><FileSearch className="size-4 text-muted" aria-hidden /> SENTRIX checks it</span>
      <ArrowRight className="size-4 text-faint" aria-hidden />
      <span className={box}><MessageCircle className="size-4 text-muted" aria-hidden /> The result lands in your chat with the bot</span>
    </div>
  );
}

export function TelegramSetup({ t, busy, onLink }: { t: TelegramStatus; busy: boolean; onLink: (code: string) => void }) {
  const [code, setCode] = useState('');
  const r = t.relay;
  const ready = code.replace(/[^A-Za-z0-9]/g, '').length === 8;
  return (
    <Card className="p-6">
      {r.removedRemotely && (
        <div className="mb-5">
          <Notice tone="warn" title="This computer was unlinked in the bot">Results are not reaching you. Link it again below.</Notice>
        </div>
      )}
      <h2 className="text-lg font-semibold tracking-tight text-ink">Get results in Telegram</h2>
      <p className="mt-1 max-w-xl text-sm text-muted">SENTRIX has its own bot. You do not make one. Link this computer to your chat with it once, and every result arrives there, privately.</p>

      <ol className="mt-6">
        <Step n={1} active title={`Open @${r.botUsername ?? 'the SENTRIX bot'} and press Start`}>
          <p>Telegram opens a chat with the bot. Press <span className="font-medium text-ink">Start</span>. That is how the bot learns it may write to you.</p>
          {r.botLink && <div className="mt-3"><Button variant="primary" onClick={() => void openLink(r.botLink!)}>Open the bot in Telegram</Button></div>}
        </Step>
        <Step n={2} active title="Choose Protect my account">
          <p>The bot offers two choices. Choose <span className="font-medium text-ink">Protect my account</span> and it shows a code. (<span className="font-medium text-ink">Protect a group</span> works without this app: the bot walks you through it.)</p>
        </Step>
        <li className="flex gap-4">
          <span className="grid size-7 shrink-0 place-items-center rounded-full border border-accent bg-accent text-xs font-semibold text-accentink">3</span>
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-semibold text-ink">Type the code here</h3>
            <form
              className="mt-2 flex max-w-sm gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (ready) onLink(code);
              }}
            >
              <input
                value={code}
                onChange={(e) => setCode(formatCode(e.target.value))}
                inputMode="text"
                autoCapitalize="characters"
                autoComplete="off"
                spellCheck={false}
                placeholder="ABCD-EFGH"
                aria-label="Code from the bot"
                className="h-10 w-44 rounded-lg border border-strong bg-solid px-3 font-mono text-base tracking-widest text-ink placeholder:text-faint"
              />
              <Button type="submit" variant="primary" busy={busy} disabled={!ready}>Link this computer</Button>
            </form>
            <p className="mt-1.5 text-xs text-muted">The code works once and for 10 minutes. Ask the bot for a new one if it has expired.</p>
          </div>
        </li>
      </ol>

      <div className="mt-6 border-t border-line pt-5">
        <Flow />
        <p className="mt-4 max-w-2xl text-xs text-muted">What leaves this computer is the text of each result (file name, verdict, time), sent to the SENTRIX bot so it can reach your chat. Files are checked here and are never uploaded. Your Telegram login is never asked for and never sent.</p>
      </div>
    </Card>
  );
}
