import { useState } from 'react';
import { openUrl } from '@tauri-apps/plugin-opener';
import { ArrowRight, FileSearch, MessageCircle, Paperclip } from 'lucide-react';
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

/** The bot's link with a built-in action: `account` shows the link code the moment Start is pressed, `group` the group steps. */
export function botLink(base: string | null, action: 'account' | 'group'): string | null {
  return base ? `${base}?start=${action}` : null;
}

/** `ABCD-EFGH`, whatever the person typed or pasted. */
export function formatCode(raw: string): string {
  const c = raw.replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 8);
  return c.length > 4 ? `${c.slice(0, 4)}-${c.slice(4)}` : c;
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

/** A picture of what the person is about to see in Telegram, so nothing there is a surprise. It is labelled as a preview. */
function ChatPreview({ bot }: { bot: string }) {
  return (
    <figure className="w-full max-w-[19rem] shrink-0 rounded-2xl border border-line bg-surface2 p-3.5">
      <figcaption className="mb-2 flex items-center justify-between text-[0.65rem] font-semibold uppercase tracking-[0.14em] text-muted">
        <span>What you will see</span>
        <span className="rounded bg-surface px-1.5 py-0.5 normal-case tracking-normal">Preview</span>
      </figcaption>
      <div className="space-y-2 text-[0.8rem] leading-snug">
        <div className="ml-auto w-fit rounded-2xl rounded-br-md bg-accent px-3 py-1.5 text-accentink">Start</div>
        <div className="max-w-[16rem] rounded-2xl rounded-bl-md border border-line bg-surface px-3 py-2 text-ink">
          <div className="font-semibold">Protect my account</div>
          <div className="mt-1 text-muted">Type this code in the SENTRIX app:</div>
          <div className="mt-1.5 rounded-md bg-surface2 py-1.5 text-center font-mono text-base tracking-[0.25em] text-ink">AB7K-9QXD</div>
          <div className="mt-2 rounded-md border border-line py-1 text-center text-[0.72rem] text-muted">Get a new code</div>
        </div>
        <p className="pt-1 text-[0.7rem] text-muted">From @{bot}. Your real code will be different.</p>
      </div>
    </figure>
  );
}

export function TelegramSetup({ t, busy, onLink }: { t: TelegramStatus; busy: boolean; onLink: (code: string) => void }) {
  const [code, setCode] = useState('');
  const r = t.relay;
  const ready = code.replace(/[^A-Za-z0-9]/g, '').length === 8;
  const link = botLink(r.botLink, 'account');
  return (
    <Card className="p-7">
      {r.removedRemotely && (
        <div className="mb-5">
          <Notice tone="warn" title="This computer was unlinked in the bot">Results are not reaching you. Link it again below.</Notice>
        </div>
      )}
      <div className="flex flex-wrap gap-x-10 gap-y-7">
        <div className="min-w-0 flex-1 basis-80">
          <h2 className="font-display text-2xl font-semibold text-ink">Get your results in Telegram</h2>
          <p className="mt-1.5 max-w-md text-sm text-muted">SENTRIX has its own bot, so you do not make one. Link this computer once, and every result arrives in your private chat.</p>

          <ol className="mt-6 space-y-6">
            <li className="flex gap-4">
              <span className="grid size-8 shrink-0 place-items-center rounded-full bg-accent font-display text-sm font-semibold text-accentink">1</span>
              <div>
                <h3 className="text-sm font-semibold text-ink">Open the bot and press Start</h3>
                <p className="mt-0.5 text-sm text-muted">The bot answers with a code straight away.</p>
                {link && <div className="mt-3"><Button variant="primary" onClick={() => void openLink(link)}>Open @{r.botUsername} in Telegram</Button></div>}
              </div>
            </li>
            <li className="flex gap-4">
              <span className="grid size-8 shrink-0 place-items-center rounded-full bg-accent font-display text-sm font-semibold text-accentink">2</span>
              <div className="min-w-0">
                <h3 className="text-sm font-semibold text-ink">Type the code here</h3>
                <form
                  className="mt-2.5 flex flex-wrap gap-2"
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
                    className="h-11 w-48 rounded-xl border border-strong bg-solid px-3.5 font-mono text-lg tracking-[0.2em] text-ink placeholder:text-faint"
                  />
                  <Button type="submit" variant="primary" busy={busy} disabled={!ready} className="h-11 px-5">Link this computer</Button>
                </form>
                <p className="mt-1.5 text-xs text-muted">Works once, for 10 minutes. If it expires, press Get a new code in the bot.</p>
              </div>
            </li>
          </ol>
        </div>
        {r.botUsername && <ChatPreview bot={r.botUsername} />}
      </div>

      <div className="mt-8 border-t border-line pt-5">
        <Flow />
        <p className="mt-4 max-w-2xl text-xs text-muted">What leaves this computer is the text of each result (file name, verdict, time), sent to the SENTRIX bot so it can reach your chat. Files are checked here and are never uploaded. Your Telegram login is never asked for and never sent.</p>
      </div>
    </Card>
  );
}
