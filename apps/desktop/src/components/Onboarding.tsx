import { useState } from 'react';
import { Check, Download } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { Logo } from './Logo';
import { Button, Notice } from './ui';

const STEPS = ['Before you start', 'Set up protection'] as const;

function Item({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-t border-line py-3 first:border-t-0 first:pt-0">
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
      <p className="mt-0.5 text-sm text-muted">{children}</p>
    </div>
  );
}

export function Onboarding() {
  const { status, refresh, toast } = useApp();
  const [step, setStep] = useState(0);
  const [realtime, setRealtime] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [updated, setUpdated] = useState<null | boolean>(null);
  const [finishing, setFinishing] = useState(false);

  const engineReady = status?.engine.clamav_database_present && status.engine.state !== 'unavailable';

  const update = async () => {
    setUpdating(true);
    try {
      const r = await api.updateProtection();
      setUpdated(r.ok);
      if (!r.ok) toast('danger', r.message);
      await refresh();
    } catch (e) {
      setUpdated(false);
      toast('danger', errText(e));
    } finally {
      setUpdating(false);
    }
  };

  const finish = async () => {
    setFinishing(true);
    try {
      await api.completeOnboarding(realtime);
      await refresh();
    } catch (e) {
      toast('danger', errText(e));
      setFinishing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40 grid place-items-center overflow-auto bg-bg p-6">
      <div className="panel flex w-full max-w-3xl overflow-hidden rounded-lg shadow-xl">
        <aside className="hidden w-52 shrink-0 flex-col border-r border-line bg-elev p-5 sm:flex">
          <div className="flex items-center gap-2.5">
            <Logo size={26} />
            <span className="text-[13px] font-semibold tracking-[0.12em] text-ink">SENTRIX</span>
          </div>
          <ol className="mt-8 space-y-3 text-sm" aria-label="Setup progress">
            {STEPS.map((s, i) => (
              <li key={s} aria-current={i === step ? 'step' : undefined} className={`flex items-center gap-2.5 ${i === step ? 'font-semibold text-ink' : 'text-muted'}`}>
                <span className={`grid size-5 place-items-center rounded-full border text-xs ${i < step ? 'border-ok bg-ok text-white' : i === step ? 'border-accent text-accent' : 'border-strong text-faint'}`}>
                  {i < step ? <Check className="size-3" /> : i + 1}
                </span>
                {s}
              </li>
            ))}
          </ol>
        </aside>

        <div className="min-w-0 flex-1 p-7">
          {step === 0 && (
            <div>
              <h1 className="text-xl font-semibold text-ink">Before you start</h1>
              <p className="mt-1 text-sm text-muted">SENTRIX checks files and tells you what it found. It is one layer of protection, not all of it.</p>
              <div className="mt-5">
                <Item title="What it does">Scans the files you pick, and new files in the folders you choose, with the ClamAV signature engine plus structure, signature and heuristic checks. Every report lists what ran and what could not.</Item>
                <Item title="What it does not do">It cannot stop a download, and it cannot stop a program from starting unless you turn on the execution guard for confirmed malware. No scanner finds everything: a clean result means the checks that ran found nothing. Keep Windows Security on.</Item>
                <Item title="What stays on this computer">File contents are never uploaded. History and quarantine are stored here. The only downloads are malware signatures from ClamAV&apos;s public servers, which carry no information about your files. If you connect a Telegram bot, report text (file names and verdicts) goes to Telegram.</Item>
              </div>
            </div>
          )}

          {step === 1 && (
            <div>
              <h1 className="text-xl font-semibold text-ink">Set up protection</h1>
              <p className="mt-1 text-sm text-muted">SENTRIX cannot call a file clean until the malware signatures are installed.</p>

              <div className="mt-5 rounded border border-line p-4">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <div className="text-sm font-semibold text-ink">Malware signatures</div>
                    <div className="mt-0.5 text-sm text-muted">{engineReady ? 'Installed.' : 'About 300 MB once. Later updates are much smaller.'}</div>
                  </div>
                  {engineReady ? (
                    <span className="flex items-center gap-1.5 text-sm font-semibold text-ok"><Check className="size-4" /> Ready</span>
                  ) : (
                    <Button variant="primary" busy={updating} onClick={update}>
                      <Download className="size-4" /> {updated === false ? 'Try again' : 'Download'}
                    </Button>
                  )}
                </div>
                {updating && <p className="mt-3 text-xs text-muted">Downloading and verifying. This can take a few minutes.</p>}
              </div>

              <label className="mt-3 flex cursor-pointer items-start gap-3 rounded border border-line p-4">
                <input type="checkbox" className="mt-0.5 size-4 accent-[var(--accent)]" checked={realtime} onChange={(e) => setRealtime(e.target.checked)} />
                <span className="text-sm">
                  <span className="block font-semibold text-ink">Scan new files in Downloads automatically</span>
                  <span className="text-muted">You can change the folders or turn this off later under Real-Time Protection.</span>
                </span>
              </label>

              {!engineReady && (
                <div className="mt-3">
                  <Notice tone="warn">You can continue without signatures, but files will show as &quot;Unable to verify&quot; until they are installed.</Notice>
                </div>
              )}
            </div>
          )}

          <div className="mt-7 flex items-center justify-between border-t border-line pt-4">
            <Button variant="ghost" disabled={step === 0} onClick={() => setStep((s) => s - 1)}>
              Back
            </Button>
            {step < STEPS.length - 1 ? (
              <Button variant="primary" onClick={() => setStep((s) => s + 1)}>
                Continue
              </Button>
            ) : (
              <Button variant="primary" busy={finishing} disabled={updating} onClick={finish}>
                Finish
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
