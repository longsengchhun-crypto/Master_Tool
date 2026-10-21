import { useState } from 'react';
import { Check, Download, Eye, Lock, ShieldCheck, TriangleAlert } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { Logo } from './Logo';
import { Button, Notice } from './ui';

const STEPS = ['Welcome', 'What to expect', 'Privacy', 'Set up'] as const;

function Point({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <li className="flex gap-4">
      <span className="mt-0.5 grid size-9 shrink-0 place-items-center rounded-xl bg-surface2 text-accent">{icon}</span>
      <div>
        <div className="text-sm font-semibold text-ink">{title}</div>
        <div className="mt-0.5 text-sm text-muted">{children}</div>
      </div>
    </li>
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
    <div className="ambient fixed inset-0 z-40 grid place-items-center overflow-auto bg-bg p-6">
      <div className="glass rise w-full max-w-2xl rounded-3xl p-10" style={{ background: 'var(--surface-solid)' }}>
        <div className="mb-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Logo size={36} />
            <div>
              <div className="text-lg font-semibold leading-tight tracking-tight text-ink">SENTRIX</div>
              <div className="text-xs text-muted">Intelligent File Security</div>
            </div>
          </div>
          <ol className="flex items-center gap-2" aria-label="Setup progress">
            {STEPS.map((s, i) => (
              <li key={s} aria-current={i === step ? 'step' : undefined} className={`h-1.5 w-8 rounded-full transition ${i <= step ? 'bg-gradient-to-r from-accent to-accent2' : 'bg-surface2'}`} title={s} />
            ))}
          </ol>
        </div>

        {step === 0 && (
          <div>
            <h1 className="text-3xl font-semibold tracking-tight text-ink">Know what is in a file before you open it.</h1>
            <p className="mt-3 text-muted">SENTRIX inspects files with a layered detection engine and explains each result in plain language. When something needs attention, it tells you why and what you can do next.</p>
            <ul className="mt-8 space-y-5">
              <Point icon={<ShieldCheck className="size-5" />} title="Layered checks">Malware signatures, file-structure analysis, digital signatures and heuristics work together.</Point>
              <Point icon={<Eye className="size-5" />} title="Honest results">If a check could not run or a file could not be fully inspected, SENTRIX says so instead of showing a reassuring tick.</Point>
              <Point icon={<Lock className="size-5" />} title="Safe quarantine">Suspicious files can be locked away in encrypted storage and restored if they turn out to be fine.</Point>
            </ul>
          </div>
        )}

        {step === 1 && (
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-ink">What SENTRIX can and cannot do</h1>
            <p className="mt-2 text-muted">Security tools are easy to over-trust, so here is the plain version.</p>
            <ul className="mt-6 space-y-5">
              <Point icon={<Check className="size-5" />} title="It scans and warns">It checks the files you choose, and new files in folders you pick, then tells you what it found.</Point>
              <Point icon={<TriangleAlert className="size-5" />} title="It does not block programs from running">Stopping every program from launching needs a deep operating-system component that this release does not include. Keep Windows Security turned on: SENTRIX adds to it and does not replace it.</Point>
              <Point icon={<TriangleAlert className="size-5" />} title="No scanner finds everything">"Clean" means the checks that ran found nothing. It is not a guarantee, so stay careful with files from unknown sources.</Point>
            </ul>
          </div>
        )}

        {step === 2 && (
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-ink">Your files stay on your computer</h1>
            <ul className="mt-6 space-y-5">
              <Point icon={<Lock className="size-5" />} title="Scanning is local">File contents are never uploaded. Scan history and quarantine are stored on this device.</Point>
              <Point icon={<Download className="size-5" />} title="One kind of download">SENTRIX downloads malware signatures from ClamAV's public servers. These requests do not include anything about your files.</Point>
              <Point icon={<Eye className="size-5" />} title="Nothing is shared by default">If your organization enrolls this device, you will see that clearly in Account, and you control optional health reporting in Settings. Turning it off never turns protection off.</Point>
            </ul>
          </div>
        )}

        {step === 3 && (
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-ink">Set up protection</h1>
            <p className="mt-2 text-muted">SENTRIX needs malware signatures before it can say a file is clean.</p>

            <div className="mt-6 rounded-2xl border border-line p-5">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-sm font-semibold text-ink">1. Download malware signatures</div>
                  <div className="mt-0.5 text-sm text-muted">{engineReady ? 'Signatures are installed.' : 'About 300 MB, one time. Updates afterwards are much smaller.'}</div>
                </div>
                {engineReady ? (
                  <span className="grid size-8 place-items-center rounded-full bg-okbg text-ok">
                    <Check className="size-4" />
                  </span>
                ) : (
                  <Button variant="primary" busy={updating} onClick={update}>
                    <Download className="size-4" /> {updated === false ? 'Try again' : 'Download'}
                  </Button>
                )}
              </div>
              {updating && <p className="mt-3 text-xs text-muted">Downloading and verifying signatures. This can take a few minutes…</p>}
            </div>

            <div className="mt-4 rounded-2xl border border-line p-5">
              <div className="text-sm font-semibold text-ink">2. Real-time protection</div>
              <label className="mt-3 flex cursor-pointer items-start gap-3">
                <input type="checkbox" className="mt-1 size-4 accent-[var(--accent)]" checked={realtime} onChange={(e) => setRealtime(e.target.checked)} />
                <span className="text-sm text-muted">
                  <span className="font-medium text-ink">Scan new files in my Downloads folder.</span> I can change the folders, or turn this off, under Protection at any time.
                </span>
              </label>
            </div>

            {!engineReady && (
              <div className="mt-4">
                <Notice tone="warn">You can continue without signatures, but SENTRIX will show files as "Unable to verify" until they are installed.</Notice>
              </div>
            )}
          </div>
        )}

        <div className="mt-10 flex items-center justify-between">
          <Button variant="ghost" disabled={step === 0} onClick={() => setStep((s) => s - 1)}>
            Back
          </Button>
          {step < STEPS.length - 1 ? (
            <Button variant="primary" onClick={() => setStep((s) => s + 1)}>
              Continue
            </Button>
          ) : (
            <Button variant="primary" busy={finishing} disabled={updating} onClick={finish}>
              Start using SENTRIX
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
