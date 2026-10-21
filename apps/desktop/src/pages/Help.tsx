import type { ReactNode } from 'react';
import { useApp } from '../lib/app';
import { Card, PageHeader } from '../components/ui';

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="px-5 py-4">
      <h2 className="text-sm font-semibold text-ink">{title}</h2>
      <div className="mt-2 space-y-2 text-sm text-muted">{children}</div>
    </Card>
  );
}

const L = ({ children }: { children: ReactNode }) => <li>{children}</li>;

export function Help() {
  const { status, go } = useApp();
  return (
    <div className="space-y-6">
      <PageHeader title="Help and Privacy" subtitle="What SENTRIX does, what it does not do, and exactly what leaves this computer." />

      <Section title="What the results mean">
        <ul className="list-disc space-y-1 pl-5">
          <L><strong className="text-ink">Clean</strong>: every check that was needed finished and found nothing. It is not a guarantee: no scanner detects everything.</L>
          <L><strong className="text-ink">Suspicious</strong>: indicators worth a closer look. Not proof of malware.</L>
          <L><strong className="text-ink">Malicious</strong>: a malware-signature engine identified the file.</L>
          <L><strong className="text-ink">Unable to verify</strong>: the scan could not finish (engine unavailable, file locked, too large, encrypted). The file is <em>not</em> known to be safe.</L>
        </ul>
      </Section>

      <Section title="What real-time protection does and does not do">
        <ul className="list-disc space-y-1 pl-5">
          <L>It watches folders you choose and scans files shortly after they finish downloading, then warns you or quarantines confirmed malware if you allowed that.</L>
          <L>It does <strong className="text-ink">not</strong> stop a download, intercept a program as it starts, or monitor your browser. It adds a reversible “do not run” permission to confirmed-malicious files if the execution guard is on.</L>
          <L>It runs as an app in the system tray, not as a Windows service, so it only protects you while it is running. Turn on “Start SENTRIX when I sign in” in <button className="underline" onClick={() => go('settings')}>Settings</button> to have it start with Windows.</L>
          <L>Windows Security (Defender) keeps working. SENTRIX does not turn it off or change it.</L>
        </ul>
      </Section>

      <Section title="Telegram">
        <ul className="list-disc space-y-1 pl-5">
          <L><strong className="text-ink">Your bot</strong>: you create it with @BotFather; SENTRIX sends reports to your chat only. The token is stored encrypted for your Windows user and is never shown, logged or uploaded.</L>
          <L><strong className="text-ink">Telegram Desktop folder</strong>: scans files Telegram saved to disk.</L>
          <L><strong className="text-ink">Account-level monitoring</strong>: not available in this build. SENTRIX never asks for your Telegram password, login code or two-step password, and cannot claim to see every Telegram message or attachment.</L>
          <L>Deleting the bot token: <button className="underline" onClick={() => go('telegram')}>Telegram Protection</button> → Disconnect. It wipes the token file, the chat, and queued messages.</L>
        </ul>
      </Section>

      <Section title="What leaves this computer">
        <ul className="list-disc space-y-1 pl-5">
          <L>File contents never leave this computer.</L>
          <L>If you connected a bot: report text (file name, verdict, source, optionally SHA-256) goes to Telegram, which means Telegram can read it. Do not connect a bot you do not control.</L>
          <L>Signature updates are downloaded from ClamAV's public servers; no information about your files is included.</L>
          <L>If this device is enrolled in an organization console: only counts and on/off health (engine state, queue size, whether Telegram is connected). Never file names, paths, message text, chat IDs or tokens.</L>
          <L>No analytics or crash reports are sent. Nothing is sent to anyone unless you turn it on.</L>
        </ul>
      </Section>

      <Section title="Where things are stored">
        <ul className="list-disc space-y-1 pl-5">
          <L>Data folder: <span className="break-all font-mono text-xs text-ink">{status?.dataDir ?? '…'}</span></L>
          <L>Scan history, quarantine, the scan queue and notification queue live there. Delete that folder (with SENTRIX closed) to remove everything it stored.</L>
        </ul>
      </Section>

      <Section title="Troubleshooting">
        <ul className="list-disc space-y-1 pl-5">
          <L>“Not working” on Real-Time Protection: check the folder state under “Watched folders”; a folder that is missing or access-denied is not being watched.</L>
          <L>Files stuck under “Could not be checked”: update protection, restart the engine, then press “Try again”.</L>
          <L>No Telegram messages: use “Send a test message”. The result comes from Telegram, and the last error is shown. If the app was closed, queued messages are sent when it starts again.</L>
          <L>EICAR test files are blocked by Windows Defender on disk; that is expected.</L>
        </ul>
      </Section>
    </div>
  );
}
