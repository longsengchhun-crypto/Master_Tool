/**
 * The status orb. It says one thing at a glance and moves only when something is true:
 *  - a slow breath: protection is on and healthy
 *  - a turning arc: a scan is running
 *  - still, amber or red: something needs a person
 * It is a picture of real state, never decoration; the colour and symbol come from the same level the text uses.
 */
export type OrbLevel = 'protected' | 'attention' | 'at_risk';

const COLOR: Record<OrbLevel, string> = { protected: 'var(--ok)', attention: 'var(--warn)', at_risk: 'var(--danger)' };
const TINT: Record<OrbLevel, string> = { protected: 'var(--ok-bg)', attention: 'var(--warn-bg)', at_risk: 'var(--danger-bg)' };
const LABEL: Record<OrbLevel, string> = { protected: 'Protected', attention: 'Needs attention', at_risk: 'Not fully protected' };

export function Orb({ level, scanning = false, size = 112 }: { level: OrbLevel; scanning?: boolean; size?: number }) {
  const c = COLOR[level];
  return (
    <svg width={size} height={size} viewBox="0 0 120 120" role="img" aria-label={LABEL[level]} className="shrink-0">
      {/* outer halo */}
      <circle cx="60" cy="60" r="54" fill="none" stroke={c} strokeWidth="1" opacity="0.25" className={level === 'protected' && !scanning ? 'orb-breathe' : ''} />
      <circle cx="60" cy="60" r="46" fill="none" stroke={c} strokeWidth="1" strokeDasharray="2 6" opacity="0.35" />
      {/* scan arc */}
      {scanning && <path d="M60 6a54 54 0 0 1 54 54" fill="none" stroke={c} strokeWidth="3" strokeLinecap="round" className="orb-turn" />}
      {/* core */}
      <circle cx="60" cy="60" r="34" fill={TINT[level]} stroke={c} strokeWidth="2" />
      {level === 'protected' && <path d="M44 61l11 11 21-24" fill="none" stroke={c} strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />}
      {level === 'attention' && (
        <>
          <path d="M60 42v22" stroke={c} strokeWidth="5.5" strokeLinecap="round" />
          <circle cx="60" cy="76" r="3.4" fill={c} />
        </>
      )}
      {level === 'at_risk' && (
        <>
          <path d="M46 46l28 28M74 46L46 74" stroke={c} strokeWidth="5.5" strokeLinecap="round" />
        </>
      )}
    </svg>
  );
}
