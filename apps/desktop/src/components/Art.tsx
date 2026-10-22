/**
 * Small illustrations for the places where there is nothing to show yet. Drawn with the app's own colours so they follow
 * the theme; they carry no information, only a little warmth. (The SENTRIX logo is a separate component and is not touched.)
 */
export type ArtName = 'calm' | 'inbox' | 'vault' | 'search';

const S = { stroke: 'var(--line-strong)', strokeWidth: 1.6, strokeLinecap: 'round', strokeLinejoin: 'round' } as const;
const P = { ...S, fill: 'none' } as const;

export function Art({ name, className = '' }: { name: ArtName; className?: string }) {
  return (
    <svg viewBox="0 0 160 110" width="160" height="110" className={className} aria-hidden>
      <ellipse cx="80" cy="99" rx="52" ry="5.5" fill="var(--line)" opacity="0.7" />
      {name === 'calm' && (
        <>
          <path d="M38 46h27l8-10h49a6 6 0 0 1 6 6v48a6 6 0 0 1-6 6H44a6 6 0 0 1-6-6z" fill="var(--surface)" {...S} />
          <path d="M38 46h84" {...P} />
          <circle cx="80" cy="70" r="16" fill="var(--ok-bg)" stroke="var(--ok)" strokeWidth="1.8" />
          <path d="M72 70l6 6 11-12" fill="none" stroke="var(--ok)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M132 24l2 5 5 2-5 2-2 5-2-5-5-2 5-2z" fill="var(--accent)" opacity="0.75" />
          <path d="M28 30l1.4 3.4 3.4 1.4-3.4 1.4L28 39.6l-1.4-3.4-3.4-1.4 3.4-1.4z" fill="var(--accent)" opacity="0.5" />
        </>
      )}
      {name === 'inbox' && (
        <>
          <path d="M34 66l14-26a6 6 0 0 1 5-3h54a6 6 0 0 1 5 3l14 26v22a6 6 0 0 1-6 6H40a6 6 0 0 1-6-6z" fill="var(--surface)" {...S} />
          <path d="M34 66h30a8 8 0 0 0 8 8h16a8 8 0 0 0 8-8h30" {...P} />
          <g transform="rotate(-6 80 40)">
            <rect x="62" y="14" width="36" height="42" rx="4" fill="var(--bg-elev)" stroke="var(--accent)" strokeWidth="1.6" />
            <path d="M69 26h22M69 33h22M69 40h13" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" opacity="0.7" />
          </g>
        </>
      )}
      {name === 'vault' && (
        <>
          <rect x="40" y="36" width="80" height="56" rx="8" fill="var(--surface)" {...S} />
          <path d="M40 54h80" {...P} />
          <rect x="68" y="58" width="24" height="20" rx="4" fill="var(--select)" stroke="var(--accent)" strokeWidth="1.8" />
          <path d="M73 58v-5a7 7 0 0 1 14 0v5" fill="none" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" />
          <circle cx="80" cy="68" r="2.4" fill="var(--accent)" />
        </>
      )}
      {name === 'search' && (
        <>
          <rect x="34" y="26" width="52" height="64" rx="6" fill="var(--surface)" {...S} />
          <path d="M44 42h32M44 52h32M44 62h20" {...P} />
          <circle cx="98" cy="62" r="20" fill="var(--bg-elev)" fillOpacity="0.85" stroke="var(--accent)" strokeWidth="2" />
          <path d="M113 77l14 14" stroke="var(--accent)" strokeWidth="3" strokeLinecap="round" />
        </>
      )}
    </svg>
  );
}
