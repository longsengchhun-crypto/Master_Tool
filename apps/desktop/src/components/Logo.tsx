/** The SENTRIX shield-S mark. Same geometry as brand/logo-mark.svg (single source of identity). */
export function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 256 256" role="img" aria-label="SENTRIX">
      <defs>
        <linearGradient id="lg-shield" x1="40" y1="16" x2="216" y2="240" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5EEAD4" />
          <stop offset="0.55" stopColor="#22B8CF" />
          <stop offset="1" stopColor="#2563EB" />
        </linearGradient>
      </defs>
      <path d="M128 14 L218 46 V118 C218 177 177 220 128 242 C79 220 38 177 38 118 V46 Z" fill="url(#lg-shield)" />
      <path d="M166 90 C166 73 150 64 128 64 C105 64 90 74 90 91 C90 108 105 114 128 121 C151 128 166 134 166 152 C166 170 151 180 128 180 C104 180 89 170 89 153" fill="none" stroke="#06202B" strokeWidth="19" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="128" cy="122" r="7" fill="#F8FAFC" />
    </svg>
  );
}
