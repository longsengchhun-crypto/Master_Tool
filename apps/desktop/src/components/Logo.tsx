/** The SENTRIX mark. Same geometry as brand/logo-mark.svg (single source of identity). */
export function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 256 256" role="img" aria-label="SENTRIX">
      <rect width="256" height="256" rx="56" fill="#10233C" />
      <g fill="none" stroke="#F5F3EE" strokeWidth="30">
        <path d="M164 92A36 36 0 1 0 128 128" />
        <path d="M128 128A36 36 0 1 1 92 164" />
      </g>
    </svg>
  );
}
