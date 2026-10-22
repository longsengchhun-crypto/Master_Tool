// Stages the pinned TDLib runtime into src-tauri/engine-staging/tdlib for the installer.
//   node scripts/stage-tdlib.mjs [path-to-tdlib-folder]   (default: <repo>/third_party/tdlib)
// Every file must match services/scanner/tdlib.sha256 (the same pins the app checks before it loads the library).
// A file that does not match fails the build instead of being shipped.
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const src = resolve(process.argv[2] ?? join(repo, 'third_party', 'tdlib'));
const dst = join(here, '..', 'src-tauri', 'engine-staging', 'tdlib');
const pins = readFileSync(join(repo, 'services', 'scanner', 'tdlib.sha256'), 'utf8')
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter((l) => l && !l.startsWith('#'))
  .map((l) => {
    const [hex, name] = l.split(/\s+\*?/);
    return { hex: hex.toLowerCase(), name };
  });

if (!pins.length) {
  console.error('tdlib.sha256 has no entries');
  process.exit(1);
}
rmSync(dst, { recursive: true, force: true });
mkdirSync(dst, { recursive: true });
let bytes = 0;
for (const { hex, name } of pins) {
  const p = join(src, name);
  if (!existsSync(p)) {
    console.error(`Missing ${name} in ${src}. See docs/TELEGRAM_ACCOUNT.md ("Getting TDLib").`);
    process.exit(1);
  }
  const data = readFileSync(p);
  const got = createHash('sha256').update(data).digest('hex');
  if (got !== hex) {
    console.error(`${name}: SHA-256 ${got} does not match the pin ${hex}. Refusing to stage it.`);
    process.exit(1);
  }
  cpSync(p, join(dst, name));
  bytes += data.length;
}
writeFileSync(join(dst, 'README.txt'), 'TDLib (Telegram Database Library), Boost Software License 1.0. Pinned by SHA-256; verified before it is loaded.\n');
console.log(`staged ${pins.length} TDLib files (${(bytes / 1048576).toFixed(1)} MB) -> ${dst}`);
