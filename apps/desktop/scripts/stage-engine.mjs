// Stages the minimal ClamAV runtime for the installer into src-tauri/engine-staging/clamav.
//   node scripts/stage-engine.mjs [path-to-extracted-clamav]   (default: <repo>/third_party/clamav)
// Only what clamd/freshclam need at runtime is copied (no debug symbols, import libs, headers or dev tools),
// and a SHA-256 manifest is written so builds are auditable and reproducible.
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const src = resolve(process.argv[2] ?? join(repo, 'third_party', 'clamav'));
const dst = join(here, '..', 'src-tauri', 'engine-staging', 'clamav');

if (!existsSync(join(src, 'clamd.exe')) || !existsSync(join(src, 'freshclam.exe'))) {
  console.error(`ClamAV runtime not found at ${src}. See docs/BUILD.md ("Detection engine").`);
  process.exit(1);
}

const EXE = new Set(['clamd.exe', 'freshclam.exe']);
rmSync(dst, { recursive: true, force: true });
mkdirSync(dst, { recursive: true });

const manifest = [];
for (const name of readdirSync(src)) {
  const p = join(src, name);
  const st = statSync(p);
  const lower = name.toLowerCase();
  const keep = st.isFile() ? EXE.has(lower) || lower.endsWith('.dll') || lower === 'copying.txt' : ['certs', 'copying'].includes(lower);
  if (!keep) continue;
  cpSync(p, join(dst, name), { recursive: true });
}
const walk = (d, rel = '') => {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p, `${rel}${n}/`);
    else manifest.push({ file: `${rel}${n}`, sha256: createHash('sha256').update(readFileSync(p)).digest('hex'), bytes: statSync(p).size });
  }
};
walk(dst);
writeFileSync(join(dst, '..', 'clamav-manifest.json'), JSON.stringify({ source: 'Cisco-Talos ClamAV (GPL-2.0)', files: manifest }, null, 2));
const mb = manifest.reduce((s, f) => s + f.bytes, 0) / 1048576;
console.log(`staged ${manifest.length} files (${mb.toFixed(1)} MB) -> ${dst}`);
