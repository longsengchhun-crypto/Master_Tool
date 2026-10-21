// Renders brand/app-icon.svg to brand/app-icon-1024.png; `tauri icon` then derives ICO/ICNS/PNG sizes from it.
import sharp from 'sharp';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const brand = join(dirname(fileURLToPath(import.meta.url)), '..', 'brand');
await sharp(readFileSync(join(brand, 'app-icon.svg')), { density: 384 })
  .resize(1024, 1024)
  .png()
  .toFile(join(brand, 'app-icon-1024.png'));
await sharp(readFileSync(join(brand, 'logo-mark.svg')), { density: 384 })
  .resize(512, 512)
  .png()
  .toFile(join(brand, 'logo-mark-512.png'));
console.log('rendered brand PNGs');
