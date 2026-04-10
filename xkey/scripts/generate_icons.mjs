#!/usr/bin/env node

import fs from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

const repoRoot = path.resolve(process.cwd());
const require = createRequire(path.join(repoRoot, 'frontend', 'package.json'));
const { chromium } = require('playwright');
const svgPath = path.join(repoRoot, 'frontend', 'public', 'xkey-brand.svg');
const outputDir = path.join(repoRoot, 'build', 'icons');
const sizes = [16, 32, 48, 128, 256, 512, 1024];

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

async function writeIcon(browser, svgMarkup, size, outPath) {
  const page = await browser.newPage({
    viewport: { width: size, height: size },
    deviceScaleFactor: 1,
  });

  const sizedSvg = svgMarkup.replace('<svg ', `<svg width="${size}" height="${size}" `);
  await page.setContent(
    `<html><body style="margin:0;background:transparent;display:flex;align-items:center;justify-content:center;">${sizedSvg}</body></html>`,
    { waitUntil: 'load' }
  );

  const svg = page.locator('svg');
  await svg.screenshot({ path: outPath, omitBackground: true });
  await page.close();
}

async function main() {
  const svgMarkup = await fs.readFile(svgPath, 'utf8');
  await ensureDir(outputDir);

  const browser = await chromium.launch();
  try {
    for (const size of sizes) {
      const outPath = path.join(outputDir, `appicon-${size}.png`);
      await writeIcon(browser, svgMarkup, size, outPath);
      console.log(`  ${outPath} (${size}x${size})`);
    }
  } finally {
    await browser.close();
  }

  await fs.copyFile(path.join(outputDir, 'appicon-1024.png'), path.join(repoRoot, 'build', 'appicon.png'));
  console.log(`  ${path.join(repoRoot, 'build', 'appicon.png')} (Wails convention)`);

  await ensureDir(path.join(repoRoot, 'pkg', 'gui', 'icon'));
  await fs.copyFile(path.join(outputDir, 'appicon-256.png'), path.join(repoRoot, 'pkg', 'gui', 'icon', 'appicon.png'));
  console.log(`  ${path.join(repoRoot, 'pkg', 'gui', 'icon', 'appicon.png')} (Go embed)`);

  const extDir = path.join(repoRoot, 'extension', 'src', 'icons');
  await ensureDir(extDir);
  for (const size of [16, 48, 128]) {
    const dst = path.join(extDir, `icon-${size}.png`);
    await fs.copyFile(path.join(outputDir, `appicon-${size}.png`), dst);
    console.log(`  ${dst} (extension)`);
  }

  const publicDir = path.join(repoRoot, 'frontend', 'public');
  await ensureDir(publicDir);
  await fs.copyFile(path.join(outputDir, 'appicon-32.png'), path.join(publicDir, 'favicon.png'));
  console.log(`  ${path.join(publicDir, 'favicon.png')} (favicon)`);

  console.log('\nDone. All icons generated.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
