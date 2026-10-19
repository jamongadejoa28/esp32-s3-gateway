#!/usr/bin/env node
// Build the embedded web UI (DESIGN.md §11):
//   web/src/main.js  -> esbuild bundle, ES2020, minified, then a terser compress/mangle pass
//                       (~1.8 KB gzip smaller than esbuild alone) -> assets/app.<hash>.js
//   web/styles/main.css -> esbuild CSS bundle, minified          -> assets/app.<hash>.css
//   web/index.html   -> asset links rewritten, SVG sprite (icons + MESTIO symbol) inlined, whitespace
//                       collapsed                                -> index.html (served at "/")
//   MESTIO_Symbol.svg -> metadata (<title>/<desc>) stripped, minified -> favicon.svg
// Every file is also written gzip -9 (<file>.gz). manifest.json lists {path, file, gz, mime, etag,
// immutable, size, gz_size} sorted by path (the input of tools/gen_web_assets.py); a size report
// is printed and the build FAILS when the gzip total exceeds 64 KB.
//
//   node tools/build_web.mjs [--out DIR] [--quiet]
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { gzipSync, constants as zc } from 'node:zlib';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WEB = join(ROOT, 'web');
export const BUDGET_GZ = 64 * 1024;

const sha = (buf) => createHash('sha256').update(buf).digest('hex');

/** Minify an SVG document/fragment: drop comments, <title>, <desc>, metadata and whitespace. */
export function minifySvg(svg) {
  return svg
    .replace(/<\?xml[^>]*>/g, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<title>[\s\S]*?<\/title>/g, '')
    .replace(/<desc>[\s\S]*?<\/desc>/g, '')
    .replace(/<metadata>[\s\S]*?<\/metadata>/g, '')
    .replace(/\s+/g, ' ')
    .replace(/>\s+</g, '><')
    .replace(/\s+(\/?>)/g, '$1')
    .trim();
}

/** Parse the MESTIO symbol: viewBox, group transform and fill, path data. */
function parseSymbol() {
  const src = readFileSync(join(ROOT, 'MESTIO_Symbol.svg'), 'utf8');
  const viewBox = /viewBox="([^"]+)"/.exec(src);
  const g = /<g\b([^>]*)>/.exec(src);
  const paths = [...src.matchAll(/<path\b[^>]*\bd="([^"]+)"/g)].map((m) => m[1]);
  if (!viewBox || !paths.length) throw new Error('MESTIO_Symbol.svg: viewBox/path not found');
  const transform = g && /transform="([^"]+)"/.exec(g[1]);
  const identity = !transform || /^\s*translate\(0[ ,]+0\)\s*scale\(1(\.0+)?\)\s*$/.test(transform[1]);
  const fill = (g && /fill="([^"]+)"/.exec(g[1])) || /fill="([^"]+)"/.exec(src);
  return { viewBox: viewBox[1], transform: identity ? null : transform[1], fill: fill ? fill[1] : '#3155E7', paths };
}

/** favicon.svg: the MESTIO symbol in brand blue, metadata stripped. */
export function faviconSvg() {
  const s = parseSymbol();
  const body = s.paths.map((d) => `<path d="${d}"/>`).join('');
  const inner = s.transform ? `<g transform="${s.transform}">${body}</g>` : body;
  return minifySvg(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="${s.viewBox}" fill="#3155E7">${inner}</svg>`);
}

/** Inline sprite: web/assets/icons.svg symbols + the MESTIO symbol as #logo (fill from CSS). */
export function spriteSvg() {
  const icons = readFileSync(join(WEB, 'assets', 'icons.svg'), 'utf8');
  const symbols = [...icons.matchAll(/<symbol\b[\s\S]*?<\/symbol>/g)].map((m) => m[0]).join('');
  const s = parseSymbol();
  const body = s.paths.map((d) => `<path d="${d}"/>`).join('');
  const logo = `<symbol id="logo" viewBox="${s.viewBox}">${s.transform ? `<g transform="${s.transform}">${body}</g>` : body}</symbol>`;
  return minifySvg(`<svg class="sprite" aria-hidden="true" focusable="false">${symbols}${logo}</svg>`);
}

/** Collapse inter-tag whitespace and comments of the HTML shell. */
export function collapseHtml(html) {
  return html
    .replace(/<!--(?!SPRITE)[\s\S]*?-->/g, '')
    .replace(/\n\s*/g, '')
    .replace(/>\s+</g, '><')
    .trim();
}

/** index.html for the mock server's --dev mode (unbundled sources, sprite inlined). */
export function renderIndexDev() {
  const html = readFileSync(join(WEB, 'index.html'), 'utf8');
  return html.replace('<!--SPRITE-->', spriteSvg());
}

/** All .js sources below web/src (posix-relative path -> text). */
function readSources() {
  const out = new Map();
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) out.set(p, readFileSync(p, 'utf8'));
    }
  };
  walk(join(WEB, 'src'));
  return out;
}

/**
 * i18n compaction plan (pure; unit-tested): dictionaries become value arrays, literal t('key') calls
 * become t(index), and only keys that are looked up by a computed name (template prefixes like
 * `nav.${v}`, or a key literal passed around outside t('…')) stay resolvable by name. Those runtime
 * keys are sorted to the front of the arrays, so the bundle carries them as a plain name list
 * (`runtimeKeys`, name i -> index i) instead of a key -> index object. Throws on unknown literal
 * keys and on dictionary key mismatches.
 * @param {Record<string,string>} ko
 * @param {Record<string,string>} en
 * @param {Map<string,string>} sources path -> text (excluding the dictionaries)
 */
export function i18nPlan(ko, en, sources) {
  const all = Object.keys(ko);
  const missing = all.filter((k) => !(k in en));
  const extra = Object.keys(en).filter((k) => !(k in ko));
  if (missing.length || extra.length) throw new Error(`i18n: en.js key mismatch (missing ${missing.join(', ') || '-'}; extra ${extra.join(', ') || '-'})`);
  const text = [...sources.values()].join('\n');
  const prefixes = new Set();
  for (const m of text.matchAll(/`([a-z][a-z0-9_.]*)\$\{/g)) if (m[1].includes('.') && m[1].length >= 2) prefixes.add(m[1]);
  const direct = new Map();
  for (const m of text.matchAll(/\bt\('([^'\n]+)'/g)) {
    if (!(m[1] in ko)) throw new Error(`i18n: t('${m[1]}') is not defined in ko.js`);
    direct.set(m[1], (direct.get(m[1]) || 0) + 1);
  }
  const isRuntime = (k) => {
    const quoted = text.split(`'${k}'`).length - 1;
    return quoted > (direct.get(k) || 0) || [...prefixes].some((p) => k.startsWith(p));
  };
  const runtimeKeys = all.filter(isRuntime).sort();
  const keys = runtimeKeys.concat(all.filter((k) => !isRuntime(k)));
  const index = new Map(keys.map((k, i) => [k, i]));
  const runtime = Object.fromEntries(runtimeKeys.map((k, i) => [k, i]));
  const rewrite = (src) => src.replace(/\bt\('([^'\n]+)'/g, (m, k) => `t(${index.get(k)}`);
  return {
    keys,
    runtime,
    runtimeKeys,
    ko: keys.map((k) => ko[k]),
    en: keys.map((k) => en[k]),
    rewrite,
  };
}

async function i18nPlugin() {
  const bust = `?v=${Date.now()}`;
  const ko = (await import(pathToFileURL(join(WEB, 'src', 'i18n', 'ko.js')).href + bust)).default;
  const en = (await import(pathToFileURL(join(WEB, 'src', 'i18n', 'en.js')).href + bust)).default;
  const sources = readSources();
  const dictDir = join(WEB, 'src', 'i18n');
  const isDict = (p) => p === join(dictDir, 'ko.js') || p === join(dictDir, 'en.js') || p === join(dictDir, 'keys.js');
  const plan = i18nPlan(ko, en, new Map([...sources].filter(([p]) => !isDict(p))));
  return {
    name: 'i18n-compact',
    setup(b) {
      b.onLoad({ filter: /[\\/]web[\\/]src[\\/].*\.js$/ }, (a) => {
        const p = resolve(a.path);
        if (p === join(dictDir, 'ko.js')) return { contents: `export default ${JSON.stringify(plan.ko)};`, loader: 'js' };
        if (p === join(dictDir, 'en.js')) return { contents: `export default ${JSON.stringify(plan.en)};`, loader: 'js' };
        if (p === join(dictDir, 'keys.js')) return { contents: `export default ${JSON.stringify(plan.runtimeKeys)};`, loader: 'js' };
        return { contents: plan.rewrite(sources.get(p) ?? readFileSync(p, 'utf8')), loader: 'js' };
      });
    },
  };
}

const MIME = { html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8', svg: 'image/svg+xml', json: 'application/json' };

/**
 * Build into `out`. Returns {assets, totalGz}. Throws on esbuild errors; returns ok=false when the
 * budget is exceeded (the CLI exits 1).
 */
export async function build({ out = join(WEB, 'dist'), quiet = false } = {}) {
  const esbuild = await import('esbuild');
  out = resolve(out);
  if (existsSync(out)) {
    const entries = readdirSync(out);
    if (entries.length && !entries.includes('manifest.json')) throw new Error(`refusing to clean ${out}: not a previous build output (no manifest.json)`);
    rmSync(out, { recursive: true, force: true });
  }
  mkdirSync(join(out, 'assets'), { recursive: true });

  const common = { bundle: true, minify: true, write: false, logLevel: 'silent', legalComments: 'none', charset: 'utf8' };
  const js = await esbuild.build({
    ...common, entryPoints: [join(WEB, 'src', 'main.js')], format: 'esm', target: 'es2020', platform: 'browser', drop: ['debugger'],
    plugins: [await i18nPlugin()],
  });
  const css = await esbuild.build({
    ...common, entryPoints: [join(WEB, 'styles', 'main.css')], target: ['chrome90', 'firefox90', 'safari14', 'edge90'], loader: { '.css': 'css' },
  });
  for (const r of [js, css]) {
    for (const w of r.warnings) console.warn(`esbuild warning: ${w.text}`);
  }
  const { minify } = await import('terser');
  const tj = await minify(js.outputFiles[0].text, {
    module: true, ecma: 2020, compress: { passes: 2 }, mangle: true, format: { comments: false },
  });
  if (typeof tj.code !== 'string' || !tj.code) throw new Error('terser produced no output');
  const jsBuf = Buffer.from(tj.code);
  const cssBuf = Buffer.from(css.outputFiles[0].contents);
  const jsName = `app.${sha(jsBuf).slice(0, 8)}.js`;
  const cssName = `app.${sha(cssBuf).slice(0, 8)}.css`;

  let html = collapseHtml(readFileSync(join(WEB, 'index.html'), 'utf8'));
  const swap = (from, to) => {
    if (!html.includes(from)) throw new Error(`index.html: reference ${from} not found`);
    html = html.replace(from, to);
  };
  swap('/styles/main.css', `/assets/${cssName}`);
  swap('/src/main.js', `/assets/${jsName}`);
  swap('<!--SPRITE-->', spriteSvg());
  const htmlBuf = Buffer.from(html);
  const favBuf = Buffer.from(faviconSvg());

  const files = [
    { path: '/', file: 'index.html', buf: htmlBuf, mime: MIME.html, immutable: false },
    { path: `/assets/${cssName}`, file: `assets/${cssName}`, buf: cssBuf, mime: MIME.css, immutable: true },
    { path: `/assets/${jsName}`, file: `assets/${jsName}`, buf: jsBuf, mime: MIME.js, immutable: true },
    { path: '/favicon.svg', file: 'favicon.svg', buf: favBuf, mime: MIME.svg, immutable: false },
  ].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  let totalGz = 0;
  let total = 0;
  const assets = files.map((f) => {
    const gz = gzipSync(f.buf, { level: 9, memLevel: 9, strategy: zc.Z_DEFAULT_STRATEGY });
    writeFileSync(join(out, f.file), f.buf);
    writeFileSync(join(out, `${f.file}.gz`), gz);
    totalGz += gz.length;
    total += f.buf.length;
    return { path: f.path, file: f.file, gz: `${f.file}.gz`, mime: f.mime, etag: `"${sha(f.buf).slice(0, 16)}"`, immutable: f.immutable, size: f.buf.length, gz_size: gz.length };
  });
  const manifest = { version: 1, budget_gz: BUDGET_GZ, total_size: total, total_gz: totalGz, assets };
  writeFileSync(join(out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  if (!quiet) {
    const pad = (s, n) => String(s).padEnd(n);
    const padL = (s, n) => String(s).padStart(n);
    console.log(`${pad('asset', 34)}${padL('bytes', 9)}${padL('gzip', 9)}`);
    for (const a of assets) console.log(`${pad(a.path, 34)}${padL(a.size, 9)}${padL(a.gz_size, 9)}`);
    console.log(`${pad('total', 34)}${padL(total, 9)}${padL(totalGz, 9)}  (budget ${BUDGET_GZ}, ${((totalGz / BUDGET_GZ) * 100).toFixed(1)} % used)`);
  }
  return { ok: totalGz <= BUDGET_GZ, assets, totalGz, out };
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const args = process.argv.slice(2);
  const o = { quiet: args.includes('--quiet') };
  const i = args.indexOf('--out');
  if (i >= 0) {
    if (!args[i + 1]) { console.error('--out needs a directory'); process.exit(2); }
    o.out = args[i + 1];
  }
  build(o).then((r) => {
    if (!r.ok) {
      console.error(`build_web: gzip total ${r.totalGz} B exceeds the ${BUDGET_GZ} B budget`);
      process.exit(1);
    }
  }).catch((e) => {
    console.error(`build_web: ${e.message}`);
    if (e.errors) for (const x of e.errors) console.error(`  ${x.location ? `${x.location.file}:${x.location.line}: ` : ''}${x.text}`);
    process.exit(1);
  });
}
