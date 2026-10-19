// Build test: tools/build_web.mjs output (hashed names, gzip, manifest, sprite/favicon, budget).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { build, BUDGET_GZ, minifySvg, collapseHtml, faviconSvg, spriteSvg } from '../../tools/build_web.mjs';

test('build output: manifest, hashed assets, gzip, budget', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'gw-web-'));
  const out = join(dir, 'dist');
  try {
    const r = await build({ out, quiet: true });
    assert.ok(r.ok, `gzip total ${r.totalGz} exceeds ${BUDGET_GZ}`);
    const man = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
    assert.equal(man.budget_gz, 65536);
    assert.ok(man.total_gz <= man.budget_gz);
    const paths = man.assets.map((a) => a.path);
    assert.deepEqual([...paths].sort(), paths, 'sorted by path');
    assert.equal(paths[0], '/');
    assert.ok(paths.includes('/favicon.svg'));
    assert.equal(man.assets.length, 4, 'few requests: html, js, css, favicon');
    let sum = 0;
    for (const a of man.assets) {
      const raw = readFileSync(join(out, a.file));
      const gz = readFileSync(join(out, a.gz));
      assert.deepEqual(gunzipSync(gz), raw, a.path);
      assert.equal(a.size, raw.length);
      assert.equal(a.gz_size, gz.length);
      assert.equal(a.etag, `"${createHash('sha256').update(raw).digest('hex').slice(0, 16)}"`);
      if (a.immutable) {
        assert.match(a.path, /^\/assets\/app\.[0-9a-f]{8}\.(js|css)$/);
        assert.equal(a.path.split('.')[1], createHash('sha256').update(raw).digest('hex').slice(0, 8), 'content hash');
      }
      sum += gz.length;
    }
    assert.equal(sum, man.total_gz);
    const html = readFileSync(join(out, 'index.html'), 'utf8');
    const js = man.assets.find((a) => a.path.endsWith('.js'));
    const css = man.assets.find((a) => a.path.endsWith('.css'));
    assert.ok(html.includes(`src="${js.path}"`) && html.includes(`href="${css.path}"`));
    assert.ok(!html.includes('/src/main.js') && !html.includes('<!--'));
    assert.match(html, /<svg class="sprite"[^>]*>.*<symbol id="i-dash".*<symbol id="logo"/);
    assert.doesNotMatch(html, /<style|style=|<script>(?!<)/, 'CSP: no inline style or script');
    const bundle = readFileSync(join(out, js.file), 'utf8');
    assert.doesNotMatch(bundle, /'nav\.dashboard'|"login\.title"/, 'literal i18n keys compiled to indices');
    assert.match(bundle, /로그인/);
    // a second build is deterministic
    const r2 = await build({ out, quiet: true });
    assert.equal(r2.totalGz, r.totalGz);
    // refuses to clean an unrelated directory
    const other = join(dir, 'other');
    mkdirSync(other);
    writeFileSync(join(other, 'keep.txt'), 'x');
    await assert.rejects(build({ out: other, quiet: true }), /refusing/);
    assert.ok(existsSync(join(other, 'keep.txt')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('svg/html helpers strip metadata and whitespace', () => {
  assert.equal(minifySvg('<svg>\n <title>x</title><desc>y</desc>\n <!-- c --> <path d="M0 0"/> </svg>'), '<svg><path d="M0 0"/></svg>');
  const fav = faviconSvg();
  assert.match(fav, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 256 256" fill="#3155E7"><path d="M38 203V97/);
  assert.doesNotMatch(fav, /title|desc|registered|role=/);
  const sp = spriteSvg();
  assert.match(sp, /<symbol id="logo" viewBox="0 0 256 256">/);
  assert.ok((sp.match(/<symbol /g) || []).length >= 30);
  assert.equal(collapseHtml('<a>\n  <b> x </b>\n<!-- y --></a>'), '<a><b> x </b></a>');
});
