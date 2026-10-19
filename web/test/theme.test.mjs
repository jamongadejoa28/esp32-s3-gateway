// WCAG AA contrast of the text-bearing token pairs in both themes (web/styles/tokens.css).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const css = readFileSync(new URL('../styles/tokens.css', import.meta.url), 'utf8');

function block(sel) {
  const i = css.indexOf(sel);
  assert.ok(i >= 0, `${sel} block`);
  const body = css.slice(css.indexOf('{', i) + 1, css.indexOf('}', i));
  return Object.fromEntries([...body.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})\b/g)].map((m) => [m[1], m[2]]));
}

const lum = (hex) => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((x) => (x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const ratio = (a, b) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

// [foreground, background]; '#fff' = literal white text (solid alarm badge / danger button)
const PAIRS = [
  ['text', 'bg'], ['text', 'surface'], ['text', 'surface-2'], ['text', 'accent-weak'],
  ['muted', 'bg'], ['muted', 'surface'], ['muted', 'surface-2'],
  ['accent', 'surface'], ['on-accent', 'accent-fill'], ['#ffffff', 'alarm-fill'],
  ['ok-ink', 'surface'], ['warn-ink', 'surface'], ['alarm-ink', 'surface'],
  ['ok-ink', 'ok-weak'], ['warn-ink', 'warn-weak'], ['alarm-ink', 'alarm-weak'],
];

test('text colour pairs meet WCAG AA (4.5:1) in light and dark themes', () => {
  const light = block(':root {');
  const dark = { ...light, ...block(':root[data-theme="dark"]') };
  for (const [name, tk] of [['light', light], ['dark', dark]]) {
    for (const [f, b] of PAIRS) {
      const fg = f.startsWith('#') ? f : tk[f];
      assert.ok(fg && tk[b], `${name}: --${f} / --${b} defined`);
      const r = ratio(fg, tk[b]);
      assert.ok(r >= 4.5, `${name}: ${f} on ${b} = ${r.toFixed(2)}:1`);
    }
  }
});
