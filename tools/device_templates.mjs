// The firmware and local mock use the same device catalog; never duplicate channel definitions.
import { readFileSync } from 'node:fs';
const source = new URL('../components/gw_core/device_templates.def', import.meta.url);
const argsOf = (s) => s.match(/"(?:\\.|[^"\\])*"|[^,\s]+/g).map((s) => s.startsWith('"') ? JSON.parse(s) : /^\d+$/.test(s) ? Number(s) : s);
export function readDeviceTemplates() {
  const templates = [];
  let cur;
  for (const line of readFileSync(source, 'utf8').split('\n')) {
    const m = line.match(/^(DEVICE_TEMPLATE|CHANNEL|END_TEMPLATE)\((.*)\)$/);
    if (!m) continue;
    const a = argsOf(m[2]);
    if (m[1] === 'DEVICE_TEMPLATE') {
      const [, id, name, vendor, category, description, baud, data_bits, parity, stop] = a;
      cur = { id, name, vendor, category, description, serial: { baud, data_bits, parity, stop }, channels: [] };
      templates.push(cur);
    } else if (m[1] === 'CHANNEL') {
      const [id, key, ko, en, access, source, addr, scale, unit] = a;
      cur.channels.push({ id, key, ko, en, access, source, addr: addr || null, scale, unit });
    }
  }
  return templates;
}
