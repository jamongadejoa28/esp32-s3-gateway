// POSIX TZ as stored by the gateway. UTC epochs stay unchanged; only display uses this zone.
let zone = null;
const signedSeconds = (s) => {
  const sign = s.startsWith('-') ? -1 : 1;
  const [h, m = 0, sec = 0] = s.replace(/^[+-]/, '').split(':').map(Number);
  return sign * (h * 3600 + m * 60 + sec);
};
export function parseTimeZone(text) {
  if (!text) return null;
  const m = /^(?:[A-Za-z]{3,}|<[^>]+>)([+-]?\d{1,3}(?::\d{1,2}){0,2})?(.*)$/.exec(text);
  if (!m) return null;
  const west = signedSeconds(m[1] || '0');
  if (Math.abs(west) > 24 * 3600) return null;
  if (!m[2]) return { west };
  const dst = /^(?:[A-Za-z]{3,}|<[^>]+>)([+-]?\d{1,3}(?::\d{1,2}){0,2})?(?:,([^,]+),([^,]+))?$/.exec(m[2]);
  if (!dst) return null;
  const rules = [dst[2] || 'M3.2.0/2', dst[3] || 'M11.1.0/2'];
  if (rules.some((r) => !/^(M(?:[1-9]|1[0-2])\.[1-5]\.[0-6]|J(?:[1-9]\d?|[12]\d\d|3[0-5]\d|36[0-5])|(?:\d|[1-9]\d|[12]\d\d|3[0-5]\d|36[0-5]))(?:\/[+-]?\d{1,3}(?::[0-5]\d){0,2})?$/.test(r))) return null;
  return { west, dstWest: dst[1] ? signedSeconds(dst[1]) : west - 3600, rules };
}
export function setTimeZone(tz) { zone = parseTimeZone(tz); }
function transition(year, rule, west) {
  const [day, at = '2'] = rule.split('/');
  let date;
  if (day[0] === 'M') {
    const [month, week, weekday] = day.slice(1).split('.').map(Number);
    const first = new Date(Date.UTC(year, month - 1, 1)).getUTCDay();
    let d = 1 + (weekday - first + 7) % 7 + (week - 1) * 7;
    const last = new Date(Date.UTC(year, month, 0)).getUTCDate();
    if (d > last) d -= 7;
    date = Date.UTC(year, month - 1, d);
  } else {
    let n = Number(day.replace(/^J/, ''));
    if (day[0] === 'J') {
      n--;
      if (new Date(Date.UTC(year, 1, 29)).getUTCMonth() === 1 && n >= 59) n++;
    }
    date = Date.UTC(year, 0, 1 + n);
  }
  return date + (signedSeconds(at) + west) * 1000;
}
export function displayDate(ms) {
  if (!zone) return { date: new Date(ms), utc: false };
  let west = zone.west;
  if (zone.rules) {
    const year = new Date(ms - west * 1000).getUTCFullYear();
    const start = transition(year, zone.rules[0], west);
    const end = transition(year, zone.rules[1], zone.dstWest);
    const dst = start < end ? ms >= start && ms < end : ms >= start || ms < end;
    if (dst) west = zone.dstWest;
  }
  return { date: new Date(ms - west * 1000), utc: true };
}

/** datetime-local interpreted in the gateway zone; rejects skipped/invalid calendar times. */
export function parseDisplayTime(text) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(text);
  if (!m) return null;
  const a = m.slice(1).map((x) => Number(x || 0));
  const target = Date.UTC(a[0], a[1] - 1, a[2], a[3], a[4], a[5]);
  let guess = target;
  for (let i = 0; i < 4; i++) {
    const { date: d, utc } = displayDate(guess);
    const get = (key) => d[`${utc ? 'getUTC' : 'get'}${key}`]();
    const shown = Date.UTC(get('FullYear'), get('Month'), get('Date'), get('Hours'), get('Minutes'), get('Seconds'));
    if (shown === target) {
      const d0 = new Date(target);
      if (d0.getUTCMonth() + 1 !== a[1] || d0.getUTCDate() !== a[2] || d0.getUTCHours() !== a[3] || d0.getUTCMinutes() !== a[4] || d0.getUTCSeconds() !== a[5]) return null;
      return guess;
    }
    guess += target - shown;
  }
  return null;
}
