// Alarm catalog loader (effective severities change with /config/alarms and /config/rules).
import { get } from './api.js';
import { state, emit } from './store.js';

export async function loadAlarmMeta() {
  const am = await get('/meta/alarms');
  state.alarmMeta = new Map(am.map((a) => [a.id, a]));
  emit('alarmMeta', am);
}
