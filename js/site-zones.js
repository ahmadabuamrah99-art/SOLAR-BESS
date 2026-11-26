// Zone progress calculations. Pure functions with no DOM access.
// Uses js/site-data.js. Values are sample figures until published site data is connected.
import { TABLE_ZONES, INVERTER_IDS, INVERTER_ZONES, TABLE_STATUS, INVERTER_STATUS } from "./site-data.js";

export const ZONE_IDS = ["SP1", "SP2", "SP3", "SP4"];

// Per-table capacity from the sketch's model: 32 piles, 6 C-rails and 30 vertical tubes per side, 87 modules per side.
const PER_TABLE = { piles: 32, alignment: 12, structure: 60, modules: 174 };
const STRINGS_PER_INVERTER = 24;

const pct = (done, total) => (total ? Math.round((done / total) * 1000) / 10 : 0);

export function zoneTableIndexes(zone) {
  const out = [];
  TABLE_ZONES.forEach((z, i) => { if (z === zone) out.push(i); });
  return out;
}

export function zoneStages(zone) {
  const idx = zoneTableIndexes(zone);
  const sum = (f) => idx.reduce((s, i) => s + f(TABLE_STATUS[i]), 0);
  const n = idx.length;
  const stages = [
    { key: "piling", label: "Piling (ramming)", done: sum((r) => r[0]), total: n * PER_TABLE.piles },
    { key: "alignment", label: "Structure alignment (C-rails)", done: sum((r) => r[1] + r[2]), total: n * PER_TABLE.alignment },
    { key: "structure", label: "Structure installation (vertical tubes)", done: sum((r) => r[3] + r[4]), total: n * PER_TABLE.structure },
    { key: "modules", label: "Module installation", done: sum((r) => r[5] + r[6]), total: n * PER_TABLE.modules },
  ].map((s) => ({ ...s, pct: pct(s.done, s.total) }));

  const invIdx = [];
  INVERTER_ZONES.forEach((z, i) => { if (z === zone) invIdx.push(i); });
  const invs = invIdx.map((i) => {
    const [strings, mounted, dc, ac, comm] = INVERTER_STATUS[i];
    return { id: INVERTER_IDS[i], strings, mounted: !!mounted, dc: !!dc, ac: !!ac, comm: !!comm };
  });
  const m = invs.length;
  const inverterStages = [
    { key: "strings", label: "Strings installed", done: invs.reduce((s, v) => s + v.strings, 0), total: m * STRINGS_PER_INVERTER },
    { key: "mounted", label: "Inverter mounted", done: invs.filter((v) => v.mounted).length, total: m },
    { key: "dc", label: "DC connected", done: invs.filter((v) => v.dc).length, total: m },
    { key: "ac", label: "AC connected", done: invs.filter((v) => v.ac).length, total: m },
    { key: "comm", label: "Commissioned", done: invs.filter((v) => v.comm).length, total: m },
  ].map((s) => ({ ...s, pct: pct(s.done, s.total) }));

  return {
    zone,
    tables: n,
    stages,
    inverters: { count: m, stages: inverterStages, list: invs },
  };
}

export function zoneSummaries() {
  return ZONE_IDS.map((z) => {
    const s = zoneStages(z);
    const byKey = Object.fromEntries(s.stages.map((x) => [x.key, x]));
    return { zone: z, tables: s.tables, piling: byKey.piling.pct, modules: byKey.modules.pct, inverters: s.inverters.count };
  });
}
