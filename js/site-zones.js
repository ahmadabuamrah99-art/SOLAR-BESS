// Zone progress calculations, in construction order. Pure functions with no DOM access.
// Uses js/site-data.js. Values are sample figures until published site data is connected.
//
// Steps without data in the layout model are returned with hasData: false, so the
// page can show "No data yet" instead of an invented number.
import { TABLE_ZONES, INVERTER_IDS, INVERTER_ZONES, TABLE_STATUS, INVERTER_STATUS } from "./site-data.js";

export const ZONE_IDS = ["SP1", "SP2", "SP3", "SP4"];

// Per-table capacity from the sketch's model: 32 piles, 6 C-rails and 30 vertical tubes per side, 87 modules per side.
const PER_TABLE = { piles: 32, crails: 12, vtubes: 60, modules: 174 };
const STRINGS_PER_INVERTER = 24;

const pct = (done, total) => (total ? Math.round((done / total) * 1000) / 10 : 0);

export function zoneTableIndexes(zone) {
  const out = [];
  TABLE_ZONES.forEach((z, i) => { if (z === zone) out.push(i); });
  return out;
}

function step(key, label, done, total, hasData = true) {
  return { key, label, done, total, pct: hasData ? pct(done, total) : null, hasData };
}

export function zoneStages(zone) {
  const idx = zoneTableIndexes(zone);
  const n = idx.length;
  const sum = (f) => idx.reduce((s, i) => s + f(TABLE_STATUS[i]), 0);

  const invIdx = [];
  INVERTER_ZONES.forEach((z, i) => { if (z === zone) invIdx.push(i); });
  const invs = invIdx.map((i) => {
    const [strings, mounted, dc, ac, comm] = INVERTER_STATUS[i];
    return { id: INVERTER_IDS[i], strings, mounted: !!mounted, dc: !!dc, ac: !!ac, comm: !!comm };
  });
  const m = invs.length;

  // Construction order as agreed: ramming, structure (sliding, queue, serial), inverter structure,
  // inverter install, module install, module alignment, DC cable.
  const sequence = [
    step("ramming", "1. Ramming (piling)", sum((r) => r[0]), n * PER_TABLE.piles),
    step("sliding", "2. Structure: sliding (vertical tubes)", sum((r) => r[3] + r[4]), n * PER_TABLE.vtubes),
    step("queue", "2. Structure: queue (C-rails)", sum((r) => r[1] + r[2]), n * PER_TABLE.crails),
    step("serial", "2. Structure: serial", 0, 0, false),
    step("inv-structure", "3. Install structure for inverter", 0, 0, false),
    step("inv-install", "4. Install inverter", invs.filter((v) => v.mounted).length, m),
    step("modules", "5. Install modules", sum((r) => r[5] + r[6]), n * PER_TABLE.modules),
    step("module-align", "6. Module alignment", 0, 0, false),
    step("dc-cable", "7. Pull DC cable", invs.filter((v) => v.dc).length, m),
  ];

  // Inverter electrical steps after the DC cable.
  const further = [
    step("strings", "Strings installed", invs.reduce((s, v) => s + v.strings, 0), m * STRINGS_PER_INVERTER),
    step("ac", "AC connected", invs.filter((v) => v.ac).length, m),
    step("comm", "Commissioned", invs.filter((v) => v.comm).length, m),
  ];

  return { zone, tables: n, sequence, further, inverters: { count: m, list: invs } };
}

export function zoneSummaries() {
  return ZONE_IDS.map((z) => {
    const s = zoneStages(z);
    const byKey = Object.fromEntries(s.sequence.map((x) => [x.key, x]));
    return { zone: z, tables: s.tables, piling: byKey.ramming.pct, modules: byKey.modules.pct, inverters: s.inverters.count };
  });
}
