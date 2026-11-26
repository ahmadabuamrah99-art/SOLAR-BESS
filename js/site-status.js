// Site status for the Project Overview: zones, mechanical and electrical progress,
// inverter grid, progress trend and daily report archive.
//
// IMPORTANT: this file holds DEMO DATA only. Every number is illustrative and is
// not a project fact. It is shown with a DEMO label until verified site data is connected.
// Nothing here is read from or written to the database.

export const SITE_STATUS_IS_DEMO = true;

// Six zones of the site. Piles, modules, strings and inverters are per zone.
export const ZONES = [
  { id: "Z1", name: "Zone 1", piles: { total: 1200, done: 1140 }, modules: { total: 9800, done: 8900 }, structure: { total: 160, done: 150 }, strings: { total: 620, done: 560 }, inverters: [1, 2, 3, 4], photosPending: 4 },
  { id: "Z2", name: "Zone 2", piles: { total: 1100, done: 980 }, modules: { total: 9000, done: 6100 }, structure: { total: 150, done: 118 }, strings: { total: 580, done: 360 }, inverters: [5, 6, 7, 8], photosPending: 9 },
  { id: "Z3", name: "Zone 3", piles: { total: 1000, done: 610 }, modules: { total: 8200, done: 2900 }, structure: { total: 135, done: 72 }, strings: { total: 520, done: 180 }, inverters: [9, 10, 11, 12], photosPending: 14 },
  { id: "Z4", name: "Zone 4", piles: { total: 950, done: 240 }, modules: { total: 7800, done: 0 }, structure: { total: 128, done: 20 }, strings: { total: 500, done: 0 }, inverters: [13, 14, 15, 16], photosPending: 22 },
  { id: "Z5", name: "Zone 5", piles: { total: 900, done: 0 }, modules: { total: 7400, done: 0 }, structure: { total: 120, done: 0 }, strings: { total: 470, done: 0 }, inverters: [17, 18, 19, 20], photosPending: 0 },
  { id: "Z6", name: "Zone 6", piles: { total: 850, done: 0 }, modules: { total: 7000, done: 0 }, structure: { total: 112, done: 0 }, strings: { total: 440, done: 0 }, inverters: [21, 22, 23, 24], photosPending: 0 },
];

// Inverter state per unit: "installed", "pending" or "fault".
export const INVERTERS = {
  1: "installed", 2: "installed", 3: "installed", 4: "installed",
  5: "installed", 6: "installed", 7: "installed", 8: "pending",
  9: "installed", 10: "installed", 11: "pending", 12: "pending",
  13: "installed", 14: "pending", 15: "pending", 16: "pending",
  17: "pending", 18: "pending", 19: "pending", 20: "pending",
  21: "pending", 22: "pending", 23: "pending", 24: "pending",
};

export const TRANSFORMERS = [
  { id: "TX-1", zone: "Z1", status: "installed" },
  { id: "TX-2", zone: "Z2", status: "installed" },
  { id: "TX-3", zone: "Z3", status: "pending" },
  { id: "TX-4", zone: "Z4", status: "pending" },
];

// Daily report archive. Cumulative percentages are as reported that day.
export const REPORTS = [
  { date: "2026-11-01", mech: 8, elec: 2, note: "Piling started in Zone 1 and Zone 2." },
  { date: "2026-11-08", mech: 15, elec: 4, note: "Structure installation started in Zone 1." },
  { date: "2026-11-15", mech: 24, elec: 8, note: "First inverters delivered to Zone 1." },
  { date: "2026-11-19", mech: 31, elec: 12, note: "Module installation in Zone 2." },
  { date: "2026-11-22", mech: 36, elec: 14, note: "Zone 3 piling in progress." },
  { date: "2026-11-25", mech: 41, elec: 16, note: "DEMO report: inverters 1-7 installed." },
];

// Pure calculations. No DOM access, so they can be unit tested.
export function pct(done, total) {
  return total ? Math.round((done / total) * 1000) / 10 : 0;
}

export function zoneSummary(zone) {
  const mechDone = zone.piles.done + zone.structure.done + zone.modules.done;
  const mechTotal = zone.piles.total + zone.structure.total + zone.modules.total;
  const strInstalled = zone.strings.done;
  const invInstalled = zone.inverters.filter((n) => INVERTERS[n] === "installed").length;
  const mech = pct(mechDone, mechTotal);
  const elec = pct(zone.strings.done + invInstalled, zone.strings.total + zone.inverters.length);
  const status = mech >= 100 ? "done" : mech === 0 ? "not-started" : "in-progress";
  return {
    id: zone.id, name: zone.name, mech, elec, status,
    pilesRemaining: zone.piles.total - zone.piles.done,
    modulesRemaining: zone.modules.total - zone.modules.done,
    structureRemaining: zone.structure.total - zone.structure.done,
    stringsRemaining: zone.strings.total - strInstalled,
    invInstalled, invTotal: zone.inverters.length,
    photosPending: zone.photosPending,
  };
}

export function siteTotals() {
  const sum = (f) => ZONES.reduce((s, z) => s + f(z), 0);
  const mechDone = sum((z) => z.piles.done + z.structure.done + z.modules.done);
  const mechTotal = sum((z) => z.piles.total + z.structure.total + z.modules.total);
  const invTotal = Object.keys(INVERTERS).length;
  const invInstalled = Object.values(INVERTERS).filter((s) => s === "installed").length;
  return {
    mech: pct(mechDone, mechTotal),
    elec: pct(sum((z) => z.strings.done) + invInstalled, sum((z) => z.strings.total) + invTotal),
    pilesRemaining: sum((z) => z.piles.total - z.piles.done),
    modulesRemaining: sum((z) => z.modules.total - z.modules.done),
    invInstalled, invTotal,
    invPending: Object.values(INVERTERS).filter((s) => s === "pending").length,
    invFault: Object.values(INVERTERS).filter((s) => s === "fault").length,
    photosPending: sum((z) => z.photosPending),
  };
}
