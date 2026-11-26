// GreenGrid frontend: authentication, role-aware UI and Supabase data access.
// Security is enforced by Postgres RLS and triggers. The UI only hides controls.
import { SUPABASE_URL, SUPABASE_ANON_KEY } from "./config.js";
import { PROJECT_IDENTITY } from "./project.js";
import { zoneSummaries, zoneStages } from "./site-zones.js";
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.119.0/+esm";

// ---------------------------------------------------------------------
// Constants (must match the database CHECK constraints)
// ---------------------------------------------------------------------
const DISCIPLINES = ["Mechanical", "Electrical", "QA/QC", "Commissioning"];
const CATEGORIES = ["Engineer", "Supervisor", "Technician", "Electrician", "Labour", "QA/QC", "HSE", "Commissioning", "Other"];
const ISSUE_CATEGORIES = ["Materials", "Technical", "Manpower", "Equipment", "Logistics", "Access", "Weather", "Other"];
const BLOCK_STATUSES = ["Not Started", "In Progress", "Installed", "Commissioned"];
const ROLE_LABEL = { admin: "Admin", engineer: "Engineer", viewer: "Viewer" };

// Username sign-in is postponed. It needs the profiles.username column, the
// Edge Function and the migration, none of which are applied yet. While this is false,
// the app never reads or writes that column and the login form is email-only.
const USERNAME_LOGIN_ENABLED = false;

// Project identity comes from js/project.js only. It is never read from the database.

// ---------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (v, d = 0) => Number(v ?? 0).toLocaleString("en-US", { maximumFractionDigits: d, minimumFractionDigits: 0 });
const fmtPct = (v) => (v == null || v === "" ? "—" : `${Number(v).toFixed(1)}%`);
const iso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const today = () => iso(new Date());
const empty = (cols, text = "No records yet") => `<tr><td colspan="${cols}" class="empty">${esc(text)}</td></tr>`;
const emptyBox = (text) => `<div class="empty">${esc(text)}</div>`;
const numOrNull = (v) => (v == null || String(v).trim() === "" ? null : Number(v));
const initials = (name) => (name || "?").split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("") || "?";

function pillFor(status) {
  const map = {
    Draft: "pill gray", Submitted: "pill warn", Approved: "pill", Rejected: "pill bad", Closed: "pill gray",
    Open: "pill warn", "In Progress": "pill warn",
    High: "pill bad", Medium: "pill warn", Low: "pill gray",
  };
  return `<span class="${map[status] || "pill gray"}">${esc(status)}</span>`;
}

// ---------------------------------------------------------------------
// Configuration and key safety checks
// ---------------------------------------------------------------------
function configProblem() {
  if (!SUPABASE_URL.startsWith("https://") || SUPABASE_URL.includes("YOUR-")) return "SUPABASE_URL is not set.";
  if (!SUPABASE_ANON_KEY || SUPABASE_ANON_KEY.includes("YOUR-")) return "SUPABASE_ANON_KEY is not set.";
  return null;
}

// Returns the JWT role or key type so a service-role key is never used in the browser.
function keyRole(key) {
  if (/^sb_secret_/i.test(key)) return "service_role";
  if (key.startsWith("eyJ")) {
    try {
      let b64 = key.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      b64 += "=".repeat((4 - (b64.length % 4)) % 4);
      return JSON.parse(atob(b64)).role || null;
    } catch {
      return null;
    }
  }
  return null;
}

// ---------------------------------------------------------------------
// Views and messages
// ---------------------------------------------------------------------
const VIEWS = ["viewSetup", "viewLogin", "viewReset", "viewNewPassword", "viewInactive", "viewApp"];
function showView(id) {
  for (const v of VIEWS) $(v).classList.toggle("hidden", v !== id);
}
function setMsg(id, text, kind = "") {
  const el = $(id);
  el.textContent = text;
  el.className = "msg" + (kind ? ` ${kind}` : "");
}
let toastTimer;
function toast(text, isErr = false) {
  const t = $("toast");
  t.textContent = text;
  t.className = "toast show" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = "toast"), 4500);
}
function friendly(err) {
  switch (err?.code) {
    case "42501": return "Your role is not allowed to do this.";
    case "23505": return "A record with this reference or key already exists.";
    case "23514": return "A value is outside the allowed range. " + (err.message || "");
    case "P0001": return err.message;
    default: return err?.message || "Something went wrong. Please try again.";
  }
}

// ---------------------------------------------------------------------
// Application state (loaded from the database; the UI never invents data)
// ---------------------------------------------------------------------
const state = {};
function resetState() {
  Object.assign(state, {
    user: null, profile: null, project: null, activities: [], overview: null, byDiscipline: [],
    blocks: [], progress: [], qaqc: [], hse: [], manpower: [], equipment: [], equipLogs: [],
    issues: [], reports: [], profiles: [], names: {},
  });
  document.body.className = "";
}
resetState();

const isAdmin = () => state.profile?.role === "admin";
const isWriter = () => ["admin", "engineer"].includes(state.profile?.role);
const needProject = () => {
  if (!state.project) { toast("Create the project first (Reports & Data → Project settings).", true); return false; }
  return true;
};

// Run a write, show the result, and reload data. Returns true on success.
async function save(builder, okMsg) {
  const { error } = await builder;
  if (error) { toast(friendly(error), true); return false; }
  if (okMsg) toast(okMsg);
  await loadAll();
  return true;
}

// ---------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------
let sb;

async function loadAll() {
  // Profiles load first: admins need the user list even before a project exists.
  // Only columns that exist in the current database. "username" is added back only when the feature is enabled.
  const profileColumns = USERNAME_LOGIN_ENABLED ? "id,full_name,role,is_active,username" : "id,full_name,role,is_active";
  const { data: profs, error: profErr } = await sb.from("profiles").select(profileColumns).order("full_name");
  if (profErr) { toast(friendly(profErr), true); return; }
  state.profiles = profs ?? [];
  state.names = Object.fromEntries(state.profiles.map((p) => [p.id, p.full_name || "(no name)"]));

  const { data: projects, error: pErr } = await sb.from("projects").select("*").order("created_at").limit(1);
  if (pErr) { toast(friendly(pErr), true); return; }
  state.project = projects?.[0] ?? null;
  if (!state.project) {
    Object.assign(state, { activities: [], overview: null, byDiscipline: [], blocks: [], progress: [], qaqc: [], hse: [], manpower: [], equipment: [], equipLogs: [], issues: [], reports: [] });
    renderAll();
    return;
  }
  const pid = state.project.id;
  const q = (table) => sb.from(table).select("*").eq("project_id", pid);
  const results = await Promise.all([
    q("activity_progress").order("sort_order"),
    q("project_progress_overview"),
    q("progress_by_discipline"),
    q("bess_blocks").order("block_no"),
    q("progress_entries").order("entry_date", { ascending: false }).order("created_at", { ascending: false }).limit(1000),
    q("qaqc_records").order("record_date", { ascending: false }),
    q("hse_records").order("record_date", { ascending: false }),
    q("manpower_daily").order("log_date", { ascending: false }).limit(2000),
    q("equipment").order("equipment_code"),
    q("equipment_daily_log").order("log_date", { ascending: false }).limit(5000),
    q("issues").order("issue_no"),
    q("report_snapshots").order("created_at", { ascending: false }).limit(200),
  ]);
  const failed = results.find((r) => r.error);
  if (failed) { toast(friendly(failed.error), true); return; }
  const [act, ov, disc, blocks, prog, qaqc, hse, man, eq, eqlog, iss, reps] = results.map((r) => r.data ?? []);
  Object.assign(state, {
    activities: act, overview: ov[0] ?? null, byDiscipline: disc, blocks, progress: prog, qaqc, hse,
    manpower: man, equipment: eq, equipLogs: eqlog, issues: iss, reports: reps,
  });
  renderAll();
}

const actName = (id) => state.activities.find((a) => a.activity_id === id)?.name ?? "—";

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// Zone progress (Project Overview). Sample figures from the site sketch's layout (js/site-data.js).
// ---------------------------------------------------------------------
let selectedZone = null;

function renderZones() {
  const btns = $("zoneButtons");
  if (!btns) return;
  btns.innerHTML = zoneSummaries().map((s) =>
    `<button type="button" class="zone-tile${selectedZone === s.zone ? " sel" : ""}" data-zone="${esc(s.zone)}"><b>${esc(s.zone)}</b><span>Piling ${fmtPct(s.piling)} · Modules ${fmtPct(s.modules)}</span><span>${s.tables} tables · ${s.inverters} inverters</span></button>`).join("");

  // Fly the drawing to the selected zone (the sketch listens for this message).
  const frame = document.querySelector("iframe.site-sketch");
  if (frame && frame.contentWindow && selectedZone) {
    frame.contentWindow.postMessage({ type: "zone", zone: selectedZone }, location.origin);
  }

  if (!selectedZone) {
    $("zoneTitle").textContent = "Select a zone";
    $("zoneDetail").innerHTML = `<p class="kpi-note">No zone selected.</p>`;
    return;
  }
  const z = zoneStages(selectedZone);
  const row = (x) => `<div class="progressrow"><div class="rowtop"><span>${esc(x.label)}</span><b>${fmtPct(x.pct)} <span class="kpi-note">(${num(x.done)} of ${num(x.total)})</span></b></div><div class="track"><div class="fill" style="width:${x.pct}%"></div></div></div>`;
  const chip = (v) => {
    const colour = v.comm ? "#5E9A2B" : (v.strings > 0 || v.mounted || v.dc || v.ac) ? "#D9831A" : "#8FA39F";
    const short = v.id.replace(/^TX\d+-/, "");
    return `<span class="inv-cell" style="background:${colour}" title="${esc(v.id)}: strings ${v.strings} of 24, mounted ${v.mounted ? "yes" : "no"}, DC ${v.dc ? "yes" : "no"}, AC ${v.ac ? "yes" : "no"}, commissioned ${v.comm ? "yes" : "no"}">${esc(short)}</span>`;
  };
  $("zoneTitle").textContent = `${z.zone} · ${z.tables} tables · ${z.inverters.count} inverters`;
  $("zoneDetail").innerHTML = `
    <h4 class="zone-h">Mechanical</h4>${z.stages.map(row).join("")}
    <h4 class="zone-h">Inverters</h4>${z.inverters.stages.map(row).join("")}
    <h4 class="zone-h">Inverter status (green = commissioned, amber = in progress, grey = not started)</h4>
    <div class="inv-grid">${z.inverters.list.map(chip).join("")}</div>`;
}

function renderAll() {
  renderHeader();
  renderZones();
  renderNotice();
  renderOverview();
  renderSolar();
  renderBess();
  renderSchedule();
  renderQaqc();
  renderHse();
  renderManpower();
  renderIssues();
  renderReportList();
  renderSettings();
  renderUsers();
}

// Project identity shown in the header, sidebar and login screen.
function renderIdentity() {
  // The Soventix logo above already carries the company name. Below it: project name, then location.
  $("sideIdentity").innerHTML = `<b>${esc(PROJECT_IDENTITY.name)}</b><span>${esc(PROJECT_IDENTITY.location)}</span>`;
  $("loginProjectName").textContent = PROJECT_IDENTITY.name;
  $("loginProjectLocation").textContent = PROJECT_IDENTITY.location;
}

function renderHeader() {
  const name = state.profile?.full_name || state.user?.email || "User";
  $("userName").textContent = name;
  $("userRole").textContent = ROLE_LABEL[state.profile?.role] || "—";
  $("avatar").textContent = initials(name);
  document.body.className = state.profile ? `role-${state.profile.role}` : "";
}

function renderNotice() {
  const n = $("overviewNotice");
  if (!state.project) {
    n.className = "notice";
    n.textContent = "No project record exists yet. An Admin can create it under Reports & Data → Project settings.";
  } else if (state.project.is_demo) {
    n.className = "notice demo";
    n.innerHTML = "<strong>DEMO DATA.</strong> Sample quantities are illustrative only. Replace them with approved baseline quantities and verified installed quantities before issuing any report.";
  } else {
    n.className = "notice";
    n.textContent = `Live project data: ${PROJECT_IDENTITY.name}.`;
  }
}

function statusOf(a) {
  if (a.planned_pct == null) return ["No plan", "pill gray"];
  const d = Number(a.progress_pct) - Number(a.planned_pct);
  if (d >= 3) return ["Ahead", "pill"];
  if (d <= -5) return ["Delayed", "pill bad"];
  return ["On Track", "pill"];
}
const statusPill = (a) => { const [t, c] = statusOf(a); return `<span class="${c}">${t}</span>`; };

function renderOverview() {
  const acts = state.activities;
  const ov = state.overview;
  const weighted = ov?.weighted_overall_pct;
  $("overall").textContent = weighted != null ? fmtPct(weighted) : "Pending";
  $("overallNote").textContent = weighted != null
    ? "Weighted by verified activity weights"
    : "Needs verified weights (Budget or Man-hours) on every activity";
  $("planned").textContent = "Not set";
  $("plannedNote").textContent = "Schedule baseline required";
  const done = acts.filter((a) => Number(a.progress_pct) >= 100).length;
  $("completeCount").textContent = `${done}/${acts.length}`;
  $("openIssues").textContent = state.issues.filter((i) => i.status !== "Closed").length;

  const scored = acts
    .filter((a) => a.planned_pct != null)
    .map((a) => ({ a, v: Number(a.progress_pct) - Number(a.planned_pct) }))
    .sort((x, y) => x.v - y.v)
    .slice(0, 6);
  $("priorityRows").innerHTML = scored.length
    ? scored.map(({ a, v }) => `<tr><td class="wrap">${esc(a.name)}</td><td>${esc(a.discipline)}</td><td>${fmtPct(a.planned_pct)}</td><td>${fmtPct(a.progress_pct)}</td><td>${v.toFixed(1)}%</td><td>${statusPill(a)}</td></tr>`).join("")
    : empty(6, "No planned % set yet");
}

function progressBar(a) {
  return `<div class="progressrow"><div class="rowtop"><span>${esc(a.name)}</span><b>${fmtPct(a.progress_pct)}</b></div><div class="track"><div class="fill" style="width:${Math.min(100, Number(a.progress_pct))}%"></div></div></div>`;
}

function activityRow(a) {
  return `<tr><td class="wrap">${esc(a.name)}</td><td>${esc(a.discipline)}</td><td>${esc(a.unit)}</td><td>${num(a.planned_qty)}</td><td>${num(a.installed_qty)}</td><td>${fmtPct(a.progress_pct)}</td><td class="inline"><button class="secondary small-btn" data-write data-action="log-progress" data-id="${esc(a.activity_id)}">Log</button><button class="secondary small-btn" data-admin data-action="edit-activity" data-id="${esc(a.activity_id)}">Edit</button></td></tr>`;
}

function renderSolar() {
  const solar = state.activities.filter((a) => a.workstream === "Solar PV");
  $("solarMechanical").innerHTML = solar.filter((a) => a.discipline === "Mechanical").map(progressBar).join("") || emptyBox("No mechanical activities.");
  $("solarElectrical").innerHTML = solar.filter((a) => a.discipline === "Electrical").map(progressBar).join("") || emptyBox("No electrical activities.");
  $("solarRows").innerHTML = solar.map(activityRow).join("") || empty(7, "No Solar PV activities yet");
}

function renderBess() {
  const bess = state.activities.filter((a) => a.workstream === "BESS");
  $("bessCards").innerHTML = state.blocks.length
    ? state.blocks.map((b) => `<div class="card"><div class="kpi-label">${esc(b.block_name || `Block ${b.block_no}`)}</div><div class="kpi small">${esc(b.status)}</div><div class="kpi-note">Block ${b.block_no}</div><div style="margin-top:10px" data-write><select data-action="block-status" data-id="${esc(b.id)}" aria-label="Status for block ${b.block_no}">${BLOCK_STATUSES.map((s) => `<option ${s === b.status ? "selected" : ""}>${s}</option>`).join("")}</select></div></div>`).join("")
    : `<div class="card empty">No BESS blocks defined yet. Use "Add Block".</div>`;
  $("bessRows").innerHTML = bess.map(activityRow).join("") || empty(7, "No BESS activities yet");
}

function renderSchedule() {
  const p = state.progress;
  const count = (t) => p.filter((x) => x.period_type === t).length;
  $("dailyCount").textContent = count("Daily");
  $("weeklyCount").textContent = count("Weekly");
  $("monthlyCount").textContent = count("Monthly");
  $("updateRows").innerHTML = p.slice(0, 200).map((x) => {
    const a = state.activities.find((y) => y.activity_id === x.activity_id);
    return `<tr><td>${esc(x.entry_date)}</td><td>${esc(x.period_type)}</td><td class="wrap">${esc(a?.name ?? "—")}</td><td>${num(x.qty_added, 2)} ${esc(a?.unit ?? "")}</td><td class="wrap">${esc(x.notes)}</td><td>${esc(state.names[x.created_by] ?? "—")}</td></tr>`;
  }).join("") || empty(6, "No progress updates logged yet");
}

function renderQaqc() {
  const q = state.qaqc;
  $("qaqcKpis").innerHTML = [["Total Records", q.length], ["Approved", q.filter((x) => x.status === "Approved").length], ["Awaiting Review", q.filter((x) => x.status === "Submitted").length]]
    .map(([l, v]) => `<div class="card"><div class="kpi-label">${l}</div><div class="kpi">${v}</div></div>`).join("");
  $("qaqcRows").innerHTML = q.map((r) => {
    let actions = "";
    if (r.status === "Draft" || r.status === "Rejected") {
      actions += `<button class="small-btn" data-write data-action="qaqc-submit" data-id="${esc(r.id)}">Submit</button>`;
    }
    if (r.status === "Submitted") {
      actions += `<button class="secondary small-btn" data-write data-action="qaqc-withdraw" data-id="${esc(r.id)}">Withdraw</button>`;
      actions += `<button class="small-btn" data-admin data-action="qaqc-review" data-decision="Approved" data-id="${esc(r.id)}">Approve</button>`;
      actions += `<button class="danger small-btn" data-admin data-action="qaqc-review" data-decision="Rejected" data-id="${esc(r.id)}">Reject</button>`;
    }
    if (r.status === "Approved" || r.status === "Rejected") {
      actions += `<button class="secondary small-btn" data-admin data-action="qaqc-close" data-id="${esc(r.id)}">Close</button>`;
    }
    return `<tr><td>${esc(r.ref)}</td><td>${esc(r.record_type)}</td><td class="wrap">${esc(r.description)}</td><td>${esc(r.record_date)}</td><td>${pillFor(r.status)}</td><td>${esc(r.owner)}</td><td class="inline">${actions || "—"}</td></tr>`;
  }).join("") || empty(7, "No QA/QC records yet");
}

function renderHse() {
  const h = state.hse;
  $("hseKpis").innerHTML = [["Records", h.length], ["Open Actions", h.filter((x) => x.status !== "Closed").length], ["Incidents", h.filter((x) => x.category === "Incident").length]]
    .map(([l, v]) => `<div class="card"><div class="kpi-label">${l}</div><div class="kpi">${v}</div></div>`).join("");
  $("hseRows").innerHTML = h.map((x) => `<tr><td>${esc(x.record_date)}</td><td>${esc(x.category)}</td><td class="wrap">${esc(x.description)}</td><td>${esc(x.severity)}</td><td>${pillFor(x.status)}</td><td>${esc(x.owner)}</td><td><button class="secondary small-btn" data-write data-action="hse-toggle" data-id="${esc(x.id)}" data-status="${esc(x.status)}">${x.status === "Closed" ? "Reopen" : "Close"}</button></td></tr>`).join("") || empty(7, "No HSE records yet");
}

function renderManpower() {
  // Daily headcount grid: one row per date, one column per category (summed over contractors).
  const dates = [...new Set(state.manpower.map((m) => m.log_date))].sort().reverse().slice(0, 30);
  $("manpowerHead").innerHTML = `<tr><th>Date</th>${CATEGORIES.map((c) => `<th>${esc(c)}</th>`).join("")}<th>Total</th></tr>`;
  $("manpowerRows").innerHTML = dates.length
    ? dates.map((d) => {
        const day = state.manpower.filter((m) => m.log_date === d);
        let total = 0;
        const cells = CATEGORIES.map((c) => {
          const v = day.filter((m) => m.category === c).reduce((s, m) => s + Number(m.headcount), 0);
          total += v;
          return `<td>${v || "—"}</td>`;
        }).join("");
        return `<tr><td>${esc(d)}</td>${cells}<td><b>${total}</b></td></tr>`;
      }).join("")
    : empty(CATEGORIES.length + 2, "No daily headcount yet");

  const latest = dates[0];
  const workforce = latest ? state.manpower.filter((m) => m.log_date === latest).reduce((s, m) => s + Number(m.headcount), 0) : null;
  const available = latest ? state.equipLogs.filter((l) => l.log_date === latest && l.availability === "Available").length : null;
  $("resourceKpis").innerHTML = [
    ["Workforce (latest day)", workforce ?? "—"],
    ["Equipment Available (latest day)", available ?? "—"],
    ["Equipment in Register", state.equipment.length],
  ].map(([l, v]) => `<div class="card"><div class="kpi-label">${l}</div><div class="kpi">${v}</div></div>`).join("");

  $("equipmentRows").innerHTML = state.equipment.map((e) => `<tr><td>${esc(e.equipment_code)}</td><td class="wrap">${esc(e.description)}</td><td>${esc(e.equipment_type)}</td><td>${esc(e.area)}</td><td>${esc(e.supplier)}</td><td>${esc(e.register_status)}</td></tr>`).join("") || empty(6, "No equipment registered yet");

  const dateInput = $("equipDate");
  if (!dateInput.value) dateInput.value = today();
  const codeOf = Object.fromEntries(state.equipment.map((e) => [e.id, e]));
  const logs = state.equipLogs.filter((l) => l.log_date === dateInput.value);
  $("equipmentLogRows").innerHTML = logs.map((l) => `<tr><td>${esc(codeOf[l.equipment_id]?.equipment_code ?? "—")}</td><td>${esc(l.availability)}</td><td>${esc(l.operating_status)}</td><td>${num(l.hours_available, 1)}</td><td>${num(l.hours_used, 1)}</td><td class="wrap">${esc(l.notes)}</td></tr>`).join("")
    || empty(6, "No equipment status logged for this date");
}

function renderIssues() {
  $("issueRows").innerHTML = state.issues.map((i) => `<tr><td>ISS-${String(i.issue_no).padStart(3, "0")}</td><td>${esc(i.item_type)}</td><td class="wrap">${esc(i.title)}</td><td>${esc(i.category)}</td><td>${pillFor(i.priority)}</td><td>${esc(i.due_date || "—")}</td><td>${esc(i.owner)}</td><td>${pillFor(i.status)}</td><td><button class="secondary small-btn" data-write data-action="issue-toggle" data-id="${esc(i.id)}" data-status="${esc(i.status)}">${i.status === "Closed" ? "Reopen" : "Close"}</button></td></tr>`).join("")
    || empty(9, "No issues or risks recorded");
}

function renderReportList() {
  $("savedReportRows").innerHTML = state.reports.map((r) => `<tr><td class="wrap">${esc(r.title)}</td><td>${esc(r.report_type)} · ${esc(r.period_start)} to ${esc(r.period_end)}</td><td>${pillFor(r.status)}</td><td class="inline"><button class="secondary small-btn" data-action="report-view" data-id="${esc(r.id)}">View</button>${r.status === "Draft" ? `<button class="small-btn" data-admin data-action="report-issue" data-id="${esc(r.id)}">Issue</button>` : ""}</td></tr>`).join("")
    || empty(4, "No saved reports");
}

function renderSettings() {
  // The project name is fixed in js/project.js. Only the capacity figures are editable here.
  const box = $("settingsBox");
  const p = state.project;
  const identity = `<p><b>${esc(PROJECT_IDENTITY.name)}</b></p><p class="kpi-note">${esc(PROJECT_IDENTITY.company)} · ${esc(PROJECT_IDENTITY.location)} · Project name is fixed in the application.</p>`;
  if (!isAdmin()) {
    box.innerHTML = identity + (p
      ? `<p class="kpi-note">PV capacity: ${p.pv_capacity_mw ?? "Not verified"} MW · BESS capacity: ${p.bess_capacity_mwh ?? "Not verified"} MWh</p>`
      : `<p class="sub">No project record yet. An Admin creates it.</p>`);
    return;
  }
  box.innerHTML = identity + `<form id="settingsForm" novalidate>
    <div class="formgrid">
      ${field("PV capacity (MW)", input("pv", { type: "number", min: 0, step: "any", value: p?.pv_capacity_mw ?? "" }))}
      ${field("BESS capacity (MWh)", input("bess", { type: "number", min: 0, step: "any", value: p?.bess_capacity_mwh ?? "" }))}
    </div>
    <p class="kpi-note">Leave capacities blank until they are verified.</p>
    <button type="submit">${p ? "Save Settings" : "Create Project"}</button>
  </form>`;
  $("settingsForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    // The name is always PROJECT_IDENTITY.name. It is never taken from the form or the database.
    const capacities = { pv_capacity_mw: numOrNull(fd.get("pv")), bess_capacity_mwh: numOrNull(fd.get("bess")) };
    if (p) await save(sb.from("projects").update(capacities).eq("id", p.id), "Settings saved");
    else await save(sb.from("projects").insert({ name: PROJECT_IDENTITY.name, ...capacities }), "Project created");
  });
}

function renderUsers() {
  const head = $("usersHead");
  if (!isAdmin()) { $("usersRows").innerHTML = ""; head.innerHTML = ""; return; }
  head.innerHTML = `<tr><th>Name</th>${USERNAME_LOGIN_ENABLED ? "<th>Username</th>" : ""}<th>Role</th><th>Active</th></tr>`;
  const cols = USERNAME_LOGIN_ENABLED ? 4 : 3;
  $("usersRows").innerHTML = state.profiles.map((p) => {
    const nameCell = `<td>${esc(p.full_name || "(no name)")}${p.id === state.user?.id ? " (you)" : ""}</td>`;
    const usernameCell = USERNAME_LOGIN_ENABLED
      ? `<td><input data-action="user-username" data-id="${esc(p.id)}" value="${esc(p.username || "")}" maxlength="30" placeholder="not set" aria-label="Username for ${esc(p.full_name || "user")}" style="min-width:160px;padding:6px 8px;border:1px solid var(--line);border-radius:8px"></td>`
      : "";
    const roleCell = `<td><select data-action="user-role" data-id="${esc(p.id)}">${["admin", "engineer", "viewer"].map((r) => `<option value="${r}" ${r === p.role ? "selected" : ""}>${ROLE_LABEL[r]}</option>`).join("")}</select></td>`;
    const activeCell = `<td><input type="checkbox" data-action="user-active" data-id="${esc(p.id)}" ${p.is_active ? "checked" : ""} aria-label="Active"></td>`;
    return `<tr>${nameCell}${usernameCell}${roleCell}${activeCell}</tr>`;
  }).join("") || empty(cols, "No users yet");
}

// ---------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------
function periodRange(type, dateStr) {
  const d = new Date(`${dateStr}T00:00:00`);
  if (type === "Daily") return [dateStr, dateStr];
  if (type === "Weekly") {
    const offset = (d.getDay() + 6) % 7; // Monday start
    const s = new Date(d); s.setDate(d.getDate() - offset);
    const e = new Date(s); e.setDate(s.getDate() + 6);
    return [iso(s), iso(e)];
  }
  return [iso(new Date(d.getFullYear(), d.getMonth(), 1)), iso(new Date(d.getFullYear(), d.getMonth() + 1, 0))];
}

function buildReport() {
  const type = $("reportPeriod").value;
  const date = $("reportDate").value || today();
  const [start, end] = periodRange(type, date);
  const inRange = (d) => d >= start && d <= end;

  // Quantities are reported per activity, never summed across different units.
  const byAct = {};
  state.progress.filter((p) => inRange(p.entry_date)).forEach((p) => {
    byAct[p.activity_id] = (byAct[p.activity_id] || 0) + Number(p.qty_added);
  });
  const lines = Object.entries(byAct).map(([id, qty]) => {
    const a = state.activities.find((x) => x.activity_id === id);
    return { name: a?.name ?? "—", workstream: a?.workstream ?? "", unit: a?.unit ?? "", qty: Math.round(qty * 100) / 100 };
  });

  const qaqc = state.qaqc.filter((r) => inRange(r.record_date));
  const hse = state.hse.filter((r) => inRange(r.record_date));
  const manDates = [...new Set(state.manpower.filter((m) => inRange(m.log_date)).map((m) => m.log_date))].sort();
  const manLatest = manDates.at(-1) ?? null;

  return {
    type, date, start, end, lines,
    qaqc: {
      total: qaqc.length,
      approved: qaqc.filter((r) => r.status === "Approved").length,
      pending: qaqc.filter((r) => r.status === "Submitted").length,
    },
    hse: { records: hse.length, incidents: hse.filter((h) => h.category === "Incident").length },
    manpower: {
      date: manLatest,
      headcount: manLatest ? state.manpower.filter((m) => m.log_date === manLatest).reduce((s, m) => s + Number(m.headcount), 0) : null,
    },
    openIssues: state.issues.filter((i) => i.status !== "Closed").length,
  };
}

function renderReportPreview(r) {
  const lines = r.lines.map((l) => `<tr><td class="wrap">${esc(l.name)}</td><td>${esc(l.workstream)}</td><td>${num(l.qty, 2)} ${esc(l.unit)}</td></tr>`).join("")
    || `<tr><td colspan="3" class="empty">No progress logged in this period</td></tr>`;
  $("reportPreview").innerHTML = `
    <div class="notice">${esc(r.type)} report · ${esc(r.start)} to ${esc(r.end)} · ${esc(PROJECT_IDENTITY.name)}${state.project?.is_demo ? " · DEMO DATA" : ""}</div>
    <h3>Progress logged in period</h3>
    <div class="tablewrap"><table><thead><tr><th>Activity</th><th>Workstream</th><th>Quantity added</th></tr></thead><tbody>${lines}</tbody></table></div>
    <h3 style="margin-top:14px">QA/QC</h3><p>${r.qaqc.total} records dated in period · ${r.qaqc.approved} approved · ${r.qaqc.pending} awaiting review</p>
    <h3>HSE</h3><p>${r.hse.records} records · ${r.hse.incidents} incident(s)</p>
    <h3>Manpower</h3><p>${r.manpower.date ? `Headcount on ${esc(r.manpower.date)}: <b>${r.manpower.headcount}</b>` : "No manpower logged in this period"}</p>
    <h3>Issues</h3><p>${r.openIssues} open issue(s)</p>
    <p class="kpi-note">No overall percentage is shown: quantities use different units. Weighted progress appears only after verified weights are entered.</p>`;
}

async function saveReport() {
  if (!needProject()) return;
  const r = buildReport();
  await save(sb.from("report_snapshots").insert({
    project_id: state.project.id,
    report_type: r.type,
    report_date: r.date,
    period_start: r.start,
    period_end: r.end,
    title: `${r.type} progress report ${r.start} to ${r.end}`,
    status: "Draft",
    summary: r,
  }), "Draft report saved");
}

// ---------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const csvCell = (x) => {
  let s = String(x ?? "");
  if (/^[=+\-@]/.test(s)) s = "'" + s; // prevent spreadsheet formula injection
  return `"${s.replace(/"/g, '""')}"`;
};
function exportCsv() {
  const rows = [
    ["Area", "Activity", "Discipline", "Unit", "Planned Qty", "Installed Qty", "Progress %", "Planned %", "Status"],
    ...state.activities.map((a) => [a.workstream, a.name, a.discipline, a.unit, a.planned_qty, a.installed_qty, a.progress_pct, a.planned_pct ?? "", statusOf(a)[0]]),
  ];
  download(`greengrid-activities-${today()}.csv`, rows.map((r) => r.map(csvCell).join(",")).join("\n"), "text/csv");
}
function backup() {
  download(`greengrid-backup-${today()}.json`, JSON.stringify({
    exported_at: new Date().toISOString(),
    project: state.project,
    activities: state.activities,
    bess_blocks: state.blocks,
    progress_entries: state.progress,
    qaqc_records: state.qaqc,
    hse_records: state.hse,
    manpower_daily: state.manpower,
    equipment: state.equipment,
    equipment_daily_log: state.equipLogs,
    issues: state.issues,
    report_snapshots: state.reports,
  }, null, 2), "application/json");
}

// ---------------------------------------------------------------------
// Modal forms
// ---------------------------------------------------------------------
function openModal(title, html, onSubmit) {
  $("modalTitle").textContent = title;
  $("modalBody").innerHTML = `<form id="modalForm" novalidate>${html}<div class="actions" style="margin-top:12px"><button type="submit">Save</button><button type="button" class="secondary" data-action="close-modal">Cancel</button></div></form>`;
  const form = $("modalForm");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = form.querySelector("button[type=submit]");
    btn.disabled = true;
    const ok = await onSubmit(new FormData(form));
    btn.disabled = false;
    if (ok) closeModal();
  });
  $("modal").classList.add("open");
}
function closeModal() {
  $("modal").classList.remove("open");
  $("modalBody").innerHTML = "";
}
const field = (label, control) => `<div class="field"><label>${esc(label)}</label>${control}</div>`;
const input = (name, o = {}) => `<input name="${name}" type="${o.type || "text"}" ${o.min != null ? `min="${o.min}"` : ""} ${o.max != null ? `max="${o.max}"` : ""} ${o.step ? `step="${o.step}"` : ""} value="${esc(o.value ?? "")}">`;
const select = (name, options, selected = "") => `<select name="${name}">${options.map((o) => {
  const v = typeof o === "string" ? o : o.value;
  const t = typeof o === "string" ? o : o.label;
  return `<option value="${esc(v)}" ${v === selected ? "selected" : ""}>${esc(t)}</option>`;
}).join("")}</select>`;
const textarea = (name, value = "") => `<textarea name="${name}">${esc(value)}</textarea>`;
const formgrid = (...items) => `<div class="formgrid">${items.join("")}</div>`;
const nextSort = () => Math.max(0, ...state.activities.map((a) => Number(a.sort_order) || 0)) + 1;

function openProgressForm(preId) {
  if (!needProject()) return;
  if (!state.activities.length) return toast("Add activities first (Admin).", true);
  const opts = state.activities.map((a) => ({ value: a.activity_id, label: `${a.name} (${a.workstream})` }));
  openModal("Log Progress Update",
    field("Activity", select("activity_id", opts, preId || opts[0].value)) +
    formgrid(
      field("Reporting period", select("period_type", ["Daily", "Weekly", "Monthly"], "Daily")),
      field("Entry date", input("entry_date", { type: "date", value: today() })),
      field("Quantity added (activity unit)", input("qty_added", { type: "number", min: 0, step: "any" })),
    ) +
    field("Notes / site observations", textarea("notes")),
    async (fd) => {
      const qty = Number(fd.get("qty_added"));
      if (!(qty > 0)) { toast("Quantity added must be greater than zero.", true); return false; }
      return save(sb.from("progress_entries").insert({
        project_id: state.project.id,
        activity_id: fd.get("activity_id"),
        entry_date: fd.get("entry_date"),
        period_type: fd.get("period_type"),
        qty_added: qty,
        notes: String(fd.get("notes") || ""),
      }), "Progress logged");
    });
}

function openActivityForm(id, area) {
  if (!needProject()) return;
  const a = id ? state.activities.find((x) => x.activity_id === id) : null;
  const ws = a ? a.workstream : area;
  const v = (k, d = "") => (a && a[k] != null ? a[k] : d);
  openModal(a ? "Edit Activity Baseline" : `Add ${ws} Activity`,
    formgrid(
      field("Activity name", input("name", { value: v("name") })),
      field("Discipline", select("discipline", DISCIPLINES, v("discipline", "Mechanical"))),
      field("Unit", input("unit", { value: v("unit") })),
      field("Planned quantity", input("planned_qty", { type: "number", min: 0, step: "any", value: v("planned_qty") })),
      field("Opening installed quantity", input("opening_qty", { type: "number", min: 0, step: "any", value: v("opening_qty", 0) })),
      field("Planned progress (%)", input("planned_pct", { type: "number", min: 0, max: 100, step: "any", value: v("planned_pct") })),
      field("Weight (blank until verified)", input("weight", { type: "number", min: 0, step: "any", value: v("weight") })),
      field("Weight basis", select("weight_basis", [{ value: "", label: "— none —" }, "Budget", "Man-hours"], v("weight_basis"))),
    ) + `<p class="kpi-note">Workstream: ${esc(ws)}. Quantities come from verified baseline data; installed progress comes from the progress log.</p>`,
    async (fd) => {
      const planned = Number(fd.get("planned_qty"));
      const opening = Number(fd.get("opening_qty") || 0);
      const pct = numOrNull(fd.get("planned_pct"));
      const weight = numOrNull(fd.get("weight"));
      const basis = fd.get("weight_basis") || null;
      if (!(planned > 0)) return toast("Planned quantity must be greater than zero.", true), false;
      if (!(opening >= 0)) return toast("Opening quantity cannot be negative.", true), false;
      if (pct != null && (pct < 0 || pct > 100)) return toast("Planned progress must be between 0 and 100.", true), false;
      if ((weight == null) !== (basis == null)) return toast("Enter both a weight and a weight basis, or neither.", true), false;
      if (weight != null && !(weight > 0)) return toast("Weight must be greater than zero.", true), false;
      const row = {
        name: String(fd.get("name") || "").trim(),
        discipline: fd.get("discipline"),
        unit: String(fd.get("unit") || "").trim(),
        planned_qty: planned, opening_qty: opening, planned_pct: pct, weight, weight_basis: basis,
      };
      if (a) return save(sb.from("activities").update(row).eq("id", a.activity_id), "Activity baseline saved");
      return save(sb.from("activities").insert({ ...row, project_id: state.project.id, workstream: ws, sort_order: nextSort() }), "Activity added");
    });
}

function openBlockForm() {
  if (!needProject()) return;
  const n = Math.max(0, ...state.blocks.map((b) => b.block_no)) + 1;
  openModal("Add BESS Block",
    field("Block name", input("block_name", { value: `Block ${n}` })) +
    field("Status", select("status", BLOCK_STATUSES, "Not Started")),
    async (fd) => save(sb.from("bess_blocks").insert({
      project_id: state.project.id, block_no: n,
      block_name: String(fd.get("block_name") || `Block ${n}`).trim(),
      status: fd.get("status"),
    }), "Block added"));
}

function openQaqcForm() {
  if (!needProject()) return;
  const acts = [{ value: "", label: "— none —" }, ...state.activities.map((a) => ({ value: a.activity_id, label: a.name }))];
  openModal("Add QA/QC Record",
    formgrid(
      field("Reference", input("ref")),
      field("Type", select("record_type", ["IR", "ITR", "WIR", "NCR", "Test Report"], "IR")),
      field("Record date", input("record_date", { type: "date", value: today() })),
      field("Owner", input("owner")),
      field("Activity (optional)", select("activity_id", acts)),
      field("Start as", select("status", ["Draft", "Submitted"], "Draft")),
    ) + field("Description", textarea("description")),
    async (fd) => {
      const ref = String(fd.get("ref") || "").trim();
      const description = String(fd.get("description") || "").trim();
      if (!ref || !description) return toast("Reference and description are required.", true), false;
      return save(sb.from("qaqc_records").insert({
        project_id: state.project.id, ref, description,
        record_type: fd.get("record_type"),
        record_date: fd.get("record_date"),
        owner: String(fd.get("owner") || "").trim(),
        activity_id: fd.get("activity_id") || null,
        status: fd.get("status"),
      }), "QA/QC record created");
    });
}

function openReviewForm(id, decision) {
  const r = state.qaqc.find((x) => x.id === id);
  openModal(`${decision === "Approved" ? "Approve" : "Reject"} ${r?.ref ?? "QA/QC record"}`,
    field("Review comment", textarea("review_comment")),
    async (fd) => save(
      sb.from("qaqc_records").update({ status: decision, review_comment: String(fd.get("review_comment") || "").trim() }).eq("id", id),
      `Record ${decision.toLowerCase()}`));
}

function openHseForm() {
  if (!needProject()) return;
  openModal("Add HSE Record",
    formgrid(
      field("Date", input("record_date", { type: "date", value: today() })),
      field("Category", select("category", ["Safety Observation", "Toolbox Talk", "Incident", "Inspection"], "Safety Observation")),
      field("Severity", select("severity", ["Low", "Medium", "High", "Not Applicable"], "Not Applicable")),
      field("Status", select("status", ["Open", "In Progress", "Closed"], "Open")),
      field("Owner", input("owner")),
    ) + field("Description", textarea("description")),
    async (fd) => {
      const description = String(fd.get("description") || "").trim();
      if (!description) return toast("Description is required.", true), false;
      return save(sb.from("hse_records").insert({
        project_id: state.project.id, description,
        record_date: fd.get("record_date"), category: fd.get("category"),
        severity: fd.get("severity"), status: fd.get("status"),
        owner: String(fd.get("owner") || "").trim(),
      }), "HSE record added");
    });
}

function openManpowerForm() {
  if (!needProject()) return;
  openModal("Add Daily Headcount",
    formgrid(
      field("Date", input("log_date", { type: "date", value: today() })),
      field("Category", select("category", CATEGORIES, "Labour")),
      field("Contractor (blank = direct staff)", input("contractor")),
      field("Headcount", input("headcount", { type: "number", min: 0, step: 1, value: 0 })),
    ) + field("Notes", input("notes")),
    async (fd) => {
      const hc = Number(fd.get("headcount"));
      if (!Number.isInteger(hc) || hc < 0) return toast("Headcount must be a whole number, 0 or more.", true), false;
      // Upsert: one row per date, category and contractor. Re-entering a day updates it.
      return save(sb.from("manpower_daily").upsert({
        project_id: state.project.id,
        log_date: fd.get("log_date"),
        category: fd.get("category"),
        contractor: String(fd.get("contractor") || "").trim(),
        headcount: hc,
        notes: String(fd.get("notes") || ""),
      }, { onConflict: "project_id,log_date,category,contractor" }), "Headcount saved");
    });
}

function openEquipmentForm() {
  if (!needProject()) return;
  openModal("Add Equipment",
    formgrid(
      field("Equipment code", input("equipment_code")),
      field("Type", input("equipment_type")),
      field("Area", select("area", ["Solar PV", "BESS", "Common"], "Common")),
      field("Register status", select("register_status", ["Active", "Inactive", "Off Hire"], "Active")),
      field("Supplier", input("supplier")),
    ) + field("Description", input("description")),
    async (fd) => {
      const code = String(fd.get("equipment_code") || "").trim();
      const description = String(fd.get("description") || "").trim();
      const type = String(fd.get("equipment_type") || "").trim();
      if (!code || !description || !type) return toast("Code, type and description are required.", true), false;
      return save(sb.from("equipment").insert({
        project_id: state.project.id, equipment_code: code, description, equipment_type: type,
        area: fd.get("area"), register_status: fd.get("register_status"),
        supplier: String(fd.get("supplier") || "").trim(),
      }), "Equipment added");
    });
}

function openEquipmentLogForm() {
  if (!needProject()) return;
  if (!state.equipment.length) return toast("Add equipment to the register first.", true);
  const date = $("equipDate").value || today();
  openModal("Log Equipment Status",
    formgrid(
      field("Equipment", select("equipment_id", state.equipment.map((e) => ({ value: e.id, label: `${e.equipment_code} — ${e.description}` })))),
      field("Date", input("log_date", { type: "date", value: date })),
      field("Availability", select("availability", ["Available", "Partially Available", "Unavailable"], "Available")),
      field("Operating status", select("operating_status", ["Running", "Standby", "Idle", "Breakdown", "Maintenance", "Off Hire"], "Running")),
      field("Hours available (0–24)", input("hours_available", { type: "number", min: 0, max: 24, step: "0.5", value: 8 })),
      field("Hours used (0–24)", input("hours_used", { type: "number", min: 0, max: 24, step: "0.5", value: 0 })),
    ) + field("Notes", input("notes")),
    async (fd) => {
      const avail = Number(fd.get("hours_available"));
      const used = Number(fd.get("hours_used"));
      if (avail < 0 || avail > 24 || used < 0 || used > 24) return toast("Hours must be between 0 and 24.", true), false;
      if (used > avail) return toast("Hours used cannot exceed hours available.", true), false;
      // Upsert: one status per equipment per day.
      return save(sb.from("equipment_daily_log").upsert({
        project_id: state.project.id,
        equipment_id: fd.get("equipment_id"),
        log_date: fd.get("log_date"),
        availability: fd.get("availability"),
        operating_status: fd.get("operating_status"),
        hours_available: avail, hours_used: used,
        notes: String(fd.get("notes") || ""),
      }, { onConflict: "equipment_id,log_date" }), "Equipment status saved");
    });
}

function openIssueForm() {
  if (!needProject()) return;
  openModal("Add Issue or Risk",
    formgrid(
      field("Type", select("item_type", ["Issue", "Risk"], "Issue")),
      field("Category", select("category", ISSUE_CATEGORIES, "Other")),
      field("Priority", select("priority", ["High", "Medium", "Low"], "Medium")),
      field("Due date", input("due_date", { type: "date" })),
      field("Owner", input("owner")),
    ) + field("Title", input("title")) + field("Description", textarea("description")),
    async (fd) => {
      const title = String(fd.get("title") || "").trim();
      if (!title) return toast("Title is required.", true), false;
      return save(sb.from("issues").insert({
        project_id: state.project.id, title,
        item_type: fd.get("item_type"), category: fd.get("category"), priority: fd.get("priority"),
        due_date: fd.get("due_date") || null, owner: String(fd.get("owner") || "").trim(),
        description: String(fd.get("description") || ""),
      }), "Issue added");
    });
}

// ---------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------
const PAGE_TITLES = {
  overview: "Project Overview", solar: "Solar PV Progress", bess: "BESS Progress", schedule: "Schedule & Planning",
  qaqc: "QA/QC Register", hse: "HSE Register", manpower: "Manpower & Equipment", issues: "Issues & Risks", reports: "Reports & Data",
};
function nav(page) {
  document.querySelectorAll(".section").forEach((x) => x.classList.remove("active"));
  $(page).classList.add("active");
  document.querySelectorAll(".nav button").forEach((x) => x.classList.toggle("active", x.dataset.page === page));
  // Header: project name, slash, then the page name (Overview for the dashboard).
  $("topTitle").textContent = `${PROJECT_IDENTITY.name} / ${page === "overview" ? "Overview" : (PAGE_TITLES[page] ?? "")}`;
  window.scrollTo({ top: 0 });
}

// ---------------------------------------------------------------------
// Event handling (delegated)
// ---------------------------------------------------------------------
document.addEventListener("click", async (e) => {
  const zoneBtn = e.target.closest("[data-zone]");
  if (zoneBtn) { selectedZone = zoneBtn.dataset.zone; return renderZones(); }
  const navBtn = e.target.closest("button[data-page]");
  if (navBtn) return nav(navBtn.dataset.page);

  const el = e.target.closest("[data-action]");
  if (!el || el.tagName === "SELECT" || el.tagName === "INPUT") return;
  const { action, id } = el.dataset;
  switch (action) {
    case "close-modal": return closeModal();
    case "export-csv": return exportCsv();
    case "backup": return backup();
    case "print-report": return window.print();
    case "report-generate": return renderReportPreview(buildReport());
    case "report-save": return saveReport();
    case "report-view": {
      const r = state.reports.find((x) => x.id === id);
      return r ? renderReportPreview(r.summary) : null;
    }
    case "report-issue": return save(sb.from("report_snapshots").update({ status: "Issued" }).eq("id", id), "Report issued and locked");
    case "log-progress": return openProgressForm(id);
    case "add-activity": return openActivityForm(null, el.dataset.area);
    case "edit-activity": return openActivityForm(id);
    case "add-block": return openBlockForm();
    case "add-qaqc": return openQaqcForm();
    case "qaqc-submit": return save(sb.from("qaqc_records").update({ status: "Submitted" }).eq("id", id), "Submitted for review");
    case "qaqc-withdraw": return save(sb.from("qaqc_records").update({ status: "Draft" }).eq("id", id), "Withdrawn to Draft");
    case "qaqc-review": return openReviewForm(id, el.dataset.decision);
    case "qaqc-close": return save(sb.from("qaqc_records").update({ status: "Closed" }).eq("id", id), "Record closed");
    case "add-hse": return openHseForm();
    case "hse-toggle": return save(sb.from("hse_records").update({ status: el.dataset.status === "Closed" ? "Open" : "Closed" }).eq("id", id), "HSE status updated");
    case "add-issue": return openIssueForm();
    case "issue-toggle": return save(sb.from("issues").update({ status: el.dataset.status === "Closed" ? "Open" : "Closed" }).eq("id", id), "Issue updated");
    case "add-manpower": return openManpowerForm();
    case "add-equipment": return openEquipmentForm();
    case "log-equipment": return openEquipmentLogForm();
    default: return;
  }
});

document.addEventListener("change", async (e) => {
  const el = e.target;
  if (el.id === "equipDate") return renderManpower();
  if (el.id === "reportPeriod" || el.id === "reportDate") return; // preview is generated on demand
  const { action, id } = el.dataset ?? {};
  if (action === "block-status") {
    return save(sb.from("bess_blocks").update({ status: el.value }).eq("id", id), "Block status updated");
  }
  if (action === "user-role") {
    return save(sb.from("profiles").update({ role: el.value }).eq("id", id), "Role updated");
  }
  if (action === "user-username") {
    if (!USERNAME_LOGIN_ENABLED) return; // feature postponed: the column does not exist yet
    const current = state.profiles.find((p) => p.id === id)?.username ?? "";
    const value = el.value.trim().toLowerCase();
    if (value && !/^[a-z][a-z0-9_]{2,29}$/.test(value)) {
      toast("Username: 3 to 30 letters, digits or underscores, starting with a letter.", true);
      el.value = current;
      return;
    }
    if (value === current) return;
    const { error } = await sb.from("profiles").update({ username: value || null }).eq("id", id);
    if (error) {
      toast(error.code === "23505" ? "That username is already taken." : friendly(error), true);
      el.value = current;
      return;
    }
    toast(value ? "Username saved" : "Username removed");
    return loadAll();
  }
  if (action === "user-active") {
    return save(sb.from("profiles").update({ is_active: el.checked }).eq("id", id), el.checked ? "User activated" : "User deactivated");
  }
});

// ---------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// Password recovery
// With PKCE the reset link returns ?code=..., which supabase-js exchanges for a
// normal session. That exchange may emit SIGNED_IN instead of PASSWORD_RECOVERY,
// so recovery is recognised in three ways (any one is enough):
//   1. the PASSWORD_RECOVERY event;
//   2. a marker stored when this browser requested a reset (valid for 2 hours);
//   3. the session's access token reporting the "recovery" auth method.
// While recovery is active, the app stays on the new-password form and does not enter the dashboard.
// ---------------------------------------------------------------------
const RECOVERY_KEY = "gg_recovery_requested_at";
const RECOVERY_WINDOW_MS = 2 * 60 * 60 * 1000;
let recoveryMode = false;
let arrivedWithAuthCode = false; // set once at start, from the URL before supabase-js clears it

function markRecoveryRequested() {
  try { localStorage.setItem(RECOVERY_KEY, String(Date.now())); } catch { /* storage unavailable */ }
}
function recoveryRequested() {
  try {
    const t = Number(localStorage.getItem(RECOVERY_KEY) || 0);
    return t > 0 && Date.now() - t < RECOVERY_WINDOW_MS;
  } catch { return false; }
}
function clearRecoveryMarker() {
  try { localStorage.removeItem(RECOVERY_KEY); } catch { /* ignore */ }
}
function jwtPayload(token) {
  try {
    let b64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(b64));
  } catch { return null; }
}
function sessionIsRecovery(session) {
  const amr = jwtPayload(session?.access_token || "")?.amr || [];
  return amr.some((a) => a?.method === "recovery");
}
function enterRecovery() {
  recoveryMode = true;
  showView("viewNewPassword");
}
function leaveRecovery() {
  recoveryMode = false;
  clearRecoveryMarker();
}
// Errors from an expired or already-used link arrive in the URL (hash or query).
function linkErrorCode() {
  const h = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const q = new URLSearchParams(window.location.search);
  return h.get("error_code") || q.get("error_code") || "";
}

// Username sign-in goes through the login-with-username Edge Function.
// The browser sends only the public anon key. It never holds a service-role key.
const LOGIN_FUNCTION_PATH = "/functions/v1/login-with-username";
async function signInWithUsername(identifier, password) {
  let res;
  try {
    res = await fetch(SUPABASE_URL + LOGIN_FUNCTION_PATH, {
      method: "POST",
      headers: { "content-type": "application/json", apikey: SUPABASE_ANON_KEY },
      body: JSON.stringify({ identifier, password }),
    });
  } catch {
    return { ok: false, reason: "unavailable" };
  }
  if (res.status === 429) return { ok: false, reason: "too_many" };
  if (res.status === 400 || res.status === 401) return { ok: false, reason: "invalid" };
  if (!res.ok) return { ok: false, reason: "unavailable" };

  let body;
  try { body = await res.json(); } catch { return { ok: false, reason: "unavailable" }; }
  const s = body?.session;
  if (!s?.access_token || !s?.refresh_token) return { ok: false, reason: "unavailable" };
  // setSession triggers the normal SIGNED_IN flow, so roles and the dashboard load as usual.
  const { error } = await sb.auth.setSession({ access_token: s.access_token, refresh_token: s.refresh_token });
  return error ? { ok: false, reason: "unavailable" } : { ok: true };
}

async function enter(session) {
  const user = session.user;
  const { data: profile, error } = await sb.from("profiles").select("id,full_name,role,is_active").eq("id", user.id).maybeSingle();
  if (error) toast(friendly(error), true);
  if (error || !profile || !profile.is_active) {
    resetState();
    showView("viewInactive");
    return;
  }
  state.user = user;
  state.profile = profile;
  renderHeader();
  showView("viewApp");
  await loadAll();
}

function wireAuthForms() {
  $("showResetBtn").addEventListener("click", () => { setMsg("resetMsg", ""); showView("viewReset"); });
  $("showLoginBtn").addEventListener("click", () => showView("viewLogin"));
  $("cancelRecoveryBtn").addEventListener("click", async () => {
    leaveRecovery();
    await sb.auth.signOut();
    setMsg("loginMsg", "Password not changed. You can request a new reset link.", "");
    showView("viewLogin");
  });

  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const identifier = String(fd.get("identifier") || "").trim();
    const password = String(fd.get("password") || "");
    if (!identifier || !password) return setMsg("loginMsg", "Enter your email address and password.", "err");
    if (!identifier.includes("@") && !USERNAME_LOGIN_ENABLED) {
      // Username sign-in is postponed, so only email addresses are accepted for now.
      return setMsg("loginMsg", "Enter your email address.", "err");
    }
    setMsg("loginMsg", "Signing in…");

    if (identifier.includes("@")) {
      // Email: standard Supabase sign-in, unchanged.
      const { error } = await sb.auth.signInWithPassword({ email: identifier, password });
      // Same message for every failure, so the form does not reveal which emails exist.
      setMsg("loginMsg", error ? "Email or password is not correct." : "", error ? "err" : "");
      if (!error) clearRecoveryMarker(); // a normal sign-in must not be treated as recovery
    } else {
      // Same normalization as the database and the Edge Function: trimmed, lowercase.
      const result = await signInWithUsername(identifier.trim().toLowerCase(), password);
      if (result.ok) {
        clearRecoveryMarker();
        setMsg("loginMsg", "");
      } else if (result.reason === "too_many") {
        setMsg("loginMsg", "Too many sign-in attempts. Wait 15 minutes and try again.", "err");
      } else if (result.reason === "unavailable") {
        setMsg("loginMsg", "Sign-in is temporarily unavailable. Try again shortly.", "err");
      } else {
        setMsg("loginMsg", "Email or password is not correct.", "err");
      }
    }
    e.target.password.value = "";
  });

  $("resetForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = String(new FormData(e.target).get("email") || "").trim();
    if (!email) return setMsg("resetMsg", "Enter your email.", "err");
    markRecoveryRequested();
    const { error } = await sb.auth.resetPasswordForEmail(email, {
      redirectTo: window.location.origin + window.location.pathname,
    });
    if (error) {
      // Show the real reason (no secrets are in this message) and log details for debugging.
      console.error("resetPasswordForEmail failed:", { status: error.status, code: error.code, message: error.message });
      const rate = error.status === 429 || /rate limit/i.test(error.message || "");
      setMsg("resetMsg", rate
        ? "Too many reset emails were requested recently. Wait about an hour and try again."
        : `Reset email could not be sent: ${error.message || "unknown error"}${error.code ? ` (${error.code})` : ""}.`, "err");
    } else {
      setMsg("resetMsg", "If an account exists for this email, a reset link has been sent.", "ok");
    }
  });

  $("newPasswordForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const p1 = String(e.target.password.value || "");
    const p2 = String(e.target.password2.value || "");
    if (p1.length < 8) return setMsg("newPasswordMsg", "Use at least 8 characters.", "err");
    if (p1 !== p2) return setMsg("newPasswordMsg", "The two passwords do not match.", "err");
    const { error } = await sb.auth.updateUser({ password: p1 });
    if (error) return setMsg("newPasswordMsg", "Could not save the password. Request a new reset link.", "err");
    e.target.reset();
    setMsg("newPasswordMsg", "");
    leaveRecovery();
    window.history.replaceState(null, "", window.location.pathname);
    const { data: { session } } = await sb.auth.getSession();
    if (session) await enter(session);
    else showView("viewLogin");
  });

  $("logoutBtn").addEventListener("click", () => sb.auth.signOut());
  $("inactiveSignOutBtn").addEventListener("click", () => sb.auth.signOut());
}

// ---------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------
function start() {
  renderIdentity();
  const problem = configProblem();
  if (problem) {
    showView("viewSetup");
    return;
  }
  const role = keyRole(SUPABASE_ANON_KEY);
  if (role === "service_role") {
    showView("viewSetup");
    document.querySelector("#viewSetup p").textContent = "Refused: a service-role key is configured. Use the publishable/anon key only.";
    return;
  }

  sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, flowType: "pkce" },
  });

  wireAuthForms();
  $("reportDate").value = today();
  $("equipDate").value = today();
  nav("overview");

  // Read the URL before supabase-js processes and clears it.
  arrivedWithAuthCode = /[?&#](code|access_token|type)=/.test(window.location.search + window.location.hash);
  const linkError = linkErrorCode();
  if (linkError) {
    const expired = /otp_expired|expired/.test(linkError);
    setMsg("loginMsg", expired
      ? "This reset link has expired or was already used. Request a new one."
      : "The link could not be verified. Request a new reset link.", "err");
    window.history.replaceState(null, "", window.location.pathname);
  }

  sb.auth.onAuthStateChange((event, session) => {
    if (event === "PASSWORD_RECOVERY") { enterRecovery(); return; }
    if (event === "TOKEN_REFRESHED" || event === "USER_UPDATED") return;
    if (!session) {
      if (recoveryMode) return; // keep the new-password form open
      resetState();
      return showView("viewLogin");
    }
    const recoveryLink = arrivedWithAuthCode && recoveryRequested();
    if (recoveryMode || recoveryLink || sessionIsRecovery(session)) {
      enterRecovery();
      return;
    }
    // Defer: calling Supabase inside the auth callback can deadlock.
    setTimeout(() => enter(session), 0);
  });
}

start();
