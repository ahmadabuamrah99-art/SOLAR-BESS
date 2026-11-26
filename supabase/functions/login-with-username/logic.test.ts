// Unit tests for username sign-in logic. No network and no Supabase project needed.
// Run from the repository root:
//   node --experimental-strip-types --test supabase/functions/login-with-username/logic.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { handleLogin, LIMITS, type LoginDeps, type Session } from "./logic.ts";

const ACCOUNT_EMAIL = "owner@example.test";     // test-only address, never a real account
const ACCOUNT_USERNAME = "baomahun_soventix";
const ACCOUNT_PASSWORD = "correct-horse-1";
const ALLOWED_ORIGIN = "https://preview.example.test";
const ATTACKER_IP = "198.51.100.66";
const ADMIN_IP = "203.0.113.7";

function makeDeps(overrides: Partial<LoginDeps> = {}) {
  const failures: Array<{ key: string; at: number }> = [];
  let clock = 1_000_000_000_000;
  let ip = ADMIN_IP;
  const session: Session = { access_token: "tok-access", refresh_token: "tok-refresh", expires_in: 3600, token_type: "bearer" };
  const deps: LoginDeps = {
    originAllowed: (o) => o === ALLOWED_ORIGIN,
    // Real SHA-256 in tests, so distinct inputs never share a key.
    hmac: async (v) => createHash("sha256").update(v).digest("hex"),
    countRecent: async (key, since) => failures.filter((f) => f.key === key && f.at >= since).length,
    recordFailure: async (keys) => { for (const k of keys) failures.push({ key: k, at: clock }); },
    clearFailures: async (key) => { for (let i = failures.length - 1; i >= 0; i--) if (failures[i].key === key) failures.splice(i, 1); },
    findActiveEmail: async (u) => (u === ACCOUNT_USERNAME ? ACCOUNT_EMAIL : null),
    signIn: async (email, pw) => (email === ACCOUNT_EMAIL && pw === ACCOUNT_PASSWORD ? session : null),
    sleep: async () => {},
    clientIp: () => ip,
    now: () => clock,
    ...overrides,
  };
  return {
    deps,
    failures,
    advance: (ms: number) => { clock += ms; },
    setIp: (v: string) => { ip = v; },
  };
}

const post = (body: unknown, headers: Record<string, string> = {}) =>
  new Request("https://fn.example.test/login-with-username", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

const attempt = (deps: LoginDeps, identifier: string, password = "wrong-pass") =>
  handleLogin(post({ identifier, password }), deps);

test("successful username sign-in returns a session and no email", async () => {
  const { deps } = makeDeps();
  const res = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  const text = await res.text();
  assert.equal(res.status, 200);
  const body = JSON.parse(text);
  assert.equal(body.session.access_token, "tok-access");
  assert.equal(body.session.refresh_token, "tok-refresh");
  assert.ok(!text.includes(ACCOUNT_EMAIL), "response must not contain the account email");
  assert.equal(res.headers.get("cache-control"), "no-store");
});

test("usernames are normalized: case and surrounding spaces do not matter", async () => {
  const { deps } = makeDeps();
  for (const id of ["Baomahun_Soventix", "BAOMAHUN_SOVENTIX", "  baomahun_soventix  "]) {
    const res = await handleLogin(post({ identifier: id, password: ACCOUNT_PASSWORD }), deps);
    assert.equal(res.status, 200, `identifier ${JSON.stringify(id)} should sign in`);
  }
});

test("rate-limit keys use the normalized username, so case cannot split the counters", async () => {
  const { deps, failures } = makeDeps();
  await attempt(deps, "Baomahun_Soventix");
  await attempt(deps, "BAOMAHUN_SOVENTIX");
  await attempt(deps, "baomahun_soventix");
  const userKey = createHash("sha256").update("user:baomahun_soventix").digest("hex");
  assert.equal(failures.filter((f) => f.key === userKey).length, 3);
});

test("wrong password, unknown username and invalid format return the same response", async () => {
  const { deps } = makeDeps();
  const wrongPw = await attempt(deps, ACCOUNT_USERNAME);
  const unknown = await attempt(deps, "someone_else");
  const badFormat = await attempt(deps, "1bad name");
  for (const r of [wrongPw, unknown, badFormat]) {
    assert.equal(r.status, 401);
    assert.deepEqual(await r.json(), { error: "invalid_credentials" });
  }
});

test("email addresses are refused by this function (they use the standard path)", async () => {
  const { deps } = makeDeps();
  const res = await attempt(deps, ACCOUNT_EMAIL, ACCOUNT_PASSWORD);
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "use_email_sign_in" });
});

test("five failures from one IP for one username block only that pair", async () => {
  const { deps, setIp } = makeDeps();
  setIp(ATTACKER_IP);
  for (let i = 0; i < LIMITS.pairFailures; i++) await attempt(deps, ACCOUNT_USERNAME);
  const blocked = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(blocked.status, 429, "attacker is blocked from this username");
  assert.equal(blocked.headers.get("retry-after"), String(LIMITS.retryAfterPairSec));
});

test("ADMIN PROTECTION: an attacker's lockout does not stop the Admin from another network", async () => {
  const { deps, setIp } = makeDeps();
  setIp(ATTACKER_IP);
  for (let i = 0; i < LIMITS.pairFailures + 5; i++) await attempt(deps, ACCOUNT_USERNAME);
  setIp(ADMIN_IP);
  const admin = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(admin.status, 200, "Admin signs in from their own IP while the attacker is blocked");
});

test("one attacker cannot exhaust the per-IP budget for an Admin on another address", async () => {
  const { deps, setIp } = makeDeps();
  setIp(ATTACKER_IP);
  for (let i = 0; i < LIMITS.ipFailures; i++) await attempt(deps, `sweep_name_${i}`);
  setIp(ADMIN_IP);
  const admin = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(admin.status, 200);
});

test("per-IP limit blocks many different usernames from one address", async () => {
  const { deps, setIp } = makeDeps();
  setIp(ATTACKER_IP);
  for (let i = 0; i < LIMITS.ipFailures; i++) await attempt(deps, `sweep_name_${i}`);
  const r = await attempt(deps, "another_name");
  assert.equal(r.status, 429);
  assert.equal(r.headers.get("retry-after"), String(LIMITS.retryAfterIpSec));
});

test("username ceiling: many addresses hitting one username eventually get a longer block", async () => {
  const { deps, setIp } = makeDeps();
  // Spread across addresses so the per-pair and per-IP limits never trigger.
  for (let i = 0; i < LIMITS.userFailures; i++) {
    setIp(`192.0.2.${i}`);
    await attempt(deps, ACCOUNT_USERNAME);
  }
  setIp("192.0.2.250");
  const r = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(r.status, 429);
  assert.equal(r.headers.get("retry-after"), String(LIMITS.retryAfterUserSec));
  // The ceiling is per username: other usernames are unaffected.
  setIp(ADMIN_IP);
  const other = await attempt(deps, "unrelated_name");
  assert.equal(other.status, 401, "unrelated username is not rate-limited by this ceiling");
});

test("a successful sign-in clears that IP+username pair, not other counters", async () => {
  const { deps, setIp, failures } = makeDeps();
  setIp(ATTACKER_IP);
  for (let i = 0; i < LIMITS.pairFailures - 1; i++) await attempt(deps, ACCOUNT_USERNAME);
  const ok = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(ok.status, 200);
  const ipKey = createHash("sha256").update(`ip:${ATTACKER_IP}`).digest("hex");
  assert.ok(failures.some((f) => f.key === ipKey), "IP counter is kept after a success");
  for (let i = 0; i < LIMITS.pairFailures - 1; i++) await attempt(deps, ACCOUNT_USERNAME);
  const still = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(still.status, 200, "pair counter was reset by the earlier success");
});

test("the pair window expires", async () => {
  const { deps, advance, setIp } = makeDeps();
  setIp(ATTACKER_IP);
  for (let i = 0; i < LIMITS.pairFailures; i++) await attempt(deps, ACCOUNT_USERNAME);
  advance(LIMITS.pairWindowMs + 1);
  const r = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(r.status, 200);
});

test("bad request bodies are rejected without touching accounts", async () => {
  let lookups = 0;
  const { deps } = makeDeps({ findActiveEmail: async () => { lookups++; return null; } });
  const cases: unknown[] = ["not json", "[1,2]", { identifier: 5, password: "x" }, { identifier: "ab", password: "x" }, { identifier: "valid_name", password: "" }];
  for (const c of cases) {
    const r = await handleLogin(post(c), deps);
    assert.equal(r.status, 400, `case ${JSON.stringify(c)}`);
  }
  assert.equal(lookups, 0);
});

test("oversized bodies are refused", async () => {
  const { deps } = makeDeps();
  const big = JSON.stringify({ identifier: "valid_name", password: "x".repeat(5000) });
  const r = await handleLogin(post(big), deps);
  assert.equal(r.status, 400);
});

test("unexpected server errors return a generic 500 without internal details", async () => {
  const { deps } = makeDeps({
    findActiveEmail: async () => { const e = new Error("db password=hunter2 host=internal"); e.name = "PostgrestError"; throw e; },
  });
  const r = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "x" }), deps);
  const text = await r.text();
  assert.equal(r.status, 500);
  assert.deepEqual(JSON.parse(text), { error: "server_error" });
  assert.ok(!text.includes("hunter2") && !text.includes("internal"));
});

test("unknown browser origins are refused; the exact allowed origin gets CORS headers", async () => {
  const { deps } = makeDeps();
  const bad = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "x" }, { origin: "https://evil.example" }), deps);
  assert.equal(bad.status, 403);
  const good = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }, { origin: ALLOWED_ORIGIN }), deps);
  assert.equal(good.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN);
});

test("a look-alike origin (subdomain or other path) is refused", async () => {
  const { deps } = makeDeps();
  for (const o of ["https://preview.example.test.evil.example", "http://preview.example.test", "https://preview.example.test:8443"]) {
    const r = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "x" }, { origin: o }), deps);
    assert.equal(r.status, 403, `origin ${o} must be refused`);
  }
});

test("preflight requests succeed for the allowed origin and send no CORS grant otherwise", async () => {
  const { deps } = makeDeps();
  const pre = new Request("https://fn.example.test/x", { method: "OPTIONS", headers: { origin: ALLOWED_ORIGIN } });
  const r = await handleLogin(pre, deps);
  assert.equal(r.status, 204);
  assert.equal(r.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN);
  const other = new Request("https://fn.example.test/x", { method: "OPTIONS" });
  const r2 = await handleLogin(other, deps);
  assert.equal(r2.headers.get("access-control-allow-origin"), null);
});

test("only POST is accepted", async () => {
  const { deps } = makeDeps();
  const r = await handleLogin(new Request("https://fn.example.test/x", { method: "GET" }), deps);
  assert.equal(r.status, 405);
});

test("a rejected password is never echoed back", async () => {
  const { deps } = makeDeps();
  const r = await attempt(deps, ACCOUNT_USERNAME, "SECRET-VALUE-123");
  assert.ok(!(await r.text()).includes("SECRET-VALUE-123"));
});
