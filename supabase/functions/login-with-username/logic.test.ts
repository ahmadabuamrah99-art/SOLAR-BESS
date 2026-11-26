// Unit tests for username sign-in logic. No network and no Supabase project needed.
// Run from the repository root:
//   node --experimental-strip-types --test supabase/functions/login-with-username/logic.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { handleLogin, LIMITS, type LoginDeps, type Session } from "./logic.ts";

const ACCOUNT_EMAIL = "owner@example.test";     // test-only address, never a real account
const ACCOUNT_USERNAME = "baomahun_soventix";
const ACCOUNT_PASSWORD = "correct-horse-1";
const ALLOWED_ORIGIN = "https://app.example.test";

function makeDeps(overrides: Partial<LoginDeps> = {}) {
  const failures: Array<{ key: string; at: number }> = [];
  let clock = 1_000_000_000_000;
  const session: Session = { access_token: "tok-access", refresh_token: "tok-refresh", expires_in: 3600, token_type: "bearer" };
  const deps: LoginDeps = {
    originAllowed: (o) => o === ALLOWED_ORIGIN,
    hmac: async (v) => "k" + Buffer.from(v).toString("hex").padEnd(63, "0").slice(0, 63), // 64-char test key
    countRecent: async (key, since) => failures.filter((f) => f.key === key && f.at >= since).length,
    recordFailure: async (keys) => { for (const k of keys) failures.push({ key: k, at: clock }); },
    clearFailures: async (key) => { for (let i = failures.length - 1; i >= 0; i--) if (failures[i].key === key) failures.splice(i, 1); },
    findActiveEmail: async (u) => (u === ACCOUNT_USERNAME ? ACCOUNT_EMAIL : null),
    signIn: async (email, pw) => (email === ACCOUNT_EMAIL && pw === ACCOUNT_PASSWORD ? session : null),
    sleep: async () => {},
    clientIp: () => "203.0.113.7",
    now: () => clock,
    ...overrides,
  };
  return { deps, failures, advance: (ms: number) => { clock += ms; } };
}

const post = (body: unknown, headers: Record<string, string> = {}) =>
  new Request("https://fn.example.test/login-with-username", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

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

test("username lookup is case-insensitive and ignores surrounding spaces", async () => {
  const { deps } = makeDeps();
  for (const id of ["Baomahun_Soventix", "BAOMAHUN_SOVENTIX", "  baomahun_soventix  "]) {
    const res = await handleLogin(post({ identifier: id, password: ACCOUNT_PASSWORD }), deps);
    assert.equal(res.status, 200, `identifier ${JSON.stringify(id)} should sign in`);
  }
});

test("wrong password, unknown username and invalid format return the same response", async () => {
  const { deps } = makeDeps();
  const wrongPw = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "nope-nope" }), deps);
  const unknown = await handleLogin(post({ identifier: "someone_else", password: "x" }), deps);
  const badFormat = await handleLogin(post({ identifier: "1bad name", password: "x" }), deps);
  for (const r of [wrongPw, unknown, badFormat]) {
    assert.equal(r.status, 401);
    assert.deepEqual(await r.json(), { error: "invalid_credentials" });
  }
});

test("email addresses are refused by this function (they use the standard path)", async () => {
  const { deps } = makeDeps();
  const res = await handleLogin(post({ identifier: ACCOUNT_EMAIL, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "use_email_sign_in" });
});

test("five failures for one username lock that username with 429 and Retry-After", async () => {
  const { deps } = makeDeps();
  for (let i = 0; i < LIMITS.userFailures; i++) {
    const r = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "wrong" }), deps);
    assert.equal(r.status, 401);
  }
  const locked = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(locked.status, 429, "correct password is refused while locked");
  assert.equal(locked.headers.get("retry-after"), String(LIMITS.retryAfterSec));
});

test("lockout applies equally to unknown usernames (no account-existence signal)", async () => {
  const { deps } = makeDeps();
  for (let i = 0; i < LIMITS.userFailures; i++) await handleLogin(post({ identifier: "ghost_user", password: "x" }), deps);
  const r = await handleLogin(post({ identifier: "ghost_user", password: "x" }), deps);
  assert.equal(r.status, 429);
});

test("per-IP limit blocks many different usernames from one address", async () => {
  const { deps } = makeDeps();
  for (let i = 0; i < LIMITS.ipFailures; i++) {
    await handleLogin(post({ identifier: `user_${i}_x`, password: "x" }), deps);
  }
  const r = await handleLogin(post({ identifier: "another_name", password: "x" }), deps);
  assert.equal(r.status, 429);
});

test("a successful sign-in clears that username's failure count", async () => {
  const { deps } = makeDeps();
  for (let i = 0; i < LIMITS.userFailures - 1; i++) await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "wrong" }), deps);
  const ok = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(ok.status, 200);
  for (let i = 0; i < LIMITS.userFailures - 1; i++) await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "wrong" }), deps);
  const still = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }), deps);
  assert.equal(still.status, 200, "counter was reset by the earlier success");
});

test("the lockout window expires", async () => {
  const { deps, advance } = makeDeps();
  for (let i = 0; i < LIMITS.userFailures; i++) await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "wrong" }), deps);
  advance(LIMITS.windowMs + 1);
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

test("unknown browser origins are refused; allowed origins get CORS headers", async () => {
  const { deps } = makeDeps();
  const bad = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "x" }, { origin: "https://evil.example" }), deps);
  assert.equal(bad.status, 403);
  const good = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: ACCOUNT_PASSWORD }, { origin: ALLOWED_ORIGIN }), deps);
  assert.equal(good.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN);
});

test("preflight requests succeed for allowed origins and send no CORS grant otherwise", async () => {
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
  const r = await handleLogin(post({ identifier: ACCOUNT_USERNAME, password: "SECRET-VALUE-123" }), deps);
  assert.ok(!(await r.text()).includes("SECRET-VALUE-123"));
});
