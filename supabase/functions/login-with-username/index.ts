// Supabase Edge Function: sign in with a username and password.
// Deploy with: supabase functions deploy login-with-username --no-verify-jwt
// (the caller is not signed in yet, so JWT verification must be off for this function)
//
// Environment (set with `supabase secrets set`, never in the repository):
//   LOGIN_HASH_PEPPER   random string, 32+ characters, used to hash rate-limit keys
//   ALLOWED_ORIGINS     comma-separated EXACT origins, e.g. https://solar-bess-git-....vercel.app
//                       No wildcards. Pattern matching is intentionally not supported.
// Supabase provides SUPABASE_URL, SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY automatically.
// The service-role key is read here on the server only. It is never sent to the browser.

import { createClient } from "npm:@supabase/supabase-js@2.119.0";
import { handleLogin, LIMITS, normalizeUsername, type LoginDeps, type Session } from "./logic.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const PEPPER = Deno.env.get("LOGIN_HASH_PEPPER") ?? "";
const ALLOWED = (Deno.env.get("ALLOWED_ORIGINS") ?? "").split(",").map((s) => s.trim()).filter(Boolean);

if (PEPPER.length < 32) throw new Error("LOGIN_HASH_PEPPER must be set to at least 32 characters");
if (ALLOWED.some((o) => o.includes("*"))) throw new Error("ALLOWED_ORIGINS must not contain wildcards");
for (const o of ALLOWED) {
  // Exact origins only: scheme and host, no path, no trailing slash.
  if (!/^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(o)) throw new Error(`ALLOWED_ORIGINS entry is not an exact origin: ${o}`);
}

// Server-side client with the service role. Used for profile lookup, the email lookup
// and rate-limit storage. Never leaves the server.
const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
// Client with the anon key. Used only to check the password through Supabase Auth.
const anon = createClient(SUPABASE_URL, ANON_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const encoder = new TextEncoder();
const hmacKey = crypto.subtle.importKey(
  "raw", encoder.encode(PEPPER), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
);

async function hmac(value: string): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey, encoder.encode(value));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const deps: LoginDeps = {
  originAllowed: (origin) => ALLOWED.includes(origin),
  hmac,
  countRecent: async (keyHash, sinceMs) => {
    const { count, error } = await admin
      .from("auth_login_attempts")
      .select("id", { count: "exact", head: true })
      .eq("key_hash", keyHash)
      .gte("attempted_at", new Date(sinceMs).toISOString());
    if (error) throw error;
    return count ?? 0;
  },
  recordFailure: async (keyHashes) => {
    const { error } = await admin.from("auth_login_attempts").insert(keyHashes.map((key_hash) => ({ key_hash })));
    if (error) throw error;
  },
  clearFailures: async (keyHash) => {
    const { error } = await admin.from("auth_login_attempts").delete().eq("key_hash", keyHash);
    if (error) throw error;
  },
  findActiveEmail: async (username) => {
    const { data, error } = await admin
      .from("profiles")
      .select("id")
      .eq("username", normalizeUsername(username))
      .eq("is_active", true)
      .maybeSingle();
    if (error) throw error;
    if (!data) return null;
    const { data: user, error: userErr } = await admin.auth.admin.getUserById(data.id);
    if (userErr) throw userErr;
    return user?.user?.email ?? null;
  },
  signIn: async (email, password): Promise<Session | null> => {
    const { data, error } = await anon.auth.signInWithPassword({ email, password });
    if (error || !data.session) return null; // wrong password, unconfirmed or banned account
    return data.session as unknown as Session;
  },
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  clientIp: (req) => {
    // The client can set the first x-forwarded-for entry, so it is not trusted.
    // The LAST entry is appended by the edge proxy in front of this function.
    const xff = req.headers.get("x-forwarded-for");
    if (xff) {
      const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
      if (parts.length) return parts[parts.length - 1];
    }
    return req.headers.get("x-real-ip") || "unknown";
  },
  now: () => Date.now(),
};

Deno.serve(async (req) => {
  // Occasionally remove attempt records older than the longest window, to keep the table small.
  if (Math.random() < 0.05) {
    const longest = Math.max(LIMITS.pairWindowMs, LIMITS.ipWindowMs, LIMITS.userWindowMs);
    const cutoff = new Date(Date.now() - longest * 2).toISOString();
    await admin.from("auth_login_attempts").delete().lt("attempted_at", cutoff);
  }
  return handleLogin(req, deps);
});
