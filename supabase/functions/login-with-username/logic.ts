// Username sign-in logic for GreenGrid. Pure TypeScript with no runtime-specific imports,
// so it runs unchanged in Supabase Edge Functions (Deno) and in Node tests.
//
// Security properties:
//   * The response never contains the account email.
//   * Unknown usernames, wrong passwords, invalid formats and inactive accounts all
//     return the same 401 body, after a small random delay.
//   * Failed attempts are counted per username and per client IP (hashed keys),
//     and requests are refused with 429 once a limit is reached.
//   * Responses that contain a session are never cached.

export const USERNAME_PATTERN = /^[a-z][a-z0-9_]{2,29}$/;
export const LIMITS = {
  userFailures: 5,       // failed attempts per username per window
  ipFailures: 30,        // failed attempts per client IP per window
  windowMs: 15 * 60 * 1000,
  retryAfterSec: 900,
};
export const MAX_BODY_BYTES = 2048;

export interface Session {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at?: number;
  token_type: string;
}

export interface LoginDeps {
  originAllowed(origin: string): boolean;
  hmac(value: string): Promise<string>;                 // keyed hash, 64 hex characters
  countRecent(keyHash: string, sinceMs: number): Promise<number>;
  recordFailure(keyHashes: string[]): Promise<void>;
  clearFailures(keyHash: string): Promise<void>;
  findActiveEmail(username: string): Promise<string | null>;  // active accounts only
  signIn(email: string, password: string): Promise<Session | null>; // null = rejected
  sleep(ms: number): Promise<void>;
  clientIp(req: Request): string;
  now(): number;
}

export function normalizeUsername(raw: string): string {
  return raw.trim().toLowerCase();
}

function corsHeaders(origin: string | null, deps: LoginDeps): Record<string, string> {
  const h: Record<string, string> = {
    Vary: "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, apikey, x-client-info",
    "Access-Control-Max-Age": "600",
  };
  if (origin && deps.originAllowed(origin)) h["Access-Control-Allow-Origin"] = origin;
  return h;
}

function json(status: number, body: unknown, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
}

async function readJsonBody(req: Request): Promise<Record<string, unknown> | null> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return null;
  const text = await req.text();
  if (text.length > MAX_BODY_BYTES) return null;
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

export async function handleLogin(req: Request, deps: LoginDeps): Promise<Response> {
  const origin = req.headers.get("origin");
  if (origin && !deps.originAllowed(origin)) {
    return json(403, { error: "forbidden_origin" }, { Vary: "Origin" });
  }
  const cors = corsHeaders(origin, deps);

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") {
    return json(405, { error: "method_not_allowed" }, { ...cors, Allow: "POST, OPTIONS" });
  }

  try {
    const body = await readJsonBody(req);
    const identifier = body?.identifier;
    const password = body?.password;
    if (typeof identifier !== "string" || typeof password !== "string"
        || identifier.trim().length < 3 || identifier.length > 254
        || password.length < 1 || password.length > 128) {
      return json(400, { error: "invalid_request" }, cors);
    }

    const username = normalizeUsername(identifier);
    if (username.includes("@")) {
      // Email addresses use the standard sign-in path, not this function.
      return json(400, { error: "use_email_sign_in" }, cors);
    }

    // Rate limits are checked before any account lookup.
    const userKey = await deps.hmac("user:" + username);
    const ipKey = await deps.hmac("ip:" + deps.clientIp(req));
    const since = deps.now() - LIMITS.windowMs;
    const [userFailures, ipFailures] = await Promise.all([
      deps.countRecent(userKey, since),
      deps.countRecent(ipKey, since),
    ]);
    if (userFailures >= LIMITS.userFailures || ipFailures >= LIMITS.ipFailures) {
      return json(429, { error: "too_many_attempts" }, { ...cors, "Retry-After": String(LIMITS.retryAfterSec) });
    }

    const reject = async (): Promise<Response> => {
      await deps.recordFailure([userKey, ipKey]);
      await deps.sleep(150 + Math.floor(Math.random() * 150));
      return json(401, { error: "invalid_credentials" }, cors);
    };

    if (!USERNAME_PATTERN.test(username)) return reject();

    const email = await deps.findActiveEmail(username);
    if (!email) return reject();

    const session = await deps.signIn(email, password);
    if (!session) return reject();

    await deps.clearFailures(userKey);
    return json(200, {
      session: {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_in: session.expires_in,
        expires_at: session.expires_at,
        token_type: session.token_type,
      },
    }, cors);
  } catch (err) {
    // Log only the error type. Messages can contain account details.
    console.error("login-with-username failed:", (err as { name?: string })?.name ?? "unknown");
    return json(500, { error: "server_error" }, cors);
  }
}
