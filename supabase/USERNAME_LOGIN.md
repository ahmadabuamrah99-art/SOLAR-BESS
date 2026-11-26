# Username sign-in: review and deployment guide

Status: **drafted on the development branch. Nothing has been applied to the live database, nothing is deployed, and production is unchanged.**

## Files

| File | Purpose |
|---|---|
| `migrations/20261126100007_usernames.sql` | Adds `profiles.username`, a case-insensitive unique index on `lower(username)`, a trigger that normalizes usernames to trimmed lowercase, the login rate-limit table (service role only), and the Admin-only rule for usernames. Wrapped in a transaction. |
| `functions/login-with-username/index.ts` | Edge Function entry point. Reads secrets from the environment, validates the allow-list, calls Supabase. |
| `functions/login-with-username/logic.ts` | Login logic: normalization, rate limits, error handling, CORS. No secrets. |
| `functions/login-with-username/logic.test.ts` | 20 unit tests. |
| `tests/01_rls_security_tests.sql` | 90 database checks. U01–U19 cover usernames and the rate-limit table. |

Email sign-in is unchanged. Password recovery is unchanged and remains email-only.

## How sign-in works

1. The form sends the username trimmed and lowercased. Anything containing `@` uses the standard email sign-in.
2. The function checks three counters before looking up the account:

| Counter | Limit | Who it affects |
|---|---|---|
| Username + IP address | 5 failures / 15 min | Only the attacker's own address |
| IP address | 30 failures / 15 min | Only that address |
| Username (any address) | 100 failures / 60 min | The username, as a high ceiling against distributed guessing |

3. Unknown usernames, wrong passwords and inactive accounts all return the same `invalid_credentials` response after a short random delay.
4. A correct password from another network is accepted, even while an attacker is blocked from one address. This is the Admin protection.
5. The account email is never sent to the browser.

## Residual risks (accepted, to review)

- **IP-based limits depend on the proxy.** The function trusts the *last* `x-forwarded-for` entry, which the edge proxy appends. Confirm this after deployment by checking the logs. If the address is wrong, the pair and IP limits are weaker, and the 100-per-hour username ceiling is the remaining protection.
- **Shared networks.** Many people behind one office IP share the 30-per-15-minutes IP budget.
- **No CAPTCHA.** Add one later if guessing attempts are seen in the logs.
- **Email sign-in** has only Supabase's built-in rate limits. This is the same as before this change.

---

## Deployment steps (only after review)

### Step 1: Review

Review the migration, the function files, and this guide. Nothing is applied until you say so.

### Step 2: Apply the migration

1. Supabase Dashboard → SQL Editor → New query. Paste the whole migration file and click **Run**. Expect "Success".
2. Check it:

```sql
select column_name from information_schema.columns
where table_name = 'profiles' and column_name = 'username';
```

One row, `username`, should come back.

**Do not run `supabase db push`.** It would apply every pending migration in the folder.

### Step 3: Generate a pepper (once, on your computer)

```bash
openssl rand -base64 48
```

Keep the output in your password manager. Do not commit it or paste it into chat.

### Step 4: Set the function secrets

Use the **exact** Preview address. It must start with `https://` and have no trailing slash or path. You can copy it from the Preview's address bar.

```bash
supabase login
supabase link --project-ref zxmxjsfeboalahjslgcl
supabase secrets set \
  LOGIN_HASH_PEPPER="<pepper from Step 3>" \
  ALLOWED_ORIGINS="<exact Preview origin, for example https://solar-bess-git-claude-youthful-wozniak-uwyeg9-yourteam.vercel.app>"
```

Notes:

- Do **not** add the production address yet. Add it only after the Preview tests pass and you approve production.
- Do **not** set `SUPABASE_SERVICE_ROLE_KEY`. Supabase provides it to the function automatically.
- The function refuses to start if an entry is not an exact origin or contains a wildcard.

### Step 5: Deploy the function

```bash
supabase functions deploy login-with-username --no-verify-jwt
```

`--no-verify-jwt` is required, because a user who is not signed in yet must be able to call it.

### Step 6: Set the username

1. Sign in to the Preview as Admin with your email and password.
2. Reports & Data → User Access. Type `baomahun_soventix` in your row's Username box and press **Tab**.
3. You should see "Username saved".

### Step 7: Safe test (no real password)

Replace `<PUBLISHABLE_KEY>`. This uses a fake username and is safe to run:

```bash
curl -s -X POST "https://zxmxjsfeboalahjslgcl.supabase.co/functions/v1/login-with-username" \
  -H "apikey: <PUBLISHABLE_KEY>" -H "content-type: application/json" \
  -d '{"identifier":"not_a_real_user","password":"test-only"}'
```

Expected: `{"error":"invalid_credentials"}`.

### Step 8: Preview tests

1. Sign in with `baomahun_soventix` and your current password. You should reach the dashboard as Admin.
2. Sign in with your email and password. This must still work.
3. Type `Baomahun_Soventix` (with capitals). It should sign in.
4. Enter a wrong password 5 times with the username from one network. The next attempt should show "Too many sign-in attempts". Email sign-in must still work from the same network.
5. From a different network (for example, phone data), sign in with the username and correct password. It should work, which shows the Admin is protected.
6. Wait 15 minutes before testing the lockout again.

### Step 9: Logs

Supabase Dashboard → Edge Functions → `login-with-username` → Logs. Logs should show only error types, never passwords or emails.

---

## Rollback

Use this if anything goes wrong. Email sign-in is not affected by any of these steps.

1. Remove the function:

```bash
supabase functions delete login-with-username
```

2. In the SQL Editor, paste and run:

```sql
begin;
drop trigger if exists profiles_username_normalize on public.profiles;
drop function if exists public.normalize_username();
drop table if exists public.auth_login_attempts;
alter table public.profiles drop constraint if exists profiles_username_format_chk;
drop index if exists public.profiles_username_lower_key;
alter table public.profiles drop column if exists username;
commit;
```

3. Restore the earlier profile guard. Paste the `guard_profiles` function from `migrations/20261125100002_auth_helpers.sql` (the version without the username check) and run it.

4. Check: `select column_name from information_schema.columns where table_name = 'profiles' and column_name = 'username';` should return no rows.

## Running the tests

From the repository root:

```bash
node --experimental-strip-types --test supabase/functions/login-with-username/logic.test.ts
```

Requires Node 22 or later.
