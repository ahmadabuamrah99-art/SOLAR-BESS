# Username sign-in: review and deployment guide

Status: **drafted on the development branch. Nothing has been applied to the live database and nothing is deployed.**

## What is included

| File | Purpose |
|---|---|
| `migrations/20261126100007_usernames.sql` | Adds `profiles.username` (lowercase, unique, 3–30 characters), the login rate-limit table, and the Admin-only rule for usernames. Wrapped in a transaction. |
| `functions/login-with-username/index.ts` | Edge Function entry point. Reads secrets from the environment and calls Supabase. |
| `functions/login-with-username/logic.ts` | Login logic: validation, rate limits, error handling, CORS. No secrets. |
| `functions/login-with-username/logic.test.ts` | 16 unit tests for the logic. |
| `tests/01_rls_security_tests.sql` | Now 88 checks. U01–U19 cover usernames and the rate-limit table. |

Email sign-in is unchanged. Password recovery is unchanged and remains email-only.

## How it works

1. The sign-in form sends a username to the Edge Function. Anything containing `@` goes through the normal email sign-in, as before.
2. The function checks rate limits first: 5 failed attempts per username, or 30 per IP address, within 15 minutes.
3. It finds the active account with that username and checks the password through Supabase Auth.
4. On success it returns a session. The account email is never returned to the browser.
5. Every failure returns the same message, so the form does not reveal which usernames exist.

**Security points to know**

- The service-role key is read only inside the function, from Supabase's own environment. It is never in the browser code or the repository.
- Rate-limit keys are HMAC hashes using a secret pepper. Raw usernames and IP addresses are not stored.
- The lockout can be used against you: someone who knows the username can lock it for 15 minutes by guessing wrong 5 times. Email sign-in still works during a lockout.
- The browser only ever sends the publishable key.

---

## Deployment steps (run only after you have reviewed the files)

### Step 1: Review the migration

Open `migrations/20261126100007_usernames.sql` and check it. It makes no changes to passwords, emails, roles or existing permissions.

### Step 2: Apply the migration

1. Supabase Dashboard → project → **SQL Editor** → **New query**.
2. Paste the whole file and click **Run**. Expect "Success".
3. Check it worked. Paste and run:

```sql
select column_name from information_schema.columns
where table_name = 'profiles' and column_name = 'username';
```

You should see one row: `username`.

**Do not run `supabase db push` yet.** It would apply every pending migration in the folder.

### Step 3: Generate a pepper (once, on your computer)

The pepper is a secret string used to hash rate-limit keys. Generate it in your terminal and keep it private:

```bash
openssl rand -base64 48
```

Store the output in your password manager. Do not commit it or paste it into chat.

### Step 4: Set the function secrets

Install the Supabase CLI on your computer if you don't have it, then:

```bash
supabase login
supabase link --project-ref zxmxjsfeboalahjslgcl
supabase secrets set \
  LOGIN_HASH_PEPPER="<paste the pepper from Step 3>" \
  ALLOWED_ORIGINS="https://solar-bess-eight.vercel.app" \
  ALLOWED_ORIGIN_REGEX="^https://solar-bess-git-claude-youthful-wozniak-uwyeg9-[a-z0-9-]+\.vercel\.app$"
```

Do **not** set `SUPABASE_SERVICE_ROLE_KEY` yourself. Supabase provides it to the function automatically.

If your Preview address looks different, adjust `ALLOWED_ORIGIN_REGEX` to match it. The browser will show a CORS error if the Preview origin is not allowed.

### Step 5: Deploy the function

```bash
supabase functions deploy login-with-username --no-verify-jwt
```

`--no-verify-jwt` is required, because a user who is not signed in yet must be able to call it.

### Step 6: Set the username for the Admin account

1. Sign in to the GreenGrid Preview as Admin using your email and password.
2. Go to **Reports & Data** → **User Access**.
3. In your row, type `baomahun_soventix` in the **Username** box and press **Tab**.
4. You should see "Username saved".

### Step 7: Test the function (safe test, no real password needed)

Replace `<PUBLISHABLE_KEY>` with your publishable key. This request uses a fake username, so it is safe to run:

```bash
curl -s -X POST "https://zxmxjsfeboalahjslgcl.supabase.co/functions/v1/login-with-username" \
  -H "apikey: <PUBLISHABLE_KEY>" -H "content-type: application/json" \
  -d '{"identifier":"not_a_real_user","password":"test-only"}'
```

Expected: `{"error":"invalid_credentials"}`.

### Step 8: Test sign-in in the Preview

1. Sign in with `baomahun_soventix` and your current password. You should reach the dashboard as Admin.
2. Sign in with your email and password. This should still work.
3. Try a wrong password 5 times with the username. The 6th attempt should show "Too many sign-in attempts". Email sign-in should still work.
4. Wait 15 minutes before testing again.

### Step 9: Check the logs

Supabase Dashboard → **Edge Functions** → `login-with-username` → **Logs**. Logs should show only errors, never passwords or emails.

---

## Rollback (if needed)

1. Remove the function: `supabase functions delete login-with-username`
2. In the SQL Editor:

```sql
drop table if exists public.auth_login_attempts;
alter table public.profiles drop constraint if exists profiles_username_format_chk;
drop index if exists public.profiles_username_key;
alter table public.profiles drop column if exists username;
```

3. Restore the earlier `guard_profiles` function from migration `20261125100002_auth_helpers.sql` (the version without the username check).

Email sign-in is not affected by any of these steps.

## Running the unit tests

From the repository root:

```bash
node --experimental-strip-types --test supabase/functions/login-with-username/logic.test.ts
```

Requires Node 22 or later.
