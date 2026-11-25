# GreenGrid — Solar PV & BESS Project Control Dashboard

Multi-user project control dashboard for Solar PV and BESS works. Data is stored in Supabase (Postgres), with sign-in and role-based access.

Live site: https://solar-bess-eight.vercel.app/ (production: do not overwrite without review)

## What it includes

- Overview with per-activity and per-discipline progress (overall weighted progress appears only after verified weights are entered)
- Solar PV and BESS activity registers and BESS block status
- Daily / weekly / monthly progress log
- QA/QC register with submit-for-review workflow (Admin approves)
- HSE register, issues and risks
- Manpower by category (daily), equipment register and daily equipment status
- Reports: preview, save as draft, Admin issues (locks the report)
- Project settings, user access (Admin), JSON backup, CSV export

## Roles

| Role | Access |
|---|---|
| Admin | Everything, including baseline data, QA/QC approval, report issue, users and settings |
| Engineer | Logs progress, QA/QC drafts and submissions, HSE, manpower, equipment, issues, report drafts |
| Viewer | Read-only |

Access rules are enforced by Postgres Row Level Security in the database. The interface only hides controls.

## Project structure

```
index.html              App shell, layout and styles (GreenGrid design)
js/config.js            Public browser config: Supabase URL and publishable/anon key
js/app.js               Sign-in, data loading and forms
supabase/               Database migrations, RLS policies and security tests (see supabase/README.md)
```

## Setup

1. **Database:** apply the migrations in `supabase/` (see `supabase/README.md`).
2. **Config:** edit `js/config.js` with your project URL and **publishable or anon key** (Supabase Dashboard → Project Settings → API Keys).
   - Never put the `service_role` key, or any `sb_secret_` key, in this repository or in frontend code. The app refuses to start if it detects one.
3. **Auth settings** (Supabase Dashboard → Authentication):
   - Turn off public sign-ups.
   - Site URL: `https://solar-bess-eight.vercel.app`.
   - Redirect URLs: add `https://solar-bess-eight.vercel.app/` (and `http://127.0.0.1:8099/` only for local testing).
4. **First Admin:** invite a user, then promote them with the SQL in `supabase/README.md`.

## Run locally

Serve the folder with any static server (the app has no build step), for example:

```bash
python3 -m http.server 8000
```

Then open http://127.0.0.1:8000/. Sign-in requires the Supabase settings above.

## Security notes

- Only the public URL and publishable/anon key are used in the browser.
- Row Level Security and database triggers enforce every rule (roles, QA/QC transitions, locked reports, last-Admin protection).
- Demo data (`is_demo`) is marked on screen until verified project data replaces it. Capacities stay blank until verified.
- Restore from JSON is disabled, because it would overwrite shared project data.
