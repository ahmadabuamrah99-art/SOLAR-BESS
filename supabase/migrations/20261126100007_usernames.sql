-- =====================================================================
-- 20261126100007_usernames.sql
-- Username sign-in support (Option B: Edge Function).
--
-- DRAFT: written for review. NOT applied to any database yet.
--
-- What this does:
--   1. Adds profiles.username (optional, lowercase, unique case-insensitively).
--   2. Normalizes every username to lowercase and trimmed in the database itself,
--      so no code path can store "Baomahun_Soventix" as a different value.
--   3. Adds a login rate-limit table, readable and writable only by the
--      service role (the Edge Function). Clients have no access.
--   4. Extends the profile guard so only Admins can set or change usernames.
--
-- What this does NOT do:
--   * It does not touch auth.users, so no passwords or emails change.
--   * It does not change any role or permission.
--   * It does not set any username. An Admin sets usernames afterwards.
-- =====================================================================

begin;

-- ---------------------------------------------------------------------
-- 1. Username column (empty for every existing user)
-- ---------------------------------------------------------------------
alter table public.profiles add column if not exists username text;

alter table public.profiles drop constraint if exists profiles_username_format_chk;
alter table public.profiles add constraint profiles_username_format_chk
  check (username is null or username ~ '^[a-z][a-z0-9_]{2,29}$');

-- Case-insensitive uniqueness. Expression index on lower(username), so two names
-- that differ only by case can never both exist, even if the normalizing trigger
-- were bypassed.
create unique index if not exists profiles_username_lower_key
  on public.profiles (lower(username));

-- ---------------------------------------------------------------------
-- 2. Normalize on write: trim and lowercase. Empty string becomes NULL.
-- ---------------------------------------------------------------------
create or replace function public.normalize_username()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.username is not null then
    new.username := lower(btrim(new.username));
    if new.username = '' then
      new.username := null;
    end if;
  end if;
  return new;
end;
$$;

revoke execute on function public.normalize_username() from public, anon, authenticated;

drop trigger if exists profiles_username_normalize on public.profiles;
create trigger profiles_username_normalize
  before insert or update of username on public.profiles
  for each row execute function public.normalize_username();

-- ---------------------------------------------------------------------
-- 3. Login rate-limit storage. Keys are HMAC hashes, never raw usernames or IPs.
-- ---------------------------------------------------------------------
create table if not exists public.auth_login_attempts (
  id            bigint generated always as identity primary key,
  key_hash      text not null check (length(key_hash) = 64),
  attempted_at  timestamptz not null default now()
);

create index if not exists auth_login_attempts_key_time_idx
  on public.auth_login_attempts (key_hash, attempted_at);
create index if not exists auth_login_attempts_time_idx
  on public.auth_login_attempts (attempted_at);

alter table public.auth_login_attempts enable row level security;
-- No policies on purpose: anon and authenticated are denied. The service role
-- (used only by the Edge Function) bypasses RLS.

revoke all on public.auth_login_attempts from anon, authenticated;
grant select, insert, delete on public.auth_login_attempts to service_role;
-- Needed for the identity column's insert. Granted on this one sequence only.
grant usage on sequence public.auth_login_attempts_id_seq to service_role;

-- ---------------------------------------------------------------------
-- 4. Guard: only Admins may change role, status or username.
--    Replaces guard_profiles from migration 2; the rest of its behaviour is unchanged.
-- ---------------------------------------------------------------------
create or replace function public.guard_profiles()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if current_user in ('anon', 'authenticated') and not public.is_admin() then
    if new.id is distinct from old.id
       or new.role is distinct from old.role
       or new.is_active is distinct from old.is_active
       or new.username is distinct from old.username then
      raise exception 'Only an Admin can change roles, account status or usernames'
        using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;

commit;
