-- =====================================================================
-- 20261125100002_auth_helpers.sql
-- Profiles, role helper functions, signup trigger and role-change guard.
--
-- Roles: 'admin', 'engineer', 'viewer'.
--   * New accounts are ALWAYS created as 'viewer'. The role in sign-up
--     metadata is ignored, so nobody can self-assign a role at sign-up.
--   * Only an Admin can change a role or activate/deactivate an account.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Profiles (one row per auth user). Contains no email or secrets.
-- ---------------------------------------------------------------------
create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text not null default '' check (length(full_name) <= 120),
  role        text not null default 'viewer' check (role in ('admin', 'engineer', 'viewer')),
  is_active   boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create trigger profiles_updated_at before update on public.profiles
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------
-- Role helpers used by RLS policies.
-- SECURITY DEFINER lets them read profiles without recursing into RLS.
-- search_path is fixed to prevent search-path hijacking.
-- ---------------------------------------------------------------------
create or replace function public.app_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select p.role
  from public.profiles p
  where p.id = (select auth.uid())
    and p.is_active
$$;

create or replace function public.can_read()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.app_role() is not null
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(public.app_role() = 'admin', false)
$$;

create or replace function public.is_writer()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(public.app_role() in ('admin', 'engineer'), false)
$$;

revoke execute on function public.app_role(), public.can_read(), public.is_admin(), public.is_writer()
  from public, anon;
grant execute on function public.app_role(), public.can_read(), public.is_admin(), public.is_writer()
  to authenticated;

-- ---------------------------------------------------------------------
-- Signup: create a viewer profile for every new auth user.
-- ---------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name, role, is_active)
  values (
    new.id,
    left(coalesce(new.raw_user_meta_data ->> 'full_name', ''), 120),
    'viewer',   -- never taken from user metadata
    true
  );
  return new;
end;
$$;

revoke execute on function public.handle_new_user() from public, anon, authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------
-- Guard: only Admins may change role or is_active. Users may edit their own name.
-- SQL editor / migrations run as postgres and are not affected.
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
       or new.is_active is distinct from old.is_active then
      raise exception 'Only an Admin can change roles or account status'
        using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;

create trigger profiles_guard before update on public.profiles
  for each row execute function public.guard_profiles();
