-- =====================================================================
-- 00_local_auth_shim.sql
-- LOCAL TEST ONLY. Do NOT run this against the Supabase project.
--
-- Supabase provides the anon/authenticated roles, the auth schema and
-- auth.uid() automatically. This file recreates a minimal version so the
-- migrations and RLS tests can run on a plain PostgreSQL 15+ server.
-- If you use the Supabase CLI (supabase start), skip this file.
-- =====================================================================

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  -- Supabase's service role (bypasses RLS). Used by the Edge Function.
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
end $$;

create schema if not exists auth;
grant usage on schema auth to anon, authenticated;
grant usage on schema public to anon, authenticated;

create table if not exists auth.users (
  id                  uuid primary key default gen_random_uuid(),
  email               text,
  encrypted_password  text,
  raw_user_meta_data  jsonb not null default '{}'::jsonb,
  created_at          timestamptz not null default now()
);
alter table auth.users add column if not exists encrypted_password text;

-- Same claim lookup as Supabase's auth.uid().
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;
grant execute on function auth.uid() to anon, authenticated;
