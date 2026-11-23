-- SOC2 Readiness Suite — enable Row Level Security
-- Run once in the Supabase SQL editor, after db/migrations.sql.
--
-- Before running: set SUPABASE_KEY to the project's service-role key. That
-- key bypasses RLS and never leaves the server. With the anon key the app
-- can no longer read or write these tables once this has run.
--
-- With RLS on and no policy defined, the anon and authenticated roles can see
-- and change nothing through the project's public API, so knowing the project
-- URL and the anon key is no longer enough to read stored findings.

alter table if exists soc2_snapshots         enable row level security;
alter table if exists soc2_controls_override enable row level security;

-- Per-user access (for example one organisation per signed-in user) needs
-- Supabase Auth identities and policies written against them. Nothing in the
-- app uses those yet, so no policy is created here.
