-- SOC2 Readiness Suite — Supabase schema
-- Run this once in your Supabase SQL editor before first use.

-- ── Assessment snapshots ─────────────────────────────────────────────────────
create table if not exists soc2_snapshots (
    id               uuid primary key default gen_random_uuid(),
    org_name         text not null,
    run_date         timestamptz not null default now(),
    audit_type       text not null,                 -- 'Type I' | 'Type II'
    tsc_scope        text[] not null,               -- e.g. ['CC','A','PI','C','P']
    overall_score    numeric(5,2),                  -- 0-100 readiness %
    scores_by_category jsonb,                       -- {"CC": 72.5, "A": 100, ...}
    findings         jsonb                          -- full control-level findings
);

create index if not exists idx_snapshots_org_date
    on soc2_snapshots (org_name, run_date desc);


-- ── Accepted-risk / manual overrides ────────────────────────────────────────
create table if not exists soc2_controls_override (
    id              uuid primary key default gen_random_uuid(),
    org_name        text not null,
    control_id      text not null,                  -- e.g. 'CC6.1'
    status_override text not null,                  -- 'compliant' | 'accepted_risk' | 'not_applicable'
    justification   text not null,
    overridden_by   text not null default 'user',
    overridden_at   timestamptz not null default now(),

    unique (org_name, control_id)
);

create index if not exists idx_overrides_org
    on soc2_controls_override (org_name);


-- ── Row Level Security (enable after confirming app works) ───────────────────
-- alter table soc2_snapshots         enable row level security;
-- alter table soc2_controls_override enable row level security;

-- Example policy (adjust to your auth model):
-- create policy "org users can read own data"
--     on soc2_snapshots for select
--     using (org_name = current_setting('app.org_name', true));
