-- Warrant issuer v0.1 schema. All tables are service-role only: RLS on, no policies.
create schema if not exists warrant;

-- Identity roots this issuer accepts. Public keys are raw Ed25519, base64url.
create table warrant.roots (
  id          text primary key,            -- "eudi-wallet", "aadhaar", "okta:acme.com"
  kid         text not null unique,        -- key id used in assertions
  public_key  text not null,
  kind        text not null,               -- government-wallet | government-id | kyc-vendor | enterprise-idp | device
  max_level   text not null check (max_level in ('low','substantial','high')),
  created_at  timestamptz not null default now()
);

-- Agent signing keys, registered by operators. Stand-in for DID resolution in v0.1.
create table warrant.agent_keys (
  kid         text primary key,            -- did:web:agents.tripwise.com#k1
  did         text not null,
  public_key  text not null,
  operator    text,
  created_at  timestamptz not null default now(),
  constraint kid_belongs_to_did check (position(did || '#' in kid) = 1)
);
create index agent_keys_did on warrant.agent_keys (did);

-- A mandate request: what an agent asks for, before the principal has seen it.
create table warrant.requests (
  id            text primary key,          -- req_<ulid>
  agent_did     text not null,
  draft         jsonb not null,            -- scope, limits, delegation, nbf, exp, purpose
  state         text not null default 'pending' check (state in ('pending','prepared','approved','declined','expired')),
  unsigned      jsonb,                     -- the mandate awaiting the principal's signature (state = prepared)
  mandate_id    text,
  principal_sub text,
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null default now() + interval '15 minutes',
  decided_at    timestamptz
);
create index requests_agent on warrant.requests (agent_did, created_at desc);

-- Issued mandates, hop 1 and sub-mandates alike. Spend and status live on the tree root.
create table warrant.mandates (
  id              text primary key,        -- wrt_<ulid>
  root_id         text not null,           -- = id for hop 1
  parent_id       text references warrant.mandates (id),
  hop             int  not null check (hop between 1 and 5),
  agent_did       text not null,
  principal_root  text not null,
  principal_sub   text not null,
  principal_org   text,
  status          text not null default 'active' check (status in ('active','revoked','suspended','expired')),
  spent           bigint not null default 0,       -- meaningful on the root row only
  ccy             text,
  total_limit     bigint,
  nbf             timestamptz not null,
  exp             timestamptz not null,
  mandate         jsonb not null,          -- the full signed object
  token           text not null,           -- wrt.<base64url>
  revoked_at      timestamptz,
  revoked_by      text,                    -- principal | issuer | agent:<did>
  revoke_reason   text,
  created_at      timestamptz not null default now()
);
create index mandates_root on warrant.mandates (root_id);
create index mandates_principal on warrant.mandates (principal_root, principal_sub, created_at desc);
create index mandates_agent on warrant.mandates (agent_did, created_at desc);
create index mandates_parent on warrant.mandates (parent_id);

-- Append-only, hash-chained per tree root. prev of the first record is null.
create table warrant.ledger (
  ref           text primary key,          -- led_<ulid>
  root_id       text not null references warrant.mandates (id),
  mandate_id    text not null references warrant.mandates (id),
  seq           bigint not null,
  prev          text,
  hash          text not null,             -- recordHash(record) after issuer countersign
  decision      text not null check (decision in ('allow','confirm','deny')),
  reason        text,
  amount        bigint,
  counterparty  text not null,
  record        jsonb not null,
  at            timestamptz not null,
  created_at    timestamptz not null default now(),
  unique (root_id, seq)
);
create index ledger_root_seq on warrant.ledger (root_id, seq desc);

-- Confirm requests awaiting the principal.
create table warrant.confirmations (
  ref           text primary key,          -- cfm_<ulid>
  root_id       text not null references warrant.mandates (id),
  mandate_id    text not null references warrant.mandates (id),
  ledger_ref    text not null references warrant.ledger (ref),
  action_type   text not null,
  amount        bigint,
  counterparty  text not null,
  action_hash   text not null,
  state         text not null default 'pending' check (state in ('pending','allow','deny','expired','cancelled')),
  reply_sig     text,
  replied_at    timestamptz,
  expires_at    timestamptz not null,
  created_at    timestamptz not null default now()
);
create index confirmations_root_state on warrant.confirmations (root_id, state);

-- Every revocation, for the signed revocation list.
create table warrant.revocations (
  mandate_id  text primary key references warrant.mandates (id),
  root_id     text not null,
  by          text not null,
  reason      text,
  cascade_of  text,                         -- the mandate whose revocation took this one down, if any
  at          timestamptz not null default now()
);
create index revocations_at on warrant.revocations (at desc);

alter table warrant.roots          enable row level security;
alter table warrant.agent_keys     enable row level security;
alter table warrant.requests       enable row level security;
alter table warrant.mandates       enable row level security;
alter table warrant.ledger         enable row level security;
alter table warrant.confirmations  enable row level security;
alter table warrant.revocations    enable row level security;

-- Atomic ledger append: assigns seq, checks prev, bumps spend on the root. Called by the edge function only.
create or replace function warrant.append_ledger(
  p_ref text, p_root_id text, p_mandate_id text, p_prev text, p_hash text,
  p_decision text, p_reason text, p_amount bigint, p_counterparty text, p_record jsonb, p_at timestamptz,
  p_bump_spend boolean
) returns bigint
language plpgsql security definer set search_path = warrant, pg_temp as $$
declare
  v_seq bigint;
  v_last_hash text;
begin
  perform 1 from warrant.mandates where id = p_root_id for update;
  select coalesce(max(seq), 0), (select hash from warrant.ledger where root_id = p_root_id order by seq desc limit 1)
    into v_seq, v_last_hash from warrant.ledger where root_id = p_root_id;
  if v_last_hash is distinct from p_prev then
    raise exception 'prev_mismatch: expected %, got %', v_last_hash, p_prev using errcode = 'P0001';
  end if;
  v_seq := v_seq + 1;
  insert into warrant.ledger (ref, root_id, mandate_id, seq, prev, hash, decision, reason, amount, counterparty, record, at)
  values (p_ref, p_root_id, p_mandate_id, v_seq, p_prev, p_hash, p_decision, p_reason, p_amount, p_counterparty, p_record, p_at);
  if p_bump_spend and p_amount is not null then
    update warrant.mandates set spent = spent + p_amount where id = p_root_id;
  end if;
  return v_seq;
end $$;

-- Cascade revoke: the mandate and every descendant.
create or replace function warrant.revoke_tree(p_mandate_id text, p_by text, p_reason text)
returns setof text
language plpgsql security definer set search_path = warrant, pg_temp as $$
begin
  return query
  with recursive tree as (
    select id, root_id from warrant.mandates where id = p_mandate_id
    union all
    select m.id, m.root_id from warrant.mandates m join tree t on m.parent_id = t.id
  ), upd as (
    update warrant.mandates m
       set status = 'revoked', revoked_at = now(), revoked_by = p_by, revoke_reason = p_reason
      from tree t where m.id = t.id and m.status = 'active'
    returning m.id, m.root_id
  ), rev as (
    insert into warrant.revocations (mandate_id, root_id, by, reason, cascade_of)
    select id, root_id, p_by, p_reason, case when id = p_mandate_id then null else p_mandate_id end from upd
    on conflict do nothing
    returning mandate_id
  ), cancel as (
    update warrant.confirmations c set state = 'cancelled'
      from tree t where c.mandate_id = t.id and c.state = 'pending'
  )
  select mandate_id from rev;
end $$;
