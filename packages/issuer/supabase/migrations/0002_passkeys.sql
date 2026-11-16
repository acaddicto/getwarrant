-- Passkeys (WebAuthn credentials) registered by principals, and the one-shot challenges used to register them.
create table warrant.passkeys (
  credential_id   text primary key,          -- base64url credential id
  principal_root  text not null,
  principal_sub   text not null,
  kid             text not null unique,      -- p256:<base64url compressed P-256 point>; what mandates carry as principal.key
  public_key      text not null,             -- same point, kept for joins
  rp_id           text not null,
  label           text,
  created_at      timestamptz not null default now(),
  last_used_at    timestamptz
);
create index passkeys_principal on warrant.passkeys (principal_root, principal_sub);

create table warrant.challenges (
  challenge       text primary key,          -- base64url 32 random bytes
  purpose         text not null check (purpose in ('register')),
  principal_root  text not null,
  principal_sub   text not null,
  expires_at      timestamptz not null default now() + interval '5 minutes',
  created_at      timestamptz not null default now()
);

alter table warrant.passkeys   enable row level security;
alter table warrant.challenges enable row level security;
grant all on warrant.passkeys, warrant.challenges to service_role;
