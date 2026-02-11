create extension if not exists "uuid-ossp";

create table if not exists users (
  id uuid primary key default uuid_generate_v4(),
  email text unique not null,
  username text unique not null,
  password_hash text not null,
  avatar_url text,
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists servers (
  id uuid primary key default uuid_generate_v4(),
  owner_id uuid not null references users(id) on delete cascade,
  name text not null,
  icon_url text,
  created_at timestamptz not null default now()
);

create table if not exists roles (
  id uuid primary key default uuid_generate_v4(),
  server_id uuid not null references servers(id) on delete cascade,
  name text not null,
  position int not null default 0,
  permissions jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists server_members (
  server_id uuid not null references servers(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  role_id uuid references roles(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (server_id, user_id)
);

create table if not exists channels (
  id uuid primary key default uuid_generate_v4(),
  server_id uuid not null references servers(id) on delete cascade,
  name text not null,
  type text not null check (type in ('text','voice')),
  created_at timestamptz not null default now()
);

create table if not exists messages (
  id uuid primary key default uuid_generate_v4(),
  channel_id uuid not null references channels(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  content text not null,
  created_at timestamptz not null default now()
);

create table if not exists friendships (
  requester_id uuid not null references users(id) on delete cascade,
  addressee_id uuid not null references users(id) on delete cascade,
  status text not null check (status in ('pending','accepted')),
  created_at timestamptz not null default now(),
  primary key (requester_id, addressee_id)
);

create index if not exists idx_messages_channel on messages(channel_id, created_at);