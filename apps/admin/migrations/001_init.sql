-- SENTRIX control plane schema. Idempotency is handled by scripts/migrate.mjs (schema_migrations).
-- Privacy: no file contents are stored. Scan/quarantine tables hold hashes + verdict metadata only.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE platform_role AS ENUM ('super_admin','security_admin','support','auditor');
CREATE TYPE org_role      AS ENUM ('org_admin','member');
CREATE TYPE verdict       AS ENUM ('CLEAN','SUSPICIOUS','MALICIOUS','UNABLE_TO_VERIFY','PENDING');
CREATE TYPE release_status AS ENUM ('draft','staged','published','cancelled','rolled_back');
CREATE TYPE license_status AS ENUM ('active','suspended','revoked','expired');
CREATE TYPE device_status  AS ENUM ('enrolled','revoked');

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         citext NOT NULL UNIQUE,
  name          text   NOT NULL,
  password_hash text   NOT NULL,                -- argon2id
  platform_role platform_role,                  -- NULL for ordinary customers
  is_active     boolean NOT NULL DEFAULT true,
  mfa_enabled   boolean NOT NULL DEFAULT false,
  mfa_secret    text,                           -- AES-256-GCM envelope (see lib/crypto.ts)
  mfa_recovery  text[] NOT NULL DEFAULT '{}',   -- sha256 hashes of one-time recovery codes
  failed_logins int  NOT NULL DEFAULT 0,
  locked_until  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role    org_role NOT NULL DEFAULT 'member',
  PRIMARY KEY (user_id, org_id)
);

CREATE TABLE sessions (
  id           text PRIMARY KEY,               -- sha256(token); raw token only lives in the cookie
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  mfa_verified boolean NOT NULL DEFAULT false,
  reauth_at    timestamptz,                    -- last password re-entry, gates sensitive actions
  csrf_token   text NOT NULL,
  ip           inet,
  user_agent   text
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE devices (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  hostname         text NOT NULL,
  os               text NOT NULL,
  os_version       text,
  app_version      text,
  engine_version   text,
  intel_version    text,
  intel_updated_at timestamptz,
  protection       jsonb NOT NULL DEFAULT '{}'::jsonb,  -- reported state: realtime, engine health
  status           device_status NOT NULL DEFAULT 'enrolled',
  token_hash       text NOT NULL,              -- HMAC(device token); the token is shown once
  last_seen_at     timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_org_idx ON devices(org_id);

CREATE TABLE device_enrollments (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code_hash  text NOT NULL UNIQUE,
  created_by uuid REFERENCES users(id),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  device_id  uuid REFERENCES devices(id)
);

CREATE TABLE licenses (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  key_hash   text NOT NULL UNIQUE,
  key_hint   text NOT NULL,                    -- last 4 chars, for support lookups
  plan       text NOT NULL DEFAULT 'standard',
  seats      int  NOT NULL DEFAULT 1 CHECK (seats > 0),
  status     license_status NOT NULL DEFAULT 'active',
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE license_activations (
  license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  activated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (license_id, device_id)
);

CREATE TABLE releases (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version       text NOT NULL,
  platform      text NOT NULL CHECK (platform IN ('windows-x64','macos-arm64','macos-x64','linux-x64')),
  channel       text NOT NULL DEFAULT 'stable',
  status        release_status NOT NULL DEFAULT 'draft',
  rollout_pct   int  NOT NULL DEFAULT 0 CHECK (rollout_pct BETWEEN 0 AND 100),
  notes         text NOT NULL DEFAULT '',
  artifact_url  text,
  sha256        text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  signature     text,                          -- minisign/Tauri updater signature
  code_signed   boolean NOT NULL DEFAULT false, -- Authenticode/notarization status, shown honestly
  size_bytes    bigint,
  min_supported text,
  published_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (version, platform, channel)
);

CREATE TABLE intel_versions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  engine       text NOT NULL,                  -- e.g. clamav
  version      text NOT NULL,
  published_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (engine, version)
);

CREATE TABLE scan_sessions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  started_at  timestamptz NOT NULL,
  finished_at timestamptz,
  kind        text NOT NULL CHECK (kind IN ('file','folder','full','realtime')),
  files_total int NOT NULL DEFAULT 0,
  files_failed int NOT NULL DEFAULT 0,
  complete    boolean NOT NULL DEFAULT false
);
CREATE INDEX scan_sessions_device_idx ON scan_sessions(device_id, started_at DESC);

CREATE TABLE scan_findings (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id  uuid NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
  device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  sha256      text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  file_name   text,                            -- only sent when the device policy allows it
  verdict     verdict NOT NULL,
  source      text NOT NULL,                   -- detecting engine / heuristic id
  engine_version text,
  detail      text,
  found_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_findings_device_idx ON scan_findings(device_id, found_at DESC);

CREATE TABLE security_events (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  kind       text NOT NULL,                    -- engine_stopped, intel_outdated, quarantined, ...
  severity   text NOT NULL CHECK (severity IN ('info','warning','critical')),
  detail     text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX security_events_device_idx ON security_events(device_id, created_at DESC);

CREATE TABLE quarantine_records (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  sha256      text NOT NULL,
  verdict     verdict NOT NULL,
  reason      text,
  state       text NOT NULL CHECK (state IN ('quarantined','restored','deleted')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_policies (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name       text NOT NULL,
  version    int  NOT NULL DEFAULT 1,
  config     jsonb NOT NULL,                   -- validated against contracts/policy schema
  is_default boolean NOT NULL DEFAULT false,
  updated_by uuid REFERENCES users(id),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE update_jobs (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  kind       text NOT NULL CHECK (kind IN ('scan_quick','intel_update','app_update')),  -- closed set: no arbitrary commands
  state      text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivered','succeeded','failed','cancelled')),
  requested_by uuid REFERENCES users(id),
  result     text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only, hash-chained audit log (tamper-evident). UPDATE/DELETE are blocked by trigger.
CREATE TABLE audit_events (
  seq        bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  actor_id   uuid,
  actor_email text,
  org_id     uuid,
  action     text NOT NULL,
  target     text,
  detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip         inet,
  prev_hash  text NOT NULL,
  hash       text NOT NULL
);
CREATE INDEX audit_events_org_idx ON audit_events(org_id, seq DESC);

CREATE FUNCTION audit_events_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_events is append-only'; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

CREATE TABLE rate_limits (
  bucket     text PRIMARY KEY,
  count      int  NOT NULL,
  window_end timestamptz NOT NULL
);
