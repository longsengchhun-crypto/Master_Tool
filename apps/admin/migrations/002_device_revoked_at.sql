-- Needed by the retention job: how long ago a device left management.
ALTER TABLE devices ADD COLUMN revoked_at timestamptz;
UPDATE devices SET revoked_at = now() WHERE status = 'revoked' AND revoked_at IS NULL;
CREATE INDEX devices_revoked_idx ON devices(revoked_at) WHERE revoked_at IS NOT NULL;
