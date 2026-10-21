-- Phase 2: operational health reported by devices. Counts and booleans only; no file names, chat ids or tokens.
ALTER TABLE devices ADD COLUMN queue jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE devices ADD COLUMN telegram jsonb NOT NULL DEFAULT '{}'::jsonb;
