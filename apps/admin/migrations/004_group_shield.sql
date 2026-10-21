-- Group Shield: counts reported by devices. Numbers only: never group names, chat ids, member names or file names.
ALTER TABLE devices ADD COLUMN tg_groups jsonb NOT NULL DEFAULT '{}'::jsonb;
