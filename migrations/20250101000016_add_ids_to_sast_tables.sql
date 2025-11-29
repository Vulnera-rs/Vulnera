-- 20250101000016_add_ids_to_sast_tables.sql
-- Add UUID `id` columns to SAST rule tables (compatibility migration)
-- - Adds an `id UUID` column to both `sast_rules` and `sast_semgrep_rules`
-- - Backfills all existing rows with `gen_random_uuid()` values
-- - Ensures the column is NOT NULL and creates a unique index
-- This migration is idempotent and safe to run multiple times


-- Add id column to sast_rules
ALTER TABLE IF EXISTS sast_rules
    ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();

-- Backfill id for existing rows (if any)
UPDATE sast_rules
SET id = gen_random_uuid()
WHERE id IS NULL;

-- Ensure NOT NULL (safe if update above backfilled)
ALTER TABLE IF EXISTS sast_rules
    ALTER COLUMN id SET NOT NULL;

-- Create unique index on id for faster lookups and uniqueness guarantee
CREATE UNIQUE INDEX IF NOT EXISTS idx_sast_rules_id ON sast_rules (id);

-- Add id column to sast_semgrep_rules
ALTER TABLE IF EXISTS sast_semgrep_rules
    ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();

-- Backfill id for existing rows (if any)
UPDATE sast_semgrep_rules
SET id = gen_random_uuid()
WHERE id IS NULL;

-- Ensure NOT NULL
ALTER TABLE IF EXISTS sast_semgrep_rules
    ALTER COLUMN id SET NOT NULL;

-- Create unique index on id
CREATE UNIQUE INDEX IF NOT EXISTS idx_sast_semgrep_rules_id ON sast_semgrep_rules (id);

-- Optional: Add comments for new columns to improve documentation
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'sast_rules' AND column_name = 'id') THEN
        COMMENT ON COLUMN sast_rules.id IS 'Internal UUID id for SAST rule row (compatibility), not the human rule_id';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'sast_semgrep_rules' AND column_name = 'id') THEN
        COMMENT ON COLUMN sast_semgrep_rules.id IS 'Internal UUID id for Semgrep SAST rule row (compatibility), not the human rule_id';
    END IF;
END;
$$;
