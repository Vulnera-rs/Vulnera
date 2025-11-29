-- 20250101000015_create_update_updated_at_alias.sql
-- Add backward-compatibility alias for update_updated_at trigger function
-- This migration adds `update_updated_at()` as an alias to the existing
-- `update_updated_at_column()` trigger function. It is idempotent and safe
-- to run on databases that already have either name.
--
-- Why: Some migrations or legacy triggers referenced `update_updated_at()`
-- while the original migration created `update_updated_at_column()`. This
-- alias provides backward compatibility without modifying old migrations.

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Keep the same behavior as the historical update_updated_at_column() function
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION update_updated_at() IS
    'Alias for update_updated_at_column() trigger function - updates updated_at timestamp';
