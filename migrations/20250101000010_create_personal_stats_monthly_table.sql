-- Personal stats monthly table for user-level analytics
-- Tracks statistics for individual users (without organization context)
-- Separate from org stats - user personal history is preserved even when joining orgs

CREATE TABLE IF NOT EXISTS personal_stats_monthly (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Year-month partition key (format: YYYY-MM)
    year_month VARCHAR(7) NOT NULL,
    
    -- Findings aggregates
    findings_count INTEGER NOT NULL DEFAULT 0,
    findings_critical INTEGER NOT NULL DEFAULT 0,
    findings_high INTEGER NOT NULL DEFAULT 0,
    findings_medium INTEGER NOT NULL DEFAULT 0,
    findings_low INTEGER NOT NULL DEFAULT 0,
    findings_info INTEGER NOT NULL DEFAULT 0,
    
    -- Usage metrics
    reports_generated INTEGER NOT NULL DEFAULT 0,
    api_calls_used INTEGER NOT NULL DEFAULT 0,
    scans_completed INTEGER NOT NULL DEFAULT 0,
    scans_failed INTEGER NOT NULL DEFAULT 0,
    
    -- Module-specific breakdown
    sast_findings INTEGER NOT NULL DEFAULT 0,
    secrets_findings INTEGER NOT NULL DEFAULT 0,
    dependency_findings INTEGER NOT NULL DEFAULT 0,
    api_findings INTEGER NOT NULL DEFAULT 0,
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Unique constraint: one row per user per month
CREATE UNIQUE INDEX IF NOT EXISTS idx_personal_stats_monthly_user_month 
    ON personal_stats_monthly(user_id, year_month);

-- Index for user-level stats lookup
CREATE INDEX IF NOT EXISTS idx_personal_stats_monthly_user_id 
    ON personal_stats_monthly(user_id);

-- Index for time-based queries across all users (admin dashboard)
CREATE INDEX IF NOT EXISTS idx_personal_stats_monthly_year_month 
    ON personal_stats_monthly(year_month DESC);

-- Apply updated_at trigger
DROP TRIGGER IF EXISTS update_personal_stats_monthly_updated_at ON personal_stats_monthly;
CREATE TRIGGER update_personal_stats_monthly_updated_at
    BEFORE UPDATE ON personal_stats_monthly
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE personal_stats_monthly IS 'Pre-aggregated monthly statistics per user for personal dashboard. Kept separate from org stats - personal history preserved when joining organizations.';
COMMENT ON COLUMN personal_stats_monthly.year_month IS 'Year-month key in YYYY-MM format for partitioning';
COMMENT ON COLUMN personal_stats_monthly.findings_count IS 'Total findings discovered in personal scans this month';
COMMENT ON COLUMN personal_stats_monthly.api_calls_used IS 'Total API calls made by user (personal context) in this month';
COMMENT ON COLUMN personal_stats_monthly.scans_completed IS 'Number of successfully completed personal analysis jobs';
