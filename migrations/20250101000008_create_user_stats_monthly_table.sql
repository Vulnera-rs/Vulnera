-- User stats monthly table for pre-aggregated analytics
-- This is a denormalized cache of analysis_events for fast dashboard queries
-- Updated on job completion (dual-write pattern)

CREATE TABLE IF NOT EXISTS user_stats_monthly (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
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

-- Unique constraint: one row per org per month
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_stats_monthly_org_month 
    ON user_stats_monthly(organization_id, year_month);

-- Index for org-level stats lookup
CREATE INDEX IF NOT EXISTS idx_user_stats_monthly_org_id 
    ON user_stats_monthly(organization_id);

-- Index for time-based queries across all orgs (admin dashboard)
CREATE INDEX IF NOT EXISTS idx_user_stats_monthly_year_month 
    ON user_stats_monthly(year_month DESC);

-- Apply updated_at trigger
DROP TRIGGER IF EXISTS update_user_stats_monthly_updated_at ON user_stats_monthly;
CREATE TRIGGER update_user_stats_monthly_updated_at
    BEFORE UPDATE ON user_stats_monthly
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE user_stats_monthly IS 'Pre-aggregated monthly statistics per organization for fast dashboard queries. Dual-written on job completion.';
COMMENT ON COLUMN user_stats_monthly.year_month IS 'Year-month key in YYYY-MM format for partitioning';
COMMENT ON COLUMN user_stats_monthly.findings_count IS 'Total findings discovered across all jobs in this month';
COMMENT ON COLUMN user_stats_monthly.api_calls_used IS 'Total API calls made by org members in this month';
COMMENT ON COLUMN user_stats_monthly.scans_completed IS 'Number of successfully completed analysis jobs';
