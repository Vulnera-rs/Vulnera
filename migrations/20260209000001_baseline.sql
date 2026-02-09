-- Vulnera baseline schema (2026-02-09)

-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================================================
-- Core tables
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    roles JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id_active ON api_keys(user_id, revoked_at)
    WHERE revoked_at IS NULL;

-- =========================================================
-- Organizations & membership
-- =========================================================

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organizations_owner_id ON organizations(owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_owner_name ON organizations(owner_id, name);
CREATE INDEX IF NOT EXISTS idx_organizations_created_at ON organizations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_organizations_parent_id ON organizations(parent_id);

COMMENT ON TABLE organizations IS 'Team organizations for grouping users and tracking usage/analytics';
COMMENT ON COLUMN organizations.owner_id IS 'User who created and owns the organization (has full control)';
COMMENT ON COLUMN organizations.name IS 'Display name of the organization';
COMMENT ON COLUMN organizations.description IS 'Optional description of the organization purpose';
COMMENT ON COLUMN organizations.parent_id IS 'Parent organization for hierarchical inheritance. NULL for root organizations.';

CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_members_org_user
    ON organization_members(organization_id, user_id);
CREATE INDEX IF NOT EXISTS idx_organization_members_user_id
    ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_organization_members_org_id
    ON organization_members(organization_id);

COMMENT ON TABLE organization_members IS 'Tracks non-owner members of organizations. Owner is stored in organizations.owner_id';
COMMENT ON COLUMN organization_members.organization_id IS 'The organization this membership belongs to';
COMMENT ON COLUMN organization_members.user_id IS 'The user who is a member (not owner) of the organization';
COMMENT ON COLUMN organization_members.joined_at IS 'When the user joined/was invited to the organization';

-- =========================================================
-- Billing limits / entitlements
-- =========================================================

CREATE TABLE IF NOT EXISTS subscription_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,

    tier VARCHAR(50) NOT NULL DEFAULT 'free',

    max_scans_monthly INTEGER NOT NULL DEFAULT 5,
    max_api_calls_monthly INTEGER NOT NULL DEFAULT 1000,
    max_members INTEGER NOT NULL DEFAULT 1,
    max_repos INTEGER NOT NULL DEFAULT 3,
    max_private_repos INTEGER NOT NULL DEFAULT 0,

    scan_results_retention_days INTEGER NOT NULL DEFAULT 30,

    features JSONB NOT NULL DEFAULT '{
        "dependency_analysis": true,
        "sast": false,
        "secrets_detection": false,
        "api_security": false,
        "custom_rules": false,
        "priority_support": false,
        "sso": false,
        "compliance_reports": false
    }',

    overage_enabled BOOLEAN NOT NULL DEFAULT false,
    overage_rate_per_scan DECIMAL(10, 4) DEFAULT 0.10,
    overage_rate_per_api_call DECIMAL(10, 6) DEFAULT 0.01,

    stripe_subscription_id VARCHAR(255),
    billing_email VARCHAR(255),
    billing_cycle_start DATE,

    inherit_limits BOOLEAN NOT NULL DEFAULT false,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscription_limits_tier ON subscription_limits(tier);

COMMENT ON TABLE subscription_limits IS 'Subscription tier and usage limits per organization. v1: schema ready, no enforcement. v2: billing integration.';
COMMENT ON COLUMN subscription_limits.tier IS 'Pricing tier: free, starter, professional, enterprise';
COMMENT ON COLUMN subscription_limits.features IS 'JSONB feature flags for tier-specific capabilities';
COMMENT ON COLUMN subscription_limits.overage_enabled IS 'v2: Whether to allow usage beyond limits at overage rates';
COMMENT ON COLUMN subscription_limits.stripe_subscription_id IS 'v2: Stripe subscription ID for billing integration';
COMMENT ON COLUMN subscription_limits.inherit_limits IS 'When true, inherit limits from parent organization instead of using own limits.';

-- Insert default limits when organization is created
CREATE OR REPLACE FUNCTION create_default_subscription_limits()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO subscription_limits (organization_id, tier)
    VALUES (NEW.id, 'free')
    ON CONFLICT (organization_id) DO NOTHING;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS create_subscription_limits_on_org_create ON organizations;
CREATE TRIGGER create_subscription_limits_on_org_create
    AFTER INSERT ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION create_default_subscription_limits();

-- =========================================================
-- Analysis results & analytics
-- =========================================================

CREATE TABLE IF NOT EXISTS persisted_job_results (
    job_id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    project_id VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    source_uri TEXT NOT NULL,
    status VARCHAR(50) NOT NULL,

    findings_json JSONB NOT NULL DEFAULT '[]',
    module_results_json JSONB NOT NULL DEFAULT '[]',
    summary_json JSONB,
    findings_by_type_json JSONB,

    total_findings INTEGER NOT NULL DEFAULT 0,
    findings_critical INTEGER NOT NULL DEFAULT 0,
    findings_high INTEGER NOT NULL DEFAULT 0,
    findings_medium INTEGER NOT NULL DEFAULT 0,
    findings_low INTEGER NOT NULL DEFAULT 0,
    findings_info INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_persisted_job_results_org_created
    ON persisted_job_results(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_user_id
    ON persisted_job_results(user_id);
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_status
    ON persisted_job_results(status);
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_project_id
    ON persisted_job_results(project_id);
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_findings_gin
    ON persisted_job_results USING GIN (findings_json);
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_completed
    ON persisted_job_results(organization_id, completed_at DESC)
    WHERE status = 'Completed';

COMMENT ON TABLE persisted_job_results IS 'Long-term storage of analysis job results. Dragonfly holds hot cache (24h), this table holds permanent history.';
COMMENT ON COLUMN persisted_job_results.findings_json IS 'JSONB array of all findings from the job, queryable via GIN index';
COMMENT ON COLUMN persisted_job_results.module_results_json IS 'JSONB array of module execution results with metadata';
COMMENT ON COLUMN persisted_job_results.summary_json IS 'Aggregated summary statistics from the analysis';

CREATE TABLE IF NOT EXISTS analysis_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    job_id UUID,

    event_type VARCHAR(50) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analysis_events_org_timestamp
    ON analysis_events(organization_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_events_job_id
    ON analysis_events(job_id);
CREATE INDEX IF NOT EXISTS idx_analysis_events_user_id
    ON analysis_events(user_id);
CREATE INDEX IF NOT EXISTS idx_analysis_events_type
    ON analysis_events(event_type);
CREATE INDEX IF NOT EXISTS idx_analysis_events_org_type_timestamp
    ON analysis_events(organization_id, event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_events_completed
    ON analysis_events(organization_id, timestamp DESC)
    WHERE event_type = 'JobCompleted';

COMMENT ON TABLE analysis_events IS 'Time-series event log for analytics aggregation and audit trail. Events older than 24 months may be archived.';
COMMENT ON COLUMN analysis_events.event_type IS 'Type of event: JobStarted, JobCompleted, FindingsRecorded, ApiCallMade, ReportGenerated';
COMMENT ON COLUMN analysis_events.metadata IS 'Event-specific data: findings_count, severity_breakdown, api_endpoint, etc.';
COMMENT ON COLUMN analysis_events.job_id IS 'References persisted_job_results.job_id but without FK constraint to allow early event recording before job persistence';

CREATE TABLE IF NOT EXISTS user_stats_monthly (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    year_month VARCHAR(7) NOT NULL,

    findings_count INTEGER NOT NULL DEFAULT 0,
    findings_critical INTEGER NOT NULL DEFAULT 0,
    findings_high INTEGER NOT NULL DEFAULT 0,
    findings_medium INTEGER NOT NULL DEFAULT 0,
    findings_low INTEGER NOT NULL DEFAULT 0,
    findings_info INTEGER NOT NULL DEFAULT 0,

    reports_generated INTEGER NOT NULL DEFAULT 0,
    api_calls_used INTEGER NOT NULL DEFAULT 0,
    scans_completed INTEGER NOT NULL DEFAULT 0,
    scans_failed INTEGER NOT NULL DEFAULT 0,

    sast_findings INTEGER NOT NULL DEFAULT 0,
    secrets_findings INTEGER NOT NULL DEFAULT 0,
    dependency_findings INTEGER NOT NULL DEFAULT 0,
    api_findings INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_user_stats_monthly_year_month
        CHECK (year_month ~ '^[0-9]{4}-[0-9]{2}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_stats_monthly_org_month
    ON user_stats_monthly(organization_id, year_month);
CREATE INDEX IF NOT EXISTS idx_user_stats_monthly_org_id
    ON user_stats_monthly(organization_id);
CREATE INDEX IF NOT EXISTS idx_user_stats_monthly_year_month
    ON user_stats_monthly(year_month DESC);

COMMENT ON TABLE user_stats_monthly IS 'Pre-aggregated monthly statistics per organization for fast dashboard queries. Dual-written on job completion.';
COMMENT ON COLUMN user_stats_monthly.year_month IS 'Year-month key in YYYY-MM format for partitioning';
COMMENT ON COLUMN user_stats_monthly.findings_count IS 'Total findings discovered across all jobs in this month';
COMMENT ON COLUMN user_stats_monthly.api_calls_used IS 'Total API calls made by org members in this month';
COMMENT ON COLUMN user_stats_monthly.scans_completed IS 'Number of successfully completed analysis jobs';

CREATE TABLE IF NOT EXISTS personal_stats_monthly (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    year_month VARCHAR(7) NOT NULL,

    findings_count INTEGER NOT NULL DEFAULT 0,
    findings_critical INTEGER NOT NULL DEFAULT 0,
    findings_high INTEGER NOT NULL DEFAULT 0,
    findings_medium INTEGER NOT NULL DEFAULT 0,
    findings_low INTEGER NOT NULL DEFAULT 0,
    findings_info INTEGER NOT NULL DEFAULT 0,

    reports_generated INTEGER NOT NULL DEFAULT 0,
    api_calls_used INTEGER NOT NULL DEFAULT 0,
    scans_completed INTEGER NOT NULL DEFAULT 0,
    scans_failed INTEGER NOT NULL DEFAULT 0,

    sast_findings INTEGER NOT NULL DEFAULT 0,
    secrets_findings INTEGER NOT NULL DEFAULT 0,
    dependency_findings INTEGER NOT NULL DEFAULT 0,
    api_findings INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_personal_stats_monthly_year_month
        CHECK (year_month ~ '^[0-9]{4}-[0-9]{2}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_personal_stats_monthly_user_month
    ON personal_stats_monthly(user_id, year_month);
CREATE INDEX IF NOT EXISTS idx_personal_stats_monthly_user_id
    ON personal_stats_monthly(user_id);
CREATE INDEX IF NOT EXISTS idx_personal_stats_monthly_year_month
    ON personal_stats_monthly(year_month DESC);

COMMENT ON TABLE personal_stats_monthly IS 'Pre-aggregated monthly statistics per user for personal dashboard. Kept separate from org stats - personal history preserved when joining organizations.';
COMMENT ON COLUMN personal_stats_monthly.year_month IS 'Year-month key in YYYY-MM format for partitioning';
COMMENT ON COLUMN personal_stats_monthly.findings_count IS 'Total findings discovered in personal scans this month';
COMMENT ON COLUMN personal_stats_monthly.api_calls_used IS 'Total API calls made by user (personal context) in this month';
COMMENT ON COLUMN personal_stats_monthly.scans_completed IS 'Number of successfully completed personal analysis jobs';

-- =========================================================
-- Timestamp helpers (triggers)
-- =========================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION update_updated_at() IS
    'Alias for update_updated_at_column() trigger function - updates updated_at timestamp';

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_subscription_limits_updated_at ON subscription_limits;
CREATE TRIGGER update_subscription_limits_updated_at
    BEFORE UPDATE ON subscription_limits
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_user_stats_monthly_updated_at ON user_stats_monthly;
CREATE TRIGGER update_user_stats_monthly_updated_at
    BEFORE UPDATE ON user_stats_monthly
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_personal_stats_monthly_updated_at ON personal_stats_monthly;
CREATE TRIGGER update_personal_stats_monthly_updated_at
    BEFORE UPDATE ON personal_stats_monthly
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =========================================================
-- Derived views
-- =========================================================

CREATE OR REPLACE FUNCTION get_effective_subscription_limits(org_id UUID)
RETURNS subscription_limits AS $$
DECLARE
    current_org_id UUID := org_id;
    limits subscription_limits%ROWTYPE;
    parent_org_id UUID;
    max_depth INTEGER := 10;
    depth INTEGER := 0;
BEGIN
    LOOP
        SELECT * INTO limits FROM subscription_limits WHERE organization_id = current_org_id;

        IF NOT FOUND THEN
            RETURN NULL;
        END IF;

        IF NOT limits.inherit_limits OR depth >= max_depth THEN
            RETURN limits;
        END IF;

        SELECT o.parent_id INTO parent_org_id FROM organizations o WHERE o.id = current_org_id;

        IF parent_org_id IS NULL THEN
            RETURN limits;
        END IF;

        current_org_id := parent_org_id;
        depth := depth + 1;
    END LOOP;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE VIEW organizations_with_effective_limits AS
SELECT
    o.id,
    o.owner_id,
    o.name,
    o.description,
    o.parent_id,
    o.created_at,
    o.updated_at,
    COALESCE((get_effective_subscription_limits(o.id)).tier, 'free') AS effective_tier,
    COALESCE((get_effective_subscription_limits(o.id)).max_scans_monthly, 5) AS effective_max_scans_monthly,
    COALESCE((get_effective_subscription_limits(o.id)).max_api_calls_monthly, 1000) AS effective_max_api_calls_monthly
FROM organizations o;

COMMENT ON FUNCTION get_effective_subscription_limits IS 'Resolves effective subscription limits by walking up the organization hierarchy.';
