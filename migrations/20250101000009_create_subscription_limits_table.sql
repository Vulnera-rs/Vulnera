-- Subscription limits table for v2 billing support
-- Schema ready for future billing implementation (no enforcement in v1)

CREATE TABLE IF NOT EXISTS subscription_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Subscription tier
    tier VARCHAR(50) NOT NULL DEFAULT 'free',  -- free, starter, professional, enterprise
    
    -- Usage limits 
    max_scans_monthly INTEGER NOT NULL DEFAULT 5,
    max_api_calls_monthly INTEGER NOT NULL DEFAULT 1000,
    max_members INTEGER NOT NULL DEFAULT 1,
    max_repos INTEGER NOT NULL DEFAULT 3,
    max_private_repos INTEGER NOT NULL DEFAULT 0,
    
    -- Retention limits (days)
    scan_results_retention_days INTEGER NOT NULL DEFAULT 30,
    
    -- Feature flags (extensible JSONB for tier-specific features)
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
    
    -- Overage settings (v2)
    overage_enabled BOOLEAN NOT NULL DEFAULT false,
    overage_rate_per_scan DECIMAL(10, 4) DEFAULT 0.10,
    overage_rate_per_api_call DECIMAL(10, 6) DEFAULT 0.01,
    
    -- Billing metadata (v2)
    stripe_subscription_id VARCHAR(255),
    billing_email VARCHAR(255),
    billing_cycle_start DATE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for tier-based queries (admin reporting)
CREATE INDEX IF NOT EXISTS idx_subscription_limits_tier 
    ON subscription_limits(tier);

-- Apply updated_at trigger
DROP TRIGGER IF EXISTS update_subscription_limits_updated_at ON subscription_limits;
CREATE TRIGGER update_subscription_limits_updated_at
    BEFORE UPDATE ON subscription_limits
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default limits when organization is created (via trigger)
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

COMMENT ON TABLE subscription_limits IS 'Subscription tier and usage limits per organization. v1: schema ready, no enforcement. v2: billing integration.';
COMMENT ON COLUMN subscription_limits.tier IS 'Pricing tier: free, starter, professional, enterprise';
COMMENT ON COLUMN subscription_limits.features IS 'JSONB feature flags for tier-specific capabilities';
COMMENT ON COLUMN subscription_limits.overage_enabled IS 'v2: Whether to allow usage beyond limits at overage rates';
COMMENT ON COLUMN subscription_limits.stripe_subscription_id IS 'v2: Stripe subscription ID for billing integration';
