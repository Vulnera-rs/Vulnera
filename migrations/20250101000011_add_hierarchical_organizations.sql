-- Add hierarchical organization support
-- Organizations can have a parent organization for inheritance of settings

-- Add parent_id column to organizations table
ALTER TABLE organizations
ADD COLUMN parent_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

-- Index for finding child organizations
CREATE INDEX IF NOT EXISTS idx_organizations_parent_id ON organizations(parent_id);

-- Add inherit_limits flag to subscription_limits
-- When true, limits are inherited from parent org (if any)
ALTER TABLE subscription_limits
ADD COLUMN inherit_limits BOOLEAN NOT NULL DEFAULT false;

-- Function to get effective subscription limits (with inheritance)
-- Returns the subscription_limits row for an org, walking up the hierarchy if inherit_limits is true
CREATE OR REPLACE FUNCTION get_effective_subscription_limits(org_id UUID)
RETURNS subscription_limits AS $$
DECLARE
    current_org_id UUID := org_id;
    limits subscription_limits%ROWTYPE;
    parent_org_id UUID;
    max_depth INTEGER := 10; -- Prevent infinite loops
    depth INTEGER := 0;
BEGIN
    LOOP
        -- Get limits for current org
        SELECT * INTO limits FROM subscription_limits WHERE organization_id = current_org_id;
        
        -- If no limits found, return NULL
        IF NOT FOUND THEN
            RETURN NULL;
        END IF;
        
        -- If inherit_limits is false or we've reached max depth, return these limits
        IF NOT limits.inherit_limits OR depth >= max_depth THEN
            RETURN limits;
        END IF;
        
        -- Get parent organization
        SELECT o.parent_id INTO parent_org_id FROM organizations o WHERE o.id = current_org_id;
        
        -- If no parent, return current limits
        IF parent_org_id IS NULL THEN
            RETURN limits;
        END IF;
        
        -- Move to parent
        current_org_id := parent_org_id;
        depth := depth + 1;
    END LOOP;
END;
$$ LANGUAGE plpgsql STABLE;

-- View for organizations with their effective tier
CREATE OR REPLACE VIEW organizations_with_effective_limits AS
SELECT 
    o.id,
    o.owner_id,
    o.name,
    o.description,
    o.parent_id,
    o.created_at,
    o.updated_at,
    COALESCE(
        (get_effective_subscription_limits(o.id)).tier,
        'free'
    ) as effective_tier,
    COALESCE(
        (get_effective_subscription_limits(o.id)).max_scans_monthly,
        5
    ) as effective_max_scans_monthly,
    COALESCE(
        (get_effective_subscription_limits(o.id)).max_api_calls_monthly,
        1000
    ) as effective_max_api_calls_monthly
FROM organizations o;

COMMENT ON COLUMN organizations.parent_id IS 'Parent organization for hierarchical inheritance. NULL for root organizations.';
COMMENT ON COLUMN subscription_limits.inherit_limits IS 'When true, inherit limits from parent organization instead of using own limits.';
COMMENT ON FUNCTION get_effective_subscription_limits IS 'Resolves effective subscription limits by walking up the organization hierarchy.';
