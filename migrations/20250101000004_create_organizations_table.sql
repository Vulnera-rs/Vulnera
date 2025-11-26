-- Organizations table for multi-tenant team support
-- Each organization has exactly one owner and can have multiple members

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for finding organizations by owner
CREATE INDEX IF NOT EXISTS idx_organizations_owner_id ON organizations(owner_id);

-- Prevent duplicate organization names per owner
CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_owner_name ON organizations(owner_id, name);

-- Index for listing all organizations (admin view)
CREATE INDEX IF NOT EXISTS idx_organizations_created_at ON organizations(created_at DESC);

-- Apply updated_at trigger (reuses function from migration 000003)
DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE organizations IS 'Team organizations for grouping users and tracking usage/analytics';
COMMENT ON COLUMN organizations.owner_id IS 'User who created and owns the organization (has full control)';
COMMENT ON COLUMN organizations.name IS 'Display name of the organization';
COMMENT ON COLUMN organizations.description IS 'Optional description of the organization purpose';
