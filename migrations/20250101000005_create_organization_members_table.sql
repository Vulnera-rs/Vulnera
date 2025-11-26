-- Organization members table for tracking team membership
-- Note: Owner is tracked via organizations.owner_id, not in this table
-- This table tracks non-owner members only

CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Prevent duplicate memberships (one user per org)
CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_members_org_user 
    ON organization_members(organization_id, user_id);

-- Index for finding all organizations a user belongs to
CREATE INDEX IF NOT EXISTS idx_organization_members_user_id 
    ON organization_members(user_id);

-- Index for listing members of an organization
CREATE INDEX IF NOT EXISTS idx_organization_members_org_id 
    ON organization_members(organization_id);

COMMENT ON TABLE organization_members IS 'Tracks non-owner members of organizations. Owner is stored in organizations.owner_id';
COMMENT ON COLUMN organization_members.organization_id IS 'The organization this membership belongs to';
COMMENT ON COLUMN organization_members.user_id IS 'The user who is a member (not owner) of the organization';
COMMENT ON COLUMN organization_members.joined_at IS 'When the user joined/was invited to the organization';
