-- Create SAST rules table for tree-sitter pattern rules
CREATE TABLE IF NOT EXISTS sast_rules (
    rule_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    languages TEXT[] NOT NULL DEFAULT '{}',
    pattern_type VARCHAR(50) NOT NULL DEFAULT 'tree_sitter_query',
    query TEXT NOT NULL,
    cwe_ids TEXT[] NOT NULL DEFAULT '{}',
    owasp_categories TEXT[] NOT NULL DEFAULT '{}',
    tags TEXT[] NOT NULL DEFAULT '{}',
    options JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_sast_rules_languages ON sast_rules USING GIN (languages);
CREATE INDEX IF NOT EXISTS idx_sast_rules_tags ON sast_rules USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_sast_rules_severity ON sast_rules(severity);
CREATE INDEX IF NOT EXISTS idx_sast_rules_enabled ON sast_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_sast_rules_updated_at ON sast_rules(updated_at);

-- Apply updated_at trigger
CREATE TRIGGER sast_rules_updated_at
    BEFORE UPDATE ON sast_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE sast_rules IS 'Tree-sitter pattern-based SAST rules';
COMMENT ON COLUMN sast_rules.rule_id IS 'Unique rule identifier (e.g., PY-SQLI-001)';
COMMENT ON COLUMN sast_rules.pattern_type IS 'Pattern type: tree_sitter_query, ast_node_type, function_call, method_call, regex';
COMMENT ON COLUMN sast_rules.query IS 'Tree-sitter S-expression query or pattern string';
COMMENT ON COLUMN sast_rules.cwe_ids IS 'CWE identifiers (e.g., CWE-89)';
COMMENT ON COLUMN sast_rules.owasp_categories IS 'OWASP categories (e.g., A03:2021 - Injection)';
