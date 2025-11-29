-- Create Semgrep rules table for taint analysis and complex patterns
CREATE TABLE IF NOT EXISTS sast_semgrep_rules (
    rule_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    languages TEXT[] NOT NULL DEFAULT '{}',
    severity VARCHAR(50) NOT NULL DEFAULT 'warning',
    mode VARCHAR(20) NOT NULL DEFAULT 'search',
    
    -- Search mode fields
    pattern TEXT,
    patterns JSONB,
    pattern_either JSONB,
    pattern_regex TEXT,
    
    -- Taint mode fields
    taint_sources JSONB,
    taint_sinks JSONB,
    taint_sanitizers JSONB,
    taint_propagators JSONB,
    
    -- Metadata
    cwe_ids TEXT[] NOT NULL DEFAULT '{}',
    owasp_categories TEXT[] NOT NULL DEFAULT '{}',
    tags TEXT[] NOT NULL DEFAULT '{}',
    fix TEXT,
    fix_regex JSONB,
    metadata JSONB NOT NULL DEFAULT '{}',
    
    -- Status
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_sast_semgrep_rules_languages ON sast_semgrep_rules USING GIN (languages);
CREATE INDEX IF NOT EXISTS idx_sast_semgrep_rules_tags ON sast_semgrep_rules USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_sast_semgrep_rules_mode ON sast_semgrep_rules(mode);
CREATE INDEX IF NOT EXISTS idx_sast_semgrep_rules_severity ON sast_semgrep_rules(severity);
CREATE INDEX IF NOT EXISTS idx_sast_semgrep_rules_enabled ON sast_semgrep_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_sast_semgrep_rules_updated_at ON sast_semgrep_rules(updated_at);

-- Apply updated_at trigger
CREATE TRIGGER sast_semgrep_rules_updated_at
    BEFORE UPDATE ON sast_semgrep_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- Add comments for documentation
COMMENT ON TABLE sast_semgrep_rules IS 'Semgrep YAML rules for taint analysis and complex pattern matching';
COMMENT ON COLUMN sast_semgrep_rules.mode IS 'Rule mode: search (pattern matching) or taint (dataflow analysis)';
COMMENT ON COLUMN sast_semgrep_rules.taint_sources IS 'JSON array of taint source patterns for taint mode';
COMMENT ON COLUMN sast_semgrep_rules.taint_sinks IS 'JSON array of taint sink patterns for taint mode';
COMMENT ON COLUMN sast_semgrep_rules.taint_sanitizers IS 'JSON array of sanitizer patterns for taint mode';
COMMENT ON COLUMN sast_semgrep_rules.taint_propagators IS 'JSON array of propagator specs for taint mode';
