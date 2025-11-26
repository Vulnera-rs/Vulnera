-- Persisted job results for long-term storage of analysis results
-- Complements the Dragonfly cache (hot storage) with PostgreSQL (permanent storage)

CREATE TABLE IF NOT EXISTS persisted_job_results (
    job_id UUID PRIMARY KEY,  -- Not auto-generated, comes from the job
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    project_id VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) NOT NULL,  -- git, file_upload, s3_bucket, directory
    source_uri TEXT NOT NULL,
    status VARCHAR(50) NOT NULL,  -- Pending, Running, Completed, Failed
    
    -- Findings data stored as JSONB for queryability
    findings_json JSONB NOT NULL DEFAULT '[]',
    module_results_json JSONB NOT NULL DEFAULT '[]',
    summary_json JSONB,
    findings_by_type_json JSONB,
    
    -- Metadata
    total_findings INTEGER NOT NULL DEFAULT 0,
    findings_critical INTEGER NOT NULL DEFAULT 0,
    findings_high INTEGER NOT NULL DEFAULT 0,
    findings_medium INTEGER NOT NULL DEFAULT 0,
    findings_low INTEGER NOT NULL DEFAULT 0,
    findings_info INTEGER NOT NULL DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Error tracking
    error_message TEXT
);

-- Index for org-based time-range queries (dashboard analytics)
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_org_created 
    ON persisted_job_results(organization_id, created_at DESC);

-- Index for user's job history
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_user_id 
    ON persisted_job_results(user_id);

-- Index for status-based queries
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_status 
    ON persisted_job_results(status);

-- Index for project lookups
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_project_id 
    ON persisted_job_results(project_id);

-- GIN index on findings_json for JSONB containment queries
-- Enables queries like: WHERE findings_json @> '[{"severity": "Critical"}]'
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_findings_gin 
    ON persisted_job_results USING GIN (findings_json);

-- Partial index for completed jobs (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_persisted_job_results_completed 
    ON persisted_job_results(organization_id, completed_at DESC) 
    WHERE status = 'Completed';

COMMENT ON TABLE persisted_job_results IS 'Long-term storage of analysis job results. Dragonfly holds hot cache (24h), this table holds permanent history.';
COMMENT ON COLUMN persisted_job_results.findings_json IS 'JSONB array of all findings from the job, queryable via GIN index';
COMMENT ON COLUMN persisted_job_results.module_results_json IS 'JSONB array of module execution results with metadata';
COMMENT ON COLUMN persisted_job_results.summary_json IS 'Aggregated summary statistics from the analysis';
