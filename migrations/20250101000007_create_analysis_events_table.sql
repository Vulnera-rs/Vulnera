-- Analysis events table for time-series event tracking
-- Used for computing monthly aggregates and audit trail

CREATE TABLE IF NOT EXISTS analysis_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    job_id UUID REFERENCES persisted_job_results(job_id) ON DELETE SET NULL,
    
    -- Event classification
    event_type VARCHAR(50) NOT NULL,  -- JobStarted, JobCompleted, FindingsRecorded, ApiCallMade, ReportGenerated
    
    -- Flexible metadata for different event types
    metadata JSONB NOT NULL DEFAULT '{}',
    
    -- Timestamp for time-series queries
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Primary index for monthly aggregates: all events for an org in a time range
CREATE INDEX IF NOT EXISTS idx_analysis_events_org_timestamp 
    ON analysis_events(organization_id, timestamp DESC);

-- Index for job event history
CREATE INDEX IF NOT EXISTS idx_analysis_events_job_id 
    ON analysis_events(job_id);

-- Index for user activity tracking
CREATE INDEX IF NOT EXISTS idx_analysis_events_user_id 
    ON analysis_events(user_id);

-- Index for filtering by event type
CREATE INDEX IF NOT EXISTS idx_analysis_events_type 
    ON analysis_events(event_type);

-- Composite index for monthly aggregation queries
-- Enables efficient: SELECT ... WHERE org_id = ? AND timestamp >= ? AND timestamp < ?
CREATE INDEX IF NOT EXISTS idx_analysis_events_org_type_timestamp 
    ON analysis_events(organization_id, event_type, timestamp DESC);

-- Partial index for completed jobs only (common query)
CREATE INDEX IF NOT EXISTS idx_analysis_events_completed 
    ON analysis_events(organization_id, timestamp DESC) 
    WHERE event_type = 'JobCompleted';

COMMENT ON TABLE analysis_events IS 'Time-series event log for analytics aggregation and audit trail. Events older than 24 months may be archived.';
COMMENT ON COLUMN analysis_events.event_type IS 'Type of event: JobStarted, JobCompleted, FindingsRecorded, ApiCallMade, ReportGenerated';
COMMENT ON COLUMN analysis_events.metadata IS 'Event-specific data: findings_count, severity_breakdown, api_endpoint, etc.';
