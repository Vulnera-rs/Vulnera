-- Drop the foreign key constraint on analysis_events.job_id
-- This allows recording events before the job is persisted to persisted_job_results
-- The job_id column remains for querying, just without DB-level enforcement

ALTER TABLE analysis_events 
    DROP CONSTRAINT IF EXISTS analysis_events_job_id_fkey;

-- Add a comment explaining why the FK was removed
COMMENT ON COLUMN analysis_events.job_id IS 'References persisted_job_results.job_id but without FK constraint to allow early event recording before job persistence';
