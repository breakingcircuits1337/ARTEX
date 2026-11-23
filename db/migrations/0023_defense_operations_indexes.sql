-- PR #13: bounded read-only operational observability indexes.
-- No live-event triggers, stored tokens, mutable metrics counters or new
-- enforcement policy. Existing audit/retention semantics stay unchanged.
CREATE INDEX IF NOT EXISTS idx_defense_ops_investigation_failed_recent
 ON defense_investigation_runs(completed_at DESC,id DESC)
 WHERE status='failed' AND completed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_defense_ops_emergency_failed_recent
 ON defense_emergency_actions(created_at DESC,id DESC)
 WHERE status='failed';
CREATE INDEX IF NOT EXISTS idx_defense_ops_collector_active
 ON defense_collectors(id DESC)
 WHERE revoked_at IS NULL;
