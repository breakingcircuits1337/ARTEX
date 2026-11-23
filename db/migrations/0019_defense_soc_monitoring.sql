-- Phase 8: bounded, indexed read-side SOC monitoring.
-- No triggers or write-contention added to the machine-speed event path.
-- Previous migrations (0001-0018) are immutable.
CREATE INDEX IF NOT EXISTS idx_defense_events_ingest_recent
  ON defense_events(ingested_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS idx_defense_cases_updated_recent
  ON defense_cases(updated_at DESC,id DESC);
