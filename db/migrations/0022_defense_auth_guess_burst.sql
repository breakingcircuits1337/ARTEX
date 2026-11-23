-- PR #12: scoped, indexed authentication-failure burst review.
-- Only normalized events already persisted by authorized ingestion are counted.
CREATE INDEX IF NOT EXISTS idx_defense_auth_guess_burst
ON defense_events(company_id,collector_id,src_ip,lower(username),observed_at DESC)
WHERE kind='authentication' AND outcome='failure'
  AND username<>'' AND src_ip<>'';
