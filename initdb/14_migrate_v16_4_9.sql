-- ArgusWatch v16.4.9 hotfix
-- Align DB schema with ORM expectations for reports/chat/stats
CREATE TABLE IF NOT EXISTS dark_web_mentions (
  id BIGSERIAL PRIMARY KEY,
  customer_id INTEGER REFERENCES customers(id),
  source VARCHAR(100) NOT NULL,
  mention_type VARCHAR(50),
  title VARCHAR(500),
  content_snippet TEXT,
  url TEXT,
  threat_actor VARCHAR(255),
  severity severitylevel DEFAULT 'HIGH',
  published_at TIMESTAMP,
  discovered_at TIMESTAMP DEFAULT NOW(),
  metadata JSONB DEFAULT '{}',
  triage_classification VARCHAR(50),
  triage_action VARCHAR(50),
  triage_narrative TEXT,
  triaged_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_darkweb_source ON dark_web_mentions(source);
CREATE INDEX IF NOT EXISTS ix_darkweb_discovered ON dark_web_mentions(discovered_at);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS detection_id BIGINT REFERENCES detections(id);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS match_strategy VARCHAR(50);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_match_confidence FLOAT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_match_reasoning TEXT;
