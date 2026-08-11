-- Idempotent alignment for columns added to existing runtime tables.
-- Missing ORM tables are created by Base.metadata.create_all before this file runs.

ALTER TABLE campaigns
    ADD COLUMN IF NOT EXISTS narrative TEXT;

ALTER TABLE fp_patterns
    ADD COLUMN IF NOT EXISTS pattern_hash VARCHAR(128);

ALTER TABLE fp_patterns
    ADD COLUMN IF NOT EXISTS auto_close_count INTEGER DEFAULT 0;
