-- Unified Telegram intelligence evidence and operational state.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Consolidate the pre-v16.4.9 dark-web table into the ORM-canonical table.
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
DO $$
BEGIN
    IF to_regclass('public.darkweb_mentions') IS NOT NULL THEN
        INSERT INTO dark_web_mentions (
            id, customer_id, source, mention_type, title, content_snippet, url,
            threat_actor, severity, published_at, discovered_at, metadata,
            triage_classification, triage_action, triage_narrative, triaged_at
        )
        SELECT
            id, customer_id, source, mention_type, title, content_snippet, url,
            threat_actor, severity, published_at, discovered_at, metadata,
            triage_classification, triage_action, triage_narrative, triaged_at
        FROM darkweb_mentions
        ON CONFLICT (id) DO NOTHING;
        PERFORM setval(
            pg_get_serial_sequence('dark_web_mentions', 'id'),
            GREATEST(COALESCE((SELECT MAX(id) FROM dark_web_mentions), 1), 1),
            EXISTS (SELECT 1 FROM dark_web_mentions)
        );
        DROP TABLE darkweb_mentions CASCADE;
    END IF;
END
$$;
CREATE INDEX IF NOT EXISTS ix_darkweb_source ON dark_web_mentions(source);
CREATE INDEX IF NOT EXISTS ix_darkweb_discovered ON dark_web_mentions(discovered_at);
ALTER TABLE dark_web_mentions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS darkweb_customer_isolation ON dark_web_mentions;
CREATE POLICY darkweb_customer_isolation ON dark_web_mentions
    FOR ALL TO arguswatch_api
    USING (
        current_customer_id() IS NULL
        OR customer_id IS NULL
        OR customer_id = current_customer_id()
    );

CREATE TABLE IF NOT EXISTS telegram_messages (
    id BIGSERIAL PRIMARY KEY,
    channel_id VARCHAR(255) NOT NULL,
    channel_name VARCHAR(500),
    message_id BIGINT NOT NULL,
    sender_id VARCHAR(255),
    sender_username VARCHAR(255),
    posted_at TIMESTAMP NOT NULL,
    ingested_at TIMESTAMP NOT NULL DEFAULT NOW(),
    text TEXT NOT NULL DEFAULT '',
    has_media BOOLEAN NOT NULL DEFAULT FALSE,
    media_name VARCHAR(500),
    media_size BIGINT,
    classification VARCHAR(50) NOT NULL DEFAULT 'general',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    flagged BOOLEAN NOT NULL DEFAULT FALSE,
    iocs JSONB NOT NULL DEFAULT '[]',
    external_channels JSONB NOT NULL DEFAULT '[]',
    risk_reasons JSONB NOT NULL DEFAULT '[]',
    source VARCHAR(100) NOT NULL DEFAULT 'telegram',
    metadata JSONB NOT NULL DEFAULT '{}',
    CONSTRAINT uq_telegram_channel_message UNIQUE (channel_id, message_id)
);

CREATE INDEX IF NOT EXISTS ix_telegram_posted ON telegram_messages(posted_at DESC);
CREATE INDEX IF NOT EXISTS ix_telegram_flagged ON telegram_messages(flagged, risk_score DESC);
CREATE INDEX IF NOT EXISTS ix_telegram_channel ON telegram_messages(channel_id);
CREATE INDEX IF NOT EXISTS ix_telegram_classification ON telegram_messages(classification);
CREATE INDEX IF NOT EXISTS ix_telegram_text_search ON telegram_messages USING GIN (to_tsvector('simple', text));
CREATE INDEX IF NOT EXISTS ix_telegram_text_trgm ON telegram_messages USING GIN (text gin_trgm_ops);

CREATE TABLE IF NOT EXISTS telegram_channels (
    id BIGSERIAL PRIMARY KEY,
    slug VARCHAR(255) UNIQUE NOT NULL,
    title VARCHAR(500),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    authorized BOOLEAN NOT NULL DEFAULT FALSE,
    joined BOOLEAN NOT NULL DEFAULT FALSE,
    discovery_source VARCHAR(100),
    discovered_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP,
    last_error TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_telegram_channel_enabled ON telegram_channels(enabled, authorized);

CREATE TABLE IF NOT EXISTS telegram_import_runs (
    id BIGSERIAL PRIMARY KEY,
    filename VARCHAR(500) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'running',
    parsed_count INTEGER NOT NULL DEFAULT 0,
    imported_count INTEGER NOT NULL DEFAULT 0,
    flagged_count INTEGER NOT NULL DEFAULT 0,
    error_detail TEXT,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP
);
