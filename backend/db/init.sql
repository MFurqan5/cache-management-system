-- ============================================================
-- init.sql  —  PostgreSQL Schema for AI Cybersecurity Detector
-- This file runs AUTOMATICALLY when Docker creates the DB.
-- You never need to run this by hand.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── TABLE 1: users ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) NOT NULL UNIQUE,
    username      VARCHAR(80)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(20)  DEFAULT 'user',
    created_at    TIMESTAMPTZ  DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

-- ── TABLE 2: scan_requests ──────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_requests (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id),
    input_type  VARCHAR(10)  NOT NULL,   -- 'url' or 'email'
    input_value TEXT         NOT NULL,
    input_hash  CHAR(64)     NOT NULL UNIQUE,  -- SHA-256 of input_value
    status      VARCHAR(20)  DEFAULT 'pending',
    created_at  TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_requests_user_id    ON scan_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_requests_created_at ON scan_requests(created_at DESC);

-- ── TABLE 3: ai_predictions ─────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_predictions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id       UUID UNIQUE REFERENCES scan_requests(id),
    prediction_label VARCHAR(20)  NOT NULL,   -- 'safe' or 'malicious'
    threat_type      VARCHAR(30)  NOT NULL,   -- 'phishing', 'spam', 'clean'
    confidence_score FLOAT        NOT NULL,
    explanation      TEXT,
    indicators       JSONB        DEFAULT '[]',
    model_version    VARCHAR(30)  NOT NULL,
    inference_ms     INTEGER,
    created_at       TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_predictions_threat_type  ON ai_predictions(threat_type);
CREATE INDEX IF NOT EXISTS idx_ai_predictions_label        ON ai_predictions(prediction_label);
CREATE INDEX IF NOT EXISTS idx_ai_predictions_created_at   ON ai_predictions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_predictions_indicators   ON ai_predictions USING GIN (indicators);

-- ── TABLE 4: threat_logs ────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prediction_id UUID REFERENCES ai_predictions(id),
    severity      VARCHAR(20) NOT NULL,   -- 'low', 'medium', 'high', 'critical'
    action_taken  VARCHAR(50) DEFAULT 'none',
    notes         TEXT,
    logged_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_logs_prediction_id ON threat_logs(prediction_id);
CREATE INDEX IF NOT EXISTS idx_threat_logs_severity      ON threat_logs(severity);
CREATE INDEX IF NOT EXISTS idx_threat_logs_logged_at     ON threat_logs(logged_at DESC);