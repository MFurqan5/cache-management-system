-- Enable UUID support
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =========================================================
-- USERS TABLE
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================
-- SCAN REQUESTS TABLE
-- =========================================================

CREATE TABLE IF NOT EXISTS scan_requests (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,

    input_type TEXT NOT NULL,
    input_value TEXT NOT NULL,

    input_hash TEXT UNIQUE NOT NULL,

    status TEXT DEFAULT 'pending',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================
-- AI PREDICTIONS TABLE
-- =========================================================

CREATE TABLE IF NOT EXISTS ai_predictions (
    id UUID PRIMARY KEY,

    request_id UUID UNIQUE REFERENCES scan_requests(id)
    ON DELETE CASCADE,

    prediction_label TEXT NOT NULL,
    threat_type TEXT NOT NULL,

    confidence_score FLOAT NOT NULL,

    explanation TEXT,

    indicators JSONB,

    model_version TEXT,

    inference_ms INTEGER,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================
-- THREAT LOGS TABLE
-- =========================================================

CREATE TABLE IF NOT EXISTS threat_logs (
    id SERIAL PRIMARY KEY,

    prediction_id UUID REFERENCES ai_predictions(id)
    ON DELETE CASCADE,

    severity TEXT NOT NULL,

    action_taken TEXT,

    notes TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);