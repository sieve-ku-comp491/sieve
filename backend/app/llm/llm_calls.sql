-- The LLM call log (requirement N3). PostgresCallStore.create_table() runs this file until the
-- findings store (T2.3) adds migrations. job_id will reference jobs once that table exists.
CREATE TABLE IF NOT EXISTS llm_calls (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id uuid,
    provider text NOT NULL,
    model text NOT NULL,
    model_version text,
    template_name text,
    template_version text,
    messages jsonb NOT NULL,
    response_text text,
    stop_reason text CHECK (stop_reason IN ('complete', 'max_tokens', 'refusal', 'other')),
    raw_stop_reason text,
    attempts jsonb NOT NULL DEFAULT '[]',
    input_tokens integer NOT NULL DEFAULT 0,
    output_tokens integer NOT NULL DEFAULT 0,
    cache_read_tokens integer NOT NULL DEFAULT 0,
    cache_write_tokens integer NOT NULL DEFAULT 0,
    cost_usd numeric(14, 8) NOT NULL DEFAULT 0,
    duration_ms integer NOT NULL DEFAULT 0,
    cached boolean NOT NULL DEFAULT false,
    cache_key text NOT NULL,
    temperature numeric(3, 2),
    effort text,
    max_tokens integer NOT NULL,
    request_id text,
    error text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS llm_calls_cache_lookup ON llm_calls (cache_key, created_at DESC)
    WHERE NOT cached AND error IS NULL AND stop_reason = 'complete';

CREATE INDEX IF NOT EXISTS llm_calls_job ON llm_calls (job_id);
