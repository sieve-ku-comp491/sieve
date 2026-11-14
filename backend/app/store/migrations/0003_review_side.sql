-- The review side of the findings store (docs/database.md): triage runs, verdicts, edits,
-- reviews and reports, and the links from groups and verdicts to the LLM calls behind them.

CREATE TABLE triage_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id uuid NOT NULL REFERENCES scans,
    cheap_model text NOT NULL,
    strong_model text NOT NULL,
    budget_usd numeric(10, 4) NOT NULL CHECK (budget_usd > 0),
    cost_usd numeric(10, 4) NOT NULL DEFAULT 0 CHECK (cost_usd >= 0),
    status text NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'finished', 'stopped_at_budget')),
    grouped_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

CREATE INDEX triage_runs_scan_created ON triage_runs (scan_id, created_at);

ALTER TABLE llm_calls ADD COLUMN triage_run_id uuid REFERENCES triage_runs;

CREATE INDEX llm_calls_triage_run ON llm_calls (triage_run_id);

CREATE TABLE duplicate_group_llm_calls (
    group_id uuid NOT NULL REFERENCES duplicate_groups,
    llm_call_id uuid NOT NULL REFERENCES llm_calls,
    PRIMARY KEY (group_id, llm_call_id)
);

CREATE TABLE verdicts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    triage_run_id uuid NOT NULL REFERENCES triage_runs,
    finding_id uuid REFERENCES findings,
    group_id uuid REFERENCES duplicate_groups,
    verdict text NOT NULL CHECK (verdict IN ('true_positive', 'false_positive', 'unsure')),
    reasoning text NOT NULL,
    cited_lines jsonb NOT NULL
        CHECK (jsonb_typeof(cited_lines) = 'array' AND jsonb_array_length(cited_lines) >= 1),
    injection_suspected boolean NOT NULL,
    injection_lines jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(injection_lines) = 'array'),
    model_version text NOT NULL,
    cvss_v4_vector text NOT NULL CHECK (cvss_v4_vector LIKE 'CVSS:4.0/%'),
    cvss_v4_score numeric(3, 1) NOT NULL CHECK (cvss_v4_score BETWEEN 0 AND 10),
    cvss_v4_level text NOT NULL
        CHECK (cvss_v4_level IN ('none', 'low', 'medium', 'high', 'critical')),
    cvss_v4_justifications jsonb NOT NULL CHECK (
        jsonb_typeof(cvss_v4_justifications) = 'object'
        AND cvss_v4_justifications
            ?& ARRAY['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']
    ),
    cvss_v31_vector text CHECK (cvss_v31_vector LIKE 'CVSS:3.1/%'),
    cvss_v31_score numeric(3, 1) CHECK (cvss_v31_score BETWEEN 0 AND 10),
    cvss_v31_level text CHECK (cvss_v31_level IN ('none', 'low', 'medium', 'high', 'critical')),
    cvss_v31_justifications jsonb CHECK (
        jsonb_typeof(cvss_v31_justifications) = 'object'
        AND cvss_v31_justifications ?& ARRAY['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (num_nonnulls(finding_id, group_id) = 1),
    CHECK (injection_suspected OR injection_lines = '[]'),
    CHECK (
        num_nulls(cvss_v31_vector, cvss_v31_score, cvss_v31_level, cvss_v31_justifications)
        IN (0, 4)
    )
);

CREATE INDEX verdicts_finding_latest ON verdicts (finding_id, created_at DESC);
CREATE INDEX verdicts_group_latest ON verdicts (group_id, created_at DESC);

CREATE TABLE verdict_llm_calls (
    verdict_id uuid NOT NULL REFERENCES verdicts,
    llm_call_id uuid NOT NULL REFERENCES llm_calls,
    role text NOT NULL CHECK (role IN ('verdict', 'severity')),
    PRIMARY KEY (verdict_id, llm_call_id)
);

CREATE INDEX verdict_llm_calls_call ON verdict_llm_calls (llm_call_id);

CREATE TABLE finding_edits (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id uuid NOT NULL REFERENCES findings,
    verdict_id uuid NOT NULL REFERENCES verdicts,
    editor text NOT NULL,
    verdict text CHECK (verdict IN ('true_positive', 'false_positive', 'unsure')),
    reasoning text,
    cvss_v4_vector text CHECK (cvss_v4_vector LIKE 'CVSS:4.0/%'),
    cvss_v4_score numeric(3, 1) CHECK (cvss_v4_score BETWEEN 0 AND 10),
    cvss_v4_level text CHECK (cvss_v4_level IN ('none', 'low', 'medium', 'high', 'critical')),
    note text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (num_nonnulls(verdict, reasoning, cvss_v4_vector) >= 1),
    CHECK (num_nulls(cvss_v4_vector, cvss_v4_score, cvss_v4_level) IN (0, 3))
);

CREATE INDEX finding_edits_finding_latest ON finding_edits (finding_id, created_at DESC);

CREATE TABLE reviews (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id uuid NOT NULL REFERENCES findings,
    decision text NOT NULL CHECK (decision IN ('approve', 'reject')),
    reviewer text NOT NULL,
    comment text,
    verdict_id uuid REFERENCES verdicts,
    finding_edit_id uuid REFERENCES finding_edits,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX reviews_finding_latest ON reviews (finding_id, created_at DESC);

ALTER TABLE findings ADD FOREIGN KEY (carried_review_id) REFERENCES reviews;

CREATE TABLE reports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id uuid REFERENCES findings,
    group_id uuid REFERENCES duplicate_groups,
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'exported')),
    format text NOT NULL DEFAULT 'markdown',
    exported_text_id uuid,
    export_path text,
    exported_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    exported_at timestamptz,
    CHECK (num_nonnulls(finding_id, group_id) = 1),
    CHECK (
        CASE status
            WHEN 'exported'
                THEN num_nulls(exported_at, exported_text_id, export_path, exported_by) = 0
            ELSE num_nonnulls(exported_at, exported_text_id, export_path, exported_by) = 0
        END
    )
);

CREATE INDEX reports_finding ON reports (finding_id);
CREATE INDEX reports_group ON reports (group_id);

CREATE TABLE report_texts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id uuid NOT NULL REFERENCES reports,
    version integer NOT NULL CHECK (version >= 1),
    source text NOT NULL CHECK (source IN ('llm_draft', 'reviewer_edit')),
    llm_call_id uuid REFERENCES llm_calls,
    author text,
    title text NOT NULL,
    summary text NOT NULL,
    impact text NOT NULL,
    steps_to_reproduce text[] NOT NULL CHECK (cardinality(steps_to_reproduce) >= 1),
    fix text NOT NULL,
    "references" text[] NOT NULL CHECK (cardinality("references") >= 1),
    cvss_v4_vector text NOT NULL CHECK (cvss_v4_vector LIKE 'CVSS:4.0/%'),
    cvss_v4_score numeric(3, 1) NOT NULL CHECK (cvss_v4_score BETWEEN 0 AND 10),
    cvss_v4_level text NOT NULL
        CHECK (cvss_v4_level IN ('none', 'low', 'medium', 'high', 'critical')),
    locations jsonb NOT NULL
        CHECK (jsonb_typeof(locations) = 'array' AND jsonb_array_length(locations) >= 1),
    approved_by text,
    approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (report_id, version),
    UNIQUE (report_id, id),
    CHECK ((source = 'llm_draft') = (llm_call_id IS NOT NULL)),
    CHECK ((source = 'reviewer_edit') = (author IS NOT NULL)),
    CHECK (num_nulls(approved_by, approved_at) IN (0, 2))
);

-- The exported text must be one of the report's own versions.
ALTER TABLE reports
    ADD FOREIGN KEY (id, exported_text_id) REFERENCES report_texts (report_id, id);

CREATE TABLE report_findings (
    report_id uuid NOT NULL REFERENCES reports,
    finding_id uuid NOT NULL REFERENCES findings,
    review_id uuid REFERENCES reviews,
    PRIMARY KEY (report_id, finding_id)
);

CREATE INDEX report_findings_finding ON report_findings (finding_id);
