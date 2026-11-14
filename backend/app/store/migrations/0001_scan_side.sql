-- The scan side of the findings store and the job queue (docs/database.md).

CREATE TABLE scans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_url text NOT NULL,
    commit_sha text CHECK (commit_sha ~ '^[0-9a-f]{40}$'),
    requested_ref text,
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed')),
    error text,
    languages text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    CHECK (commit_sha IS NOT NULL OR requested_ref IS NOT NULL)
);

CREATE INDEX scans_repo_created ON scans (repo_url, created_at);

CREATE TABLE analyzer_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id uuid NOT NULL REFERENCES scans,
    plugin text NOT NULL,
    image text NOT NULL,
    image_digest text,
    tool_version text NOT NULL,
    rules_version text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'building', 'running', 'succeeded', 'skipped', 'failed', 'timed_out')
    ),
    reason text CHECK (
        reason IN (
            'exit_code', 'missing_sarif', 'nothing_scanned', 'invalid_sarif', 'out_of_memory',
            'build_failed', 'runner_error', 'interrupted'
        )
    ),
    exit_code integer,
    files_scanned integer CHECK (files_scanned >= 0),
    result_count integer CHECK (result_count >= 0),
    dropped_count integer NOT NULL DEFAULT 0 CHECK (dropped_count >= 0),
    sarif_path text,
    log_path text,
    started_at timestamptz,
    finished_at timestamptz,
    -- The unique index also serves listing a scan's runs.
    UNIQUE (scan_id, plugin)
);

CREATE TABLE jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('scan', 'triage', 'report_draft')),
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    payload jsonb NOT NULL,
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);

CREATE INDEX jobs_queued ON jobs (created_at) WHERE status = 'queued';

CREATE TABLE duplicate_groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id uuid NOT NULL REFERENCES scans,
    representative_finding_id uuid,
    method text NOT NULL CHECK (method IN ('rule', 'similarity', 'llm')),
    rule text,
    similarity numeric(4, 3) CHECK (similarity BETWEEN 0 AND 1),
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, scan_id),
    CHECK (method <> 'rule' OR rule IS NOT NULL),
    CHECK (method <> 'similarity' OR similarity IS NOT NULL)
);

CREATE INDEX duplicate_groups_scan ON duplicate_groups (scan_id);

-- carried_review_id gets its reference to reviews with the review side.
CREATE TABLE findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id uuid NOT NULL REFERENCES scans,
    run_id uuid NOT NULL REFERENCES analyzer_runs,
    group_id uuid,
    matched_finding_id uuid REFERENCES findings,
    carried_review_id uuid,
    hidden boolean NOT NULL DEFAULT false,
    tool text NOT NULL,
    tool_version text NOT NULL,
    rule_id text NOT NULL,
    rule_description text,
    rule_help_uri text,
    cwe text[] NOT NULL DEFAULT '{}',
    message text NOT NULL,
    tool_severity text NOT NULL CHECK (tool_severity IN ('error', 'warning', 'note', 'none')),
    tool_score numeric(3, 1) CHECK (tool_score BETWEEN 0 AND 10),
    tool_confidence text CHECK (tool_confidence IN ('high', 'medium', 'low')),
    file text NOT NULL,
    start_line integer NOT NULL CHECK (start_line >= 1),
    end_line integer NOT NULL,
    start_column integer CHECK (start_column >= 1),
    end_column integer,
    snippet text,
    fingerprint text NOT NULL,
    fingerprint_ambiguous boolean NOT NULL DEFAULT false,
    context_hash text NOT NULL,
    suppressed boolean NOT NULL DEFAULT false,
    tool_fingerprint text,
    language text
        CHECK (language IN ('python', 'java', 'javascript', 'typescript', 'html', 'other')),
    raw jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (end_line >= start_line),
    CHECK (NOT hidden OR carried_review_id IS NOT NULL),
    UNIQUE (scan_id, fingerprint),
    UNIQUE (id, group_id),
    FOREIGN KEY (group_id, scan_id) REFERENCES duplicate_groups (id, scan_id)
);

CREATE INDEX findings_scan ON findings (scan_id);
CREATE INDEX findings_scan_file_line ON findings (scan_id, file, start_line);
CREATE INDEX findings_group ON findings (group_id);
CREATE INDEX findings_fingerprint ON findings (fingerprint);

-- The representative must be a member of its group. The group and its members' group_id are
-- written in one transaction, so the check waits until the commit.
ALTER TABLE duplicate_groups
    ADD FOREIGN KEY (representative_finding_id, id) REFERENCES findings (id, group_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE locations (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES findings ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('related', 'flow_step')),
    position integer NOT NULL CHECK (position >= 1),
    file text NOT NULL,
    start_line integer NOT NULL,
    end_line integer NOT NULL,
    start_column integer,
    end_column integer,
    snippet text,
    message text,
    -- The unique index also serves reading a finding's locations.
    UNIQUE (finding_id, kind, position)
);
