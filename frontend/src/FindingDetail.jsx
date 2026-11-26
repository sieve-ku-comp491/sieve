import { useState } from 'react'
import { postJson, useApi } from './api.js'
import {
  QUEUE_KEY,
  V4_METRICS,
  VERDICTS,
  levelLabel,
  lineSet,
  lines,
  metrics,
  toolName,
  verdictLabel,
  when,
} from './format.js'
import { Problem } from './Queue.jsx'

// The finding detail (docs/ui-mockups.md): everything a reviewer needs to
// decide on one screen (requirement N7), and the approve, reject and edit
// actions, saved through the endpoints of backend/app/api/reviews.py.

// Before triage there is nothing to decide on, and a reported finding is final
// (docs/finding-states.md). The API refuses both too.
const LOCKED = {
  new: 'Approve, reject and edit open once triage gives this finding a verdict.',
  grouped: 'Approve, reject and edit open once triage gives this finding a verdict.',
  reported: 'This finding is reported: its report has left Sieve, so it is final.',
}

// The first sentence of the rule's description, which for most analyzers
// names the problem, or the rule ID.
function title(finding) {
  const first = (finding.rule_description ?? '').split(/(?<=\.)\s/)[0].trim()
  if (!first) return finding.rule_id
  return first.length > 120 ? `${first.slice(0, 117)}...` : first
}

function backToQueue() {
  try {
    return window.sessionStorage.getItem(QUEUE_KEY) ?? '#/'
  } catch {
    return '#/'
  }
}

export default function FindingDetail({ findingId, reviewer }) {
  const finding = useApi(`/findings/${findingId}`)
  const [mode, setMode] = useState(null)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState(null)

  if (finding.error) return <Problem error={finding.error} />
  const f = finding.data
  if (!f) return <div className="empty-state">Loading the finding…</div>

  const locked = LOCKED[f.state] ?? (f.verdict ? null : 'This finding has no verdict to decide on.')
  const edit = f.latest_edit

  async function save(path, body) {
    if (!reviewer) {
      setProblem('Enter your name as the researcher at the top right first.')
      return
    }
    setBusy(true)
    setProblem(null)
    try {
      await postJson(path, body)
      setMode(null)
      finding.reload()
    } catch (error) {
      setProblem(error.message)
      if (error.status === 409) finding.reload()
    } finally {
      setBusy(false)
    }
  }

  // Every save names the verdict and the latest edit on screen, so the API
  // refuses it with 409 if either changed since the page loaded.
  const seen = { finding_edit_id: edit?.id ?? null, verdict_id: f.verdict?.id ?? null }

  function decide(decision, comment) {
    return save(`/findings/${f.id}/reviews`, {
      decision,
      reviewer,
      comment: comment || null,
      ...seen,
    })
  }

  const severity = edit?.cvss_v4_vector ? edit : f.verdict
  // While the edit form is open, Approve and Reject would decide on the values
  // before the edit and drop the unsaved changes, so they wait for Save or Cancel.
  const editing = mode === 'edit'
  return (
    <>
      <div className="crumbs">
        <a href={backToQueue()}>Review queue</a> / {f.group ? `Duplicate group of ${f.group.members.length} findings` : 'Finding'}
      </div>
      <div className="title-row">
        <div>
          <h1>{title(f)}</h1>
          <div className="meta">
            <span className={`pill state-${f.state}`}>{f.state}</span>
            {severity && (
              <span className={`pill level-${severity.cvss_v4_level}`}>
                {levelLabel(severity.cvss_v4_level)} {severity.cvss_v4_score.toFixed(1)}
              </span>
            )}
            <span>
              {toolName(f.tool)} {f.tool_version}
            </span>
            {f.cwe.length > 0 && <span>{f.cwe.join(', ')}</span>}
            <span className="file">
              {f.location.file}:{lines(f.location.start_line, f.location.end_line)}
            </span>
          </div>
        </div>
        <div className="actions">
          <button
            type="button"
            className="button danger"
            disabled={busy || !!locked || editing}
            title={editing ? 'Save or cancel the edit first' : undefined}
            onClick={() => setMode('reject')}
          >
            Reject
          </button>
          <button type="button" className="button" disabled={busy || !!locked} onClick={() => setMode('edit')}>
            Edit
          </button>
          <button
            type="button"
            className="button primary"
            disabled={busy || !!locked || editing}
            title={editing ? 'Save or cancel the edit first' : undefined}
            onClick={() => decide('approve')}
          >
            Approve
          </button>
        </div>
      </div>

      {locked && <div className="banner info">{locked}</div>}
      {problem && <div className="banner error">{problem}</div>}
      {mode === 'reject' && (
        <RejectForm busy={busy} onCancel={() => setMode(null)} onReject={(comment) => decide('reject', comment)} />
      )}
      {f.verdict?.injection_suspected && (
        <div className="banner warn-banner">
          ⚠ A comment or string in this code looks like an instruction to an AI. The lines are marked
          in orange, or listed under the code when they are outside it. Read the code yourself
          before you trust the verdict.
        </div>
      )}
      {f.carried_review && !f.hidden && (
        <div className="banner info">
          An earlier scan&apos;s review of this finding: {f.carried_review.decision} by{' '}
          {f.carried_review.reviewer}, {when(f.carried_review.created_at)}
          {f.carried_review.comment && ` (${f.carried_review.comment})`}. It is a suggestion only,
          because the code around the finding changed.
        </div>
      )}

      <div className="detail">
        <div className="column">
          <Code finding={f} />
          {mode === 'edit' && (
            <EditForm
              key={edit?.id ?? 'ai'}
              finding={f}
              busy={busy}
              onCancel={() => setMode(null)}
              onSave={(changes) => save(`/findings/${f.id}/edits`, { editor: reviewer, ...seen, ...changes })}
            />
          )}
          <Analyzer finding={f} />
          {f.group && <Group group={f.group} current={f.id} />}
        </div>
        <div className="column">
          <Verdict finding={f} />
          <Severity finding={f} />
          <History finding={f} />
        </div>
      </div>
    </>
  )
}

function RejectForm({ busy, onCancel, onReject }) {
  const [comment, setComment] = useState('')
  return (
    <form
      className="panel inline-form"
      onSubmit={(event) => {
        event.preventDefault()
        onReject(comment.trim())
      }}
    >
      <label>
        Why reject it? (optional)
        <input value={comment} onChange={(event) => setComment(event.target.value)} maxLength={20000} />
      </label>
      <button type="submit" className="button danger" disabled={busy}>
        Reject
      </button>
      <button type="button" className="button" onClick={onCancel}>
        Cancel
      </button>
    </form>
  )
}

function Code({ finding }) {
  const { code, location } = finding
  const file = location.file
  const flagged = lineSet([location], file)
  const cited = lineSet(finding.verdict?.cited_lines, file)
  const injected = lineSet(finding.verdict?.injection_lines, file)

  return (
    <section className="panel">
      <h2>Code</h2>
      <p className="hint">
        Yellow lines are the lines the AI cited, red lines are where the analyzer flagged it
        {injected.size > 0 && ', orange lines look like instructions to an AI'}.
      </p>
      <div className="code-head">
        <span className="file">{file}</span>
        {code && <span className="muted">lines {lines(code.start_line, code.end_line)}</span>}
      </div>
      {code ? (
        <pre className="code">
          {code.lines.map((text, index) => {
            const n = code.start_line + index
            const kind = injected.has(n) ? 'injected' : flagged.has(n) ? 'flagged' : cited.has(n) ? 'cited' : ''
            return (
              <div key={n} className={`line ${kind}`}>
                <span className="number">{n}</span>
                <span className="text">{text || ' '}</span>
              </div>
            )
          })}
        </pre>
      ) : null}
      <Outside code={code} file={file} verdict={finding.verdict} />
      {!code && (
        <div className="empty-state">
          The code can&apos;t be shown: the scan&apos;s checkout isn&apos;t in the data folder.
          {location.snippet && <pre className="code snippet">{location.snippet}</pre>}
        </div>
      )}
    </section>
  )
}

// Cited lines and lines that look like instructions to an AI can be outside
// the code window, or in another file: triage reads the whole enclosing
// function and the data-flow steps. They are listed here, so every one of
// them stays checkable.
function Outside({ code, file, verdict }) {
  const shown = (entry) => {
    if (!code || (entry.file && entry.file !== file)) return false
    const start = entry.start_line ?? entry.line
    const end = entry.end_line ?? start
    return start >= code.start_line && end <= code.end_line
  }
  const entries = [
    ...(verdict?.injection_lines ?? []).map((entry) => ({ entry, why: 'looks like an instruction to an AI' })),
    ...(verdict?.cited_lines ?? []).map((entry) => ({ entry, why: 'cited by the AI' })),
  ].filter(({ entry }) => !shown(entry))
  if (entries.length === 0) return null
  return (
    <div className="outside">
      <h3>Outside the code shown</h3>
      <ul>
        {entries.map(({ entry, why }) => {
          const start = entry.start_line ?? entry.line
          return (
            <li key={`${why}-${entry.file}-${start}`} className={why === 'cited by the AI' ? '' : 'warn'}>
              <span className="file">{entry.file ?? file}</span> lines {lines(start, entry.end_line ?? start)}, {why}
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function Analyzer({ finding }) {
  return (
    <section className="panel">
      <h2>Analyzer</h2>
      <p>{finding.message}</p>
      <dl className="facts">
        <dt>Rule</dt>
        <dd>
          <code>{finding.rule_id}</code>
          {finding.rule_help_uri && (
            <>
              {' '}
              <a href={finding.rule_help_uri} target="_blank" rel="noreferrer">
                rule documentation
              </a>
            </>
          )}
        </dd>
        <dt>Tool severity</dt>
        <dd>
          {finding.tool_severity}
          {finding.tool_confidence && `, confidence ${finding.tool_confidence}`}
        </dd>
        {finding.data_flow.length > 0 && (
          <>
            <dt>Data flow</dt>
            <dd>
              {finding.data_flow.map((step) => (
                <div key={step.step}>
                  {step.step}. {step.file}:{step.start_line} {step.message}
                </div>
              ))}
            </dd>
          </>
        )}
        {finding.related_locations.length > 0 && (
          <>
            <dt>Related</dt>
            <dd>
              {finding.related_locations.map((place) => (
                <div key={`${place.file}:${place.start_line}`}>
                  {place.file}:{place.start_line} {place.message}
                </div>
              ))}
            </dd>
          </>
        )}
      </dl>
    </section>
  )
}

function Verdict({ finding }) {
  const verdict = finding.verdict
  const edit = finding.latest_edit
  if (!verdict) {
    return (
      <section className="panel">
        <h2>AI verdict</h2>
        <p className="placeholder">
          Not triaged yet. The verdict, the reasoning and the lines the AI cited appear here once
          triage checks this finding.
        </p>
      </section>
    )
  }
  return (
    <section className="panel">
      <h2>AI verdict</h2>
      <span className={`pill verdict-${verdict.verdict}`}>{verdictLabel(verdict.verdict)}</span>
      <h3>Reasoning</h3>
      <p className="prose">{verdict.reasoning}</p>
      <dl className="facts">
        <dt>Cited lines</dt>
        <dd>
          {verdict.cited_lines
            .map((cite) => `${cite.file?.split('/').pop() ?? ''} ${lines(cite.start_line, cite.end_line ?? cite.start_line)}`)
            .join(', ')}
        </dd>
        <dt>Model</dt>
        <dd>
          {verdict.model_version} · {verdict.call_count} calls · ${verdict.cost_usd.toFixed(3)}
        </dd>
      </dl>
      {edit && (
        <div className="edited">
          <h3>
            Edited by {edit.editor}, {when(edit.created_at)}
          </h3>
          {edit.verdict && (
            <p>
              Verdict: <span className={`pill verdict-${edit.verdict}`}>{verdictLabel(edit.verdict)}</span>
            </p>
          )}
          {edit.reasoning && <p className="prose">{edit.reasoning}</p>}
          {edit.note && <p className="muted">Note: {edit.note}</p>}
        </div>
      )}
    </section>
  )
}

function Severity({ finding }) {
  const verdict = finding.verdict
  if (!verdict) {
    return (
      <section className="panel">
        <h2>Severity, CVSS v4.0</h2>
        <p className="placeholder">
          No score yet. Triage scores each finding with a CVSS v4.0 vector and a reason for each
          metric.
        </p>
      </section>
    )
  }
  const edit = finding.latest_edit?.cvss_v4_vector ? finding.latest_edit : null
  const shown = edit ?? verdict
  const values = metrics(shown.cvss_v4_vector)
  const aiValues = metrics(verdict.cvss_v4_vector)
  return (
    <section className="panel">
      <h2>Severity, CVSS v4.0</h2>
      <div className="score">
        <b>{shown.cvss_v4_score.toFixed(1)}</b>
        <span className={`pill level-${shown.cvss_v4_level}`}>{levelLabel(shown.cvss_v4_level)}</span>
        <span className="muted">computed from the vector{edit ? ', as the reviewer edited it' : ''}</span>
      </div>
      <code className="vector">{shown.cvss_v4_vector}</code>
      {edit && (
        <p className="muted">
          The AI&apos;s vector: <code>{verdict.cvss_v4_vector}</code>, {verdict.cvss_v4_score.toFixed(1)}
        </p>
      )}
      <table className="metrics">
        <thead>
          <tr>
            <th>Metric</th>
            <th>{edit ? 'Edited' : 'Value'}</th>
            {edit && <th>AI</th>}
            <th>The AI&apos;s reason</th>
          </tr>
        </thead>
        <tbody>
          {V4_METRICS.map((name) => (
            <tr key={name} className={edit && values[name] !== aiValues[name] ? 'changed' : ''}>
              <th>{name}</th>
              <td>{values[name]}</td>
              {edit && <td>{aiValues[name]}</td>}
              <td>{verdict.cvss_v4_justifications[name]}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function EditForm({ finding, busy, onCancel, onSave }) {
  const ai = finding.verdict
  const edit = finding.latest_edit
  const [verdict, setVerdict] = useState(edit?.verdict ?? ai.verdict)
  const [reasoning, setReasoning] = useState(edit?.reasoning ?? ai.reasoning)
  const [vector, setVector] = useState(edit?.cvss_v4_vector ?? ai.cvss_v4_vector)
  const [note, setNote] = useState('')

  const before = {
    verdict: edit?.verdict ?? ai.verdict,
    reasoning: edit?.reasoning ?? ai.reasoning,
    vector: edit?.cvss_v4_vector ?? ai.cvss_v4_vector,
  }
  const changes = {}
  if (verdict !== before.verdict) changes.verdict = verdict
  if (reasoning.trim() && reasoning.trim() !== before.reasoning) changes.reasoning = reasoning.trim()
  if (vector.trim() !== before.vector) changes.cvss_v4_vector = vector.trim()

  return (
    <form
      className="panel edit-form"
      onSubmit={(event) => {
        event.preventDefault()
        onSave({ ...changes, note: note.trim() || null })
      }}
    >
      <h2>Edit</h2>
      <p className="hint">
        The AI&apos;s values stay as they are: your edit is saved next to them, and the finding
        is edited until you approve or reject it.
      </p>
      <label>
        Verdict
        <select value={verdict} onChange={(event) => setVerdict(event.target.value)}>
          {VERDICTS.map((value) => (
            <option key={value} value={value}>
              {verdictLabel(value)}
            </option>
          ))}
        </select>
        <span className="ai-value">AI: {verdictLabel(ai.verdict)}</span>
      </label>
      <label>
        Reasoning
        <textarea rows={5} value={reasoning} onChange={(event) => setReasoning(event.target.value)} />
      </label>
      <label>
        CVSS v4.0 vector
        <input value={vector} onChange={(event) => setVector(event.target.value)} spellCheck={false} />
        <span className="ai-value">
          AI: {ai.cvss_v4_vector}, {ai.cvss_v4_score.toFixed(1)}. The score is computed again when
          you save.
        </span>
      </label>
      <label>
        Note (optional)
        <input value={note} onChange={(event) => setNote(event.target.value)} />
      </label>
      <div className="form-buttons">
        <button type="submit" className="button primary" disabled={busy || Object.keys(changes).length === 0}>
          Save edit
        </button>
        <button type="button" className="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  )
}

function Group({ group, current }) {
  return (
    <section className="panel">
      <h2>Findings in this group</h2>
      <p className="hint">
        Grouped by {group.method}
        {group.rule && ` (${group.rule})`}
        {group.similarity != null && `, similarity ${group.similarity}`}: {group.reason}. Each member
        is reviewed on its own.
      </p>
      <table className="findings compact">
        <thead>
          <tr>
            <th>Rule and analyzer message</th>
            <th>Lines</th>
            <th>CWE</th>
            <th>Tool severity</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {group.members.map((member) => (
            <tr
              key={member.id}
              className={member.id === current ? 'current' : ''}
              onClick={() => {
                window.location.hash = `#/findings/${member.id}`
              }}
            >
              <td>
                <code>{member.rule_id}</code>
                <div className="sub">{member.message}</div>
              </td>
              <td>{lines(member.start_line, member.end_line)}</td>
              <td>{member.cwe.join(', ')}</td>
              <td>{member.tool_severity}</td>
              <td>
                <span className={`pill state-${member.state}`}>{member.state}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function History({ finding }) {
  const entries = [
    ...finding.reviews.map((review) => ({
      at: review.created_at,
      what: review.decision === 'approve' ? 'approved' : 'rejected',
      by: `by ${review.reviewer}`,
      comment: review.comment,
    })),
    ...(finding.latest_edit
      ? [{ at: finding.latest_edit.created_at, what: 'edited', by: `by ${finding.latest_edit.editor}` }]
      : []),
    ...(finding.verdict ? [{ at: finding.verdict.created_at, what: 'triaged', by: 'by the triage agent' }] : []),
    { at: finding.created_at, what: 'new', by: `from the ${toolName(finding.tool)} run of the scan` },
  ].sort((a, b) => new Date(b.at) - new Date(a.at))

  return (
    <section className="panel">
      <h2>History</h2>
      <ul className="history">
        {entries.map((entry) => (
          <li key={`${entry.what}-${entry.at}`}>
            <b>{entry.what}</b> {entry.by} · {when(entry.at)}
            {entry.comment && <div className="muted">{entry.comment}</div>}
          </li>
        ))}
      </ul>
    </section>
  )
}
