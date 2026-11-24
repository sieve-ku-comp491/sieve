import { useEffect, useState } from 'react'
import { useApi } from './api.js'
import {
  LEVELS,
  QUEUE_KEY,
  STATES,
  VERDICTS,
  levelLabel,
  money,
  repoName,
  toolName,
  verdictLabel,
  when,
} from './format.js'

// The review queue (docs/ui-mockups.md): the scan, its findings per state, the
// filters, and one row per triage item, highest severity first.

const PAGE_SIZE = 50
const FILTERS = ['status', 'tool', 'severity', 'verdict']

const CARDS = [
  { label: 'new or grouped', states: ['new', 'grouped'] },
  { label: 'triaged', states: ['triaged'] },
  { label: 'edited', states: ['edited'] },
  { label: 'approved', states: ['approved'] },
  { label: 'rejected', states: ['rejected'] },
  { label: 'reported', states: ['reported'] },
]

export default function Queue({ scanId, query }) {
  const scans = useApi('/scans?limit=50')
  const current = scanId ?? scans.data?.[0]?.id ?? null
  const scan = useApi(current ? `/scans/${current}` : null)

  const filters = Object.fromEntries(FILTERS.map((name) => [name, query.getAll(name)]))
  const search = query.get('q') ?? ''
  const page = Math.max(0, Number(query.get('page') ?? 0) || 0)

  const params = new URLSearchParams()
  for (const name of FILTERS) for (const value of filters[name]) params.append(name, value)
  if (search) params.set('q', search)
  params.set('limit', PAGE_SIZE)
  params.set('offset', page * PAGE_SIZE)
  const findings = useApi(current ? `/scans/${current}/findings?${params}` : null)

  useEffect(() => {
    try {
      window.sessionStorage.setItem(QUEUE_KEY, window.location.hash || '#/')
    } catch {
      // The back link then goes to the latest scan.
    }
  })

  function go(changes, scan = current) {
    const next = new URLSearchParams()
    const merged = { ...filters, q: search, ...changes }
    for (const name of FILTERS) for (const value of merged[name] ?? []) next.append(name, value)
    if (merged.q) next.set('q', merged.q)
    if (merged.page) next.set('page', merged.page)
    const text = next.toString()
    window.location.hash = `#/scans/${scan}${text ? `?${text}` : ''}`
  }

  if (scans.error) return <Problem error={scans.error} />
  if (scans.data && scans.data.length === 0) {
    return (
      <>
        <Heading />
        <div className="panel empty-state">
          No scans yet. Start one with the CLI, or load a saved run with{' '}
          <code>python -m app.store load-sarif</code> as the README describes.
        </div>
      </>
    )
  }

  return (
    <>
      <Heading />
      {scans.data && scans.data.length > 1 && (
        <label className="scan-picker">
          Scan{' '}
          <select value={current ?? ''} onChange={(event) => go({ page: 0 }, event.target.value)}>
            {scans.data.map((item) => (
              <option key={item.id} value={item.id}>
                {repoName(item.repo_url)} at {(item.commit_sha ?? item.requested_ref ?? '').slice(0, 7)}{' '}
                · {when(item.created_at)} · {item.finding_count} findings
              </option>
            ))}
          </select>
        </label>
      )}
      {scan.error && <Problem error={scan.error} />}
      {scan.data && <ScanBar scan={scan.data} />}
      {scan.data && (
        <StateCards scan={scan.data} active={filters.status} onPick={(status) => go({ status, page: 0 })} />
      )}

      <section className="panel">
        <Filters
          key={search}
          filters={filters}
          search={search}
          tools={(scan.data?.runs ?? []).map((run) => run.plugin)}
          onChange={(changes) => go({ ...changes, page: 0 })}
        />
        {findings.error ? (
          <Problem error={findings.error} />
        ) : (
          <FindingTable page={findings.data} loading={findings.loading} />
        )}
        {findings.data && (
          <Pager
            page={page}
            total={findings.data.total}
            shown={findings.data.items.length}
            onPage={(next) => go({ page: next })}
          />
        )}
      </section>
    </>
  )
}

function Heading() {
  return (
    <>
      <h1>Review queue</h1>
      <p className="lead">
        Decide on each finding: read the AI&apos;s verdict, then approve, reject or edit it. Only
        approved findings get a report.
      </p>
    </>
  )
}

export function Problem({ error }) {
  return <div className="banner error">{error.message}</div>
}

function ScanBar({ scan }) {
  const commit = (scan.commit_sha ?? scan.requested_ref ?? '').slice(0, 7)
  const triage = scan.triage_run
  return (
    <section className="panel scan-bar">
      <span>
        <b>{repoName(scan.repo_url)}</b> at <code>{commit}</code>
      </span>
      <span>
        Scan of {when(scan.created_at)} <span className={`pill run-${scan.status}`}>{scan.status}</span>
      </span>
      {scan.runs.map((run) => (
        <span key={run.id}>
          {toolName(run.plugin)} {run.tool_version}
          {run.files_scanned != null && ` · ${run.files_scanned} files`}
          {run.status !== 'succeeded' && <span className={`pill run-${run.status}`}>{run.status}</span>}
        </span>
      ))}
      {triage ? (
        <span>
          Triage run <span className={`pill run-${triage.status}`}>{triage.status.replaceAll('_', ' ')}</span>{' '}
          · {money(triage.cost_usd)} of {money(triage.budget_usd)}
        </span>
      ) : (
        <span className="muted">Triage hasn&apos;t run yet, so verdicts and severities are empty.</span>
      )}
    </section>
  )
}

function StateCards({ scan, active, onPick }) {
  const counts = scan.state_counts
  const total = STATES.reduce((sum, state) => sum + counts[state], 0)
  const isActive = (states) =>
    active.length === states.length && states.every((state) => active.includes(state))
  return (
    <div className="cards">
      <button type="button" className={`card ${active.length === 0 ? 'active' : ''}`} onClick={() => onPick([])}>
        <b>{total}</b>
        findings
      </button>
      {CARDS.map((card) => (
        <button
          type="button"
          key={card.label}
          className={`card ${isActive(card.states) ? 'active' : ''}`}
          onClick={() => onPick(card.states)}
        >
          <b>{card.states.reduce((sum, state) => sum + counts[state], 0)}</b>
          {card.label}
        </button>
      ))}
      {scan.hidden_count > 0 && (
        <div className="card note">
          <b>{scan.hidden_count}</b>
          hidden: an earlier review applies
        </div>
      )}
    </div>
  )
}

function MultiSelect({ label, all, chosen, show, onChange, anyText }) {
  const text = chosen.length === 0 ? anyText : chosen.map(show).join(', ')
  return (
    <div className="filter">
      <span className="filter-label">{label}</span>
      <details className="multi">
        <summary>{text}</summary>
        <div className="multi-options">
          {all.map((value) => (
            <label key={value}>
              <input
                type="checkbox"
                checked={chosen.includes(value)}
                onChange={(event) =>
                  onChange(
                    event.target.checked ? [...chosen, value] : chosen.filter((v) => v !== value),
                  )
                }
              />
              {show(value)}
            </label>
          ))}
        </div>
      </details>
    </div>
  )
}

function Filters({ filters, search, tools, onChange }) {
  const [text, setText] = useState(search)
  const toolOptions = [...new Set([...tools, ...filters.tool])]
  const chips = [
    ...FILTERS.filter((name) => filters[name].length > 0).map((name) => ({
      name,
      text: `${name[0].toUpperCase()}${name.slice(1)}: ${filters[name].map((v) => show(name, v)).join(', ')}`,
      clear: { [name]: [] },
    })),
    ...(search ? [{ name: 'q', text: `File or rule: ${search}`, clear: { q: '' } }] : []),
  ]

  return (
    <>
      <form
        className="filters"
        onSubmit={(event) => {
          event.preventDefault()
          onChange({ q: text.trim() })
        }}
      >
        <MultiSelect label="Status" anyText="All statuses" all={STATES} chosen={filters.status} show={(v) => v} onChange={(status) => onChange({ status })} />
        <MultiSelect label="Tool" anyText="All tools" all={toolOptions} chosen={filters.tool} show={toolName} onChange={(tool) => onChange({ tool })} />
        <MultiSelect label="Severity" anyText="All levels" all={LEVELS} chosen={filters.severity} show={levelLabel} onChange={(severity) => onChange({ severity })} />
        <MultiSelect label="Verdict" anyText="All verdicts" all={VERDICTS} chosen={filters.verdict} show={verdictLabel} onChange={(verdict) => onChange({ verdict })} />
        <label className="filter">
          <span className="filter-label">File or rule</span>
          <input
            value={text}
            onChange={(event) => setText(event.target.value)}
            onBlur={() => text.trim() !== search && onChange({ q: text.trim() })}
            placeholder="part of a path or rule"
            maxLength={500}
          />
        </label>
        <button
          type="button"
          className="button"
          disabled={chips.length === 0}
          onClick={() => onChange({ status: [], tool: [], severity: [], verdict: [], q: '' })}
        >
          Clear filters
        </button>
      </form>
      <div className="chips">
        Filters:
        {chips.length === 0 && <span className="muted"> none</span>}
        {chips.map((chip) => (
          <button type="button" key={chip.name} className="chip" onClick={() => onChange(chip.clear)}>
            {chip.text} ×
          </button>
        ))}
        <span className="muted"> · sorted by severity · duplicates shown as one group</span>
      </div>
    </>
  )
}

function show(name, value) {
  if (name === 'tool') return toolName(value)
  if (name === 'severity') return levelLabel(value)
  if (name === 'verdict') return verdictLabel(value)
  return value
}

// One row per triage item: a finding on its own, or the members of a
// duplicate group on this page under the first of them.
function triageItems(items) {
  const rows = []
  const groups = new Map()
  for (const item of items) {
    if (item.group_id && groups.has(item.group_id)) {
      groups.get(item.group_id).members.push(item)
    } else {
      const row = { item, members: [item] }
      rows.push(row)
      if (item.group_id) groups.set(item.group_id, row)
    }
  }
  return rows
}

function FindingTable({ page, loading }) {
  const [open, setOpen] = useState(() => new Set())
  if (!page) return <div className="empty-state">{loading ? 'Loading findings…' : ''}</div>
  if (page.items.length === 0) {
    return <div className="empty-state">No finding matches these filters.</div>
  }

  function toggle(id) {
    setOpen((before) => {
      const next = new Set(before)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <table className={`findings ${loading ? 'stale' : ''}`}>
      <thead>
        <tr>
          <th>Tool</th>
          <th>Rule</th>
          <th>File</th>
          <th>Severity</th>
          <th>Verdict</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {triageItems(page.items).map(({ item, members }) => {
          const group = members.length > 1
          const expanded = open.has(item.id)
          return [
            <FindingRow
              key={item.id}
              item={item}
              note={
                group ? (
                  <button
                    type="button"
                    className="link-button"
                    onClick={(event) => {
                      event.stopPropagation()
                      toggle(item.id)
                    }}
                  >
                    {expanded ? '▾' : '▸'} group of {members.length}
                  </button>
                ) : null
              }
            />,
            ...(group && expanded
              ? members.map((member) => <FindingRow key={`m-${member.id}`} item={member} member />)
              : []),
          ]
        })}
      </tbody>
    </table>
  )
}

function FindingRow({ item, note, member = false }) {
  const open = () => {
    window.location.hash = `#/findings/${item.id}`
  }
  return (
    <tr
      className={member ? 'member' : ''}
      onClick={open}
      onKeyDown={(event) => event.key === 'Enter' && open()}
      tabIndex={0}
    >
      <td>{toolName(item.tool)}</td>
      <td>
        <code>{item.rule_id}</code>
        <div className="sub">
          {note}
          {note && item.cwe.length > 0 && ' · '}
          {item.cwe.join(', ')}
        </div>
      </td>
      <td>
        <span className="file">
          {item.file.split('/').map((part, index) => (
            <span key={index}>
              {index > 0 && '/'}
              {index > 0 && <wbr />}
              {part}
            </span>
          ))}
          :{item.start_line}
        </span>
        {item.injection_suspected && (
          <span className="warn" title="A comment in the code looks like an instruction to an AI">
            {' '}
            ⚠
          </span>
        )}
      </td>
      <td>
        {item.severity && !member ? (
          <span className={`pill level-${item.severity}`}>
            {levelLabel(item.severity)} {item.score?.toFixed(1)}
          </span>
        ) : (
          <span className="muted">tool: {item.tool_severity}</span>
        )}
      </td>
      <td>
        {item.verdict ? (
          <span className={`pill verdict-${item.verdict}`}>{verdictLabel(item.verdict)}</span>
        ) : (
          <span className="muted">not triaged</span>
        )}
      </td>
      <td>
        <span className={`pill state-${item.state}`}>{item.state}</span>
      </td>
    </tr>
  )
}

function Pager({ page, total, shown, onPage }) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const first = total === 0 ? 0 : page * PAGE_SIZE + 1
  return (
    <div className="pager">
      <span className="muted">
        Click a row to open its detail. ⚠ a comment in the code looks like an instruction to an AI.
      </span>
      <span>
        {first} to {page * PAGE_SIZE + shown} of {total} findings · page {page + 1} of {pages}{' '}
        <button type="button" className="button small" disabled={page === 0} onClick={() => onPage(page - 1)}>
          Previous
        </button>{' '}
        <button
          type="button"
          className="button small"
          disabled={page + 1 >= pages}
          onClick={() => onPage(page + 1)}
        >
          Next
        </button>
      </span>
    </div>
  )
}
