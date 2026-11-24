// Labels and small helpers shared by the screens. The states are those of
// docs/finding-states.md, and the levels those of CVSS v4.0.

export const STATES = ['new', 'grouped', 'triaged', 'edited', 'approved', 'rejected', 'reported']
export const LEVELS = ['critical', 'high', 'medium', 'low', 'none']
export const VERDICTS = ['true_positive', 'false_positive', 'unsure']
// Where the queue keeps its address, so the finding detail can link back to it.
export const QUEUE_KEY = 'sieve.queue'

export const V4_METRICS = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']

const TOOLS = {
  semgrep: 'Semgrep',
  bandit: 'Bandit',
  eslint: 'ESLint',
  gitleaks: 'Gitleaks',
  spotbugs: 'SpotBugs',
}

export function toolName(tool) {
  return TOOLS[tool] ?? tool
}

export function verdictLabel(verdict) {
  return verdict ? verdict.replace('_', ' ') : ''
}

export function levelLabel(level) {
  return level ? level[0].toUpperCase() + level.slice(1) : ''
}

export function lines(start, end) {
  return start === end ? `${start}` : `${start} to ${end}`
}

export function repoName(url) {
  return url.replace(/\/+$/, '').split('/').pop().replace(/\.git$/, '')
}

const DATE = new Intl.DateTimeFormat('en-GB', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

export function when(value) {
  return value ? DATE.format(new Date(value)) : ''
}

export function money(value) {
  return `$${Number(value).toFixed(2)}`
}

// The metric values of a vector, such as { AV: 'N', AC: 'L', ... }.
export function metrics(vector) {
  const values = {}
  for (const part of (vector ?? '').split('/').slice(1)) {
    const [name, value] = part.split(':')
    values[name] = value
  }
  return values
}

// Line numbers listed in cited_lines or injection_lines for one file.
export function lineSet(entries, file) {
  const numbers = new Set()
  for (const entry of entries ?? []) {
    if (entry.file && entry.file !== file) continue
    const start = entry.start_line ?? entry.line
    const end = entry.end_line ?? start
    for (let n = start; n <= end; n += 1) numbers.add(n)
  }
  return numbers
}
