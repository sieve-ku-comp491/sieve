import { useEffect, useState } from 'react'
import './index.css'

const COLUMNS = ['Tool', 'Rule', 'File', 'Severity', 'Verdict', 'Status']

// The review screen of T5.1 (issue #22) starts here. Until the findings API
// exists, the table is empty and the header shows whether the back end answers.
export default function App() {
  const [api, setApi] = useState('checking')

  useEffect(() => {
    fetch('/api/health')
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(res.statusText))))
      .then((body) => setApi(body.status === 'ok' ? 'up' : 'down'))
      .catch(() => setApi('down'))
  }, [])

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">Sieve</span>
        <span className={`api api-${api}`}>API {api}</span>
      </header>

      <main>
        <h1>Findings</h1>
        <table className="findings">
          <thead>
            <tr>
              {COLUMNS.map((column) => (
                <th key={column}>{column}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              <td colSpan={COLUMNS.length} className="empty">
                No findings yet. Start a scan to see its findings here.
              </td>
            </tr>
          </tbody>
        </table>
      </main>
    </div>
  )
}
