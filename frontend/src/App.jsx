import { useState, useSyncExternalStore } from 'react'
import { useApi } from './api.js'
import FindingDetail from './FindingDetail.jsx'
import Queue from './Queue.jsx'
import './index.css'

// The review web app of T5.1 (issue #22), built from the mockups in
// docs/ui-mockups.md. The address after # says what is shown:
//   #/                         the review queue of the latest scan
//   #/scans/<id>?status=...    the review queue of one scan, with its filters
//   #/findings/<id>            one finding

function subscribe(callback) {
  window.addEventListener('hashchange', callback)
  return () => window.removeEventListener('hashchange', callback)
}

function useRoute() {
  const hash = useSyncExternalStore(subscribe, () => window.location.hash)
  const [path, query = ''] = hash.replace(/^#/, '').split('?')
  const parts = path.split('/').filter(Boolean)
  return { parts, query: new URLSearchParams(query) }
}

const REVIEWER_KEY = 'sieve.reviewer'

function readReviewer() {
  try {
    return window.localStorage.getItem(REVIEWER_KEY) ?? ''
  } catch {
    return ''
  }
}

export default function App() {
  const route = useRoute()
  const health = useApi('/health')
  const [reviewer, setReviewer] = useState(readReviewer)

  function changeReviewer(value) {
    setReviewer(value)
    try {
      window.localStorage.setItem(REVIEWER_KEY, value)
    } catch {
      // Without storage the name lasts until the page is reloaded.
    }
  }

  const api = health.loading ? 'checking' : health.data?.status === 'ok' ? 'up' : 'down'
  const [page, id] = route.parts

  return (
    <div className="app">
      <header className="topbar">
        <nav>
          <a className="brand" href="#/">
            Sieve
          </a>
          <a className="nav-link active" href="#/">
            Review
          </a>
        </nav>
        <div className="topbar-right">
          <label className="reviewer">
            researcher:
            <input
              value={reviewer}
              onChange={(event) => changeReviewer(event.target.value)}
              placeholder="your name"
              maxLength={200}
            />
          </label>
          <span className={`api api-${api}`}>API {api}</span>
        </div>
      </header>

      <main>
        {page === 'findings' && id ? (
          <FindingDetail key={id} findingId={id} reviewer={reviewer.trim()} />
        ) : (
          <Queue scanId={page === 'scans' ? id : null} query={route.query} />
        )}
      </main>
    </div>
  )
}
