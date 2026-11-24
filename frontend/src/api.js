import { useEffect, useState } from 'react'

// Every call goes to /api, which nginx (or the Vite dev server) forwards to the
// back end with the API token, so the token never reaches the browser.

export class ApiError extends Error {
  constructor(status, detail) {
    super(describe(status, detail))
    this.status = status
  }
}

function describe(status, detail) {
  if (Array.isArray(detail)) {
    // FastAPI's validation errors: one entry per field.
    return detail.map((item) => `${item.loc?.slice(1).join('.') || 'body'}: ${item.msg}`).join('; ')
  }
  if (typeof detail === 'string') return detail
  if (status === 401) return 'The API refused the token. Check SIEVE_API_TOKEN in .env.'
  if (status === 503) return 'The back end is not ready: check SIEVE_API_TOKEN and DATABASE_URL in .env.'
  return `The API answered ${status}.`
}

async function request(path, options) {
  let response
  try {
    response = await fetch(`/api${path}`, options)
  } catch {
    throw new ApiError(0, 'The back end does not answer. Is it running?')
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) throw new ApiError(response.status, body?.detail)
  return body
}

export function getJson(path) {
  return request(path, { headers: { Accept: 'application/json' } })
}

export function postJson(path, body) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  })
}

// Reads path, and reads it again after reload(). While a new path loads, data
// is null; while the same path reloads, the old data stays on screen.
export function useApi(path) {
  const [version, setVersion] = useState(0)
  const [result, setResult] = useState({ path: null, version: -1, data: null, error: null })

  useEffect(() => {
    if (!path) return undefined
    let live = true
    getJson(path).then(
      (data) => live && setResult({ path, version, data, error: null }),
      (error) => live && setResult({ path, version, data: null, error }),
    )
    return () => {
      live = false
    }
  }, [path, version])

  const samePath = result.path === path
  return {
    data: samePath ? result.data : null,
    error: samePath ? result.error : null,
    loading: Boolean(path) && (!samePath || result.version !== version),
    reload: () => setVersion((v) => v + 1),
  }
}
