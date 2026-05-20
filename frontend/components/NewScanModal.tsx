'use client'

import { useState, useRef, useEffect } from 'react'
import { useRouter } from 'next/navigation'

export function NewScanModal() {
  const [open, setOpen] = useState(false)
  const [target, setTarget] = useState('')
  const [useAi, setUseAi] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const router = useRouter()

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [open])

  // Close on Escape
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') handleClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open])

  function handleClose() {
    if (loading) return
    setOpen(false)
    setError('')
    setDone(false)
    setTarget('')
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!target.trim() || loading) return
    setLoading(true)
    setError('')
    setDone(false)

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), use_ai: useAi }),
      })
      const data = await res.json()

      if (!res.ok) {
        setError(data.error ?? 'Scan failed with an unknown error')
        return
      }

      setDone(true)
      setTimeout(() => {
        handleClose()
        router.refresh()
      }, 1200)
    } catch {
      setError('Could not reach the scan API. Is the Next.js server running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      {/* Trigger button */}
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-mono font-semibold bg-[#ff4444]/10 hover:bg-[#ff4444]/20 border border-[#ff4444]/40 hover:border-[#ff4444]/70 text-[#ff4444] transition-all duration-150"
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
          <circle cx="7" cy="7" r="6" stroke="currentColor" strokeWidth="1.5" />
          <path d="M7 4v6M4 7h6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
        New Scan
      </button>

      {/* Modal overlay */}
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
          onClick={(e) => { if (e.target === e.currentTarget) handleClose() }}
        >
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg w-full max-w-md mx-4 shadow-2xl">
            {/* Header */}
            <div className="px-5 py-4 border-b border-[#30363d] flex items-center gap-3">
              <div className="flex items-center justify-center w-8 h-8 rounded bg-[#ff4444]/10 border border-[#ff4444]/30 flex-shrink-0">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                  <circle cx="8" cy="8" r="6" stroke="#ff4444" strokeWidth="1.5" />
                  <path d="M8 5v6M5 8h6" stroke="#ff4444" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
              </div>
              <div>
                <h2 className="text-sm font-mono font-semibold text-[#e6edf3]">New Scan</h2>
                <p className="text-xs text-[#8b949e] font-mono">Authorized targets only — HTB, THM, RFC1918</p>
              </div>
              <button
                onClick={handleClose}
                disabled={loading}
                className="ml-auto text-[#8b949e] hover:text-[#e6edf3] transition-colors disabled:opacity-40"
                aria-label="Close"
              >
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
              </button>
            </div>

            {/* Body */}
            <form onSubmit={handleSubmit} className="px-5 py-5 space-y-4">
              {/* Target input */}
              <div className="space-y-1.5">
                <label className="block text-xs font-mono text-[#8b949e] uppercase tracking-wider">
                  Target
                </label>
                <input
                  ref={inputRef}
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="10.10.11.21  or  target.htb"
                  disabled={loading || done}
                  className="w-full bg-[#0d1117] border border-[#30363d] focus:border-[#ff4444]/50 focus:ring-1 focus:ring-[#ff4444]/20 rounded-md px-3 py-2.5 text-sm font-mono text-[#e6edf3] placeholder-[#30363d] outline-none transition-all disabled:opacity-50"
                  autoComplete="off"
                  spellCheck={false}
                />
                <p className="text-xs text-[#30363d] font-mono">
                  e.g. 10.10.11.21 · 10.10.10.40 · target.htb · 192.168.1.1
                </p>
              </div>

              {/* AI toggle */}
              <label className="flex items-center gap-3 cursor-pointer group">
                <div className="relative flex-shrink-0">
                  <input
                    type="checkbox"
                    checked={useAi}
                    onChange={(e) => setUseAi(e.target.checked)}
                    disabled={loading || done}
                    className="sr-only"
                  />
                  <div
                    className={`w-9 h-5 rounded-full border transition-all duration-150 ${
                      useAi
                        ? 'bg-[#8b5cf6]/30 border-[#8b5cf6]/60'
                        : 'bg-[#0d1117] border-[#30363d]'
                    }`}
                  >
                    <div
                      className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full transition-all duration-150 ${
                        useAi ? 'translate-x-4 bg-[#8b5cf6]' : 'translate-x-0 bg-[#484f58]'
                      }`}
                    />
                  </div>
                </div>
                <div>
                  <span className="text-sm font-mono text-[#e6edf3] group-hover:text-white transition-colors">
                    AI Analysis
                  </span>
                  <span className="block text-xs font-mono text-[#8b949e]">
                    Uses Claude API — requires ANTHROPIC_API_KEY
                  </span>
                </div>
              </label>

              {/* Error */}
              {error && (
                <div className="flex items-start gap-2 px-3 py-2.5 rounded-md bg-[#ff4444]/5 border border-[#ff4444]/20">
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" className="text-[#ff4444] flex-shrink-0 mt-0.5">
                    <path d="M8 2L2 12h12L8 2z" stroke="currentColor" strokeWidth="1.5" fill="none" />
                    <path d="M8 6v4M8 11.5v.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  <p className="text-xs font-mono text-[#ff4444] leading-relaxed">{error}</p>
                </div>
              )}

              {/* Success */}
              {done && (
                <div className="flex items-center gap-2 px-3 py-2.5 rounded-md bg-[#22c55e]/5 border border-[#22c55e]/20">
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" className="text-[#22c55e] flex-shrink-0">
                    <path d="M3 8l4 4 6-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  <p className="text-xs font-mono text-[#22c55e]">Scan complete — refreshing dashboard…</p>
                </div>
              )}

              {/* Actions */}
              <div className="flex items-center gap-3 pt-1">
                <button
                  type="submit"
                  disabled={!target.trim() || loading || done}
                  className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-md text-sm font-mono font-semibold bg-[#ff4444]/15 hover:bg-[#ff4444]/25 border border-[#ff4444]/40 hover:border-[#ff4444]/70 text-[#ff4444] transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <>
                      <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none">
                        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" strokeOpacity="0.25" />
                        <path d="M12 2a10 10 0 0110 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                      </svg>
                      Scanning…
                    </>
                  ) : (
                    <>
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                        <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.5" />
                        <path d="M6 8l2 2 3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                      Start Scan
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={handleClose}
                  disabled={loading}
                  className="px-4 py-2.5 rounded-md text-sm font-mono text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#30363d]/40 border border-transparent hover:border-[#30363d] transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Cancel
                </button>
              </div>

              {/* Hint */}
              <p className="text-[10px] font-mono text-[#30363d] text-center pt-1">
                Scope: HTB (10.10.x.x) · THM (10.10.x.x, 10.8.x.x) · RFC1918 · *.htb · *.thm
              </p>
            </form>
          </div>
        </div>
      )}
    </>
  )
}
