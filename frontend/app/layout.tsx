import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'ReconAI — Offensive Recon Orchestrator',
  description: 'AI-powered recon dashboard for authorized pentesting',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#0d1117] text-[#e6edf3] font-sans antialiased">
        <nav className="border-b border-[#30363d] bg-[#161b22] sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center gap-3">
            {/* Logo mark */}
            <div className="flex items-center justify-center w-8 h-8 rounded bg-[#ff4444]/10 border border-[#ff4444]/30">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <path d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z" stroke="#ff4444" strokeWidth="1.5" fill="none" />
                <path d="M8 5L11 6.75V10.25L8 12L5 10.25V6.75L8 5Z" fill="#ff4444" fillOpacity="0.4" />
              </svg>
            </div>
            <span className="text-[#ff4444] font-mono font-bold text-lg tracking-tight">ReconAI</span>
            <span className="text-[#30363d] text-sm">|</span>
            <span className="text-[#8b949e] text-sm font-mono">Offensive Recon Orchestrator</span>
            <div className="ml-auto flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-mono bg-[#ff4444]/10 border border-[#ff4444]/20 text-[#ff4444]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#ff4444] animate-pulse" />
                AUTHORIZED USE ONLY
              </span>
            </div>
          </div>
        </nav>

        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>

        <footer className="border-t border-[#30363d] mt-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <p className="text-[#8b949e] text-xs font-mono text-center">
              Copyright © 2025 Desarrollado desde Las Breñas con 💜 por{' '}
              <a
                href="https://www.linkedin.com/in/jmsilva83"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#8b5cf6] hover:text-[#a78bfa] transition-colors"
              >
                @jmsDev
              </a>{' '}
              All rights reserved
            </p>
          </div>
        </footer>
      </body>
    </html>
  )
}
