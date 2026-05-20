import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'

const VALID_TARGET = /^[a-zA-Z0-9.\-_:]+$/
const TIMEOUT_MS = 180_000 // 3 minutes

export async function POST(request: NextRequest) {
  let body: { target?: string; use_ai?: boolean }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const { target, use_ai = false } = body

  if (!target || typeof target !== 'string' || target.trim() === '') {
    return NextResponse.json({ error: 'Target is required' }, { status: 400 })
  }

  if (!VALID_TARGET.test(target.trim())) {
    return NextResponse.json(
      { error: 'Invalid target format. Use an IP, hostname, or domain (e.g. 10.10.11.21, target.htb)' },
      { status: 400 }
    )
  }

  const args = ['scan', target.trim()]
  if (!use_ai) args.push('--no-ai')

  return new Promise<NextResponse>((resolve) => {
    let stdout = ''
    let stderr = ''
    let settled = false

    const child = spawn('reconai', args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env },
    })

    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString() })
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString() })

    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      child.kill()
      resolve(NextResponse.json({ error: 'Scan timed out after 3 minutes' }, { status: 504 }))
    }, TIMEOUT_MS)

    child.on('close', (code) => {
      if (settled) return
      settled = true
      clearTimeout(timer)

      if (code === 0) {
        resolve(NextResponse.json({ success: true, output: stdout }))
      } else {
        const message = stderr.trim() || stdout.trim() || 'Scan process exited with an error'
        resolve(NextResponse.json({ error: message }, { status: 500 }))
      }
    })

    child.on('error', (err) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(
        NextResponse.json(
          { error: `Could not start scan: ${err.message}. Make sure reconai is installed (pip install -e .).` },
          { status: 500 }
        )
      )
    })
  })
}
