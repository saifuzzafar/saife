import { NextResponse } from 'next/server';
import { spawn, execSync } from 'child_process';
import path from 'path';

// Kill all zombie scan processes — called before every new scan
export async function DELETE() {
  try { 
    const cmd = path.sep === '\\' 
      ? 'WMIC PROCESS WHERE "CommandLine LIKE \'%cli_json.py%\'" CALL TERMINATE' 
      : 'pkill -f "cli_json.py"';
    execSync(cmd); 
  } catch {}
  return NextResponse.json({ killed: true });
}

export async function POST(request: Request) {
  const { targetUrl, scanDepth = 'full' } = await request.json();
  if (!targetUrl) return NextResponse.json({ error: 'targetUrl is required' }, { status: 400 });

  const depth = ['small', 'medium', 'full'].includes(scanDepth) ? scanDepth : 'full';
  const cwd = path.resolve(process.cwd(), process.cwd().endsWith('dashboard') ? '..' : '.');
  const isWin = path.sep === '\\';
  const venvPython = path.resolve(cwd, isWin ? '.venv/Scripts/python.exe' : '.venv/bin/python');
  const encoder = new TextEncoder();
  const send = (type: string, data: unknown) =>
    encoder.encode(`data: ${JSON.stringify({ type, data })}\n\n`);

  const stream = new ReadableStream({
    start(controller) {
      let closed = false;
      const enqueue = (chunk: Uint8Array) => { if (!closed) try { controller.enqueue(chunk); } catch {} };
      const close   = () => { if (!closed) { closed = true; try { controller.close(); } catch {} } };

      const child = spawn(venvPython, ['cli_json.py', targetUrl, depth], { cwd });
      let stdout = '';

      child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });

      // Stream PROGRESS and RESULT_PARTIAL lines from stderr to the UI in real time
      child.stderr.on('data', (d: Buffer) => {
        for (const line of d.toString().split('\n')) {
          const progIdx = line.indexOf('PROGRESS:');
          if (progIdx !== -1) {
            const msg = line.slice(progIdx + 9).trim();
            if (msg) enqueue(send('progress', msg));
          }
          const partialIdx = line.indexOf('RESULT_PARTIAL:');
          if (partialIdx !== -1) {
            const raw = line.slice(partialIdx + 15).trim();
            try { enqueue(send('partial_result', JSON.parse(raw))); } catch {}
          }
        }
      });

      // Kill Python when client disconnects — no zombies
      request.signal.addEventListener('abort', () => { closed = true; child.kill('SIGTERM'); });

      child.on('close', () => {
        if (closed) { close(); return; }
        try {
          const jsonLine = stdout.split('\n').find(l => l.trim().startsWith('{'));
          if (!jsonLine) throw new Error('No JSON output from scanner');
          enqueue(send('result', JSON.parse(jsonLine.trim())));
        } catch (e: any) {
          enqueue(send('error', e.message));
        }
        close();
      });

      child.on('error', (err) => {
        enqueue(send('error', err.message));
        close();
      });
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
    },
  });
}
