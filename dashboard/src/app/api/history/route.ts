import { NextResponse } from 'next/server';
import { spawnSync } from 'child_process';
import path from 'path';

function venvPythonAndCwd() {
  const cwd = path.resolve(process.cwd(), process.cwd().endsWith('dashboard') ? '..' : '.');
  const isWin = path.sep === '\\';
  return { cwd, venvPython: path.resolve(cwd, isWin ? '.venv/Scripts/python.exe' : '.venv/bin/python') };
}

export async function DELETE() {
  const { cwd, venvPython } = venvPythonAndCwd();
  const result = spawnSync(venvPython, ['cli_history.py', '--clear'], { cwd, encoding: 'utf8' });
  if (result.error) return NextResponse.json({ cleared: false, error: result.error.message });
  return NextResponse.json({ cleared: true });
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('target');
  const { cwd, venvPython } = venvPythonAndCwd();

  const args = ['cli_history.py', ...(target ? [target] : [])];
  const result = spawnSync(venvPython, args, { cwd, encoding: 'utf8' });

  if (result.error) return NextResponse.json({ history: [], error: result.error.message });

  try {
    const history = JSON.parse(result.stdout);
    return NextResponse.json({ history });
  } catch {
    return NextResponse.json({ history: [], error: result.stderr?.slice(0, 200) });
  }
}
