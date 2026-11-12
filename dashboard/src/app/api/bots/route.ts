import { NextResponse } from 'next/server';
import { exec, spawn } from 'child_process';
import net from 'net';
import path from 'path';

const BOTS = {
  vulnerable: { port: 9001, module: 'target.vulnerable_chatbot:app' },
  partial: { port: 9002, module: 'target.partial_chatbot:app' },
  secure: { port: 9003, module: 'target.secure_chatbot:app' },
};

// Check if a port is in use by trying to connect to it
const checkPort = (port: number): Promise<boolean> => {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(500);
    
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.once('error', () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.connect(port, '127.0.0.1');
  });
};

export async function GET() {
  const statuses = await Promise.all(
    Object.entries(BOTS).map(async ([id, config]) => {
      const isRunning = await checkPort(config.port);
      return {
        id,
        port: config.port,
        status: isRunning ? 'online' : 'offline',
        url: `http://localhost:${config.port}`,
      };
    })
  );

  return NextResponse.json({ bots: statuses });
}

export async function POST(request: Request) {
  try {
    const { id, action } = await request.json();

    if (!BOTS[id as keyof typeof BOTS]) {
      return NextResponse.json({ error: 'Invalid bot ID' }, { status: 400 });
    }

    const bot = BOTS[id as keyof typeof BOTS];

    if (action === 'start') {
      const isRunning = await checkPort(bot.port);
      if (isRunning) {
        return NextResponse.json({ success: true, message: 'Already running' });
      }

      // Resolve saife root: one level up from the dashboard directory
      const cwd = path.resolve(process.cwd(), process.cwd().endsWith('dashboard') ? '..' : '.');
      // Resolve to absolute path so the venv is activated correctly
      const isWin = path.sep === '\\';
      const venvUvicorn = path.resolve(cwd, isWin ? '.venv/Scripts/uvicorn.exe' : '.venv/bin/uvicorn');

      let child;
      if (isWin) {
        child = spawn('cmd.exe', ['/c', `"${venvUvicorn}" ${bot.module} --port ${bot.port}`], { cwd, detached: true, stdio: 'ignore', windowsHide: true });
      } else {
        child = spawn('sh', ['-c', `("${venvUvicorn}" ${bot.module} --port ${bot.port} || ./.venv/bin/uvicorn ${bot.module} --port ${bot.port} || uvicorn ${bot.module} --port ${bot.port})`], { cwd, detached: true, stdio: 'ignore' });
      }

      child.on('error', (err) => {
        console.error('Failed to start bot subprocess:', err);
      });

      child.unref();

      // Wait for uvicorn to initialize, then verify it actually started
      await new Promise(resolve => setTimeout(resolve, 2000));
      const started = await checkPort(bot.port);
      return NextResponse.json({ success: started, message: started ? 'Bot started' : 'Failed to start bot' });

    } else if (action === 'stop') {
      // Find and kill the process using the port
      return new Promise((resolve) => {
        const isWin = path.sep === '\\';
        const cmd = isWin 
          ? `FOR /F "tokens=5" %P IN ('netstat -aon ^| findstr :${bot.port}') DO taskkill /F /PID %P`
          : `lsof -ti:${bot.port} | xargs kill -9`;
        exec(cmd, (_error) => {
          // Even if error occurs (e.g. not found), we return success
          resolve(NextResponse.json({ success: true, message: 'Bot stopped' }));
        });
      });
    }

    return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
