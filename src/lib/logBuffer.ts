import fs from 'fs';
import fsPromises from 'fs/promises';
import path from 'path';
import zlib from 'zlib';

type LogEntry = {
  level: string;
  time: number;
  msg: string;
  pid?: number;
  host?: string;
  url?: string;
  [k: string]: any;
};

const MAX_LOGS = 2000;
const buffer: LogEntry[] = [];

const LOG_DIR = path.resolve(process.cwd(), 'logs');
let currentStream: fs.WriteStream | null = null;
let currentFile: string | null = null;

async function ensureLogDir() {
  await fsPromises.mkdir(LOG_DIR, { recursive: true });
}

function chunkStartFor(date = new Date()) {
  const yyyy = date.getFullYear();
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const dd = String(date.getDate()).padStart(2, '0');
  const hour = date.getHours();
  const startHour = Math.floor(hour / 2) * 2;
  const hh = String(startHour).padStart(2, '0');
  return `${yyyy}${mm}${dd}-${hh}00`;
}

function filenameForChunk(startLabel: string) {
  return path.join(LOG_DIR, `logs-${startLabel}.txt`);
}

async function openStreamForNow() {
  await ensureLogDir();
  const label = chunkStartFor(new Date());
  const file = filenameForChunk(label);
  if (currentFile === file && currentStream) return;
  if (currentStream) {
    currentStream.end();
  }
  currentFile = file;
  currentStream = fs.createWriteStream(file, { flags: 'a' });
}

function scheduleRotation() {
  const now = new Date();
  const hour = now.getHours();
  const startHour = Math.floor(hour / 2) * 2;
  const nextStart = new Date(now);
  nextStart.setHours(startHour + 2, 0, 0, 0);
  const delay = nextStart.getTime() - now.getTime();
  setTimeout(async () => {
    const oldFile = currentFile;
    if (currentStream) currentStream.end();
    currentStream = null;
    currentFile = null;
    // gzip old file
    if (oldFile) {
      const gzFile = oldFile + '.gz';
      try {
        await new Promise((resolve, reject) => {
          const inp = fs.createReadStream(oldFile);
          const out = fs.createWriteStream(gzFile);
          const gz = zlib.createGzip({ level: 9 });
          inp.pipe(gz).pipe(out).on('finish', resolve).on('error', reject);
        });
        await fsPromises.unlink(oldFile);
      } catch (e) {
        // ignore gzip errors
      }
    }
    await openStreamForNow();
    scheduleRotation();
  }, delay);
}

// Initialize
(async () => {
  try {
    await openStreamForNow();
    scheduleRotation();
  } catch (e) {
    // ignore init errors
  }
})();

export function addLog(entry: LogEntry) {
  buffer.push(entry);
  if (buffer.length > MAX_LOGS) buffer.shift();
  // write to current file as JSON line
  try {
    if (!currentStream) {
      openStreamForNow().catch(() => {});
    }
    const line = JSON.stringify(entry) + '\n';
    currentStream?.write(line);
  } catch (e) {
    // ignore file write errors
  }
}

export function getLogs(since = 0, options?: { excludeAdmin?: boolean }) {
  const excludeAdmin = options?.excludeAdmin ?? true;
  let entries = since ? buffer.filter((l) => l.time > since) : buffer.slice();
  if (excludeAdmin) {
    entries = entries.filter((e) => {
      const url = (e.url || '').toString();
      if (!url) return true;
      return !url.startsWith('/admin');
    });
  }
  return entries;
}

export function clearLogs() {
  buffer.length = 0;
}

export type { LogEntry };
