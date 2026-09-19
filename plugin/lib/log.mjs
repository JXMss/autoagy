// Append-only decision log: $AUTOAGY_HOME/logs/decisions.jsonl

import fs from 'node:fs';
import path from 'node:path';

const MAX_LOG_BYTES = 5 * 1024 * 1024;

export function logDir(autoagyHome) {
  return path.join(autoagyHome, 'logs');
}

export function decisionLogPath(autoagyHome) {
  return path.join(logDir(autoagyHome), 'decisions.jsonl');
}

export function appendDecision(autoagyHome, record) {
  const file = decisionLogPath(autoagyHome);
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    try {
      if (fs.statSync(file).size > MAX_LOG_BYTES) fs.renameSync(file, file.replace(/\.jsonl$/, '.1.jsonl'));
    } catch {
      // no log yet
    }
    fs.appendFileSync(file, `${JSON.stringify({ time: new Date().toISOString(), ...record })}\n`);
  } catch {
    // Logging must never break a hook.
  }
}

/** Returns the last `limit` records, oldest first. */
export function readDecisions(autoagyHome, limit = 50) {
  const file = decisionLogPath(autoagyHome);
  let text = '';
  try {
    const size = fs.statSync(file).size;
    const start = Math.max(0, size - 1024 * 1024);
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(size - start);
      fs.readSync(fd, buf, 0, buf.length, start);
      text = buf.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return [];
  }
  const records = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line));
    } catch {
      // partial first line
    }
  }
  return records.slice(-limit);
}

/** Keeps the full reviewer exchange when `log.reviews` is enabled. */
export function writeReviewRecord(autoagyHome, id, data) {
  try {
    const dir = path.join(logDir(autoagyHome), 'reviews');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(data, null, 2));
  } catch {
    // best effort
  }
}
