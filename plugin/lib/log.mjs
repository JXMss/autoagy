// Append-only decision log: $AUTOAGY_HOME/logs/decisions.jsonl

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const MAX_LOG_BYTES = 5 * 1024 * 1024;
// Full review records kept under logs/reviews/. Each holds a whole prompt (tens to
// a couple of hundred kilobytes), so this bounds the directory at tens of megabytes.
export const MAX_REVIEW_RECORDS = 200;

export function logDir(autoagyHome) {
  return path.join(autoagyHome, 'logs');
}

export function decisionLogPath(autoagyHome) {
  return path.join(logDir(autoagyHome), 'decisions.jsonl');
}

export function appendDecision(autoagyHome, record) {
  const file = decisionLogPath(autoagyHome);
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
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

/**
 * Every record the log still holds, oldest first: the rotated file, then the
 * current one, each read whole.
 *
 * `readDecisions` reads the last megabyte of the current file, which is right for
 * `autoagy log` and wrong for anything that counts. `stats` used it, so it
 * summarised whatever fitted in that megabyte — the newest tenth or so of a full
 * log (an external audit measured 2904 of 30000) — and never opened the
 * `.1.jsonl` that rotation leaves behind, while reporting its numbers as the
 * whole picture. Rotation caps each file at `MAX_LOG_BYTES`, so this reads at most
 * twice that.
 */
export function readAllDecisions(autoagyHome) {
  const current = decisionLogPath(autoagyHome);
  const records = [];
  for (const file of [current.replace(/\.jsonl$/, '.1.jsonl'), current]) {
    let text = '';
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        records.push(JSON.parse(line));
      } catch {
        // a line cut short by a crash
      }
    }
  }
  return records;
}

/**
 * Keeps the full reviewer exchange when `log.reviews` is enabled.
 *
 * Two things this did not do. The name was `<ms>-<conversation prefix>`, so two
 * reviews in one millisecond — parallel tool calls in one conversation — wrote
 * the same file and one record silently replaced the other; a random suffix and
 * an exclusive create make that impossible. And nothing ever removed a record,
 * so with the setting on the directory grew by a whole prompt per review for as
 * long as it stayed on. The newest `MAX_REVIEW_RECORDS` are kept; the names start
 * with the time, so the oldest sort first.
 */
export function writeReviewRecord(autoagyHome, id, data, { keep = MAX_REVIEW_RECORDS } = {}) {
  try {
    const dir = path.join(logDir(autoagyHome), 'reviews');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, `${id}-${crypto.randomBytes(4).toString('hex')}.json`), JSON.stringify(data, null, 2), { flag: 'wx' });
    const records = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
    for (const old of records.slice(0, Math.max(0, records.length - keep))) fs.rmSync(path.join(dir, old), { force: true });
  } catch {
    // best effort
  }
}
