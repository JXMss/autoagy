// Reviewer model backends.
//
// - agy:    runs the plugin's tool-less `autoagy-guardian` agent headlessly
//           (`agy --agent autoagy-guardian --input-format stream-json ...`).
//           Uses the user's Antigravity login; no API key needed. The agent
//           does not inherit customizations, so these hooks do not recurse.
// - openai: any OpenAI-compatible Chat Completions endpoint (OpenAI, Gemini's
//           OpenAI endpoint, DeepSeek, local servers, ...).
// - mock:   deterministic responses for tests (AUTOAGY_MOCK_REVIEW).

import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { ReviewTimeoutError } from './guardian.mjs';

/**
 * @typedef {{ name: string, review: (prompt: { system: string, user: string }, options: { timeoutMs: number }) => Promise<string> }} Reviewer
 */

/**
 * @param {object} config
 * @param {{ env?: NodeJS.ProcessEnv, autoagyHome: string }} options
 * @returns {Reviewer | null} null when no reviewer model is configured
 */
export function createReviewer(config, { env = process.env, autoagyHome }) {
  if (env.AUTOAGY_MOCK_REVIEW) return mockReviewer(env);
  switch (config.reviewer.backend) {
    case 'agy':
      return agyReviewer(config.reviewer.agy, { env, autoagyHome });
    case 'openai':
      return openaiReviewer(config.reviewer.openai, { env });
    default:
      return null;
  }
}

/** The single message sent to the guardian agent (its system prompt is fixed in the agent file). */
export function agyMessageText({ system, user }) {
  return `<review_policy>\n${system}\n</review_policy>\n\n${user}`;
}

function agyReviewer(options, { env, autoagyHome }) {
  return {
    name: 'agy',
    review(prompt, { timeoutMs }) {
      const cwd = path.join(autoagyHome, 'guardian');
      fs.mkdirSync(cwd, { recursive: true });
      const args = ['--agent', options.agent, '--input-format', 'stream-json', '--output-format', 'stream-json'];
      if (options.model) args.push('--model', options.model);
      if (options.effort) args.push('--effort', options.effort);
      args.push('-p=');
      const line = JSON.stringify({ event: 'user', message: { content: [{ type: 'text', text: agyMessageText(prompt) }] } });
      return new Promise((resolve, reject) => {
        let settled = false;
        let stdout = '';
        let stderr = '';
        const child = spawn(options.command, args, {
          cwd,
          env: { ...env, AUTOAGY_ROLE: 'guardian' },
          stdio: ['pipe', 'pipe', 'pipe'],
          shell: process.platform === 'win32',
          windowsHide: true,
        });
        const finish = (fn, value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          fn(value);
        };
        const timer = setTimeout(() => {
          child.kill('SIGTERM');
          setTimeout(() => child.kill('SIGKILL'), 2000).unref();
          finish(reject, new ReviewTimeoutError(`agy reviewer did not answer within ${Math.round(timeoutMs / 1000)}s`));
        }, timeoutMs);
        child.stdout.on('data', (chunk) => {
          stdout += chunk;
          const result = findResultEvent(stdout);
          if (result) {
            if (result.status === 'SUCCESS' && typeof result.response === 'string') finish(resolve, result.response);
            else finish(reject, new Error(`agy reviewer ${result.status ?? 'failed'}: ${result.error ?? 'no response'}`));
            child.stdin.destroy();
          }
        });
        child.stderr.on('data', (chunk) => {
          stderr = (stderr + chunk).slice(-4000);
        });
        child.on('error', (err) => finish(reject, new Error(`cannot run ${options.command}: ${err.message}`)));
        child.on('close', (code) => {
          const result = findResultEvent(stdout);
          if (result?.status === 'SUCCESS' && typeof result.response === 'string') return finish(resolve, result.response);
          const detail = (result?.error ?? stderr.trim().split('\n').slice(-3).join(' ')) || 'no output';
          finish(reject, new Error(`agy reviewer exited with code ${code}: ${detail}`));
        });
        child.stdin.on('error', () => {});
        child.stdin.end(`${line}\n`);
      });
    },
  };
}

function findResultEvent(stdout) {
  for (const raw of stdout.split('\n')) {
    const text = raw.trim();
    if (!text.startsWith('{') || !text.includes('"result"')) continue;
    try {
      const event = JSON.parse(text);
      if (event.event === 'result' && event.result) return event.result;
    } catch {
      // partial line
    }
  }
  return null;
}

function openaiReviewer(options, { env }) {
  return {
    name: 'openai',
    async review({ system, user }, { timeoutMs }) {
      const key = env[options.apiKeyEnv];
      if (!key) throw new Error(`environment variable ${options.apiKeyEnv} is not set`);
      const body = {
        model: options.model,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      };
      if (options.jsonMode) body.response_format = { type: 'json_object' };
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(`${String(options.baseUrl).replace(/\/+$/, '')}/chat/completions`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${key}`, ...(options.headers ?? {}) },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        const text = await res.text();
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 300)}`);
        const content = JSON.parse(text)?.choices?.[0]?.message?.content;
        if (typeof content !== 'string') throw new Error('response has no message content');
        return content;
      } catch (err) {
        if (err?.name === 'AbortError') throw new ReviewTimeoutError(`reviewer did not answer within ${Math.round(timeoutMs / 1000)}s`);
        throw err;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

const MOCK_RESPONSES = {
  allow: '{"outcome":"allow"}',
  deny: '{"risk_level":"high","user_authorization":"unknown","outcome":"deny","rationale":"mock denial"}',
  critical: '{"risk_level":"critical","user_authorization":"low","outcome":"deny","rationale":"mock critical denial"}',
  garbage: 'not json',
};

function mockReviewer(env) {
  return {
    name: 'mock',
    async review(prompt, { timeoutMs }) {
      if (env.AUTOAGY_MOCK_CAPTURE) fs.appendFileSync(env.AUTOAGY_MOCK_CAPTURE, `${JSON.stringify(prompt)}\n`);
      let spec = env.AUTOAGY_MOCK_REVIEW;
      const sleep = /^sleep:(\d+):(.*)$/s.exec(spec);
      if (sleep) {
        const ms = Number(sleep[1]);
        if (ms >= timeoutMs) {
          await new Promise((r) => setTimeout(r, timeoutMs));
          throw new ReviewTimeoutError();
        }
        await new Promise((r) => setTimeout(r, ms));
        spec = sleep[2];
      }
      if (spec === 'timeout') throw new ReviewTimeoutError();
      if (spec === 'error') throw new Error('mock reviewer error');
      return MOCK_RESPONSES[spec] ?? spec;
    },
  };
}
