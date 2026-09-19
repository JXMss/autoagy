// A small POSIX shell parser for static command classification.
//
// It never executes anything. It extracts every literal command (argv) it can
// find — including commands nested in $(...), backticks, <(...), >(...),
// subshells, and heredoc bodies that expand substitutions — and records the
// shell features that make static reasoning unreliable, so callers can fail
// safe (route to review) whenever the picture is incomplete.

export const MAX_NESTING_DEPTH = 8;

const WORD_BREAK = new Set([' ', '\t', '\n', ';', '&', '|', '(', ')', '<', '>']);
// Reserved words that may precede a command in the same simple-command slot.
const PREFIX_WORDS = new Set(['if', 'then', 'elif', 'else', 'do', 'while', 'until', '!', 'time', '{']);
const TERMINATOR_WORDS = new Set(['fi', 'done', '}']);
const NULL_DEVICES = new Set(['/dev/null', '/dev/stdout', '/dev/stderr', '/dev/tty', 'nul', 'NUL']);
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/;

/**
 * @typedef {{ text: string, dynamic: boolean, glob: boolean, quoted: boolean }} Word
 * @typedef {{ op: string, fd: string | null, target: string, dynamic?: boolean }} Redirect
 * @typedef {{
 *   argv: string[], words: Word[], assignments: string[], redirects: Redirect[],
 *   heredocs: { delimiter: string, body: string, quoted: boolean }[],
 *   background: boolean, nested: boolean, depth: number,
 * }} Command
 * @typedef {{ commands: Command[], features: Set<string>, error: string | null }} ParseResult
 */

/**
 * Parses a shell script.
 * @param {string} source
 * @param {number} [depth]
 * @returns {ParseResult}
 */
export function parseShell(source, depth = 0) {
  const parser = new Parser(String(source ?? ''), depth);
  parser.run();
  return { commands: parser.commands, features: parser.features, error: parser.error };
}

function newCommand() {
  return { words: [], assignments: [], redirects: [], heredocs: [], background: false };
}

class Parser {
  constructor(src, depth) {
    this.src = src;
    this.n = src.length;
    this.i = 0;
    this.depth = depth;
    /** @type {Command[]} */
    this.commands = [];
    this.nestedCommands = [];
    this.features = new Set();
    this.error = null;
    this.cur = newCommand();
    this.pendingHeredocs = [];
    // case/esac tracking
    this.caseHeader = false;
    this.caseDepth = 0;
    this.expectPattern = false;
    // for/select headers and `function name`
    this.skipUntilSeparator = false;
    this.skipNextWord = false;
  }

  fail(message) {
    if (!this.error) this.error = message;
    this.features.add('parse-error');
  }

  run() {
    const { src } = this;
    while (this.i < this.n) {
      const c = src[this.i];
      const next = src[this.i + 1];
      if (c === ' ' || c === '\t' || c === '\r') {
        this.i++;
        continue;
      }
      if (c === '\\' && next === '\n') {
        this.i += 2;
        continue;
      }
      if (c === '\n') {
        this.i++;
        this.endCommand();
        this.readPendingHeredocs();
        continue;
      }
      if (c === '#') {
        this.features.add('comment');
        while (this.i < this.n && src[this.i] !== '\n') this.i++;
        continue;
      }
      if (c === ';') {
        // ;; ;& ;;& end a case branch.
        if (next === ';' || next === '&') {
          this.i += next === ';' && src[this.i + 2] === '&' ? 3 : 2;
          this.endCommand();
          if (this.caseDepth > 0) this.expectPattern = true;
          continue;
        }
        this.i++;
        this.endCommand();
        continue;
      }
      if (c === '&') {
        if (next === '&') {
          this.i += 2;
          this.endCommand();
          continue;
        }
        if (next === '>') {
          const op = src[this.i + 2] === '>' ? '&>>' : '&>';
          this.i += op.length;
          this.readRedirectTarget(op, null);
          continue;
        }
        this.i++;
        this.cur.background = true;
        this.features.add('background');
        this.endCommand();
        continue;
      }
      if (c === '|') {
        if (this.expectPattern) {
          // Alternative separator inside a case pattern.
          this.i++;
          continue;
        }
        this.i += next === '|' || next === '&' ? 2 : 1;
        this.endCommand();
        continue;
      }
      if (c === '(') {
        if (next === '(' && this.cur.words.length === 0) {
          // Arithmetic command ((...)).
          const end = this.scanBalanced(this.i + 2, '(', ')', 2);
          if (end < 0) return this.fail('unterminated arithmetic command');
          this.features.add('arith');
          this.scanForSubstitutions(src.slice(this.i + 2, end - 2));
          this.i = end;
          continue;
        }
        if (this.cur.words.length === 1 && this.peekNonSpace(this.i + 1) === ')') {
          // Function definition: name() compound-command
          this.features.add('function');
          this.cur.words = [];
          this.i = src.indexOf(')', this.i) + 1;
          continue;
        }
        if (this.expectPattern) {
          // Optional leading paren of a case pattern.
          this.i++;
          continue;
        }
        this.features.add('subshell');
        this.i++;
        this.endCommand();
        continue;
      }
      if (c === ')') {
        this.i++;
        if (this.expectPattern) {
          this.expectPattern = false;
          this.cur = newCommand();
          continue;
        }
        this.endCommand();
        continue;
      }
      if (c === '<' || c === '>') {
        this.readRedirect(null);
        continue;
      }
      if (c >= '0' && c <= '9') {
        let j = this.i;
        while (j < this.n && src[j] >= '0' && src[j] <= '9') j++;
        if (src[j] === '<' || src[j] === '>') {
          const fd = src.slice(this.i, j);
          this.i = j;
          this.readRedirect(fd);
          continue;
        }
      }
      const word = this.readWord();
      if (this.error) break;
      this.addWord(word);
    }
    this.endCommand();
    if (this.pendingHeredocs.length > 0) {
      this.features.add('heredoc');
      this.pendingHeredocs = [];
    }
    this.commands.push(...this.nestedCommands);
  }

  peekNonSpace(j) {
    while (j < this.n && (this.src[j] === ' ' || this.src[j] === '\t')) j++;
    return this.src[j];
  }

  addWord(word) {
    if (this.caseHeader) {
      if (!word.quoted && word.text === 'in') {
        this.caseHeader = false;
        this.expectPattern = true;
      }
      return;
    }
    if (this.expectPattern) {
      if (!word.quoted && word.text === 'esac') {
        this.caseDepth = Math.max(0, this.caseDepth - 1);
        this.expectPattern = false;
      }
      // Pattern words are not commands.
      return;
    }
    if (this.skipUntilSeparator) return;
    if (this.skipNextWord) {
      this.skipNextWord = false;
      return;
    }
    const cur = this.cur;
    if (cur.words.length === 0) {
      const assignment = ASSIGNMENT_RE.exec(word.text);
      if (assignment && assignment[0].length <= (word.plainPrefix ?? 0)) {
        cur.assignments.push(word.text);
        this.features.add('assignment');
        return;
      }
      if (!word.quoted) {
        const t = word.text;
        if (t === 'case') {
          this.caseHeader = true;
          this.caseDepth++;
          this.features.add('control-flow');
          return;
        }
        if (t === 'esac') {
          this.caseDepth = Math.max(0, this.caseDepth - 1);
          return;
        }
        if (t === 'for' || t === 'select') {
          this.skipUntilSeparator = true;
          this.features.add('control-flow');
          return;
        }
        if (t === 'function') {
          this.skipNextWord = true;
          this.features.add('function');
          return;
        }
        if (PREFIX_WORDS.has(t)) {
          if (t !== '{' && t !== '!' && t !== 'time') this.features.add('control-flow');
          return;
        }
        if (TERMINATOR_WORDS.has(t)) return;
      }
    }
    cur.words.push(word);
  }

  endCommand() {
    const cur = this.cur;
    this.skipUntilSeparator = false;
    this.skipNextWord = false;
    if (cur.words.length || cur.assignments.length || cur.redirects.length || cur.heredocs.length) {
      this.commands.push(this.finish(cur, false));
    }
    this.cur = newCommand();
  }

  finish(cur, nested) {
    const command = {
      argv: cur.words.map((w) => w.text),
      words: cur.words,
      assignments: cur.assignments,
      redirects: cur.redirects,
      heredocs: cur.heredocs,
      background: cur.background,
      nested,
      depth: this.depth,
    };
    cur.finished = command;
    return command;
  }

  readWord() {
    const { src } = this;
    let text = '';
    let dynamic = false;
    let glob = false;
    let quoted = false;
    let openBracket = false;
    // Length of the leading text produced by plain (unquoted, unexpanded) characters.
    let plainPrefix = -1;
    while (this.i < this.n) {
      const c = src[this.i];
      if (WORD_BREAK.has(c)) break;
      if (plainPrefix < 0 && (c === '\\' || c === "'" || c === '"' || c === '$' || c === '`')) {
        plainPrefix = text.length;
      }
      if (c === '\\') {
        if (src[this.i + 1] === '\n') {
          this.i += 2;
          continue;
        }
        if (this.i + 1 < this.n) text += src[this.i + 1];
        this.i += 2;
        quoted = true;
        continue;
      }
      if (c === "'") {
        const end = src.indexOf("'", this.i + 1);
        if (end < 0) {
          this.fail('unterminated single quote');
          text += src.slice(this.i + 1);
          this.i = this.n;
          break;
        }
        text += src.slice(this.i + 1, end);
        this.i = end + 1;
        quoted = true;
        continue;
      }
      if (c === '"') {
        const r = this.readDoubleQuoted(this.i + 1);
        text += r.text;
        dynamic = dynamic || r.dynamic;
        this.i = r.end;
        quoted = true;
        continue;
      }
      if (c === '$') {
        const r = this.readDollar(this.i);
        text += r.text;
        dynamic = dynamic || r.dynamic;
        quoted = quoted || r.quoted;
        this.i = r.end;
        continue;
      }
      if (c === '`') {
        const r = this.readBacktick(this.i + 1);
        text += r.text;
        dynamic = true;
        this.i = r.end;
        continue;
      }
      if (c === '*' || c === '?') glob = true;
      if (c === '[') openBracket = true;
      if (c === ']' && openBracket) glob = true;
      if (c === '{' && /^\{[^{}\s]*(,|\.\.)[^{}\s]*\}/.test(src.slice(this.i))) {
        this.features.add('brace-expansion');
      }
      text += c;
      this.i++;
    }
    if (glob) this.features.add('glob');
    return { text, dynamic, glob, quoted, plainPrefix: plainPrefix < 0 ? text.length : plainPrefix };
  }

  readDoubleQuoted(start) {
    const { src } = this;
    let text = '';
    let dynamic = false;
    let i = start;
    while (i < this.n) {
      const c = src[i];
      if (c === '"') return { text, dynamic, end: i + 1 };
      if (c === '\\') {
        const d = src[i + 1];
        if (d === '$' || d === '`' || d === '"' || d === '\\') {
          text += d;
          i += 2;
          continue;
        }
        if (d === '\n') {
          i += 2;
          continue;
        }
        text += c;
        i++;
        continue;
      }
      if (c === '$') {
        const r = this.readDollar(i);
        text += r.text;
        dynamic = dynamic || r.dynamic;
        i = r.end;
        continue;
      }
      if (c === '`') {
        const r = this.readBacktick(i + 1);
        text += r.text;
        dynamic = true;
        i = r.end;
        continue;
      }
      text += c;
      i++;
    }
    this.fail('unterminated double quote');
    return { text, dynamic, end: this.n };
  }

  readDollar(i) {
    const { src } = this;
    const next = src[i + 1];
    if (next === '(') {
      if (src[i + 2] === '(') {
        const end = this.scanBalanced(i + 3, '(', ')', 2);
        if (end < 0) {
          this.fail('unterminated arithmetic expansion');
          return { text: src.slice(i), dynamic: true, end: this.n };
        }
        this.features.add('arith');
        this.scanForSubstitutions(src.slice(i + 3, end - 2));
        return { text: src.slice(i, end), dynamic: true, end };
      }
      const end = this.scanBalanced(i + 2, '(', ')', 1);
      if (end < 0) {
        this.fail('unterminated command substitution');
        return { text: src.slice(i), dynamic: true, end: this.n };
      }
      this.features.add('substitution');
      this.nested(src.slice(i + 2, end - 1));
      return { text: src.slice(i, end), dynamic: true, end };
    }
    if (next === '{') {
      const end = this.scanBalanced(i + 2, '{', '}', 1);
      if (end < 0) {
        this.fail('unterminated parameter expansion');
        return { text: src.slice(i), dynamic: true, end: this.n };
      }
      this.features.add('variable');
      this.scanForSubstitutions(src.slice(i + 2, end - 1));
      return { text: src.slice(i, end), dynamic: true, end };
    }
    if (next === "'") {
      // ANSI-C quoting.
      let j = i + 2;
      let text = '';
      while (j < this.n && src[j] !== "'") {
        if (src[j] === '\\' && j + 1 < this.n) {
          const e = src[j + 1];
          const map = { n: '\n', t: '\t', r: '\r', '\\': '\\', "'": "'", '"': '"', a: '\x07', b: '\b', e: '\x1b', f: '\f', v: '\v', '0': '\0' };
          text += map[e] ?? e;
          j += 2;
          continue;
        }
        text += src[j];
        j++;
      }
      if (j >= this.n) this.fail('unterminated ANSI-C quote');
      return { text, dynamic: false, quoted: true, end: Math.min(j + 1, this.n) };
    }
    if (next === '"') {
      const r = this.readDoubleQuoted(i + 2);
      return { text: r.text, dynamic: r.dynamic, quoted: true, end: r.end };
    }
    if (next !== undefined && /[A-Za-z_]/.test(next)) {
      let j = i + 1;
      while (j < this.n && /[A-Za-z0-9_]/.test(src[j])) j++;
      this.features.add('variable');
      return { text: src.slice(i, j), dynamic: true, end: j };
    }
    if (next !== undefined && /[0-9@*#?$!-]/.test(next)) {
      this.features.add('variable');
      return { text: src.slice(i, i + 2), dynamic: true, end: i + 2 };
    }
    return { text: '$', dynamic: false, end: i + 1 };
  }

  readBacktick(start) {
    const { src } = this;
    let inner = '';
    let i = start;
    while (i < this.n && src[i] !== '`') {
      if (src[i] === '\\' && i + 1 < this.n && '$`\\'.includes(src[i + 1])) {
        inner += src[i + 1];
        i += 2;
        continue;
      }
      inner += src[i];
      i++;
    }
    if (i >= this.n) {
      this.fail('unterminated backtick substitution');
      return { text: '`' + inner, end: this.n };
    }
    this.features.add('substitution');
    this.nested(inner);
    return { text: '`' + inner + '`', end: i + 1 };
  }

  /**
   * Returns the index just past the closing delimiter(s), or -1.
   * Understands quotes, escapes and nested substitutions.
   */
  scanBalanced(start, open, close, closeCount) {
    const { src } = this;
    let depth = 0;
    let i = start;
    while (i < this.n) {
      const c = src[i];
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === "'") {
        const end = src.indexOf("'", i + 1);
        if (end < 0) return -1;
        i = end + 1;
        continue;
      }
      if (c === '"') {
        let j = i + 1;
        while (j < this.n && src[j] !== '"') {
          if (src[j] === '\\') j++;
          j++;
        }
        if (j >= this.n) return -1;
        i = j + 1;
        continue;
      }
      if (c === '`') {
        let j = i + 1;
        while (j < this.n && src[j] !== '`') {
          if (src[j] === '\\') j++;
          j++;
        }
        if (j >= this.n) return -1;
        i = j + 1;
        continue;
      }
      if (c === open) {
        depth++;
        i++;
        continue;
      }
      if (c === close) {
        if (depth === 0) {
          if (closeCount === 2) {
            if (src[i + 1] === close) return i + 2;
            // A lone close inside arithmetic: keep scanning.
            i++;
            continue;
          }
          return i + 1;
        }
        depth--;
        i++;
        continue;
      }
      i++;
    }
    return -1;
  }

  readRedirect(fd) {
    const { src } = this;
    const rest = src.slice(this.i, this.i + 3);
    let op;
    for (const candidate of ['<<<', '<<-', '<<', '<&', '<>', '<(', '>>', '>&', '>|', '>(', '<', '>']) {
      if (rest.startsWith(candidate)) {
        op = candidate;
        break;
      }
    }
    if (op === '<(' || op === '>(') {
      const end = this.scanBalanced(this.i + 2, '(', ')', 1);
      if (end < 0) return this.fail('unterminated process substitution');
      this.features.add('process-substitution');
      this.nested(src.slice(this.i + 2, end - 1));
      this.addWord({ text: src.slice(this.i, end), dynamic: true, glob: false, quoted: false });
      this.i = end;
      return;
    }
    this.i += op.length;
    this.readRedirectTarget(op, fd);
  }

  readRedirectTarget(op, fd) {
    while (this.i < this.n && (this.src[this.i] === ' ' || this.src[this.i] === '\t')) this.i++;
    const target = this.readWord();
    if (op === '<<' || op === '<<-') {
      this.features.add('heredoc');
      this.cur.redirects.push({ op, fd, target: target.text });
      this.pendingHeredocs.push({ delimiter: target.text, strip: op === '<<-', quoted: target.quoted, owner: this.cur });
      return;
    }
    if (op === '<<<') {
      this.features.add('herestring');
      this.cur.redirects.push({ op, fd, target: target.text, dynamic: target.dynamic });
      return;
    }
    if (op === '>&' || op === '<&') {
      if (/^(\d+|-)$/.test(target.text)) {
        this.cur.redirects.push({ op, fd, target: target.text });
        return;
      }
    }
    const writes = op !== '<' && op !== '<&';
    if (writes) {
      this.features.add(NULL_DEVICES.has(target.text) ? 'redirect-null' : 'redirect-write');
    } else {
      this.features.add('redirect-read');
    }
    this.cur.redirects.push({ op, fd, target: target.text, dynamic: target.dynamic });
  }

  readPendingHeredocs() {
    const { src } = this;
    while (this.pendingHeredocs.length > 0) {
      const doc = this.pendingHeredocs.shift();
      const lines = [];
      let found = false;
      while (this.i < this.n) {
        let end = src.indexOf('\n', this.i);
        if (end < 0) end = this.n;
        const raw = src.slice(this.i, end);
        this.i = Math.min(end + 1, this.n);
        const line = doc.strip ? raw.replace(/^\t+/, '') : raw;
        if (line === doc.delimiter) {
          found = true;
          break;
        }
        lines.push(raw);
      }
      if (!found) this.features.add('unterminated-heredoc');
      const body = lines.join('\n');
      const owner = doc.owner.finished ?? doc.owner;
      owner.heredocs.push({ delimiter: doc.delimiter, body, quoted: doc.quoted });
      if (!doc.quoted) this.scanForSubstitutions(body);
    }
  }

  /** Finds $(...) and `...` inside text that the shell will expand. */
  scanForSubstitutions(text) {
    let i = 0;
    while (i < text.length) {
      const c = text[i];
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === '$' && text[i + 1] === '(' && text[i + 2] !== '(') {
        const sub = new Parser(text, this.depth);
        const end = sub.scanBalanced(i + 2, '(', ')', 1);
        if (end < 0) {
          this.fail('unterminated command substitution');
          return;
        }
        this.features.add('substitution');
        this.nested(text.slice(i + 2, end - 1));
        i = end;
        continue;
      }
      if (c === '`') {
        const end = text.indexOf('`', i + 1);
        if (end < 0) {
          this.fail('unterminated backtick substitution');
          return;
        }
        this.features.add('substitution');
        this.nested(text.slice(i + 1, end));
        i = end + 1;
        continue;
      }
      i++;
    }
  }

  nested(script) {
    if (this.depth + 1 > MAX_NESTING_DEPTH) {
      this.features.add('too-deep');
      this.fail('shell nesting too deep');
      return;
    }
    const sub = parseShell(script, this.depth + 1);
    for (const feature of sub.features) this.features.add(feature);
    if (sub.error) this.fail(sub.error);
    for (const command of sub.commands) {
      command.nested = true;
      this.nestedCommands.push(command);
    }
  }
}

/** True when the redirect target is a file (not a null device or fd dup). */
export function isFileWriteRedirect(redirect) {
  if (redirect.op === '<' || redirect.op === '<&' || redirect.op === '<<' || redirect.op === '<<-' || redirect.op === '<<<') {
    return false;
  }
  if ((redirect.op === '>&' || redirect.op === '<&') && /^(\d+|-)$/.test(redirect.target)) return false;
  return !NULL_DEVICES.has(redirect.target);
}

/** Splits a command line into argv the way a POSIX shell would for a single simple command. */
export function splitArgs(text) {
  const parsed = parseShell(text);
  return parsed.commands[0]?.argv ?? [];
}
