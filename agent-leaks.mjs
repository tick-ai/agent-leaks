#!/usr/bin/env node
// agent-leaks: find the secrets your AI agent saw, in the logs it keeps on your machine.
// Plain Node 22, only built-in modules. Reads local files, sends nothing, writes no file.
import { readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const VERSION = '0.1.0';

const KINDS = [
  'private-key', 'anthropic-key', 'openai-key', 'aws-access-key', 'aws-secret-key', 'github-token',
  'slack-token', 'stripe-key', 'google-api-key', 'jwt', 'env-secret',
];
const PLACES = ['prompt', 'agent_message', 'tool_input', 'tool_result'];
const AGENTS = ['claude', 'codex'];

const K = Object.fromEntries(KINDS.map((name, i) => [name, i]));

// The patterns are fixed by the job. Matched with String.prototype.matchAll.
const RE = {
  privateKey: /-----BEGIN [A-Z0-9 ]*PRIVATE[ ]KEY-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE[ ]KEY-----|[\s\S]*$)/g,
  anthropic: /\bsk-ant-[A-Za-z0-9_-]{8,}/g,
  openai: /\bsk-[A-Za-z0-9_-]{20,}/g,
  awsId: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  awsSecret: /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g,
  github: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g,
  slack: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  stripe: /\b[sr]k_live_[A-Za-z0-9]{16,}/g,
  google: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
  jwt: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}/g,
  env: /^([ \t]*(?:export[ \t]+)?)((?=[A-Z])[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD))[ \t]*=(?!=)(.*)$/gm,
};

// ---------------------------------------------------------------- usage

const USAGE = `Usage: agent-leaks [--claude-dir <dir>] [--codex-dir <dir>] [--since <date>] [--kind <kind>]...
                   [--json] [--fail-on]

Finds the secrets that Claude Code and Codex session logs hold, once each, and never prints one in full.

Options:
  --claude-dir <dir>  folder of Claude Code logs (default: ~/.claude/projects)
  --codex-dir <dir>   folder of Codex logs (default: ~/.codex/sessions)
  --since <date>      only read lines from this time on: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS[.f]Z (UTC)
  --kind <kind>       report only this kind; may be repeated (default: all)
  --json              print the report as JSON
  --fail-on           exit with status 1 when the report holds a finding
  -h, --help          print this help

Kinds: ${KINDS.join(', ')}

Exit status: 0 done, 1 a finding with --fail-on, 2 usage error.
`;

class UsageError extends Error {}

function shown(arg) {
  // Echo only what plainly looks like an option name; never echo arbitrary text.
  return /^-{1,2}[A-Za-z0-9][A-Za-z0-9-]{0,30}$/.test(arg) ? arg : 'argument';
}

function parseSince(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z)?$/.exec(value);
  if (!m) return null;
  const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const hour = m[4] === undefined ? 0 : Number(m[4]);
  const minute = m[5] === undefined ? 0 : Number(m[5]);
  const second = m[6] === undefined ? 0 : Number(m[6]);
  const milli = m[7] === undefined ? 0 : Number(m[7].padEnd(3, '0'));
  if (year < 1970 || month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) return null;
  const ms = Date.UTC(year, month - 1, day, hour, minute, second, milli);
  const d = new Date(ms);
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) return null;
  return ms;
}

function parseArgs(argv) {
  const opts = { claudeDir: null, codexDir: null, sinceMs: null, kinds: new Set(), json: false, failOn: false };
  let help = false;
  let error = null;
  const fail = (message) => { if (error === null) error = message; };
  const VALUE = new Set(['--claude-dir', '--codex-dir', '--since', '--kind']);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { help = true; continue; }
    if (arg === '--json') { opts.json = true; continue; }
    if (arg === '--fail-on') { opts.failOn = true; continue; }
    let name = arg;
    let value = null;
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq > 0) { name = arg.slice(0, eq); value = arg.slice(eq + 1); }
    }
    if (!VALUE.has(name)) {
      if (arg.startsWith('-') && arg !== '-') fail(`unknown option ${shown(name)}`);
      else fail('unexpected argument: agent-leaks takes no positional arguments');
      continue;
    }
    if (value === null) {
      if (i + 1 >= argv.length) { fail(`${name} needs a value`); continue; }
      value = argv[++i];
    }
    if (name === '--claude-dir') opts.claudeDir = value;
    else if (name === '--codex-dir') opts.codexDir = value;
    else if (name === '--since') {
      const ms = parseSince(value);
      if (ms === null) fail('--since must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS[.f]Z (UTC, a real date, 1970 or later)');
      else opts.sinceMs = ms;
    } else if (name === '--kind') {
      if (Object.hasOwn(K, value)) opts.kinds.add(value);
      else fail(`unknown kind for --kind; the kinds are: ${KINDS.join(', ')}`);
    }
  }
  if (help) return { help: true };
  if (error !== null) throw new UsageError(error);
  if (opts.kinds.size === 0) for (const k of KINDS) opts.kinds.add(k);
  return opts;
}

// ---------------------------------------------------------------- finding secrets in one text

/** Returns the hits of one text: [{ kind: index, secret }], in kind order. */
function findHits(text) {
  const hits = [];
  if (text.length < 8) return hits; // the shortest secret (an env value) has 8 characters
  let mask = null; // one byte per UTF-16 unit of the text: covered by a kept hit of an earlier kind
  const free = (s, e) => {
    if (mask === null) return true;
    for (let i = s; i < e; i++) if (mask[i] === 1) return false;
    return true;
  };
  const keep = (kind, s, e, secret) => {
    if (mask === null) mask = new Uint8Array(text.length);
    mask.fill(1, s, e);
    hits.push({ kind, secret, s, e });
  };
  const simple = (kind, re) => {
    for (const m of text.matchAll(re)) {
      const s = m.index;
      const e = s + m[0].length;
      if (free(s, e)) keep(kind, s, e, m[0]);
    }
  };

  if (text.includes('-----BEGIN ')) simple(K['private-key'], RE.privateKey);
  if (text.includes('sk-ant-')) simple(K['anthropic-key'], RE.anthropic);
  if (text.includes('sk-')) simple(K['openai-key'], RE.openai);
  let ids = null;
  if (text.includes('AKIA') || text.includes('ASIA')) {
    simple(K['aws-access-key'], RE.awsId);
    ids = hits.filter((h) => h.kind === K['aws-access-key']);
    if (ids.length > 0) {
      for (const m of text.matchAll(RE.awsSecret)) {
        const c = m[0];
        if (!/[a-z]/.test(c) || !/[A-Z]/.test(c) || !/[0-9]/.test(c)) continue;
        const s = m.index;
        const e = s + c.length;
        if (!free(s, e)) continue;
        const next = ids.some((id) => (s >= id.e && s - id.e <= 200) || (e <= id.s && id.s - e <= 200));
        if (next) keep(K['aws-secret-key'], s, e, c);
      }
    }
  }
  if (text.includes('_')) simple(K['github-token'], RE.github);
  if (text.includes('xox')) simple(K['slack-token'], RE.slack);
  if (text.includes('_live_')) simple(K['stripe-key'], RE.stripe);
  if (text.includes('AIza')) simple(K['google-api-key'], RE.google);
  if (text.includes('eyJ')) simple(K.jwt, RE.jwt);
  if (text.includes('=')) {
    for (const m of text.matchAll(RE.env)) {
      const raw = m[3];
      let start = m.index + m[0].length - raw.length;
      let value = raw.trim();
      start += raw.length - raw.trimStart().length;
      if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value[value.length - 1] === value[0]) {
        value = value.slice(1, -1);
        start += 1;
      }
      if (value.length < 8 || value[0] === '$' || value[0] === '<' || value.startsWith('[redacted')) continue;
      const end = start + value.length;
      if (free(start, end)) keep(K['env-secret'], start, end, value);
    }
  }
  return hits;
}

// ---------------------------------------------------------------- reading logs

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function readTime(ts) {
  if (typeof ts !== 'string') return null;
  const ms = Date.parse(ts);
  return Number.isNaN(ms) ? null : ms;
}

/** Every string value in a parsed object or array, at any depth (a bare string is itself one). */
function stringsOf(value, out) {
  const stack = [value];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) for (let i = v.length - 1; i >= 0; i--) stack.push(v[i]);
    else if (v !== null && typeof v === 'object') {
      const values = Object.values(v);
      for (let i = values.length - 1; i >= 0; i--) stack.push(values[i]);
    }
  }
  return out;
}

/** "Values": a string that parses as an object or array stands for it; other strings are one text. */
function valueTexts(value, out) {
  if (typeof value === 'string') {
    let parsed;
    try { parsed = JSON.parse(value); } catch { parsed = undefined; }
    if (parsed !== null && typeof parsed === 'object') stringsOf(parsed, out);
    else out.push(value);
  } else if (value !== null && typeof value === 'object') {
    stringsOf(value, out);
  }
  return out;
}

function joinedTexts(blocks) {
  const parts = [];
  for (const b of blocks) if (b !== null && typeof b === 'object' && typeof b.text === 'string') parts.push(b.text);
  return parts.join('\n');
}

function projectOf(cwd) {
  if (cwd === null) return null;
  const parts = cwd.split(/[\\/]/).filter((p) => p !== '');
  return parts.length > 0 ? parts[parts.length - 1] : null;
}

function claudeTexts(obj, emit) {
  const content = obj.message.content;
  if (obj.isMeta === true) return;
  if (obj.type === 'user') {
    if (typeof content === 'string') emit(content, 0);
    else if (Array.isArray(content)) {
      for (const block of content) {
        if (!isObj(block) || block.type !== 'tool_result') continue;
        const c = block.content;
        if (typeof c === 'string') emit(c, 3);
        else if (Array.isArray(c)) emit(joinedTexts(c), 3);
      }
    }
  } else if (Array.isArray(content)) {
    for (const block of content) {
      if (!isObj(block)) continue;
      if (block.type === 'text') {
        if (typeof block.text === 'string') emit(block.text, 1);
      } else if (block.type === 'tool_use') {
        for (const t of stringsOf(block.input, [])) emit(t, 2);
      }
    }
  }
}

function codexTexts(payload, emit) {
  const type = payload.type;
  if (type === 'message') {
    const role = payload.role;
    if (role !== 'user' && role !== 'assistant') return;
    let text = '';
    if (Array.isArray(payload.content)) {
      for (const b of payload.content) {
        if (isObj(b) && (b.type === 'input_text' || b.type === 'output_text' || b.type === 'text') && typeof b.text === 'string') text += b.text;
      }
    }
    if (role === 'user') {
      if (!text.startsWith('<')) emit(text, 0);
    } else emit(text, 1);
  } else if (type === 'function_call') {
    for (const t of valueTexts(payload.arguments, [])) emit(t, 2);
  } else if (type === 'custom_tool_call') {
    for (const t of valueTexts(payload.input, [])) emit(t, 2);
  } else if (type === 'function_call_output' || type === 'custom_tool_call_output') {
    const out = payload.output;
    if (typeof out === 'string') for (const t of valueTexts(out, [])) emit(t, 3);
    else if (Array.isArray(out)) emit(joinedTexts(out), 3);
  }
}

/** All .jsonl files under dir, any depth, symbolic links not followed. null when dir is no folder. */
function listJsonl(dir) {
  const files = [];
  const stack = [dir];
  while (stack.length > 0) {
    const d = stack.pop();
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) stack.push(join(d, e.name));
      else if (e.isFile() && e.name.endsWith('.jsonl')) files.push(join(d, e.name));
    }
  }
  return files;
}

/**
 * Reads one log file. Returns null when it cannot be read, else a Map of this file's findings
 * (kind + NUL + secret -> { kind, secret, count, first, last, places }) and the file's project.
 */
function scanFile(file, agent, sinceMs) {
  let buf;
  try { buf = readFileSync(file); } catch { return null; }
  const local = new Map();
  let cwd = null;
  let curMs = 0;
  const emit = (text, place) => {
    const hits = findHits(text);
    for (const h of hits) {
      const key = `${h.kind}\0${h.secret}`;
      let f = local.get(key);
      if (f === undefined) {
        f = { kind: h.kind, secret: h.secret, count: 0, first: curMs, last: curMs, places: 0 };
        local.set(key, f);
      }
      f.count += 1;
      if (curMs < f.first) f.first = curMs;
      if (curMs > f.last) f.last = curMs;
      f.places |= 1 << place;
    }
  };
  let pos = 0;
  while (pos < buf.length) {
    let nl = buf.indexOf(10, pos);
    if (nl < 0) nl = buf.length;
    const start = pos;
    pos = nl + 1;
    if (nl === start) continue;
    let obj;
    try { obj = JSON.parse(buf.toString('utf8', start, nl)); } catch { continue; }
    if (!isObj(obj)) continue;
    if (agent === 'claude') {
      if ((obj.type !== 'user' && obj.type !== 'assistant') || !isObj(obj.message)) continue;
      const ms = readTime(obj.timestamp);
      if (ms === null) continue;
      if (cwd === null && typeof obj.cwd === 'string' && obj.cwd !== '') cwd = obj.cwd;
      if (sinceMs !== null && ms < sinceMs) continue;
      curMs = ms;
      claudeTexts(obj, emit);
    } else {
      const payload = obj.payload;
      if (!isObj(payload)) continue;
      if (obj.type === 'session_meta') {
        if (cwd === null && typeof payload.cwd === 'string' && payload.cwd !== '') cwd = payload.cwd;
      } else if (obj.type === 'response_item') {
        const ms = readTime(obj.timestamp);
        if (ms === null || (sinceMs !== null && ms < sinceMs)) continue;
        curMs = ms;
        codexTexts(payload, emit);
      }
    }
  }
  return { local, project: projectOf(cwd) };
}

// ---------------------------------------------------------------- the report

const sha256Of = (secret) => createHash('sha256').update(secret, 'utf8').digest('hex');

function fingerprintOf(secret) {
  const chars = Array.from(secret);
  const n = chars.length >= 16 ? 4 : 2;
  return `${chars.slice(0, n).join('')}…${chars.slice(-n).join('')}`;
}

function run(opts) {
  const home = homedir();
  const dirs = [
    ['claude', opts.claudeDir ?? join(home, '.claude', 'projects')],
    ['codex', opts.codexDir ?? join(home, '.codex', 'sessions')],
  ];
  const scanned = { claude: 0, codex: 0 };
  const all = new Map();
  const sessionIds = new Map();
  for (const [agent, dir] of dirs) {
    for (const file of listJsonl(dir)) {
      const r = scanFile(file, agent, opts.sinceMs);
      if (r === null) continue;
      scanned[agent] += 1;
      const abs = resolve(file);
      let id = sessionIds.get(abs);
      if (id === undefined) { id = sessionIds.size; sessionIds.set(abs, id); }
      for (const [key, f] of r.local) {
        let g = all.get(key);
        if (g === undefined) {
          g = { kind: f.kind, secret: f.secret, count: 0, sessions: new Set(), first: f.first, last: f.last, agents: 0, projects: new Set(), places: 0 };
          all.set(key, g);
        }
        g.count += f.count;
        g.sessions.add(id);
        if (f.first < g.first) g.first = f.first;
        if (f.last > g.last) g.last = f.last;
        g.agents |= 1 << AGENTS.indexOf(agent);
        if (r.project !== null) g.projects.add(r.project);
        g.places |= f.places;
      }
    }
  }
  const wanted = new Set([...opts.kinds].map((k) => K[k]));
  const findings = [];
  for (const g of all.values()) {
    if (!wanted.has(g.kind)) continue;
    findings.push({
      kind: KINDS[g.kind],
      fingerprint: fingerprintOf(g.secret),
      sha256: sha256Of(g.secret).slice(0, 12),
      length: Array.from(g.secret).length,
      count: g.count,
      sessions: g.sessions.size,
      first: new Date(g.first).toISOString(),
      last: new Date(g.last).toISOString(),
      agents: AGENTS.filter((_, i) => g.agents & (1 << i)),
      projects: [...g.projects].sort(),
      places: PLACES.filter((_, i) => g.places & (1 << i)),
      _kind: g.kind, _first: g.first, _full: sha256Of(g.secret),
    });
  }
  findings.sort((a, b) => a._kind - b._kind || a._first - b._first || (a._full < b._full ? -1 : a._full > b._full ? 1 : 0));
  for (const f of findings) { delete f._kind; delete f._first; delete f._full; }
  return { scanned, findings };
}

function plainReport(findings) {
  if (findings.length === 0) return 'agent-leaks found no secrets\n';
  const plural = (n, word) => (n === 1 ? `${n} ${word}` : `${n} ${word}s`);
  let out = `agent-leaks found ${plural(findings.length, 'secret')}\n`;
  for (const f of findings) {
    out += '\n';
    out += `${f.kind}  ${f.fingerprint}  sha256:${f.sha256}\n`;
    out += `  seen ${plural(f.count, 'time')} in ${plural(f.sessions, 'session')}\n`;
    out += `  first ${f.first}  last ${f.last}\n`;
    out += `  agent: ${f.agents.join(', ')}\n`;
    out += `  project: ${f.projects.length > 0 ? f.projects.join(', ') : '-'}\n`;
    out += `  in: ${f.places.join(', ')}\n`;
  }
  return out;
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    process.stderr.write(`agent-leaks: ${e.message}\nRun agent-leaks --help for the usage.\n`);
    return 2;
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  const { scanned, findings } = run(opts);
  if (opts.json) {
    const report = {
      tool: 'agent-leaks',
      version: VERSION,
      since: opts.sinceMs === null ? null : new Date(opts.sinceMs).toISOString(),
      kinds: KINDS.filter((k) => opts.kinds.has(k)),
      scanned,
      total: findings.length,
      findings,
    };
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(plainReport(findings));
  }
  return opts.failOn && findings.length > 0 ? 1 : 0;
}

process.stdout.on('error', () => {});
process.exitCode = main(process.argv.slice(2));
