import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, realpathSync, symlinkSync, statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const TOOL = fileURLToPath(new URL('../agent-leaks.mjs', import.meta.url));

// ------------------------------------------------------------------ fake secrets, built from pieces

const rep = (s, n) => s.repeat(n);
const ANTHROPIC = 'sk-' + 'ant-' + 'api03-' + rep('Ab1', 8); // 37 characters
const OPENAI = 'sk-' + rep('Zy9', 10); // 33
const AWS_ID = 'AK' + 'IA' + 'ABCDEFGH12345678'; // 20
const AWS_SECRET = rep('Qw3', 13) + 'Q'; // 40
const GITHUB = 'gh' + 'p_' + rep('a1B2', 9); // 40
const GITHUB_PAT = 'github' + '_pat_' + rep('Ab3_', 6); // 24 after the prefix
const SLACK = 'xo' + 'xb-' + '1234567890' + 'abc';
const STRIPE = 'sk_' + 'live_' + rep('Ab12', 4);
const STRIPE_R = 'rk_' + 'live_' + rep('Cd34', 5);
const GOOGLE = 'AI' + 'za' + rep('A1b2C3d4E5', 3) + 'Zz9Yy'; // 4 + 35
const JWT = 'ey' + 'J' + 'hbGci' + '.' + 'ey' + 'J' + 'zdWIi' + '.' + 'sig0123456';
const PEM_BEGIN = '-----BEGIN ' + 'RSA PRIVATE' + ' KEY-----';
const PEM_END = '-----END ' + 'RSA PRIVATE' + ' KEY-----';
const PEM_BODY = 'MIIEowIBAAKCAQEA' + rep('x7Qz', 12);
const PEM = `${PEM_BEGIN}\n${PEM_BODY}\n${PEM_END}`;

const KINDS = [
  'private-key', 'anthropic-key', 'openai-key', 'aws-access-key', 'aws-secret-key', 'github-token',
  'slack-token', 'stripe-key', 'google-api-key', 'jwt', 'env-secret',
];

const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

// ------------------------------------------------------------------ helpers

function sandbox() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'agent-leaks-test-')));
  mkdirSync(join(root, 'home'));
  mkdirSync(join(root, 'cwd'));
  const dirs = { claude: join(root, 'claude'), codex: join(root, 'codex') };
  return { root, home: join(root, 'home'), cwd: join(root, 'cwd'), ...dirs, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

async function withSandbox(fn) {
  const sb = sandbox();
  try { return await fn(sb); } finally { sb.cleanup(); }
}

function write(dir, rel, lines) {
  const file = join(dir, rel);
  mkdirSync(dirname(file), { recursive: true });
  const text = lines.map((l) => (typeof l === 'string' ? l : JSON.stringify(l))).join('\n') + '\n';
  writeFileSync(file, text);
  return file;
}

function run(sb, args) {
  const r = spawnSync(process.execPath, [TOOL, ...args], {
    encoding: 'utf8',
    cwd: sb.cwd,
    maxBuffer: 1 << 30,
    env: { ...process.env, HOME: sb.home, USERPROFILE: sb.home },
  });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

/** Runs on the sandbox's own two folders, with --json. */
function scan(sb, extra = []) {
  const r = run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex, '--json', ...extra]);
  assert.equal(r.code, 0, r.err);
  assert.equal(r.err, '');
  return JSON.parse(r.out);
}

const iso = (s) => `2026-11-03T10:${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}.000Z`;

const cu = (ts, content, extra = {}) => ({ type: 'user', timestamp: ts, message: { role: 'user', content }, ...extra });
const ca = (ts, content, extra = {}) => ({ type: 'assistant', timestamp: ts, message: { role: 'assistant', content }, ...extra });
const toolResult = (content) => ({ type: 'tool_result', tool_use_id: 't1', content });
const toolUse = (input) => ({ type: 'tool_use', id: 't1', name: 'Bash', input });

const cx = (ts, payload, type = 'response_item') => ({ timestamp: ts, type, payload });
const cxMsg = (ts, role, blocks) => cx(ts, { type: 'message', role, content: blocks });
const meta = (cwd) => cx(iso(0), { id: 's1', cwd }, 'session_meta');

/** The kinds and secrets that a scan finds, as "kind:sha12" strings. */
const found = (report) => report.findings.map((f) => `${f.kind}:${f.sha256}`);
const id = (kind, secret) => `${kind}:${sha(secret).slice(0, 12)}`;

// ------------------------------------------------------------------ usage

test('--help prints the usage on stdout and exits 0, and wins over usage errors', async () => {
  await withSandbox((sb) => {
    for (const args of [['--help'], ['-h'], ['--bogus', '--help'], ['--help', '--since', 'nope'], ['x', '-h', '--kind']]) {
      const r = run(sb, args);
      assert.equal(r.code, 0, args.join(' '));
      assert.match(r.out, /^Usage: agent-leaks/);
      assert.equal(r.err, '');
    }
  });
});

test('a value is the next argument whatever it looks like, so --help can be a folder name', async () => {
  await withSandbox((sb) => {
    const r = run(sb, ['--claude-dir', '--help', '--codex-dir', sb.codex]);
    assert.equal(r.code, 0);
    assert.equal(r.out, 'agent-leaks found no secrets\n');
    const j = run(sb, ['--claude-dir', '--json', '--codex-dir', sb.codex]);
    assert.equal(j.out, 'agent-leaks found no secrets\n');
  });
});

test('usage errors exit 2, print nothing on stdout and a message on stderr', async () => {
  await withSandbox((sb) => {
    const bad = [
      ['--bogus'], ['-x'], ['positional'], ['--json=1'], ['--fail-on=1'], ['--help=1'],
      ['--claude-dir'], ['--codex-dir'], ['--since'], ['--kind'], ['--json', '--kind'],
      ['--kind', 'nope'], ['--kind=nope'], ['--kind', 'env-secret', '--kind', 'nope'], ['--kind', ''], ['--kind', 'ENV-SECRET'],
      ['--since', ''], ['--since=2026-02-30'], ['--since', '2026-13-01'], ['--since', '2026-00-10'], ['--since', '2026-01-00'],
      ['--since', '2026-1-1'], ['--since', '1969-12-31'], ['--since', '2026-11-03T10:00:00'], ['--since', '2026-11-03T10:00:00+02:00'],
      ['--since', '2026-11-03T24:00:00Z'], ['--since', '2026-11-03T10:60:00Z'], ['--since', '2026-11-03T10:00:60Z'],
      ['--since', '2026-11-03T10:00:00.1234Z'], ['--since', '2026-11-03T10:00:00.Z'], ['--since', '2026-11-03 10:00:00Z'],
      ['--since', '2026-11-03T10:00Z'], ['--since', ' 2026-11-03'], ['--since', '2026-11-03\n'], ['--since', 'yesterday'],
      ['--since', '2025-02-29'], ['--since', '2026-04-31'],
    ];
    for (const args of bad) {
      const r = run(sb, [...args]);
      assert.equal(r.code, 2, JSON.stringify(args));
      assert.equal(r.out, '', JSON.stringify(args));
      assert.notEqual(r.err, '', JSON.stringify(args));
    }
  });
});

test('--since accepts dates, UTC times with 1 to 3 fraction digits, and leap days', async () => {
  await withSandbox((sb) => {
    const cases = {
      '2026-05-01': '2026-05-01T00:00:00.000Z',
      '1970-01-01': '1970-01-01T00:00:00.000Z',
      '2024-02-29': '2024-02-29T00:00:00.000Z',
      '2026-05-01T10:20:30Z': '2026-05-01T10:20:30.000Z',
      '2026-05-01T23:59:59.5Z': '2026-05-01T23:59:59.500Z',
      '2026-05-01T10:20:30.12Z': '2026-05-01T10:20:30.120Z',
      '2026-05-01T10:20:30.007Z': '2026-05-01T10:20:30.007Z',
    };
    for (const [arg, want] of Object.entries(cases)) {
      assert.equal(scan(sb, ['--since', arg]).since, want, arg);
      assert.equal(scan(sb, [`--since=${arg}`]).since, want, arg);
    }
    assert.equal(scan(sb).since, null);
  });
});

test('--kind may be repeated, the last of other options counts, and --option=value works', async () => {
  await withSandbox((sb) => {
    mkdirSync(join(sb.root, 'other'));
    const r = run(sb, [
      '--claude-dir', join(sb.root, 'nope'), `--claude-dir=${sb.claude}`, '--codex-dir=' + sb.codex,
      '--kind', 'jwt', '--kind=anthropic-key', '--kind', 'jwt', '--json',
    ]);
    assert.equal(r.code, 0);
    assert.deepEqual(JSON.parse(r.out).kinds, ['anthropic-key', 'jwt']);
    assert.deepEqual(scan(sb).kinds, KINDS);
  });
});

// ------------------------------------------------------------------ folders

test('missing, unreadable and non-folder folders are no sessions, not an error', async () => {
  await withSandbox((sb) => {
    writeFileSync(join(sb.root, 'afile'), 'x');
    const r = run(sb, ['--claude-dir', join(sb.root, 'missing'), '--codex-dir', join(sb.root, 'afile'), '--json']);
    assert.equal(r.code, 0);
    assert.equal(r.err, '');
    const j = JSON.parse(r.out);
    assert.deepEqual(j.scanned, { claude: 0, codex: 0 });
    assert.equal(j.total, 0);
    assert.deepEqual(j.findings, []);
    const plain = run(sb, ['--claude-dir', join(sb.root, 'missing'), '--codex-dir', '']);
    assert.equal(plain.code, 0);
    assert.equal(plain.out, 'agent-leaks found no secrets\n');
    const failOn = run(sb, ['--claude-dir', join(sb.root, 'missing'), '--codex-dir', join(sb.root, 'afile'), '--fail-on']);
    assert.equal(failOn.code, 0);
  });
});

test('the default folders come from the home folder, and giving one does not change the other', async () => {
  await withSandbox((sb) => {
    const aKey = 'ANTHROPIC_' + 'API_KEY=' + ANTHROPIC;
    write(join(sb.home, '.claude', 'projects'), 'p/a.jsonl', [cu(iso(1), aKey, { cwd: '/w/homeclaude' })]);
    write(join(sb.home, '.codex', 'sessions'), '2026/b.jsonl', [meta('/w/homecodex'), cxMsg(iso(2), 'assistant', [{ type: 'output_text', text: GITHUB }])]);
    const both = JSON.parse(run(sb, ['--json']).out);
    assert.deepEqual(both.scanned, { claude: 1, codex: 1 });
    assert.deepEqual(found(both), [id('anthropic-key', ANTHROPIC), id('github-token', GITHUB)]);
    const onlyCodexGiven = JSON.parse(run(sb, ['--codex-dir', join(sb.root, 'none'), '--json']).out);
    assert.deepEqual(onlyCodexGiven.scanned, { claude: 1, codex: 0 });
    assert.deepEqual(found(onlyCodexGiven), [id('anthropic-key', ANTHROPIC)]);
    const onlyClaudeGiven = JSON.parse(run(sb, ['--claude-dir', join(sb.root, 'none'), '--json']).out);
    assert.deepEqual(onlyClaudeGiven.scanned, { claude: 0, codex: 1 });
    assert.deepEqual(found(onlyClaudeGiven), [id('github-token', GITHUB)]);
  });
});

test('every .jsonl file at any depth is read; other files and symbolic links are not', async () => {
  await withSandbox((sb) => {
    const line = cu(iso(1), 'x', {});
    write(sb.claude, 'a.jsonl', [line]);
    write(sb.claude, 'deep/er/still/b.jsonl', [line]);
    write(sb.claude, 'UPPER.JSONL', [cu(iso(1), STRIPE)]);
    write(sb.claude, 'c.jsonl.bak', [cu(iso(1), STRIPE)]);
    write(sb.claude, 'd.json', [cu(iso(1), STRIPE)]);
    write(sb.claude, 'dir.jsonl/inside.jsonl', [line]);
    write(sb.claude, 'empty.jsonl', []);
    write(sb.root, 'outside/o.jsonl', [cu(iso(1), STRIPE)]);
    let linked = false;
    try {
      symlinkSync(join(sb.root, 'outside'), join(sb.claude, 'linkdir'), 'dir');
      symlinkSync(join(sb.root, 'outside', 'o.jsonl'), join(sb.claude, 'link.jsonl'));
      linked = true;
    } catch { /* no symbolic links on this system */ }
    const j = scan(sb);
    assert.equal(j.scanned.claude, 4, `linked=${linked}`); // a, b, dir.jsonl/inside, empty
    assert.equal(j.total, 0);
  });
});

test('files under --claude-dir are Claude logs and under --codex-dir Codex logs, whatever the content', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'codexshaped.jsonl', [cxMsg(iso(1), 'assistant', [{ type: 'output_text', text: GITHUB }])]);
    write(sb.codex, 'claudeshaped.jsonl', [cu(iso(1), GITHUB)]);
    const j = scan(sb);
    assert.equal(j.total, 0);
    assert.deepEqual(j.scanned, { claude: 1, codex: 1 });
  });
});

// ------------------------------------------------------------------ the kinds

test('every kind is found by its pattern, with the stated fields', async () => {
  await withSandbox((sb) => {
    const texts = [
      PEM, ANTHROPIC, OPENAI, `${AWS_ID} ${AWS_SECRET}`, GITHUB, GITHUB_PAT, SLACK, STRIPE, STRIPE_R, GOOGLE, JWT,
    ];
    const lines = texts.map((t, i) => cu(iso(i + 1), `use ${t} now`, { cwd: '/home/p/shop' }));
    lines.push(cu(iso(20), 'export DB_' + 'PASSWORD="hunter2hunter2"'));
    write(sb.claude, 'p/s.jsonl', lines);
    const j = scan(sb);
    const byKind = Object.groupBy(j.findings, (f) => f.kind);
    assert.deepEqual(Object.keys(byKind), KINDS);
    const only = (kind) => byKind[kind].map((f) => f.sha256).sort();
    const sha12 = (s) => sha(s).slice(0, 12);
    assert.deepEqual(only('private-key'), [sha12(PEM)]);
    assert.deepEqual(only('anthropic-key'), [sha12(ANTHROPIC)]);
    assert.deepEqual(only('openai-key'), [sha12(OPENAI)]);
    assert.deepEqual(only('aws-access-key'), [sha12(AWS_ID)]);
    assert.deepEqual(only('aws-secret-key'), [sha12(AWS_SECRET)]);
    assert.deepEqual(only('github-token').sort(), [sha12(GITHUB), sha12(GITHUB_PAT)].sort());
    assert.deepEqual(only('slack-token'), [sha12(SLACK)]);
    assert.deepEqual(only('stripe-key').sort(), [sha12(STRIPE), sha12(STRIPE_R)].sort());
    assert.deepEqual(only('google-api-key'), [sha12(GOOGLE)]);
    assert.deepEqual(only('jwt'), [sha12(JWT)]);
    assert.deepEqual(only('env-secret'), [sha12('hunter2hunter2')]);
    assert.equal(j.total, 13);
    const anth = j.findings.find((f) => f.kind === 'anthropic-key');
    assert.deepEqual(anth, {
      kind: 'anthropic-key', fingerprint: ANTHROPIC.slice(0, 4) + '…' + ANTHROPIC.slice(-4), sha256: sha(ANTHROPIC).slice(0, 12),
      length: ANTHROPIC.length, count: 1, sessions: 1, first: iso(2), last: iso(2), agents: ['claude'], projects: ['shop'], places: ['prompt'],
    });
  });
});

test('a private key block runs to its END line, or to the end of the text without one', async () => {
  await withSandbox((sb) => {
    const open = PEM_BEGIN + '\n' + PEM_BODY + '\nsecond line and a key ' + ANTHROPIC;
    write(sb.claude, 'a.jsonl', [
      cu(iso(1), `before\n${PEM}\nafter ${GITHUB}`),
      cu(iso(2), open),
      cu(iso(3), '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'),
      cu(iso(4), '-----BEGIN ' + 'EC PRIVATE' + ' KEY-----' + '\nabc\n' + '-----END ' + 'EC PRIVATE' + ' KEY-----'),
      cu(iso(5), '-----BEGIN ' + 'PRIVATE' + ' KEY-----' + '\nabc'),
    ]);
    const j = scan(sb);
    const pk = j.findings.filter((f) => f.kind === 'private-key');
    assert.equal(pk.length, 4);
    assert.equal(pk.filter((f) => f.fingerprint === '----…----').length, 2); // the two blocks with an END line
    assert.ok(pk.every((f) => f.fingerprint.startsWith('----…')));
    const lengths = pk.map((f) => f.length).sort((a, b) => a - b);
    assert.deepEqual(lengths, [
      ('-----BEGIN ' + 'PRIVATE' + ' KEY-----' + '\nabc').length,
      ('-----BEGIN ' + 'EC PRIVATE' + ' KEY-----' + '\nabc\n' + '-----END ' + 'EC PRIVATE' + ' KEY-----').length,
      PEM.length,
      open.length,
    ].sort((a, b) => a - b));
    // an Anthropic key inside the open-ended block is part of the block, and the GitHub token after END is its own finding
    assert.ok(!found(j).includes(id('anthropic-key', ANTHROPIC)));
    assert.ok(found(j).includes(id('github-token', GITHUB)));
  });
});

test('look-alikes just short of a pattern are not secrets', async () => {
  await withSandbox((sb) => {
    const lookalikes = [
      'sk-' + 'ant-' + 'abcdefg', // 7 after sk-ant-
      'sk-' + rep('a', 19),
      'x' + ANTHROPIC, // no word boundary before
      'x' + OPENAI,
      'AK' + 'IA' + rep('A', 15),
      'AK' + 'IA' + rep('A', 17),
      'AK' + 'IB' + rep('A', 16),
      'ak' + 'ia' + rep('A', 16),
      'gh' + 'p_' + rep('a', 35),
      'gh' + 'x_' + rep('a', 40),
      'github' + '_pat_' + rep('a', 21),
      'xo' + 'xb-' + '123456789',
      'xo' + 'xz-' + '1234567890',
      'sk_' + 'live_' + rep('a', 15),
      'sk_' + 'test_' + rep('a', 24),
      'AI' + 'za' + rep('A', 34),
      'AI' + 'za' + rep('A', 36),
      'ey' + 'J' + 'abcd' + '.' + 'ey' + 'J' + 'abcde' + '.' + 'sig0123456',
      'ey' + 'J' + 'abcde' + '.' + 'ey' + 'J' + 'abcde' + '.' + 'sig012345',
      'ey' + 'J' + 'abcde' + '.' + 'ab' + 'J' + 'abcde' + '.' + 'sig0123456',
      '-----BEGIN ' + 'PRIVATE' + 'KEY-----\nabc\n-----END PRIVATEKEY-----',
      '-----BEGIN ' + 'private' + ' key-----\nabc',
      rep('0123456789abcdef', 2) + '01234567', // 40-character hex hash
      'api_' + 'key=' + 'abcdef123456',
      '"api_' + 'key": "abcdef123456"',
      'API_' + 'KEYS=abcdef123456',
      '# API_' + 'KEY comment abcdef123456',
    ];
    write(sb.claude, 'a.jsonl', lookalikes.map((t, i) => cu(iso(i + 1), t)));
    const j = scan(sb);
    assert.deepEqual(j.findings, []);
  });
});

test('an AWS secret key is found only within 200 characters of an access key id in the same text', async () => {
  await withSandbox((sb) => {
    const s2 = rep('Mn7', 13) + 'M';
    const s3 = rep('Pq5', 13) + 'P';
    const s4 = rep('Rs6', 13) + 'R';
    const s5 = rep('Tu8', 13) + 'T';
    const noDigit = rep('Kl', 20);
    const noUpper = rep('k1', 20);
    const noLower = rep('K1', 20);
    const id2 = 'AK' + 'IA' + 'BBBBBBBB22222222';
    const near200 = (s) => `${AWS_ID}${rep('.', 200)}${s}`;
    const far201 = (s) => `${AWS_ID}${rep('.', 201)}${s}`;
    write(sb.claude, 'a.jsonl', [
      cu(iso(1), `${AWS_ID}\n${AWS_SECRET}`), // after
      cu(iso(2), near200(s2)), // exactly 200 between
      cu(iso(3), far201(s3)), // 201: no
      cu(iso(4), `${s4} ${rep('x', 190)} ${id2}`), // before the id
      cu(iso(5), `${s5}`), // no id at all
      cu(iso(6), `${AWS_ID} ${noDigit} ${noUpper} ${noLower}`), // class rules
      cu(iso(7), `${rep('Vw9', 13)}V`), // in another text than an id: no
    ]);
    write(sb.claude, 'b.jsonl', [cu(iso(8), AWS_ID), cu(iso(9), rep('Xy2', 13) + 'X')]); // id in another text: no
    const j = scan(sb);
    const secrets = j.findings.filter((f) => f.kind === 'aws-secret-key').map((f) => f.sha256).sort();
    assert.deepEqual(secrets, [AWS_SECRET, s2, s4].map((s) => sha(s).slice(0, 12)).sort());
    assert.equal(j.findings.filter((f) => f.kind === 'aws-access-key').length, 2);
  });
});

test('an AWS secret candidate must stand alone: no neighbouring base64 characters', async () => {
  await withSandbox((sb) => {
    const forty = rep('Qw3', 13) + 'Q';
    write(sb.claude, 'a.jsonl', [
      cu(iso(1), `${AWS_ID} x${forty}`),
      cu(iso(2), `${AWS_ID} ${forty}/`),
      cu(iso(3), `${AWS_ID} ${forty}=`), // = is not a base64 character of the pattern
    ]);
    const j = scan(sb);
    const aws = j.findings.filter((f) => f.kind === 'aws-secret-key');
    assert.equal(aws.length, 1);
    assert.equal(aws[0].count, 1);
    assert.equal(aws[0].first, iso(3));
  });
});

test('NAME=value follows the quoting, trimming, length and placeholder rules', async () => {
  await withSandbox((sb) => {
    const lines = [
      'API_KEY=abc12345', // found
      'API_KEY="abc12345"', // same secret
      "  export   API_KEY='abc12345'  ", // same secret, trimmed
      'DB_PASSWORD = \t pass-word-1  ', // spaces around =; value trimmed
      'GITHUB_TOKEN=short12', // 7? no: 7 characters
      'SECRET="abcdefg"', // 7 inside the quotes
      'MY_SECRET="abcdefgh', // quote only at the start: kept, 9 characters
      'MY2_SECRET=\'abcdefgh"', // different quotes are not stripped
      'X_TOKEN=$HOME_TOKEN_VALUE', // starts with $
      'X_TOKEN=<your-token-here>', // starts with <
      'X_TOKEN=[redacted:env-secret]', // placeholder
      'X_TOKEN="[redacted-by-me]"', // the quotes are removed first
      'X_TOKEN="$OTHER_VARIABLE"',
      'x_api_key=abcdefgh1234', // lower case name
      'ApiKey=abcdefgh1234', // not upper case
      '1API_KEY=abcdefgh1234', // starts with a digit
      'API_KEYS=abcdefgh1234', // does not end in KEY
      'API_KEY==abcdefgh1234', // ==
      'foo API_KEY=abcdefgh1234', // does not start its line
      '# API_KEY=abcdefgh1234', // comment
      '"API_KEY": "abcdefgh1234"', // JSON
      'API_KEY: abcdefgh1234',
      '_KEY=underscore1234', // name may start with... no: must start with a letter
      'KEY=justkey1234',
      'PASSWORD=pw12345678',
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENG',
      'NAME=\'  spaced value  \'', // not a secret name
      'Q_TOKEN=""',
      'Q2_TOKEN="   padded   "', // quotes removed, inner spaces kept: 12 characters
    ];
    write(sb.claude, 'a.jsonl', lines.map((l, i) => cu(iso(i + 1), l)));
    const j = scan(sb, ['--kind', 'env-secret']);
    const want = {
      'abc12345': 3, 'pass-word-1': 1, '"abcdefgh': 1, '\'abcdefgh"': 1, 'justkey1234': 1, 'pw12345678': 1,
      'wJalrXUtnFEMIK7MDENG': 1, '   padded   ': 1,
    };
    const got = Object.fromEntries(j.findings.map((f) => [f.sha256, f.count]));
    const expected = Object.fromEntries(Object.entries(want).map(([s, n]) => [sha(s).slice(0, 12), n]));
    assert.deepEqual(got, expected);
  });
});

test('NAME=value: several lines in one text, CRLF and other line terminators, and two kinds of the same value', async () => {
  await withSandbox((sb) => {
    const block = 'A_KEY=firstvalue1\r\nB_TOKEN=secondvalue2\rC_SECRET=thirdvalue3\u2028D_PASSWORD=fourthvalue4\u2029E_KEY=fifthvalue5\nplain line';
    write(sb.claude, 'a.jsonl', [cu(iso(1), block)]);
    const j = scan(sb);
    assert.deepEqual(
      j.findings.map((f) => f.sha256).sort(),
      ['firstvalue1', 'secondvalue2', 'thirdvalue3', 'fourthvalue4', 'fifthvalue5'].map((s) => sha(s).slice(0, 12)).sort(),
    );
    assert.ok(j.findings.every((f) => f.kind === 'env-secret' && f.count === 1));
  });
});

test('a secret already found as a more specific kind is not found again as an env-secret', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [
      cu(iso(1), 'ANTHROPIC_' + 'API_KEY=' + ANTHROPIC),
      cu(iso(2), 'export OPENAI_' + 'API_KEY="' + OPENAI + '"'),
      cu(iso(3), 'GITHUB_' + 'TOKEN=' + GITHUB),
      cu(iso(4), 'NOTE_' + 'KEY=' + ANTHROPIC + ' and more'), // the value overlaps a hit
      cu(iso(5), 'PLAIN_' + 'KEY=plainvalue123'),
      cu(iso(6), 'AWS_ACCESS_' + 'KEY_ID=' + AWS_ID),
      cu(iso(7), `${PEM_BEGIN}\nPRIVATE_KEY=insideblock123\n${PEM_END}`),
    ]);
    const j = scan(sb);
    assert.deepEqual(
      found(j).sort(),
      [
        id('anthropic-key', ANTHROPIC), id('openai-key', OPENAI), id('github-token', GITHUB), id('aws-access-key', AWS_ID),
        id('private-key', `${PEM_BEGIN}\nPRIVATE_KEY=insideblock123\n${PEM_END}`), id('env-secret', 'plainvalue123'),
      ].sort(),
    );
    assert.equal(j.findings.find((f) => f.kind === 'anthropic-key').count, 2);
  });
});

test('an Anthropic key is not an OpenAI key; the same secret as two kinds is not possible but two kinds are two findings', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [cu(iso(1), ANTHROPIC), cu(iso(2), OPENAI)]);
    const j = scan(sb);
    assert.deepEqual(found(j), [id('anthropic-key', ANTHROPIC), id('openai-key', OPENAI)]);
  });
});

test('--kind only filters the report; it never changes which secrets are found or their kind', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [
      cu(iso(1), 'ANTHROPIC_' + 'API_KEY=' + ANTHROPIC),
      cu(iso(2), 'DB_' + 'PASSWORD=plainvalue123'),
      cu(iso(3), JWT),
    ]);
    const all = scan(sb);
    assert.equal(all.total, 3);
    const onlyEnv = scan(sb, ['--kind', 'env-secret']);
    assert.deepEqual(found(onlyEnv), [id('env-secret', 'plainvalue123')]);
    assert.deepEqual(onlyEnv.kinds, ['env-secret']);
    const two = scan(sb, ['--kind', 'jwt', '--kind', 'anthropic-key']);
    assert.deepEqual(found(two), [id('anthropic-key', ANTHROPIC), id('jwt', JWT)]);
    assert.deepEqual(two.kinds, ['anthropic-key', 'jwt']);
    const none = scan(sb, ['--kind', 'openai-key']);
    assert.equal(none.total, 0);
    assert.deepEqual(none.scanned, { claude: 1, codex: 0 });
    // each finding is the same with and without the filter
    assert.deepEqual(two.findings, all.findings.filter((f) => f.kind === 'anthropic-key' || f.kind === 'jwt'));
  });
});

// ------------------------------------------------------------------ what is read: Claude Code

test('Claude Code: only prompts, agent text, tool inputs and tool results are read', async () => {
  await withSandbox((sb) => {
    const S = (n) => 'sk_' + 'live_' + rep(String(n), 16);
    write(sb.claude, 'p/a.jsonl', [
      cu(iso(1), S(1), { cwd: '/w/proj' }), // prompt
      ca(iso(2), [{ type: 'text', text: S(2) }]), // agent_message
      ca(iso(3), [toolUse({ command: `echo ${S(3)}`, nested: { list: ['a', { deep: S(4) }], n: 5, b: true, z: null }, [S(5)]: 'key is not read' })]), // tool_input
      cu(iso(4), [toolResult(S(6))]), // tool_result string
      cu(iso(5), [toolResult([{ type: 'text', text: 'one' }, { type: 'image' }, { type: 'text', text: S(7) }])]), // tool_result array
      // not read:
      ca(iso(6), [{ type: 'thinking', thinking: S(11), signature: S(12) }]),
      ca(iso(7), [{ type: 'tool_use', id: 't', name: S(13), input: {} }]), // tool name
      cu(iso(8), S(14), { isMeta: true }),
      ca(iso(9), [{ type: 'text', text: S(15) }], { isMeta: true }),
      cu(iso(10), [{ type: 'text', text: S(16) }]), // typed text of an array-content user line
      cu(iso(11), [{ type: 'image', source: { data: S(17) } }]),
      ca(iso(12), S(18)), // string content of an assistant line
      ca(iso(13), [{ type: 'redacted_thinking', data: S(19) }]),
      ca(iso(14), [{ type: 'server_tool_use', input: { q: S(20) } }]),
      { type: 'summary', timestamp: iso(15), summary: S(21), message: { content: S(21) } },
      { type: 'system', timestamp: iso(16), message: { content: S(22) } },
      { type: 'user', timestamp: iso(17), message: S(23) }, // message not an object
      { type: 'user', message: { content: S(24) } }, // no timestamp
      { type: 'user', timestamp: 'not a time', message: { content: S(25) } },
      { type: 'user', timestamp: 1730628000000, message: { content: S(26) } }, // not a string
      cu(iso(18), [toolResult({ text: S(27) })]), // tool_result content an object
      cu(iso(19), [toolResult(5)]),
      cu(iso(20), [toolResult(['plain string in array', S(28)])]),
      cu(iso(21), [{ type: 'tool_results', content: [{ type: 'text', text: S(29) }] }]),
      '', '   ', 'not json {', '[1,2]', '"string"', '42', 'null', '{"type":"user"', '{}',
    ]);
    const j = scan(sb);
    const got = j.findings.map((f) => f.sha256).sort();
    const want = [1, 2, 3, 4, 6, 7].map((n) => sha(S(n)).slice(0, 12)).sort();
    assert.deepEqual(got, want);
    const byRep = (n) => j.findings.find((f) => f.sha256 === sha(S(n)).slice(0, 12));
    assert.deepEqual(byRep(1).places, ['prompt']);
    assert.deepEqual(byRep(2).places, ['agent_message']);
    assert.deepEqual(byRep(3).places, ['tool_input']);
    assert.deepEqual(byRep(4).places, ['tool_input']);
    assert.deepEqual(byRep(6).places, ['tool_result']);
    assert.deepEqual(byRep(7).places, ['tool_result']);
    assert.equal(j.scanned.claude, 1);
  });
});

test('Claude Code: a tool_result array joins the text of its blocks with one newline, one text', async () => {
  await withSandbox((sb) => {
    // two blocks: a secret never spans two texts, but the env line starts its own line after the join
    write(sb.claude, 'a.jsonl', [
      cu(iso(1), [toolResult([{ text: 'first line' }, { text: 'SOME_' + 'KEY=valuefrom2nd' }])]),
      cu(iso(2), [toolResult([{ text: 'SOME_' + 'KEY=' }, { text: 'valuesplit1' }])]), // joined by \n: value is empty
      cu(iso(3), [toolResult([{ text: 'sk_live_' }, { text: rep('a', 16) }])]), // not one secret
    ]);
    const j = scan(sb);
    assert.deepEqual(found(j), [id('env-secret', 'valuefrom2nd')]);
  });
});

test('Claude Code: a secret never spans two texts', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [
      ca(iso(1), [toolUse({ a: 'sk_' + 'live_', b: rep('a', 16) })]),
      ca(iso(2), [{ type: 'text', text: 'sk_' + 'live_' }, { type: 'text', text: rep('a', 16) }]),
    ]);
    assert.equal(scan(sb).total, 0);
  });
});

test('Claude Code: a string tool input is one text, and input values are not JSON-parsed', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [
      ca(iso(1), [toolUse(ANTHROPIC)]),
      ca(iso(2), [toolUse(JSON.stringify({ k: GITHUB }))]), // the text is the JSON text itself, the token is found in it
      ca(iso(3), [toolUse([[[['deep ' + OPENAI]]]])]),
    ]);
    const j = scan(sb);
    assert.deepEqual(found(j).sort(), [id('anthropic-key', ANTHROPIC), id('github-token', GITHUB), id('openai-key', OPENAI)].sort());
  });
});

test('Claude Code: the project is the last folder name of the first non-empty cwd among the used lines', async () => {
  await withSandbox((sb) => {
    const S = (n) => 'sk_' + 'live_' + rep(String(n), 16);
    const file = (rel, lines) => write(sb.claude, rel, [...lines, cu(iso(50), S(rel.length))]);
    file('a.jsonl', [
      { type: 'summary', timestamp: iso(1), cwd: '/ignored/summary' },
      { type: 'user', cwd: '/ignored/no-timestamp', message: { content: 'x' } },
      cu(iso(2), 'x', { cwd: '' }),
      cu(iso(3), 'x', { cwd: 5 }),
      cu(iso(4), 'x', { cwd: '/home/p/shop/' }),
      cu(iso(5), 'x', { cwd: '/home/p/other' }),
    ]);
    file('bb.jsonl', [cu(iso(1), 'x', { cwd: 'C:\\Users\\p\\winproj' })]);
    file('ccc.jsonl', [cu(iso(1), 'x', { cwd: '///' })]); // no folder name: no project
    file('dddd.jsonl', [cu(iso(1), 'x')]); // no cwd
    file('eeeee.jsonl', [cu(iso(1), 'x', { cwd: '/mixed\\style/dir\\' })]);
    const j = scan(sb);
    const projectOf = (n) => j.findings.find((f) => f.sha256 === sha(S(n)).slice(0, 12)).projects;
    assert.deepEqual(projectOf('a.jsonl'.length), ['shop']);
    assert.deepEqual(projectOf('bb.jsonl'.length), ['winproj']);
    assert.deepEqual(projectOf('ccc.jsonl'.length), []);
    assert.deepEqual(projectOf('dddd.jsonl'.length), []);
    assert.deepEqual(projectOf('eeeee.jsonl'.length), ['dir']);
  });
});

test('Claude Code: the cwd of the file counts also from lines before --since', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [
      cu(iso(1), 'x', { cwd: '/w/early' }),
      cu(iso(100), ANTHROPIC, { cwd: '/w/late' }),
    ]);
    const j = scan(sb, ['--since', '2026-11-03T10:01:00Z']);
    assert.deepEqual(j.findings[0].projects, ['early']);
  });
});

// ------------------------------------------------------------------ what is read: Codex

test('Codex: messages, calls and call outputs are read as stated', async () => {
  await withSandbox((sb) => {
    const S = (n) => 'sk_' + 'live_' + rep(String(n), 16);
    const half = (s) => [s.slice(0, 10), s.slice(10)];
    write(sb.codex, '2026/11/rollout-a.jsonl', [
      meta('/home/p/codexproj'),
      // message text blocks are concatenated with nothing between: a secret may span blocks
      cxMsg(iso(1), 'user', half(S(1)).map((text) => ({ type: 'input_text', text }))),
      cxMsg(iso(2), 'assistant', [{ type: 'output_text', text: S(2) }, { type: 'other', text: 'ignored' }]),
      cxMsg(iso(3), 'assistant', [{ type: 'text', text: S(3) }]),
      cxMsg(iso(4), 'user', [{ type: 'input_text', text: '<environment_context> ' + S(10) }]), // Codex's own context
      cxMsg(iso(5), 'user', [{ type: 'input_text', text: S(11) }, { type: 'input_text', text: ' <fine>' }]),
      cxMsg(iso(6), 'system', [{ type: 'input_text', text: S(12) }]),
      cxMsg(iso(7), 'developer', [{ type: 'input_text', text: S(13) }]),
      cxMsg(iso(8), 'assistant', [{ type: 'image', text: S(14) }]),
      cx(iso(9), { type: 'function_call', name: S(15), arguments: JSON.stringify({ cmd: `echo ${S(4)}`, args: [S(5)], n: 1 }) }),
      cx(iso(10), { type: 'function_call', arguments: `plain text ${S(6)}` }), // not JSON: one text
      cx(iso(11), { type: 'function_call', arguments: JSON.stringify(S(7)) }), // a JSON string, not an object: the text as it is
      cx(iso(12), { type: 'custom_tool_call', name: 'apply_patch', input: `*** Begin Patch ${S(8)}` }),
      cx(iso(13), { type: 'custom_tool_call', input: JSON.stringify([{ a: S(9) }]) }),
      cx(iso(14), { type: 'function_call_output', call_id: 'c', output: JSON.stringify({ output: S(16), metadata: { exit_code: 0 } }) }),
      cx(iso(15), { type: 'function_call_output', call_id: 'c', output: `raw output ${S(17)}` }),
      cx(iso(16), { type: 'custom_tool_call_output', output: [{ text: 'a' }, { type: 'x' }, { text: S(18) }] }),
      cx(iso(17), { type: 'custom_tool_call_output', output: { text: S(19) } }), // object output: nothing
      cx(iso(18), { type: 'function_call_output', output: 7 }),
      // not read
      cx(iso(19), { type: 'reasoning', summary: [{ text: S(20) }], content: S(20) }),
      cx(iso(20), { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: S(21) }] }, 'event_msg'),
      cx(iso(21), { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: S(22) }] }, 'turn_context'),
      cx(iso(22), { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: S(23) }] }, 'compacted'),
      { type: 'response_item', payload: { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: S(24) }] } }, // no timestamp
      { timestamp: 'garbage', type: 'response_item', payload: { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: S(25) }] } },
      { timestamp: iso(23), type: 'response_item', payload: 'string payload ' + S(26) },
      { timestamp: iso(24), type: 'response_item', payload: [S(27)] },
      cx(iso(25), { type: 'function_call', arguments: 5 }),
      cx(iso(26), { type: 'function_call', arguments: null }),
      cx(iso(27), { type: 'function_call_output', output: [S(28)] }), // array of strings: no text fields
      'not json', '[]', '',
    ]);
    const j = scan(sb);
    const got = j.findings.map((f) => f.sha256).sort();
    const want = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 16, 17, 18].map((n) => sha(S(n)).slice(0, 12)).sort();
    assert.deepEqual(got, want);
    const place = (n) => j.findings.find((f) => f.sha256 === sha(S(n)).slice(0, 12)).places;
    for (const n of [1, 11]) assert.deepEqual(place(n), ['prompt']);
    for (const n of [2, 3]) assert.deepEqual(place(n), ['agent_message']);
    for (const n of [4, 5, 6, 7, 8, 9]) assert.deepEqual(place(n), ['tool_input']);
    for (const n of [16, 17, 18]) assert.deepEqual(place(n), ['tool_result']);
    assert.deepEqual(j.scanned, { claude: 0, codex: 1 });
    assert.deepEqual(j.findings[0].agents, ['codex']);
    assert.deepEqual(j.findings[0].projects, ['codexproj']);
  });
});

test('Codex: JSON in a string is parsed, strings inside it are not parsed again', async () => {
  await withSandbox((sb) => {
    write(sb.codex, 'a.jsonl', [
      cx(iso(1), { type: 'function_call', arguments: JSON.stringify({ inner: JSON.stringify({ k: ANTHROPIC }) }) }),
      cx(iso(2), { type: 'function_call_output', output: JSON.stringify(['line one', 'DB_' + 'PASSWORD=pw-from-output']) }),
    ]);
    const j = scan(sb);
    // the inner string is a text as it is: the key inside its escaped quotes is still found
    assert.deepEqual(found(j).sort(), [id('anthropic-key', ANTHROPIC), id('env-secret', 'pw-from-output')].sort());
  });
});

test('Codex: the project comes from the first non-empty session_meta cwd, whatever its timestamp', async () => {
  await withSandbox((sb) => {
    write(sb.codex, 'a.jsonl', [
      { timestamp: 'bad', type: 'session_meta', payload: { cwd: '' } },
      { type: 'turn_context', payload: { cwd: '/not/meta' } },
      { timestamp: 'bad', type: 'session_meta', payload: { cwd: 'C:\\Users\\p\\first\\' } },
      meta('/second/one'),
      cxMsg(iso(1), 'assistant', [{ type: 'output_text', text: ANTHROPIC }]),
    ]);
    write(sb.codex, 'b.jsonl', [cxMsg(iso(1), 'assistant', [{ type: 'output_text', text: GITHUB }])]);
    const j = scan(sb);
    assert.deepEqual(j.findings.find((f) => f.kind === 'anthropic-key').projects, ['first']);
    assert.deepEqual(j.findings.find((f) => f.kind === 'github-token').projects, []);
  });
});

// ------------------------------------------------------------------ findings

test('one distinct secret is one finding across files, agents and projects', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'p1/a.jsonl', [
      cu('2026-11-03T12:00:00+02:00', `here ${ANTHROPIC}`, { cwd: '/home/p/Beta' }), // 10:00:00Z, prompt
      ca(iso(300), [{ type: 'text', text: `${ANTHROPIC} and again ${ANTHROPIC}` }]), // 10:05, twice in one text
    ]);
    write(sb.claude, 'p2/b.jsonl', [
      cu(iso(60), [toolResult(ANTHROPIC)], { cwd: 'C:\\work\\alpha\\' }), // 10:01, tool_result
      ca(iso(61), [toolUse({ x: ANTHROPIC })]),
    ]);
    write(sb.codex, '2026/c.jsonl', [
      meta('/x/shop'),
      cx(iso(30), { type: 'custom_tool_call', input: ANTHROPIC }), // 10:00:30
    ]);
    write(sb.codex, '2026/d.jsonl', [cxMsg(iso(1), 'assistant', [{ type: 'output_text', text: 'other file without a secret' }])]);
    const j = scan(sb);
    assert.equal(j.total, 1);
    assert.deepEqual(j.scanned, { claude: 2, codex: 2 });
    assert.deepEqual(j.findings[0], {
      kind: 'anthropic-key',
      fingerprint: ANTHROPIC.slice(0, 4) + '…' + ANTHROPIC.slice(-4),
      sha256: sha(ANTHROPIC).slice(0, 12),
      length: ANTHROPIC.length,
      count: 6,
      sessions: 3,
      first: '2026-11-03T10:00:00.000Z',
      last: iso(300),
      agents: ['claude', 'codex'],
      projects: ['Beta', 'alpha', 'shop'],
      places: ['prompt', 'agent_message', 'tool_input', 'tool_result'],
    });
  });
});

test('first and last are instants, compared as instants, written in UTC', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [
      cu('2026-11-03T10:30:00.000Z', GITHUB),
      cu('2026-11-03T12:00:00+02:00', GITHUB), // 10:00Z: earlier as an instant, later as text
      cu('2026-11-03T05:45:00-05:00', GITHUB), // 10:45Z
      cu('2026-11-03T10:15:00Z', GITHUB),
    ]);
    const f = scan(sb).findings[0];
    assert.equal(f.first, '2026-11-03T10:00:00.000Z');
    assert.equal(f.last, '2026-11-03T10:45:00.000Z');
    assert.equal(f.count, 4);
    assert.equal(f.sessions, 1);
  });
});

test('the fingerprint and length count Unicode code points; short secrets show 2 and 2', async () => {
  await withSandbox((sb) => {
    const emoji = '😀';
    const value15 = 'ab' + emoji + rep('c', 10) + 'yz'; // 15 code points (16 UTF-16 units): the short form
    const value16 = 'ab' + emoji + rep('c', 11) + 'yz'; // 16 code points: the long form
    const longer = emoji + 'Qwer' + rep('t', 10) + emoji + 'Zxcv' + emoji; // 21 code points
    const emojiValue = 'x' + emoji.repeat(4) + 'y'; // 6 code points, 10 units
    const slackShort = 'xo' + 'xb-' + 'abcdefghij'; // 15 characters
    const anthShort = 'sk-' + 'ant-' + 'abcdefgh'; // 15
    write(sb.claude, 'a.jsonl', [
      cu(iso(1), 'A_' + 'KEY=' + value15),
      cu(iso(2), 'B_' + 'KEY=' + value16),
      cu(iso(3), 'C_' + 'KEY=' + longer),
      cu(iso(4), slackShort),
      cu(iso(5), anthShort),
      cu(iso(6), PEM),
      cu(iso(7), 'D_' + 'KEY=' + emojiValue),
    ]);
    const j = scan(sb);
    const by = (s) => j.findings.find((f) => f.sha256 === sha(s).slice(0, 12));
    assert.equal(by(value15).fingerprint, 'ab…yz');
    assert.equal(by(value15).length, 15);
    assert.equal(by(value16).fingerprint, 'ab' + emoji + 'c…ccyz');
    assert.equal(by(value16).length, 16);
    assert.equal(by(longer).fingerprint, emoji + 'Qwe…xcv' + emoji);
    assert.equal(by(longer).length, 21);
    assert.equal(by(slackShort).fingerprint, 'xo…ij');
    assert.equal(by(slackShort).length, 15);
    assert.equal(by(anthShort).fingerprint, 'sk…gh');
    assert.equal(by(anthShort).length, 15);
    assert.equal(by(emojiValue).length, 6);
    assert.equal(by(emojiValue).fingerprint, 'x' + emoji + '…' + emoji + 'y');
    assert.equal(j.findings.find((f) => f.kind === 'private-key').fingerprint, '----…----');
    assert.equal(by(PEM).length, PEM.length);
  });
});

test('sha256 is the first 12 lower case hex digits of the SHA-256 of the UTF-8 bytes', async () => {
  await withSandbox((sb) => {
    const value = 'pässwörd-日本語-1';
    write(sb.claude, 'a.jsonl', [cu(iso(1), 'MY_' + 'SECRET=' + value)]);
    const f = scan(sb).findings[0];
    assert.match(f.sha256, /^[0-9a-f]{12}$/);
    assert.equal(f.sha256, createHash('sha256').update(Buffer.from(value, 'utf8')).digest('hex').slice(0, 12));
    assert.equal(f.length, Array.from(value).length);
  });
});

test('findings are sorted by kind, then first time, then the full SHA-256', async () => {
  await withSandbox((sb) => {
    const e = (n) => 'value-number-' + n;
    const envs = [1, 2, 3, 4, 5, 6].map(e);
    write(sb.claude, 'a.jsonl', [
      cu(iso(50), 'X_' + 'KEY=' + envs[0]),
      cu(iso(40), 'X_' + 'KEY=' + envs[1]),
      cu(iso(40), 'X_' + 'KEY=' + envs[2]),
      cu(iso(40), 'X_' + 'KEY=' + envs[3]),
      cu('2026-11-03T12:00:00+02:00', 'X_' + 'KEY=' + envs[4]), // 10:00:00Z, written later than "10:..." text-wise
      cu(iso(70), JWT),
      cu(iso(80), SLACK),
      cu(iso(90), OPENAI),
      cu(iso(95), ANTHROPIC),
      cu(iso(99), PEM),
    ]);
    const j = scan(sb);
    const sameTime = [envs[1], envs[2], envs[3]].sort((a, b) => (sha(a) < sha(b) ? -1 : 1));
    assert.deepEqual(j.findings.map((f) => f.kind), [
      'private-key', 'anthropic-key', 'openai-key', 'slack-token', 'jwt', 'env-secret', 'env-secret', 'env-secret', 'env-secret', 'env-secret',
    ]);
    assert.deepEqual(
      j.findings.filter((f) => f.kind === 'env-secret').map((f) => f.sha256),
      [envs[4], ...sameTime, envs[0]].map((s) => sha(s).slice(0, 12)),
    );
  });
});

test('--since keeps lines at or after the instant; a line exactly at it is read', async () => {
  await withSandbox((sb) => {
    const S = (n) => 'sk_' + 'live_' + rep(String(n), 16);
    write(sb.claude, 'a.jsonl', [
      cu('2026-11-02T23:59:59.999Z', S(1)),
      cu('2026-11-03T00:00:00.000Z', S(2)),
      cu('2026-11-03T10:00:00.500Z', S(3)),
      cu('2026-11-03T12:00:00+02:00', S(4)),
    ]);
    write(sb.codex, 'b.jsonl', [
      cxMsg('2026-11-02T23:00:00Z', 'assistant', [{ type: 'output_text', text: S(5) }]),
      cxMsg('2026-11-03T01:00:00+01:00', 'assistant', [{ type: 'output_text', text: S(6) }]), // 00:00Z
    ]);
    const names = (j) => j.findings.map((f) => f.sha256).sort();
    const shas = (...ns) => ns.map((n) => sha(S(n)).slice(0, 12)).sort();
    assert.deepEqual(names(scan(sb, ['--since', '2026-11-03'])), shas(2, 3, 4, 6));
    assert.deepEqual(names(scan(sb, ['--since', '2026-11-03T00:00:00.000Z'])), shas(2, 3, 4, 6));
    assert.deepEqual(names(scan(sb, ['--since', '2026-11-03T00:00:00.001Z'])), shas(3, 4));
    assert.deepEqual(names(scan(sb, ['--since', '2026-11-03T10:00:00Z'])), shas(3, 4));
    assert.deepEqual(names(scan(sb, ['--since', '2026-11-03T10:00:00.5Z'])), shas(3));
    assert.deepEqual(names(scan(sb, ['--since', '2026-11-04'])), []);
    assert.deepEqual(names(scan(sb)), shas(1, 2, 3, 4, 5, 6));
    const late = scan(sb, ['--since', '2026-11-04']);
    assert.deepEqual(late.scanned, { claude: 1, codex: 1 }); // files whose lines are all before --since still count
    assert.equal(late.since, '2026-11-04T00:00:00.000Z');
  });
});

test('count, sessions, first and last only use lines at or after --since', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [cu(iso(10), GITHUB), cu(iso(100), GITHUB), cu(iso(200), GITHUB)]);
    write(sb.claude, 'b.jsonl', [cu(iso(20), GITHUB)]);
    const f = scan(sb, ['--since', '2026-11-03T10:01:00Z']).findings[0];
    assert.equal(f.count, 2);
    assert.equal(f.sessions, 1);
    assert.equal(f.first, iso(100));
    assert.equal(f.last, iso(200));
  });
});

// ------------------------------------------------------------------ output forms

test('the plain report is laid out line by line as stated', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [
      cu('2026-05-01T10:00:00.000Z', `key ${ANTHROPIC}`, { cwd: '/home/p/shop' }),
      ca('2026-05-01T10:05:00.000Z', [{ type: 'text', text: ANTHROPIC }]),
      cu('2026-05-01T10:06:00.000Z', JWT),
    ]);
    const r = run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex]);
    assert.equal(r.code, 0);
    assert.equal(r.err, '');
    const fp = (s) => s.slice(0, 4) + '…' + s.slice(-4);
    assert.equal(
      r.out,
      [
        'agent-leaks found 2 secrets',
        '',
        `anthropic-key  ${fp(ANTHROPIC)}  sha256:${sha(ANTHROPIC).slice(0, 12)}`,
        '  seen 2 times in 1 session',
        '  first 2026-05-01T10:00:00.000Z  last 2026-05-01T10:05:00.000Z',
        '  agent: claude',
        '  project: shop',
        '  in: prompt, agent_message',
        '',
        `jwt  ${fp(JWT)}  sha256:${sha(JWT).slice(0, 12)}`,
        '  seen 1 time in 1 session',
        '  first 2026-05-01T10:06:00.000Z  last 2026-05-01T10:06:00.000Z',
        '  agent: claude',
        '  project: shop',
        '  in: prompt',
        '',
      ].join('\n'),
    );
    assert.ok(!r.out.includes('\u001b'));
  });
});

test('the plain report: one secret, no project, several agents, plural forms', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [cu(iso(1), GITHUB)]);
    write(sb.claude, 'b.jsonl', [cu(iso(2), GITHUB)]);
    write(sb.codex, 'c.jsonl', [cxMsg(iso(3), 'assistant', [{ type: 'output_text', text: GITHUB }])]);
    const r = run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex]);
    const fp = GITHUB.slice(0, 4) + '…' + GITHUB.slice(-4);
    assert.equal(
      r.out,
      [
        'agent-leaks found 1 secret',
        '',
        `github-token  ${fp}  sha256:${sha(GITHUB).slice(0, 12)}`,
        '  seen 3 times in 3 sessions',
        `  first ${iso(1)}  last ${iso(3)}`,
        '  agent: claude, codex',
        '  project: -',
        '  in: prompt, agent_message',
        '',
      ].join('\n'),
    );
  });
});

test('no findings: one line in the plain report, and a clean JSON report', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [cu(iso(1), 'nothing to see')]);
    const r = run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex]);
    assert.equal(r.out, 'agent-leaks found no secrets\n');
    assert.equal(r.code, 0);
    const j = JSON.parse(run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex, '--json']).out);
    assert.deepEqual(j, { tool: 'agent-leaks', version: '0.1.0', since: null, kinds: KINDS, scanned: { claude: 1, codex: 0 }, total: 0, findings: [] });
  });
});

test('--json prints exactly one JSON object with all the stated fields and types', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [cu(iso(1), ANTHROPIC, { cwd: '/p/shop' })]);
    const r = run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex, '--json', '--since', '2026-01-01']);
    assert.equal(r.code, 0);
    assert.equal(r.err, '');
    const j = JSON.parse(r.out);
    assert.ok(r.out.endsWith('\n'));
    assert.equal(j.tool, 'agent-leaks');
    assert.equal(j.version, '0.1.0');
    assert.equal(j.since, '2026-01-01T00:00:00.000Z');
    assert.deepEqual(j.kinds, KINDS);
    assert.deepEqual(j.scanned, { claude: 1, codex: 0 });
    assert.equal(j.total, 1);
    assert.equal(j.findings.length, 1);
    const f = j.findings[0];
    for (const field of ['kind', 'fingerprint', 'sha256', 'length', 'count', 'sessions', 'first', 'last', 'agents', 'projects', 'places']) {
      assert.ok(field in f, field);
    }
    assert.equal(typeof f.length, 'number');
    assert.ok(Number.isInteger(f.count) && Number.isInteger(f.sessions));
    assert.ok(Array.isArray(f.agents) && Array.isArray(f.projects) && Array.isArray(f.places));
  });
});

test('--fail-on exits 1 when a secret is reported and 0 otherwise; the report is printed all the same', async () => {
  await withSandbox((sb) => {
    write(sb.claude, 'a.jsonl', [cu(iso(1), ANTHROPIC)]);
    const base = ['--claude-dir', sb.claude, '--codex-dir', sb.codex];
    const hit = run(sb, [...base, '--fail-on']);
    assert.equal(hit.code, 1);
    assert.match(hit.out, /^agent-leaks found 1 secret\n/);
    const hitJson = run(sb, [...base, '--fail-on', '--json']);
    assert.equal(hitJson.code, 1);
    assert.equal(JSON.parse(hitJson.out).total, 1);
    assert.equal(run(sb, [...base]).code, 0);
    // after --kind: a finding of another kind is not reported, so no failure
    const filtered = run(sb, [...base, '--fail-on', '--kind', 'jwt']);
    assert.equal(filtered.code, 0);
    assert.equal(filtered.out, 'agent-leaks found no secrets\n');
    assert.equal(run(sb, [...base, '--fail-on', '--kind', 'anthropic-key']).code, 1);
    // before --since: nothing read, no failure
    assert.equal(run(sb, [...base, '--fail-on', '--since', '2027-01-01']).code, 0);
  });
});

// ------------------------------------------------------------------ safety

function snapshot(dir) {
  const out = {};
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) { out[p] = 'dir'; walk(p); } else out[p] = `${st.size}:${st.mtimeMs}:${sha(readFileSync(p, 'utf8'))}`;
    }
  };
  walk(dir);
  return out;
}

test('no secret, no middle part of one and no path is ever printed; nothing is written', async () => {
  await withSandbox((sb) => {
    const secrets = [PEM, ANTHROPIC, OPENAI, AWS_ID, AWS_SECRET, GITHUB, GITHUB_PAT, SLACK, STRIPE, GOOGLE, JWT, 'hunter2-hunter2-hunter2'];
    write(sb.claude, 'secretproj/a.jsonl', [
      cu(iso(1), secrets.join('\n') + '\nDB_' + 'PASSWORD=hunter2-hunter2-hunter2', { cwd: '/home/p/shop' }),
      '{"type":"user","timestamp":"' + iso(2) + '","message":{"content":"' + ANTHROPIC + '"',
    ]);
    write(sb.codex, 'x/b.jsonl', [cxMsg(iso(1), 'assistant', [{ type: 'output_text', text: GITHUB }])]);
    const beforeLogs = snapshot(sb.root);
    const all = [
      run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex]),
      run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex, '--json', '--fail-on']),
      run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex, '--bogus']),
      run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex, '--kind', 'x' + ANTHROPIC]),
      run(sb, ['--claude-dir', sb.claude, '--codex-dir', sb.codex, '--since', ANTHROPIC]),
      run(sb, [ANTHROPIC]),
      run(sb, ['--help']),
    ];
    for (const r of all) {
      const text = r.out + '\n' + r.err;
      for (const s of secrets) {
        const middle = s.length > 24 ? s.slice(6, -6) : s.slice(3, -3);
        assert.ok(!text.includes(middle), `middle of ${s.slice(0, 4)} printed`);
        assert.ok(!text.includes(s), 'secret printed');
      }
      assert.ok(!text.includes(sb.root), 'a path was printed');
      assert.ok(!text.includes('secretproj'), 'a path was printed');
    }
    const afterLogs = snapshot(sb.root);
    assert.deepEqual(afterLogs, beforeLogs); // logs, home and the current folder are unchanged
    assert.deepEqual(readdirSync(sb.cwd), []);
    assert.deepEqual(readdirSync(sb.home), []);
  });
});

// ------------------------------------------------------------------ speed

test('it stays quick on tens of thousands of lines', async () => {
  await withSandbox((sb) => {
    const lines = [];
    for (let i = 0; i < 40000; i++) {
      const ts = new Date(Date.UTC(2026, 10, 3, 10, 0, 0) + i * 1000).toISOString();
      const m = i % 8;
      if (m === 0) lines.push(cu(ts, `please look at file number ${i} and tell me what it does`, i === 0 ? { cwd: '/w/big' } : {}));
      else if (m === 1) lines.push(ca(ts, [{ type: 'text', text: `Sure, here is a long answer about item ${i}. ` + 'lorem ipsum dolor sit amet '.repeat(20) }]));
      else if (m === 2) lines.push(ca(ts, [toolUse({ command: `cat src/file${i}.js`, description: 'show the file' })]));
      else if (m === 3) lines.push(cu(ts, [toolResult('const x = 1;\n'.repeat(40) + 'key=abc\nAPI_KEYS=notasecret\n')]));
      else if (m === 4 && i % 400 === 4) lines.push(cu(ts, [toolResult(`GITHUB_${'TOKEN'}=${GITHUB}\nDB_${'PASSWORD'}=pw-${i % 7}-abcdefgh\n`)]));
      else if (m === 5) lines.push(ca(ts, [{ type: 'thinking', thinking: 'hmm '.repeat(50) }]));
      else if (m === 6) lines.push({ type: 'summary', summary: 'x', timestamp: ts });
      else lines.push(cu(ts, 'ok thanks'));
    }
    write(sb.claude, 'p/big.jsonl', lines);
    write(sb.codex, 'big.jsonl', lines.slice(0, 20000).map((l, i) => cx(l.timestamp ?? iso(0), {
      type: i % 3 === 0 ? 'function_call_output' : 'message', role: 'assistant', output: 'x=1\n'.repeat(30),
      content: [{ type: 'output_text', text: `answer ${i}` }],
    })));
    const started = Date.now();
    const j = scan(sb);
    const ms = Date.now() - started;
    assert.ok(ms < 20000, `took ${ms} ms`);
    assert.equal(j.findings.find((f) => f.kind === 'github-token').count, 100);
    assert.deepEqual(j.scanned, { claude: 1, codex: 1 });
  });
});
