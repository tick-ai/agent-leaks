# agent-leaks

**Find the secrets your AI agent saw, in the Claude Code and Codex session logs on your machine, and see each one once, without ever printing it.**

```sh
npx github:tick-ai/agent-leaks
```

```
$ npx github:tick-ai/agent-leaks
agent-leaks found 2 secrets

anthropic-key  sk-a…ZnQ1  sha256:3f9a1c7e02bd
  seen 4 times in 2 sessions
  first 2026-10-28T09:14:03.120Z  last 2026-11-03T16:40:55.004Z
  agent: claude, codex
  project: shop
  in: prompt, tool_result

env-secret  hunt…ter2  sha256:a1b2c3d4e5f6
  seen 1 time in 1 session
  first 2026-11-01T08:00:12.000Z  last 2026-11-01T08:00:12.000Z
  agent: claude
  project: api, shop
  in: tool_result
```

(The example is made up to show the layout; the secrets are not real.)

## Why

When an agent runs `cat .env`, reads a config file or prints the environment, the secret goes into
the session log on your disk, and to the model provider. Nobody looks. agent-leaks scans the local
session logs of Claude Code and Codex and reports every secret they hold, once each, with enough to
recognise it and to compare two findings, and never the secret itself. Run it once, then rotate your keys.

* **Local.** It reads local files and sends nothing anywhere. It needs no network and nothing
  installed: plain Node 22, only Node's built-in modules.
* **Safe.** It never prints a secret in full, and never changes a log. It writes nothing anywhere:
  no file, no log, no cache.
* **Quick.** Tens of thousands of log lines take a moment.

## Run it

```sh
npx github:tick-ai/agent-leaks            # straight from GitHub
node agent-leaks.mjs                      # from a clone of this repository
```

It is not on npm yet, so `npx agent-leaks` does not work; use the `github:` form above.

```
agent-leaks [--claude-dir <dir>] [--codex-dir <dir>] [--since <date>] [--kind <kind>]...
            [--json] [--fail-on]
```

| option | meaning |
| --- | --- |
| `--claude-dir <dir>` | The folder of Claude Code logs. Default: `.claude/projects` in the home folder (`os.homedir()`, which follows `$HOME`, or `%USERPROFILE%` on Windows). |
| `--codex-dir <dir>` | The folder of Codex logs. Default: `.codex/sessions` in the home folder. |
| `--since <date>` | Only read lines from this time on. Either a date `YYYY-MM-DD` (meaning `00:00:00.000` UTC of that day) or a UTC time `YYYY-MM-DDTHH:MM:SS[.f]Z` (`.f` is one to three digits). It must be a real date and time in the year 1970 or later; anything else (another form, a time zone offset, `2026-02-30`, an empty value) is a usage error. |
| `--kind <kind>` | Report only secrets of this kind (the names are listed below). May be given several times. It only filters the report: it never changes which kind a secret has or which secrets are found. Any other value is a usage error. Default: all kinds. |
| `--json` | Print the report as JSON instead of the plain report. |
| `--fail-on` | A flag with no value. Exit with status 1 when the report holds at least one finding (after `--kind`), so that a CI job fails. The report is printed all the same. |
| `--help`, `-h` | Print the usage on stdout and exit 0. It wins over every usage error. |

* A folder that does not exist, cannot be read, or is not a folder is no sessions, not an error.
  Giving one of the two folder options does not change the default of the other.
* A value-taking option also accepts `--option=value`. Its value is the next argument, whatever it
  looks like (`--claude-dir --json` means a folder named `--json`). Given more than once, the last
  one counts, except `--kind`. A flag with `=value` (`--json=1`) is an unknown option. There are no
  positional arguments.
* A usage error (an unknown option, a positional argument, a missing value, a bad `--since`, an
  unknown `--kind`) prints a message on stderr, prints nothing on stdout, and exits with status 2.

## What it reads

Every file whose name ends in `.jsonl` (lower case) under each folder, at any depth. Symbolic links
are not followed and other files are ignored. Files under `--claude-dir` are read as Claude Code logs
and files under `--codex-dir` as Codex logs, whatever the content. A file that cannot be read is
skipped. Blank lines, lines that are not JSON, JSON that is not an object, and fields that are
missing or of another type are skipped, never an error.

A **session** is one log file. A line is read only if its `timestamp` is a string that `Date.parse`
reads; that is its **instant**. With `--since`, a line before the `--since` instant is not read (a
line at exactly that instant is read).

Only these **texts** are searched, each on its own (a secret never spans two texts):

* **Claude Code**: lines of `type` `user` or `assistant` with an object `message`. A line whose
  `isMeta` is `true` gives nothing. A user line with string content gives a `prompt`; a user line with
  array content gives one `tool_result` text for each `tool_result` block (its string content, or the
  `text` of its blocks joined with `\n`); an assistant line gives an `agent_message` for each `text`
  block and a `tool_input` text for every string found anywhere in a `tool_use` block's `input`.
* **Codex**: `response_item` lines. Messages by `user` (a `prompt`, unless the text starts with `<`,
  which is Codex's own context) and by `assistant` (an `agent_message`) from the `input_text`,
  `output_text` and `text` blocks joined with nothing between; `function_call` arguments and
  `custom_tool_call` input (`tool_input`); `function_call_output` and `custom_tool_call_output`
  (`tool_result`). A string that holds a JSON object or array stands for it.

It does **not** read thinking blocks, tool names, meta lines, lines without a readable time, other
event types, or anything else the logs hold in other shapes than these. The project of a file is the
last folder name of its first `cwd` (Claude Code: first non-empty `cwd` of the lines it reads, also
before `--since`; Codex: from `session_meta`).

## What is a secret

Fixed patterns, tried in this order. A match that shares even one character with a match of an
earlier kind in the same text is dropped, so `ANTHROPIC_API_KEY=sk-ant-...` is one `anthropic-key`
and never also an `env-secret`.

| kind | pattern (JavaScript) |
| --- | --- |
| `private-key` | a PEM block from its BEGIN line to its END line (to the end of the text when there is no END line) |
| `anthropic-key` | `/\bsk-ant-[A-Za-z0-9_-]{8,}/g` |
| `openai-key` | `/\bsk-[A-Za-z0-9_-]{20,}/g` |
| `aws-access-key` | `/\b(?:AKIA\|ASIA)[0-9A-Z]{16}\b/g` |
| `aws-secret-key` | 40 characters of `[A-Za-z0-9/+]` (not part of a longer run) with a lower case letter, an upper case letter and a digit, that lies within 200 characters of an `aws-access-key` in the same text |
| `github-token` | `/\b(?:gh[pousr]_[A-Za-z0-9]{36,}\|github_pat_[A-Za-z0-9_]{22,})/g` |
| `slack-token` | `/\bxox[abprs]-[A-Za-z0-9-]{10,}/g` |
| `stripe-key` | `/\b[sr]k_live_[A-Za-z0-9]{16,}/g` |
| `google-api-key` | `/\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g` |
| `jwt` | `/\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}/g` |
| `env-secret` | a line `NAME=value`, see below |

The private key pattern is `/-----BEGIN [A-Z0-9 ]*PRIVATE[ ]KEY-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE[ ]KEY-----|[\s\S]*$)/g`.

**`env-secret`**: `NAME` is upper case letters, digits and underscores, starts with a letter, ends in
`KEY`, `TOKEN`, `SECRET` or `PASSWORD`, and starts its line (after spaces, tabs and an optional
`export`). The value is the rest of the line without its leading and trailing whitespace, and then,
if it has at least two characters and starts and ends with the same quote (`"` or `'`), without the
quotes. It is a secret only if it has at least 8 characters and does not start with `$`, `<` or
`[redacted`. So `API_KEY=abc12345` and `API_KEY="abc12345"` are the same secret.

**Limits.** The patterns are fixed. Nothing else is a secret: a string just short of a pattern, a
40-character hex hash, a lower case `api_key=...`, `"api_key": "..."` in JSON, `API_KEYS=...` or a
comment are not findings. There is no entropy measure and no guessing. **agent-leaks cannot find
every secret, so a clean report is not proof that no secret was seen.**

## Findings and the fingerprint

A distinct secret is the pair (kind, secret). All its hits, in all texts read, are one finding, across
files, agents and projects. The fingerprint is the secret's first 4 and last 4 characters around `…`
(U+2026), counted in Unicode characters; a secret of fewer than 16 characters (only possible for
`env-secret`, `anthropic-key` and `slack-token`) shows the first 2 and the last 2. A key block's
fingerprint is therefore `----…----`. `sha256` is the first 12 hexadecimal digits of the SHA-256 of
the secret, so you can tell whether two findings are the same secret.

Findings are sorted by kind (in the order of the table), then by the first time, then by the full SHA-256.

## The report

Without `--json`, with no finding, stdout is the one line `agent-leaks found no secrets`. With findings
it starts with `agent-leaks found N secret` (`secrets` when N is not 1), then for every finding a
blank line and:

```
<kind>  <fingerprint>  sha256:<sha256>
  seen <count> time(s) in <sessions> session(s)
  first <first>  last <last>
  agent: <agents joined with ", ">
  project: <projects joined with ", ", or - when there is none>
  in: <places joined with ", ">
```

`first` and `last` are UTC instants (`YYYY-MM-DDTHH:MM:SS.mmmZ`) of the lines with a hit. No colour, no
escape characters.

## JSON

`--json` prints exactly one JSON object:

```json
{
  "tool": "agent-leaks",
  "version": "0.1.0",
  "since": null,
  "kinds": ["private-key", "anthropic-key", "…all eleven, or those given with --kind"],
  "scanned": {"claude": 3, "codex": 1},
  "total": 1,
  "findings": [
    {"kind": "anthropic-key", "fingerprint": "sk-a…WdRc", "sha256": "0123456789ab", "length": 37,
     "count": 3, "sessions": 2, "first": "2026-05-01T10:00:00.000Z", "last": "2026-05-01T10:05:00.000Z",
     "agents": ["claude"], "projects": ["shop"], "places": ["prompt", "agent_message"]}
  ]
}
```

* `since` is `null` or the `--since` instant. `kinds` is the set of kinds reported, in the order of the table.
* `scanned` is the number of `.jsonl` files that could be read under each folder, also files without a
  secret and files whose lines are all before `--since`.
* `length` is the number of Unicode characters of the secret; `count` the number of hits (every
  appearance counts); `sessions` the number of log files with a hit; `agents` is among `claude` and
  `codex`; `projects` are sorted; `places` are among `prompt`, `agent_message`, `tool_input` and
  `tool_result`, in that order.

## Exit codes

| status | meaning |
| --- | --- |
| 0 | done, also with no sessions at all, and with `--help` |
| 1 | `--fail-on` and at least one finding in the report |
| 2 | usage error (nothing on stdout) |

## What you should know

* It reads only local files, sends nothing anywhere, never prints a secret in full and never changes a log.
* A secret found in a log has already been sent to the model provider. **The remedy is to rotate it.**
* The SHA-256 prefix of a weak secret (a short password) can be guessed by someone who holds the
  report; share reports with care.
* It finds secrets only by the patterns above, and it does not read what the logs do not hold in the
  shapes named here.

## Tests

```sh
node --test
```

## Where it came from

Built by agents on TickHub, as TickHub job `91e29b5a-04e2-4314-be24-6b1fcd3a5e70`. The job, the
hand-ins and the receipt are on TickHub's public log:
https://tick.company/hub/#/job/91e29b5a-04e2-4314-be24-6b1fcd3a5e70

`docs/the-job.md` is the job as it was given.

AI does the work. Tick makes it trustworthy. https://tick.company

## Licence

Apache-2.0, Copyright 2026 Parsa Esmaeili, see `LICENSE`.
