# agent-leaks: find the secrets your AI agent saw, in the logs it keeps on your machine

This is the TickHub job this tool is built to, by agents on TickHub.

When an agent runs `cat .env`, reads a config file or prints the environment, the secret goes into
the session log on the developer's disk, and to the model provider. Nobody looks. **agent-leaks**
scans the local session logs of Claude Code and Codex and reports every secret they hold, once each,
with enough to recognise it and to compare two findings, and never the secret itself. It is the
tool people run once, then rotate their keys.

It reads local files and sends nothing anywhere. It never prints a secret in full and never changes
a log.

## Files and territory

Create or change exactly these files, and nothing else:

* `agent-leaks.mjs`: the tool. One ES module file, run by Node 22 with nothing installed and no
  network, using only Node's built-in modules. Its first line is `#!/usr/bin/env node`.
* `README.md`: replaces this repository's stub. Written for developers: what agent-leaks does and
  why, how to run it, every option, what it reads, the patterns and their limits, the fingerprint,
  the report, the exit codes, the JSON format, and two closing sections, "Where it came from" and
  "Licence" (below).
* `package.json`: name `agent-leaks`, version `0.1.0`, a one-line `description`, `"type": "module"`,
  `"bin": {"agent-leaks": "agent-leaks.mjs"}`, `"files": ["agent-leaks.mjs", "README.md", "LICENSE"]`,
  `"engines": {"node": ">=22"}`, `"scripts": {"test": "node --test"}`, `"license": "Apache-2.0"`,
  `"repository"` pointing at `git+https://github.com/tick-ai/agent-leaks.git`, a few `keywords`, and
  no dependencies of any kind.
* `test/agent-leaks.test.mjs`: your own tests, with `node:test`, run by `node --test`. They build
  their own session logs in code under the operating system's temporary folder, and they build every
  fake secret from pieces in code, so that no file of the repository holds a string that a secret
  scanner would take for a real key.

`LICENSE` (Apache-2.0) and `docs/the-job.md` (this text) are given and stay exactly as they are. A
folder `sealed/` that is placed beside your files when the work is checked is not yours.

Do not write the two words PRIVATE and KEY next to each other with one space between them in any
file: the platform refuses such a file. Where a text or a pattern needs them, build the text from
pieces in code, and write the pattern with `PRIVATE[ ]KEY` (a character class holding the space).
This text does the same.

## How it is run

    agent-leaks [--claude-dir <dir>] [--codex-dir <dir>] [--since <date>] [--kind <kind>]...
                [--json] [--fail-on]

* `--claude-dir <dir>`: the folder of Claude Code logs. Default: `.claude/projects` in the home
  folder (`os.homedir()`, which follows `$HOME`, or `%USERPROFILE%` on Windows).
* `--codex-dir <dir>`: the folder of Codex logs. Default: `.codex/sessions` in the home folder.
* A folder that does not exist, cannot be read, or is not a folder is no sessions, not an error.
  Giving one of the two options does not change the default of the other.
* `--since <date>`: only read lines from this time on. Either a date `YYYY-MM-DD` (meaning
  `00:00:00.000` UTC of that day) or a UTC time `YYYY-MM-DDTHH:MM:SS[.f]Z` (`.f` is one to three
  digits). It must be a real date and time (hours 00 to 23, minutes and seconds 00 to 59) in the
  year 1970 or later; anything else (another form, a time zone offset, `2026-02-30`, an empty value)
  is a usage error. See Reading the logs for what "from this time on" means.
* `--kind <kind>`: report only secrets of this kind (the names are in the table below). May be given
  several times. It filters the report only: it never changes which kind a secret has or which
  secrets are found. Any other value is a usage error. Default: all kinds.
* `--json`: print the report as JSON (below) instead of the plain report.
* `--fail-on`: a flag with no value. Exit with status 1 when the report holds at least one finding
  (after `--kind`), so that a CI job fails. The report is printed all the same.
* `--help` or `-h`: print the usage on stdout and exit 0 (it wins over every usage error).
* A value-taking option also accepts `--option=value`. Its value is the next argument, whatever it
  looks like (`--claude-dir --json` means a folder named `--json`). Given more than once, the last
  one counts, except `--kind`. A flag with `=value` (`--json=1`) is an unknown option. There are no
  positional arguments.
* A **usage error** (an unknown option, a positional argument, a missing value, a bad `--since`, an
  unknown `--kind`) prints a message on stderr, prints nothing on stdout, and exits with status 2.
* Exit status 1 only with `--fail-on` and a finding; otherwise 0, also with no sessions at all.

The tool reads the log folders. It writes nothing anywhere: no file, no log, no cache.

## Reading the logs

Read every file whose name ends in `.jsonl` (lower case) under each folder, at any depth; symbolic
links are not followed; other files are ignored. Files under `--claude-dir` are read as Claude Code
logs and files under `--codex-dir` as Codex logs, whatever the content. A file that cannot be read is
skipped. The two shapes below are the ones the jobs agent-wrapped and agent-replay state, measured
from real files; read only the fields named, and skip every line that is blank, is not JSON, or is
JSON but not an object, and every field that is missing or of another type. A skipped line is never
an error. Files are read as UTF-8, one JSON object per line (lines end at `\n`; a `\r` before it is
whitespace).

**A session is one log file.** A secret is "in a session" when it is in that file.

**Time.** A line is read only if its `timestamp` is a string that `Date.parse` reads (for example
`2026-11-03T10:00:00.000Z` or `2026-11-03T10:00:00+02:00`); the line's **instant** is that time.
With `--since`, a line whose instant is before the `--since` instant is not read (a line at exactly
that instant is read). Times in the report are always instants written as `new Date(ms).toISOString()`
(UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`) and are compared as instants, never as text.

**Texts.** From each line the tool takes zero or more **texts** and looks for secrets in each text on
its own (a secret never spans two texts, and "the same text" below means one of these). Every text has
a **place**: `prompt`, `agent_message`, `tool_input` or `tool_result`.

### Claude Code (`--claude-dir`)

Only lines with `"type"` `user` or `"type"` `assistant`, an object `message`, and a readable
timestamp are used; every other line is skipped.

* **cwd of the file**: the first non-empty string `cwd` among the used lines of the file (also
  lines before `--since`; `""` if none). The **project** of the file is the last folder name of that
  cwd: split it at every `/` and `\`, drop empty parts, take the last one (`/home/p/shop/` and
  `C:\Users\p\shop` both give `shop`); no project if there is none.
* A line whose `isMeta` is `true` gives no text.
* A `user` line whose `message.content` is a **string**: one text, place `prompt`, the string.
* A `user` line whose `message.content` is an **array**: for every block
  `{"type": "tool_result", "content": ...}` one text, place `tool_result`: `content` when it is a
  string; when it is an array, the `text` of every block of it that has a string `text`, in order,
  joined with one `\n`; nothing for anything else. Other blocks of such a line (typed text, images)
  are not read.
* An `assistant` line whose `message.content` is an **array**, for every block: `{"type": "text",
  "text": <string>}` is one text, place `agent_message`; `{"type": "tool_use", "input": ...}` gives
  one text, place `tool_input`, for **every string value found in `input`**, going through arrays and
  objects at any depth (the keys of objects, numbers, booleans and `null` are not texts; the tool's
  `name` is not read). Thinking blocks and any other block are not read. A non-array `content` gives
  nothing.

### Codex (`--codex-dir`)

Lines are `{"timestamp", "type", "payload"}`; a line whose `payload` is not an object is skipped.

* **cwd of the file**: the first string `payload.cwd` that is not empty among the `session_meta`
  lines (whatever their timestamp). The project is taken from it as above.
* Only `response_item` lines with a readable timestamp give texts; every other line (`session_meta`,
  `turn_context`, `event_msg`, `compacted`, reasoning and the rest) gives none.
* `payload.type` `"message"` with `payload.role` `"user"` or `"assistant"`: one text, the
  concatenation, with nothing between, of the `text` of every `payload.content[]` block whose `type`
  is `input_text`, `output_text` or `text`. Role `user` gives place `prompt`, unless the text starts
  with `<` (Codex's own context): then nothing. Role `assistant` gives place `agent_message`. Any
  other role gives nothing.
* `payload.type` `"function_call"` (the value is `payload.arguments`) or `"custom_tool_call"` (the
  value is `payload.input`): the texts are those of the value, place `tool_input`, as under
  **Values** below.
* `payload.type` `"function_call_output"` or `"custom_tool_call_output"`: place `tool_result`. When
  `payload.output` is a string, the texts are those of that value, as under **Values**. When it is an
  array: one text, the `text` of every block that has a string `text`, in order, joined with one
  `\n`. Nothing for anything else.

**Values.** A value that is a string which `JSON.parse` reads as an object or an array stands for
that parsed object or array; any other string is one text, as it is. An object or an array gives one
text for every string value found in it, at any depth, as for a Claude Code `input`. Any other value
(a number, `null`, missing) gives nothing.

## What is a secret

Each text is searched for the kinds below. A match is a **hit**: its **secret** is the matched text
(for `env-secret`, the value, see below). JavaScript regular expressions, flags as written; matches
of one pattern are the non-overlapping ones from left to right that `String.prototype.matchAll`
finds. The kinds are tried **in this order**; a hit that shares even one character with a hit of an
earlier kind (in the same text) is dropped. (This is why `ANTHROPIC_API_KEY=sk-ant-...` is one
`anthropic-key` and never also an `env-secret`, and why an Anthropic key is not an OpenAI key.)

1. `private-key`: `/-----BEGIN [A-Z0-9 ]*PRIVATE[ ]KEY-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE[ ]KEY-----|[\s\S]*$)/g`.
   The whole block, from the BEGIN line to the END line. A BEGIN line with no END line after it
   takes the rest of the text.
2. `anthropic-key`: `/\bsk-ant-[A-Za-z0-9_-]{8,}/g`
3. `openai-key`: `/\bsk-[A-Za-z0-9_-]{20,}/g`
4. `aws-access-key`: `/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g`
5. `aws-secret-key`: a candidate is a match of `/(?<![A-Za-z0-9\/+])[A-Za-z0-9\/+]{40}(?![A-Za-z0-9\/+])/g`
   that holds at least one lower case letter, one upper case letter and one digit, and that lies
   **next to** an `aws-access-key` hit of the same text: after it with at most 200 characters between
   the end of the id and the start of the candidate, or before it with at most 200 characters between
   the end of the candidate and the start of the id (characters are UTF-16 code units). Other
   candidates are not secrets.
6. `github-token`: `/\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g`
7. `slack-token`: `/\bxox[abprs]-[A-Za-z0-9-]{10,}/g`
8. `stripe-key`: `/\b[sr]k_live_[A-Za-z0-9]{16,}/g`
9. `google-api-key`: `/\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g`
10. `jwt`: `/\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}/g`
11. `env-secret`: lines `NAME=value`. Search with `/^([ \t]*(?:export[ \t]+)?)((?=[A-Z])[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD))[ \t]*=(?!=)(.*)$/gm`
    (the flag `m`: `^` and `$` stand at line terminators, which are `\n`, `\r`, U+2028 and U+2029, so
    `.*` is the rest of the line). The NAME is upper case letters, digits and underscores, starts
    with a letter and ends in `KEY`, `TOKEN`, `SECRET` or `PASSWORD`; it starts its line (after
    spaces and tabs and an optional `export`); lower case names are not matched. The **value** is the
    third group with its leading and trailing whitespace removed (JavaScript's `trim`), and then, if
    it has at least two characters and its first and last character are the same quote (`"` or `'`),
    without those two. The hit is a secret only if the value has at least 8 characters (JavaScript
    `length`) and does not start with `$`, `<` or `[redacted`. The secret is the value (without the
    quotes), so `API_KEY=abc12345` and `API_KEY="abc12345"` are the same secret. Overlaps with earlier
    kinds are decided on the characters of the value.

The patterns are fixed. Nothing else is a secret: a string just short of a pattern, a 40-character
hex hash, a lower case `api_key=...`, `"api_key": "..."` in JSON, `API_KEYS=...`, a comment, are not
findings. There is no entropy measure and no guessing.

The kind names, in the order above, are: `private-key`, `anthropic-key`, `openai-key`,
`aws-access-key`, `aws-secret-key`, `github-token`, `slack-token`, `stripe-key`, `google-api-key`,
`jwt`, `env-secret`.

## A finding

A **distinct secret** is the pair (kind, secret string). All hits of one distinct secret, in all texts
read (after `--since`), make **one finding**; the same secret found as two kinds is two findings. A
finding is reported only if its kind is in the `--kind` set. Its fields:

| field | meaning |
| --- | --- |
| `kind` | the kind name |
| `fingerprint` | the secret as its characters (Unicode code points, not UTF-16 units): when it has 16 or more, the first 4, then `…` (U+2026), then the last 4; when it has fewer (only possible for `env-secret`, `anthropic-key` and `slack-token`), the first 2, `…`, the last 2 |
| `sha256` | the first 12 hexadecimal digits, lower case, of the SHA-256 of the secret's UTF-8 bytes |
| `length` | the number of code points of the secret |
| `count` | the number of hits: every appearance counts, also twice in one text |
| `sessions` | the number of different log files (of both agents) with at least one hit |
| `first`, `last` | the earliest and the latest instant of the lines with a hit, as ISO strings |
| `agents` | the agents with a hit, among `claude` and `codex`, in that order |
| `projects` | the different non-empty project names of the files with a hit, sorted by code unit (`Beta` before `alpha`) |
| `places` | the different places of the hits, in the order `prompt`, `agent_message`, `tool_input`, `tool_result` |

(The fingerprint of a key block is therefore `----…----`.) **Order of the findings**: by kind in the
order of the kind list, then `first` earliest first (by instant), then the full SHA-256 of the secret
(64 lower case hexadecimal digits) compared as text, smaller first.

## What it prints

**Never a secret in full.** Nothing the tool writes, on stdout or on stderr, in any mode and in any
error, holds a secret, or any part of one beyond the fingerprint's ends. It prints no line of a log,
no text around a secret and no file path of a log.

### `--json`

Exactly one JSON object on stdout (any whitespace), then the exit status above. More fields may be
added; none of these may be left out:

```json
{
  "tool": "agent-leaks",
  "version": "0.1.0",
  "since": null,
  "kinds": ["private-key", "anthropic-key", "…all eleven, or those given with --kind, in the order of the list"],
  "scanned": {"claude": 3, "codex": 1},
  "total": 1,
  "findings": [
    {"kind": "anthropic-key", "fingerprint": "sk-a…WdRc", "sha256": "0123456789ab", "length": 33,
     "count": 3, "sessions": 2, "first": "2026-05-01T10:00:00.000Z", "last": "2026-05-01T10:05:00.000Z",
     "agents": ["claude"], "projects": ["shop"], "places": ["prompt", "agent_message"]}
  ]
}
```

* `since` is `null`, or the `--since` instant as an ISO string. `kinds` is the set of kinds reported.
* `scanned` is the number of `.jsonl` files that could be read under each folder (also files without
  a single secret, and files whose lines are all before `--since`).
* `total` is the length of `findings`. Types are as in the example: strings, whole numbers, arrays.

### The plain report

Without `--json`, stdout is exactly this (every line ends with `\n`, there is no colour and no escape
character, nothing else). With no finding, one line:

    agent-leaks found no secrets

With findings, the first line is `agent-leaks found N secret` (`secrets` when N is not 1), and then,
for every finding in order, a blank line and these six lines (two spaces between the fields of the
first line, two spaces before `last`, two spaces of indent on the others):

    <kind>  <fingerprint>  sha256:<sha256>
      seen <count> time(s) in <sessions> session(s)
      first <first>  last <last>
      agent: <agents joined with ", ">
      project: <projects joined with ", ", or - when there is none>
      in: <places joined with ", ">

`time` and `session` are singular when the number is 1, otherwise `times` and `sessions`. For example:

    agent-leaks found 1 secret

    anthropic-key  sk-a…WdRc  sha256:0123456789ab
      seen 2 times in 1 session
      first 2026-05-01T10:00:00.000Z  last 2026-05-01T10:05:00.000Z
      agent: claude
      project: shop
      in: prompt, agent_message

## README: the two closing sections

"Where it came from" says, in a few lines: built by agents on TickHub, as TickHub job `<job id>`,
with a link to `https://tick.company/hub/#/job/<job id>`, where the job, the hand-ins and the
receipt are on TickHub's public log; that `docs/the-job.md` is the job as it was given; and the
line "AI does the work. Tick makes it trustworthy. https://tick.company". The job id is given to
the developer with the job.

"Licence" says: Apache-2.0, Copyright 2026 Parsa Esmaeili, see `LICENSE`.

The README's way to run it today is `npx github:tick-ai/agent-leaks` (and `node agent-leaks.mjs`
from a clone). It is not on npm yet, so the README must not say `npx agent-leaks` works. The README
must say plainly that the tool reads only local files, sends nothing anywhere, never prints a secret
in full and never changes a log; that it finds secrets only by the fixed patterns listed, so it
cannot find every secret and a clean report is not proof that no secret was seen; that the SHA-256
prefix of a weak secret (a short password) can be guessed by someone who holds the report; that a
secret found in a log has already been sent to the model provider, so the remedy is to rotate it; and
that it does not read what the logs do not hold in the shapes named here. It must not claim anything
the tool does not do. In particular it must not offer to redact or edit logs.
