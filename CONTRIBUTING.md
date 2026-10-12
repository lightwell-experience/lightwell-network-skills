# Contributing

This repository is a collection of skills for using and interacting with Lightwell.
Each skill teaches an agent (or a person) how to perform one task reliably — querying an
API, following a workflow, applying a pattern.

## What belongs here

Add a skill when:

- The technique isn't obvious and you'd reference it again.
- It applies broadly to working with Lightwell (not a one-off script).
- Others would benefit from it.

Don't add a skill for one-off solutions, standard practices documented elsewhere, or
things better expressed as a plain script.

## Repository layout

```
.claude/skills/<name>/
    SKILL.md              # required — the skill itself
    scripts/              # optional — bundled, co-located helper scripts
    <reference>.md        # optional — heavy reference split out of SKILL.md
README.md                 # top-level overview + skill table
SKILLS.md                 # the skill catalog (keep in sync)
```

Skills live in a **flat namespace** — one directory per skill, named for what it does.
Keep each skill self-contained: co-locate its scripts and reference files under its own
directory so it can be copied or installed as a unit.

## Authoring a `SKILL.md`

### Frontmatter

YAML frontmatter, max 1024 characters total:

```yaml
---
name: skill-name
description: Use when <specific triggering conditions and symptoms>.
user-invocable: true   # optional — only if the skill should run as /skill-name
---
```

- **`name`** — letters, numbers, and hyphens only. Match the directory name. Prefer
  verb-first / active names (`fetch-advisories`, not `advisory-fetcher`).
- **`description`** — third person, starts with **"Use when…"**, and describes *only when
  to use the skill* — the triggering conditions, symptoms, and keywords someone would
  search for. **Do not summarize the skill's steps or workflow** in the description; that
  causes agents to follow the summary instead of reading the full skill. Keep it under
  ~500 characters.

```yaml
# ❌ summarizes workflow
description: Fetches packages by calling the API with a token then prints a table.

# ✅ triggering conditions only
description: Use when asked to look up, fetch, query, or list Lightwell package information.
```

### Body

Write for an agent discovering the skill under time pressure. Put searchable keywords
(error messages, symptoms, tool names) early and often. A typical structure:

- **Overview** — what it is and the core idea, in a sentence or two.
- **Setup / prerequisites** — credentials, roles, entitlements.
- **Usage** — the commands or steps, with a concrete, runnable example.
- **Reference** — flags, filters, endpoints (a table scans well).
- **Troubleshooting** — symptom → cause/fix table.

Guidelines:

- One excellent, runnable example beats many mediocre or multi-language ones.
- Invoke bundled scripts through their interpreter in prose (`python3 scripts/tool.py`),
  never by bare path — some packagers strip the executable bit.
- Prefer stdlib / no third-party dependencies in bundled scripts where practical, so a
  skill runs without an install step. (See `network-api` for the house style.)
- Move a reference section over ~100 lines into its own file in the skill directory and
  link to it, rather than bloating `SKILL.md`.

### Skill types

Tag your skill (in `SKILLS.md`) as one of:

- **Reference** — API or command documentation (e.g. `network-api`).
- **Technique** — a concrete method with steps.
- **Pattern** — a way of thinking about a class of problems.

## Secrets

Never commit credentials. Read secrets from environment variables and prefer them over
CLI flags (flags land in shell history). Check that nothing sensitive is staged before
you commit.

## Before you open a PR

- [ ] `SKILL.md` has valid frontmatter (`name`, `description`; `user-invocable` if relevant).
- [ ] `description` starts with "Use when…" and names triggers, not workflow steps.
- [ ] Bundled scripts run as documented, invoked via their interpreter.
- [ ] Added the skill to the table in [`SKILLS.md`](SKILLS.md).
- [ ] No secrets committed.
- [ ] You tested that the skill actually accomplishes its task.
