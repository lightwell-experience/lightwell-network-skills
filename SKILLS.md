# Skills index

Every skill in this repository lives under `.claude/skills/<name>/SKILL.md`. This file
is the catalog. When you add or rename a skill, update the table below in the same change.

| Skill | Type | User-invocable | Description |
|-------|------|:--------------:|-------------|
| [network-api](.claude/skills/network-api/SKILL.md) | Reference | ✓ | Look up, fetch, query, or list Lightwell validated, remediated, or predisclosure package, package-version, and advisory information from the `console.redhat.com` Lightwell Network API. |

## Legend

- **Type** — one of `Reference` (API/command docs), `Technique` (a concrete how-to),
  or `Pattern` (a way of thinking about a problem). See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **User-invocable** — whether the skill sets `user-invocable: true` so it can be run
  directly as `/<name>`.
