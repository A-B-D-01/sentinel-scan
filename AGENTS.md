# SentinelScan — AI Development Instructions

## Before coding

Read:

1. README.md
2. docs/PROJECT_CONTEXT.md
3. docs/CURRENT_STATE.md
4. docs/DEVELOPMENT_HISTORY.md
5. docs/ROADMAP.md

Then inspect the actual relevant source files.

---

## Rules

- Preserve working functionality.
- Do not rewrite unrelated files.
- Do not remove localhost authorization.
- Do not perform unauthorized scanning.
- Do not expose secrets.
- Never hardcode .env credentials.
- Do not fabricate vulnerability findings.
- Preserve evidence and confidence.
- Prefer accuracy over feature count.
- Test changes before moving to another task.
- Keep documentation synchronized with implementation.

---

## Coding Style

The project is a beginner/intermediate Python Flask project.

Prefer:

- readable Python
- clear functions
- descriptive variable names
- simple architecture
- explicit error handling

Avoid unnecessary abstraction.

---

## File Modification

Before modifying a file:

1. Read the existing file.
2. Understand its current structure.
3. Make the smallest safe change.

When a file requires major modification, provide/produce the complete updated file.

---

## Security

This scanner is restricted to authorized local targets.

Never remove or weaken:

- localhost restriction
- 127.0.0.1 restriction

Do not introduce functionality intended for unauthorized scanning.

---

## Testing

After changes:

1. Start the local vulnerable lab.
2. Start SentinelScan.
3. Run relevant tests.
4. Verify dashboard behavior.
5. Verify database behavior when applicable.
6. Verify reports when applicable.

---

## Documentation

After completing a significant feature:

Update:

- docs/CURRENT_STATE.md
- docs/DEVELOPMENT_HISTORY.md
- docs/ROADMAP.md

Update README.md when user-facing architecture or setup changes.

---

## Current Immediate Task

Improve Comparison Module (Phase 3).

Implement evidence changes, confidence changes, severity increase/decrease tracking, and a comparison summary.