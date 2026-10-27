# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

> Task storage: shared Dolt SQL server. Source: `.beads/metadata.json`; no `bd dolt push/pull` in server mode.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ccf33ec3 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files
- This project's beads DB runs in server mode (central Dolt server) — there is no `dolt` git remote configured. Do NOT run `bd dolt push`/`bd dolt pull`; they will fail.

Task storage: shared Dolt SQL server. Source: `.beads/metadata.json`; no `bd dolt push/pull` in server mode.

## Session Completion

**When ending a work session**, wrap up cleanly:

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Commit** freely and proactively as work progresses — do not wait until end of session or for permission to commit
5. **Do NOT push to remote** unless the developer explicitly asks — leaving finished work committed but unpushed locally is the expected default
7. **Hand off** - Provide context for next session

**Rules:**
- Commit early and often; never leave finished work uncommitted
- Never `git push` (or `bd dolt push`) proactively — only when the developer asks in this session
<!-- END BEADS INTEGRATION -->

<!-- bd-doctor-divergence: ok -->


<!-- BEGIN WORKSHOP CAPABILITIES -->
# Качество нод, каналов и роутерного VPN

Для «проверь ноду/канал», потерь, retransmits, RTT/jitter, реконнектов или
BBR/pacing/shaper сначала читай общий навык `net-diag` в infra-docker:
[SKILL.md](C:/Users/Dee/GitHub/infra-docker/tools/skills/net-diag/SKILL.md),
[процесс](C:/Users/Dee/GitHub/infra-docker/tools/net-diag/WORKFLOW.md).
На другой машине найди локальный checkout infra-docker; не копируй методику сюда.

Здесь владелец кода MT и роутерных улик: `tools/reconnect-debug/README.md`,
watchdog, conntrack, RST и синхронные captures. Общий net-diag ссылается обратно.
Конфиги конкретного роутера и доставка —
[keenetic_config](C:/Users/Dee/GitHub/keenetic_config/AGENTS.md);
код прокси — [mihomo](C:/Users/Dee/GitHub/mihomo/FORK.md).
Диагностика не разрешает постоянный тюнинг. Сначала оцени путь без системных
изменений, затем предложи узкий эксперимент и проверь до/после в порученной области.
<!-- END WORKSHOP CAPABILITIES -->
