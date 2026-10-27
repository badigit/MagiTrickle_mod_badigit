# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:7510c1e2 -->
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

- Prefer `bd` for cross-session task tracking with dependencies/blockers
- Run `bd prime` for detailed command reference
- Commit freely and proactively as work progresses — push to remote only when the developer explicitly asks

Task storage: shared Dolt SQL server. Source: `.beads/metadata.json`; no `bd dolt push/pull` in server mode.
<!-- END BEADS INTEGRATION -->


## Build & Test

_Add your build and test commands here_

```bash
# Example:
# npm install
# npm test
```

## Architecture Overview

_Add a brief overview of your project architecture_

## Conventions & Patterns

_Add your project-specific conventions here_


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
